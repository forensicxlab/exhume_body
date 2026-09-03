//! **AFF (Advanced Forensic Format) native reader**
//!
//! This module provides a pure-Rust reader for **AFF v1** forensic disk images
//! (`.aff` files).  It replaces the previous implementation that shelled out to
//! the `affcat` command-line tool.
//!
//! # On-disk layout
//!
//! An AFF file starts with an 8-byte file header (`AFF10\r\n\0`), followed by a
//! sequence of **segments**.  Each segment is composed of:
//!
//! | Part           | Size            | Description                          |
//! |----------------|-----------------|--------------------------------------|
//! | **Head magic** | 4 bytes         | `AFF\0`                              |
//! | **name_len**   | 4 bytes (BE)    | Length of the segment name            |
//! | **data_len**   | 4 bytes (BE)    | Length of the data payload            |
//! | **flag**       | 4 bytes (BE)    | Segment flag (compression, type …)   |
//! | **name**       | `name_len`      | UTF-8 segment name                   |
//! | **data**       | `data_len`      | Segment data payload                 |
//! | **Tail magic** | 4 bytes         | `ATT\0`                              |
//! | **seg_len**    | 4 bytes (BE)    | Total segment length (head+…+tail)   |
//!
//! Data pages are named `page0`, `page1`, …, `pageN`.  Their flag is a bitfield
//! containing a compressed bit, a maximum-compression hint, and a compression
//! algorithm.  AFF v1 defines uncompressed, zlib, LZMA, and run-length encoded
//! zero pages.  Metadata segments such as `pagesize`, `imagesize`, and
//! `sectorsize` carry acquisition parameters.

use flate2::read::ZlibDecoder;
use log::info;
use lzma_rs::decompress::raw::{LzmaDecoder, LzmaParams, LzmaProperties};
use std::cmp::min;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

// ---- AFF constants ----------------------------------------------------------

/// 8-byte file header: `AFF10\r\n\0`
const AFF_FILE_MAGIC: [u8; 8] = [0x41, 0x46, 0x46, 0x31, 0x30, 0x0D, 0x0A, 0x00];

/// 4-byte segment head magic: `AFF\0`
const AFF_SEG_HEAD_MAGIC: [u8; 4] = [0x41, 0x46, 0x46, 0x00];

/// 4-byte segment tail magic: `ATT\0`
const AFF_SEG_TAIL_MAGIC: [u8; 4] = [0x41, 0x54, 0x54, 0x00];

/// Default page size when `pagesize` segment is absent (16 MiB).
const AFF_DEFAULT_PAGE_SIZE: u32 = 16 * 1024 * 1024;

/// AFFLIB's maximum supported decoded page size.
const AFF_MAX_PAGE_SIZE: u32 = 16 * 1024 * 1024;

/// Compressed pages cannot legitimately exceed AFFLIB's maximum decoded page
/// buffer. Bounding their encoded payload prevents a crafted segment from
/// forcing gigabytes of codec input work to produce at most one 16 MiB page.
const AFF_MAX_COMPRESSED_PAGE_SIZE: u32 = AFF_MAX_PAGE_SIZE;

/// Default sector size.
const AFF_DEFAULT_SECTOR_SIZE: u16 = 512;

/// Maximum segment-name length defined by AFFLIB.
const AFF_MAX_NAME_LEN: u32 = 64;

// AFF page flag bitfield, as defined by AFFLIB's public `afflib.h`.
const AFF_PAGE_COMPRESSED: u32 = 0x0001;
const AFF_PAGE_COMP_MAX: u32 = 0x0002;
const AFF_PAGE_COMP_ALG_MASK: u32 = 0x00F0;
const AFF_PAGE_COMP_ALG_ZLIB: u32 = 0x0000;
const AFF_PAGE_COMP_ALG_BZIP: u32 = 0x0010;
const AFF_PAGE_COMP_ALG_LZMA: u32 = 0x0020;
const AFF_PAGE_COMP_ALG_ZERO: u32 = 0x0030;
const AFF_PAGE_KNOWN_FLAG_BITS: u32 =
    AFF_PAGE_COMPRESSED | AFF_PAGE_COMP_MAX | AFF_PAGE_COMP_ALG_MASK;

const LZMA_PROPERTIES_SIZE: usize = 5;
const LZMA_HEADER_SIZE: usize = 13;

// ---- Helper: read big-endian u32 --------------------------------------------

fn read_be_u32(file: &mut File) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    file.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

// ---- Helper: decode an `aff_quad` (64-bit value stored as two BE u32) -------

/// Decode an `aff_quad` from 8 bytes.  The encoding is `low_u32_be` followed by
/// `high_u32_be`, both in network (big-endian) byte order.
fn decode_aff_quad(data: &[u8]) -> io::Result<u64> {
    if data.len() != 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("aff_quad requires exactly 8 bytes, got {}", data.len()),
        ));
    }
    let low = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64;
    let high = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as u64;
    Ok((high << 32) | low)
}

fn metadata_u32(name: &str, argument: u32, data: Option<&[u8]>) -> Result<u32, String> {
    let payload_value = match data {
        Some(bytes) if !bytes.is_empty() && bytes.iter().all(u8::is_ascii_digit) => Some(
            std::str::from_utf8(bytes)
                .expect("ASCII digits are UTF-8")
                .parse::<u32>()
                .map_err(|_| format!("AFF {name} ASCII value is outside the u32 range"))?,
        ),
        Some(bytes) if bytes.len() == 4 => {
            Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        }
        Some(bytes) => {
            return Err(format!(
                "AFF {name} payload is {} bytes, expected a 4-byte integer or bounded ASCII decimal",
                bytes.len()
            ));
        }
        None => None,
    };

    if argument != 0 {
        if let Some(payload_value) = payload_value {
            if payload_value != argument {
                return Err(format!(
                    "AFF {name} argument {argument} disagrees with payload {payload_value}"
                ));
            }
        }
        Ok(argument)
    } else {
        payload_value.ok_or_else(|| format!("AFF {name} segment has no value"))
    }
}

fn expected_page_len(image_size: u64, page_size: u32, page_num: usize) -> io::Result<usize> {
    let page_start = (page_num as u64)
        .checked_mul(u64::from(page_size))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "page offset overflows u64"))?;
    if page_start >= image_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("page begins at {page_start}, beyond image size {image_size}"),
        ));
    }
    Ok(min(u64::from(page_size), image_size - page_start) as usize)
}

// ---- Per-page descriptor ----------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AffPageEncoding {
    Uncompressed,
    Zlib,
    Lzma,
    Zero,
}

impl AffPageEncoding {
    fn from_flag(flag: u32) -> Result<Self, String> {
        let unknown = flag & !AFF_PAGE_KNOWN_FLAG_BITS;
        if unknown != 0 {
            return Err(format!(
                "unsupported AFF page flag bits 0x{unknown:08x} in flag 0x{flag:08x}"
            ));
        }

        if flag & AFF_PAGE_COMPRESSED == 0 {
            if flag != 0 {
                return Err(format!(
                    "malformed AFF page flag 0x{flag:08x}: compression hints require the compressed bit"
                ));
            }
            return Ok(Self::Uncompressed);
        }

        match flag & AFF_PAGE_COMP_ALG_MASK {
            AFF_PAGE_COMP_ALG_ZLIB => Ok(Self::Zlib),
            AFF_PAGE_COMP_ALG_LZMA => Ok(Self::Lzma),
            AFF_PAGE_COMP_ALG_ZERO => Ok(Self::Zero),
            AFF_PAGE_COMP_ALG_BZIP => Err(format!(
                "unsupported AFF bzip page compression in flag 0x{flag:08x}"
            )),
            algorithm => Err(format!(
                "unsupported AFF page compression algorithm 0x{algorithm:02x} in flag 0x{flag:08x}"
            )),
        }
    }
}

/// Points to a single data page inside the AFF file.
#[derive(Clone, Copy, Debug)]
struct AffPage {
    /// Absolute file offset where the page *data* begins.
    data_offset: u64,
    /// Length of the (possibly compressed) data payload in bytes.
    data_len: u32,
    /// Original segment flag, retained for precise corruption diagnostics.
    flag: u32,
    /// Validated page representation selected from the flag bitfield.
    encoding: AffPageEncoding,
}

// ---- Public AFF reader ------------------------------------------------------

/// Native AFF image reader.
///
/// Implements [`Read`], [`Seek`] and [`Clone`] so it can be used as a drop-in
/// source of evidence bytes inside the [`Body`](crate::Body) abstraction.
pub struct AFF {
    /// Open file handle to the `.aff` file.
    file: File,
    /// Original path (kept for display / cloning).
    path: String,
    /// Virtual cursor position inside the *uncompressed* image.
    position: u64,
    /// Total uncompressed image size (from `imagesize` segment).
    image_size: u64,
    /// Size of each uncompressed page in bytes (from `pagesize` segment).
    page_size: u32,
    /// Sector size (from `sectorsize` segment, default 512).
    sector_size: u16,
    /// Ordered index of data pages (`page0`, `page1`, …).
    pages: Vec<AffPage>,
    /// Page number currently held in `cache_data` (`None` = empty cache).
    cache_page: Option<usize>,
    /// Decompressed bytes of the cached page.
    cache_data: Vec<u8>,
}

impl AFF {
    // ---- Construction -------------------------------------------------------

    /// Open and parse an AFF image.
    ///
    /// The constructor validates the file header, scans every segment to build a
    /// page index, and extracts metadata (`pagesize`, `imagesize`, `sectorsize`).
    pub fn new(file_path: &str) -> Result<AFF, String> {
        let path = Path::new(file_path);
        let mut file = File::open(path).map_err(|e| format!("Error opening AFF image: {}", e))?;
        let file_len = file
            .metadata()
            .map_err(|e| format!("Error reading AFF file metadata: {e}"))?
            .len();

        // --- Validate file header ---
        let mut header = [0u8; 8];
        file.read_exact(&mut header)
            .map_err(|e| format!("Error reading AFF header: {}", e))?;
        if header != AFF_FILE_MAGIC {
            return Err("Invalid AFF signature (expected AFF10)".to_string());
        }

        // --- Scan segments ---
        let mut pages_map: HashMap<usize, AffPage> = HashMap::new();
        let mut page_size: Option<u32> = None;
        let mut image_size: Option<u64> = None;
        let mut sector_size: Option<u16> = None;

        loop {
            let segment_start = file
                .stream_position()
                .map_err(|e| format!("Error getting AFF segment position: {e}"))?;
            if segment_start == file_len {
                break;
            }
            if file_len.saturating_sub(segment_start) < 24 {
                return Err(format!(
                    "Truncated AFF segment header at file offset {segment_start}"
                ));
            }

            let mut seg_magic = [0u8; 4];
            file.read_exact(&mut seg_magic)
                .map_err(|e| format!("Error reading segment head: {e}"))?;
            if seg_magic != AFF_SEG_HEAD_MAGIC {
                return Err(format!(
                    "Invalid AFF segment signature at file offset {segment_start}"
                ));
            }

            // Read fixed header fields (all big-endian u32).
            let name_len = read_be_u32(&mut file)
                .map_err(|e| format!("Error reading segment name_len: {}", e))?;
            let data_len = read_be_u32(&mut file)
                .map_err(|e| format!("Error reading segment data_len: {}", e))?;
            let flag =
                read_be_u32(&mut file).map_err(|e| format!("Error reading segment flag: {}", e))?;

            if name_len > AFF_MAX_NAME_LEN {
                return Err(format!(
                    "AFF segment name at offset {segment_start} is {name_len} bytes; maximum is {AFF_MAX_NAME_LEN}"
                ));
            }

            let segment_len = 24u64
                .checked_add(u64::from(name_len))
                .and_then(|len| len.checked_add(u64::from(data_len)))
                .ok_or_else(|| format!("AFF segment length overflows at offset {segment_start}"))?;
            let segment_end = segment_start
                .checked_add(segment_len)
                .ok_or_else(|| format!("AFF segment end overflows at offset {segment_start}"))?;
            if segment_end > file_len {
                return Err(format!(
                    "Truncated AFF segment at offset {segment_start}: end {segment_end} exceeds file length {file_len}"
                ));
            }

            // Read segment name.
            let mut name_buf = vec![0u8; name_len as usize];
            file.read_exact(&mut name_buf)
                .map_err(|e| format!("Error reading segment name: {}", e))?;
            let name = String::from_utf8(name_buf).map_err(|_| {
                format!("AFF segment name at offset {segment_start} is not valid UTF-8")
            })?;
            let page_num = match name.strip_prefix("page") {
                Some(suffix)
                    if !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()) =>
                {
                    Some(suffix.parse::<usize>().map_err(|_| {
                        format!("AFF page suffix '{suffix}' exceeds this platform's limits")
                    })?)
                }
                _ => None,
            };

            match name.as_str() {
                // AFFLIB stores these in the argument, while some producers
                // use a short ASCII decimal payload (for example `512`).
                // Bound the compatibility form before allocating it.
                "pagesize" | "sectorsize" if data_len > 10 => {
                    return Err(format!(
                        "AFF {name} payload is {data_len} bytes, expected at most 10"
                    ));
                }
                "imagesize" if data_len != 8 => {
                    return Err(format!(
                        "AFF imagesize payload is {data_len} bytes, expected exactly 8"
                    ));
                }
                _ => {}
            }

            // Record position of the data payload.
            let data_offset = file
                .stream_position()
                .map_err(|e| format!("Error getting data offset: {}", e))?;

            // Only the three metadata values below need their payload.  Page
            // payloads and all other metadata are indexed/skipped without a
            // potentially large temporary allocation.
            let needs_data = matches!(name.as_str(), "pagesize" | "imagesize" | "sectorsize");
            let data = if needs_data && data_len > 0 {
                let mut buf = vec![0u8; data_len as usize];
                file.read_exact(&mut buf)
                    .map_err(|e| format!("Error reading segment data for '{name}': {e}"))?;
                Some(buf)
            } else {
                file.seek(SeekFrom::Start(data_offset + u64::from(data_len)))
                    .map_err(|e| format!("Error skipping segment data for '{name}': {e}"))?;
                None
            };

            // Skip segment tail (4 bytes magic + 4 bytes segment_len).
            let mut tail_buf = [0u8; 8];
            file.read_exact(&mut tail_buf)
                .map_err(|e| format!("Error reading segment tail: {}", e))?;

            // Verify tail magic.
            if tail_buf[0..4] != AFF_SEG_TAIL_MAGIC {
                return Err(format!(
                    "Corrupt segment tail for '{}' (expected ATT\\0)",
                    name
                ));
            }
            let stored_segment_len =
                u32::from_be_bytes([tail_buf[4], tail_buf[5], tail_buf[6], tail_buf[7]]);
            let calculated_segment_len = u32::try_from(segment_len).map_err(|_| {
                format!("AFF segment '{name}' at offset {segment_start} is too large")
            })?;
            if stored_segment_len != calculated_segment_len {
                return Err(format!(
                    "Corrupt AFF segment length for '{name}': stored {stored_segment_len}, expected {calculated_segment_len}"
                ));
            }

            // ---- Interpret known segment names ----
            if let Some(page_num) = page_num {
                let encoding = AffPageEncoding::from_flag(flag)
                    .map_err(|error| format!("Invalid page{page_num}: {error}"))?;
                if pages_map
                    .insert(
                        page_num,
                        AffPage {
                            data_offset,
                            data_len,
                            flag,
                            encoding,
                        },
                    )
                    .is_some()
                {
                    return Err(format!("AFF image contains duplicate page{page_num}"));
                }
            } else if name == "pagesize" {
                page_size = Some(metadata_u32("pagesize", flag, data.as_deref())?);
            } else if name == "imagesize" {
                let data = data
                    .as_deref()
                    .ok_or_else(|| "AFF imagesize segment has no payload".to_string())?;
                image_size = Some(
                    decode_aff_quad(data)
                        .map_err(|e| format!("Invalid AFF imagesize segment: {e}"))?,
                );
            } else if name == "sectorsize" {
                let value = metadata_u32("sectorsize", flag, data.as_deref())?;
                sector_size = Some(u16::try_from(value).map_err(|_| {
                    format!("AFF sectorsize {value} exceeds the supported u16 range")
                })?);
            }
        }

        let ps = page_size.unwrap_or(AFF_DEFAULT_PAGE_SIZE);
        if ps == 0 || ps > AFF_MAX_PAGE_SIZE {
            return Err(format!(
                "Invalid AFF pagesize {ps}; supported range is 1..={AFF_MAX_PAGE_SIZE}"
            ));
        }
        let ss = sector_size.unwrap_or(AFF_DEFAULT_SECTOR_SIZE);
        if ss == 0 || !ps.is_multiple_of(u32::from(ss)) {
            return Err(format!(
                "Invalid AFF geometry: pagesize {ps} is not divisible by sectorsize {ss}"
            ));
        }

        let indexed_page_count = pages_map.len();
        let inferred_size = (indexed_page_count as u64)
            .checked_mul(u64::from(ps))
            .ok_or_else(|| "AFF inferred image size overflows u64".to_string())?;
        let image_size = image_size.unwrap_or(inferred_size);
        let expected_page_count = if image_size == 0 {
            0
        } else {
            usize::try_from((image_size - 1) / u64::from(ps) + 1)
                .map_err(|_| "AFF page count exceeds this platform's limits".to_string())?
        };
        if let Some(out_of_range) = pages_map
            .keys()
            .copied()
            .find(|page_num| *page_num >= expected_page_count)
        {
            return Err(format!(
                "AFF page{out_of_range} is outside the valid range 0..{expected_page_count}"
            ));
        }
        if indexed_page_count != expected_page_count {
            return Err(format!(
                "AFF image geometry requires {expected_page_count} pages for {image_size} bytes, but {} pages were indexed",
                indexed_page_count
            ));
        }

        // The metadata-derived bound has now been checked, so no page suffix
        // can drive an unbounded reserve or inclusive range iteration.
        let mut pages = Vec::with_capacity(expected_page_count);
        for page_num in 0..expected_page_count {
            pages.push(pages_map.remove(&page_num).ok_or_else(|| {
                format!(
                    "AFF image is missing page{page_num} (have {indexed_page_count} pages total)"
                )
            })?);
        }

        for (page_num, page) in pages.iter().enumerate() {
            let expected_len = expected_page_len(image_size, ps, page_num)
                .map_err(|e| format!("Invalid page{page_num}: {e}"))?;
            match page.encoding {
                AffPageEncoding::Uncompressed if page.data_len as usize != expected_len => {
                    return Err(format!(
                        "Invalid page{page_num}: uncompressed payload is {} bytes, expected {expected_len}",
                        page.data_len
                    ));
                }
                AffPageEncoding::Zero if page.data_len != 4 => {
                    return Err(format!(
                        "Invalid page{page_num}: zero-page payload is {} bytes, expected 4",
                        page.data_len
                    ));
                }
                AffPageEncoding::Zlib | AffPageEncoding::Lzma
                    if page.data_len > AFF_MAX_COMPRESSED_PAGE_SIZE =>
                {
                    return Err(format!(
                        "Invalid page{page_num}: compressed payload is {} bytes, maximum is {AFF_MAX_COMPRESSED_PAGE_SIZE}",
                        page.data_len
                    ));
                }
                AffPageEncoding::Zlib if page.data_len == 0 => {
                    return Err(format!("Invalid page{page_num}: empty zlib payload"));
                }
                AffPageEncoding::Lzma if page.data_len < LZMA_HEADER_SIZE as u32 => {
                    return Err(format!(
                        "Invalid page{page_num}: LZMA payload is {} bytes, expected at least {LZMA_HEADER_SIZE}",
                        page.data_len
                    ));
                }
                _ => {}
            }
        }

        info!(
            "AFF: parsed {} pages, pagesize={}, imagesize={}",
            pages.len(),
            ps,
            image_size
        );

        Ok(AFF {
            file,
            path: file_path.to_string(),
            position: 0,
            image_size,
            page_size: ps,
            sector_size: ss,
            pages,
            cache_page: None,
            cache_data: Vec::new(),
        })
    }

    // ---- Info helpers -------------------------------------------------------

    /// Print parsed metadata to the log.
    pub fn print_info(&self) {
        info!("AFF Image Information:");
        info!("Path          : {}", self.path);
        info!("Image Size    : {} bytes", self.image_size);
        info!("Page Size     : {} bytes", self.page_size);
        info!("Sector Size   : {}", self.sector_size);
        info!("Total Pages   : {}", self.pages.len());
    }

    /// Returns the sector size parsed from the image (default 512).
    pub fn get_sector_size(&self) -> u16 {
        self.sector_size
    }

    /// Returns the logical (uncompressed) size of the disk image in bytes.
    pub fn get_image_size(&self) -> u64 {
        self.image_size
    }

    // ---- Internal page reading ----------------------------------------------

    /// Read and (if necessary) decompress a single page into the reusable cache.
    fn load_page(&mut self, page_num: usize) -> io::Result<()> {
        if page_num >= self.pages.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "page{} is out of range (have {})",
                    page_num,
                    self.pages.len()
                ),
            ));
        }

        let page = self.pages[page_num];
        let expected_len = expected_page_len(self.image_size, self.page_size, page_num)?;

        self.cache_page = None;
        self.cache_data.clear();
        self.file.seek(SeekFrom::Start(page.data_offset))?;

        match page.encoding {
            AffPageEncoding::Uncompressed => {
                self.cache_data.resize(expected_len, 0);
                self.file.read_exact(&mut self.cache_data)?;
            }
            AffPageEncoding::Zero => {
                let mut count = [0u8; 4];
                self.file.read_exact(&mut count)?;
                let count = u32::from_be_bytes(count) as usize;
                if count != expected_len {
                    return Err(invalid_page_data(
                        page_num,
                        page.flag,
                        format!("zero count is {count}, expected {expected_len}"),
                    ));
                }
                self.cache_data.resize(expected_len, 0);
            }
            AffPageEncoding::Zlib => {
                let limited = self.file.by_ref().take(u64::from(page.data_len));
                let decoder = ZlibDecoder::new(limited);
                let mut bounded = decoder.take(expected_len as u64 + 1);
                self.cache_data.reserve(expected_len);
                bounded.read_to_end(&mut self.cache_data).map_err(|error| {
                    invalid_page_data(
                        page_num,
                        page.flag,
                        format!("zlib decompression failed: {error}"),
                    )
                })?;
                let decoder = bounded.into_inner();
                if self.cache_data.len() != expected_len {
                    return Err(invalid_page_data(
                        page_num,
                        page.flag,
                        format!(
                            "zlib output is {} bytes, expected {expected_len}",
                            self.cache_data.len()
                        ),
                    ));
                }
                if decoder.total_in() != u64::from(page.data_len) {
                    return Err(invalid_page_data(
                        page_num,
                        page.flag,
                        format!(
                            "zlib stream consumed {} of {} payload bytes",
                            decoder.total_in(),
                            page.data_len
                        ),
                    ));
                }
            }
            AffPageEncoding::Lzma => {
                let mut limited = self.file.by_ref().take(u64::from(page.data_len));
                // AFFLIB writes the standard LZMA-Alone framing: five coder
                // property bytes followed by the decoded size as a little-
                // endian u64, then the raw range-coded stream.
                let mut header = [0u8; LZMA_HEADER_SIZE];
                limited.read_exact(&mut header).map_err(|error| {
                    invalid_page_data(
                        page_num,
                        page.flag,
                        format!("LZMA header is truncated: {error}"),
                    )
                })?;
                let properties_header: &[u8; LZMA_PROPERTIES_SIZE] = header[..LZMA_PROPERTIES_SIZE]
                    .try_into()
                    .expect("fixed LZMA header prefix");
                let (properties, dict_size) = parse_lzma_properties(properties_header)
                    .map_err(|error| invalid_page_data(page_num, page.flag, error.to_string()))?;
                let declared_len = u64::from_le_bytes(
                    header[LZMA_PROPERTIES_SIZE..LZMA_HEADER_SIZE]
                        .try_into()
                        .expect("fixed LZMA decoded-size field"),
                );
                if declared_len != expected_len as u64 {
                    return Err(invalid_page_data(
                        page_num,
                        page.flag,
                        format!(
                            "LZMA header declares {declared_len} decoded bytes, expected {expected_len}"
                        ),
                    ));
                }
                let params = LzmaParams::new(properties, dict_size, Some(expected_len as u64));
                let mut decoder =
                    LzmaDecoder::new(params, Some(expected_len)).map_err(|error| {
                        invalid_page_data(
                            page_num,
                            page.flag,
                            format!("cannot initialize LZMA decoder: {error}"),
                        )
                    })?;
                let mut input = BufReader::new(limited);
                self.cache_data.reserve(expected_len);
                decoder
                    .decompress(&mut input, &mut self.cache_data)
                    .map_err(|error| {
                        invalid_page_data(
                            page_num,
                            page.flag,
                            format!("LZMA decompression failed: {error}"),
                        )
                    })?;
                if self.cache_data.len() != expected_len {
                    return Err(invalid_page_data(
                        page_num,
                        page.flag,
                        format!(
                            "LZMA output is {} bytes, expected {expected_len}",
                            self.cache_data.len()
                        ),
                    ));
                }
                let remaining = input.buffer().len() as u64 + input.get_ref().limit();
                if remaining != 0 {
                    return Err(invalid_page_data(
                        page_num,
                        page.flag,
                        format!("LZMA stream has {remaining} trailing payload bytes"),
                    ));
                }
            }
        }

        self.cache_page = Some(page_num);
        Ok(())
    }

    /// Ensure that `cache_data` contains the decompressed content for `page_num`.
    fn ensure_cached(&mut self, page_num: usize) -> io::Result<()> {
        if self.cache_page == Some(page_num) {
            return Ok(());
        }
        self.load_page(page_num)
    }
}

fn invalid_page_data(page_num: usize, flag: u32, detail: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("Invalid AFF page{page_num} (flag 0x{flag:08x}): {detail}"),
    )
}

fn parse_lzma_properties(header: &[u8; LZMA_PROPERTIES_SIZE]) -> io::Result<(LzmaProperties, u32)> {
    let encoded = u32::from(header[0]);
    if encoded >= 225 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid LZMA properties byte {encoded}; expected less than 225"),
        ));
    }

    let lc = encoded % 9;
    let remainder = encoded / 9;
    let lp = remainder % 5;
    let pb = remainder / 5;
    let dict_size = u32::from_le_bytes([header[1], header[2], header[3], header[4]]).max(0x1000);

    Ok((LzmaProperties { lc, lp, pb }, dict_size))
}

// ---- Clone ------------------------------------------------------------------

impl Clone for AFF {
    fn clone(&self) -> Self {
        Self {
            file: self
                .file
                .try_clone()
                .expect("failed to clone AFF file handle"),
            path: self.path.clone(),
            position: self.position,
            image_size: self.image_size,
            page_size: self.page_size,
            sector_size: self.sector_size,
            pages: self.pages.clone(),
            // Reset cache – will be lazily filled.
            cache_page: None,
            cache_data: Vec::new(),
        }
    }
}

// ---- Read -------------------------------------------------------------------

impl Read for AFF {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.image_size {
            return Ok(0);
        }

        let mut total = 0usize;

        while total < buf.len() && self.position < self.image_size {
            let page_num = (self.position / self.page_size as u64) as usize;
            let offset_in_page = (self.position % self.page_size as u64) as usize;

            if page_num >= self.pages.len() {
                break;
            }

            self.ensure_cached(page_num)?;

            let available = self.cache_data.len().saturating_sub(offset_in_page);
            if available == 0 {
                break;
            }

            // Clamp to remaining buffer space and image boundary.
            let remaining_image = (self.image_size - self.position) as usize;
            let to_copy = min(min(available, buf.len() - total), remaining_image);

            buf[total..total + to_copy]
                .copy_from_slice(&self.cache_data[offset_in_page..offset_in_page + to_copy]);

            total += to_copy;
            self.position += to_copy as u64;
        }

        Ok(total)
    }
}

// ---- Seek -------------------------------------------------------------------

impl Seek for AFF {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let next = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(delta) => {
                if delta >= 0 {
                    self.position.checked_add(delta as u64).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "Seek overflow")
                    })?
                } else {
                    self.position
                        .checked_sub(delta.unsigned_abs())
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "Cannot seek before start")
                        })?
                }
            }
            SeekFrom::End(delta) => {
                if delta >= 0 {
                    self.image_size.checked_add(delta as u64).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "Seek overflow")
                    })?
                } else {
                    self.image_size
                        .checked_sub(delta.unsigned_abs())
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "Cannot seek before start")
                        })?
                }
            }
        };

        self.position = next;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::{AffPageEncoding, AFF, AFF_FILE_MAGIC, AFF_SEG_HEAD_MAGIC, AFF_SEG_TAIL_MAGIC};
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use lzma_rs::compress::{Options as LzmaOptions, UnpackedSize};
    use std::fs;
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};
    use std::process::Command;

    const PAGE_SIZE: u32 = 4096;

    fn append_segment(image: &mut Vec<u8>, name: &str, flag: u32, payload: &[u8]) {
        image.extend_from_slice(&AFF_SEG_HEAD_MAGIC);
        image.extend_from_slice(&(name.len() as u32).to_be_bytes());
        image.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        image.extend_from_slice(&flag.to_be_bytes());
        image.extend_from_slice(name.as_bytes());
        image.extend_from_slice(payload);
        image.extend_from_slice(&AFF_SEG_TAIL_MAGIC);
        let segment_len = 24 + name.len() + payload.len();
        image.extend_from_slice(&(segment_len as u32).to_be_bytes());
    }

    fn aff_quad(value: u64) -> [u8; 8] {
        let low = value as u32;
        let high = (value >> 32) as u32;
        let mut result = [0u8; 8];
        result[..4].copy_from_slice(&low.to_be_bytes());
        result[4..].copy_from_slice(&high.to_be_bytes());
        result
    }

    fn build_aff(image_size: u64, pages: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut image = AFF_FILE_MAGIC.to_vec();
        append_segment(&mut image, "pagesize", PAGE_SIZE, &[]);
        append_segment(&mut image, "sectorsize", 512, &[]);
        append_segment(&mut image, "imagesize", 2, &aff_quad(image_size));
        for (page_num, (flag, payload)) in pages.iter().enumerate() {
            append_segment(&mut image, &format!("page{page_num}"), *flag, payload);
        }
        image
    }

    fn zlib_compress(data: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn lzma_compress(data: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        let options = LzmaOptions {
            unpacked_size: UnpackedSize::WriteToHeader(Some(data.len() as u64)),
        };
        lzma_rs::lzma_compress_with_options(&mut Cursor::new(data), &mut output, &options).unwrap();
        output
    }

    fn write_fixture(bytes: &[u8]) -> (tempfile::TempDir, String) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fixture.aff");
        fs::write(&path, bytes).unwrap();
        (directory, path.to_string_lossy().into_owned())
    }

    #[test]
    fn decodes_uncompressed_zlib_lzma_and_zero_pages_with_exact_tail() {
        let uncompressed = (0..PAGE_SIZE).map(|index| index as u8).collect::<Vec<_>>();
        let zlib = (0..PAGE_SIZE)
            .map(|index| ((index * 17) % 251) as u8)
            .collect::<Vec<_>>();
        let lzma =
            b"AFF-LZMA-page".repeat(PAGE_SIZE as usize / 13 + 1)[..PAGE_SIZE as usize].to_vec();
        let tail_len = 137usize;
        let zero_payload = (tail_len as u32).to_be_bytes().to_vec();

        let fixture = build_aff(
            u64::from(PAGE_SIZE) * 3 + tail_len as u64,
            &[
                (0, uncompressed.clone()),
                (0x0003, zlib_compress(&zlib)),
                (0x0021, lzma_compress(&lzma)),
                (0x0033, zero_payload),
            ],
        );
        let (_directory, path) = write_fixture(&fixture);
        let mut reader = AFF::new(&path).unwrap();
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual).unwrap();

        let mut expected = uncompressed;
        expected.extend_from_slice(&zlib);
        expected.extend_from_slice(&lzma);
        expected.resize(expected.len() + tail_len, 0);
        assert_eq!(actual, expected);
    }

    #[test]
    fn rejects_unknown_and_unsupported_page_flags_at_open() {
        for (flag, expected_message) in [
            (0x0004, "unsupported AFF page flag bits"),
            (0x0002, "compression hints require the compressed bit"),
            (0x0011, "unsupported AFF bzip page compression"),
            (0x0041, "unsupported AFF page compression algorithm"),
        ] {
            let fixture = build_aff(u64::from(PAGE_SIZE), &[(flag, vec![0; PAGE_SIZE as usize])]);
            let (_directory, path) = write_fixture(&fixture);
            let error = AFF::new(&path)
                .err()
                .expect("invalid flag must fail closed");
            assert!(
                error.contains(expected_message),
                "unexpected error for flag 0x{flag:08x}: {error}"
            );
        }
    }

    #[test]
    fn rejects_uncompressed_length_and_zero_count_mismatches() {
        let fixture = build_aff(
            u64::from(PAGE_SIZE),
            &[(0, vec![0; PAGE_SIZE as usize - 1])],
        );
        let (_directory, path) = write_fixture(&fixture);
        let error = AFF::new(&path)
            .err()
            .expect("short uncompressed page must fail");
        assert!(error.contains("uncompressed payload"));

        let fixture = build_aff(
            u64::from(PAGE_SIZE),
            &[(0x0033, (PAGE_SIZE - 1).to_be_bytes().to_vec())],
        );
        let (_directory, path) = write_fixture(&fixture);
        let mut reader = AFF::new(&path).unwrap();
        let error = reader
            .read_to_end(&mut Vec::new())
            .expect_err("incorrect zero count must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("zero count"));
    }

    #[test]
    fn rejects_compressed_output_with_the_wrong_decoded_length() {
        let compressed = zlib_compress(&vec![0x5a; PAGE_SIZE as usize - 1]);
        let fixture = build_aff(u64::from(PAGE_SIZE), &[(0x0001, compressed)]);
        let (_directory, path) = write_fixture(&fixture);
        let mut reader = AFF::new(&path).unwrap();
        let error = reader
            .read_to_end(&mut Vec::new())
            .expect_err("short zlib output must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("zlib output"));
    }

    #[test]
    fn rejects_oversized_compressed_payloads_before_codec_work() {
        for flag in [0x0001, 0x0021] {
            let fixture = build_aff(
                u64::from(PAGE_SIZE),
                &[(
                    flag,
                    vec![0; super::AFF_MAX_COMPRESSED_PAGE_SIZE as usize + 1],
                )],
            );
            let (_directory, path) = write_fixture(&fixture);
            let error = AFF::new(&path)
                .err()
                .expect("oversized compressed input must fail at open");
            assert!(error.contains("compressed payload"), "{error}");
        }
    }

    #[test]
    fn rejects_out_of_range_page_suffix_without_reserving_from_it() {
        let mut fixture = AFF_FILE_MAGIC.to_vec();
        append_segment(&mut fixture, "pagesize", PAGE_SIZE, &[]);
        append_segment(&mut fixture, "sectorsize", 512, &[]);
        append_segment(
            &mut fixture,
            "imagesize",
            2,
            &aff_quad(u64::from(PAGE_SIZE)),
        );
        append_segment(
            &mut fixture,
            &format!("page{}", usize::MAX),
            0,
            &vec![0; PAGE_SIZE as usize],
        );
        let (_directory, path) = write_fixture(&fixture);
        let error = AFF::new(&path)
            .err()
            .expect("out-of-range page suffix must fail closed");
        assert!(error.contains("outside the valid range"));

        let mut fixture = AFF_FILE_MAGIC.to_vec();
        append_segment(&mut fixture, &format!("page{}0", usize::MAX), 0, &[0]);
        let (_directory, path) = write_fixture(&fixture);
        let error = AFF::new(&path)
            .err()
            .expect("overflowing page suffix must fail closed");
        assert!(error.contains("exceeds this platform's limits"));
    }

    #[test]
    fn rejects_oversized_known_metadata_before_allocating_its_payload() {
        for (name, payload_len, expected) in [
            ("pagesize", 11, "expected at most 10"),
            ("sectorsize", 11, "expected at most 10"),
            ("imagesize", 9, "expected exactly 8"),
        ] {
            let mut fixture = AFF_FILE_MAGIC.to_vec();
            append_segment(&mut fixture, name, 0, &vec![0; payload_len]);
            let (_directory, path) = write_fixture(&fixture);
            let error = AFF::new(&path)
                .err()
                .expect("oversized known metadata must fail closed");
            assert!(error.contains(expected), "unexpected {name} error: {error}");
        }
    }

    #[test]
    fn rejects_lzma_declared_size_mismatch_and_trailing_payload() {
        let page = b"LZMA framing validation".repeat(PAGE_SIZE as usize / 23 + 1)
            [..PAGE_SIZE as usize]
            .to_vec();

        let mut wrong_size = lzma_compress(&page);
        wrong_size[5..13].copy_from_slice(&u64::from(PAGE_SIZE - 1).to_le_bytes());
        let fixture = build_aff(u64::from(PAGE_SIZE), &[(0x0021, wrong_size)]);
        let (_directory, path) = write_fixture(&fixture);
        let mut reader = AFF::new(&path).unwrap();
        let error = reader
            .read_to_end(&mut Vec::new())
            .expect_err("mismatched LZMA decoded size must fail");
        assert!(error.to_string().contains("header declares"));

        let mut trailing = lzma_compress(&page);
        trailing.push(0xa5);
        let fixture = build_aff(u64::from(PAGE_SIZE), &[(0x0021, trailing)]);
        let (_directory, path) = write_fixture(&fixture);
        let mut reader = AFF::new(&path).unwrap();
        let error = reader
            .read_to_end(&mut Vec::new())
            .expect_err("trailing LZMA bytes must fail");
        assert!(error.to_string().contains("trailing payload"));
    }

    #[test]
    fn reads_lzma_aff_created_by_afflib_when_available() {
        if Command::new("affconvert").arg("-V").output().is_err() {
            eprintln!("affconvert is unavailable; skipping AFFLIB interoperability check");
            return;
        }

        let directory = tempfile::tempdir().unwrap();
        let raw_path = directory.path().join("lzma-interop.raw");
        let aff_path = directory.path().join("lzma-interop.aff");
        let source = b"Independent AFFLIB LZMA interoperability page."
            .repeat(PAGE_SIZE as usize / 44 * 2 + 1);
        fs::write(&raw_path, &source).unwrap();

        let output = Command::new("affconvert")
            .arg("-q")
            .arg("-L")
            .arg(format!("-s{PAGE_SIZE}b"))
            .arg(format!("-o{}", aff_path.display()))
            .arg(&raw_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "affconvert failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let mut reader = AFF::new(aff_path.to_str().unwrap()).unwrap();
        assert!(
            reader
                .pages
                .iter()
                .any(|page| page.encoding == AffPageEncoding::Lzma),
            "AFFLIB fixture did not contain an LZMA page"
        );
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, source);
    }

    #[test]
    #[ignore = "requires EXHUME_AFF_PROBE_IMAGE to name a real AFF evidence image"]
    fn real_zero_page_757_probe_from_environment() {
        let path = std::env::var("EXHUME_AFF_PROBE_IMAGE")
            .expect("set EXHUME_AFF_PROBE_IMAGE to the AFF evidence path");
        let mut reader = AFF::new(&path).unwrap();
        let page_num = 757usize;
        assert_eq!(reader.pages[page_num].encoding, AffPageEncoding::Zero);
        assert_eq!(reader.pages[page_num].flag, 0x0033);
        assert_eq!(reader.pages[page_num].data_len, 4);

        let page_start = page_num as u64 * u64::from(reader.page_size);
        reader.seek(SeekFrom::Start(page_start)).unwrap();
        let mut decoded = vec![0xff; reader.page_size as usize];
        reader.read_exact(&mut decoded).unwrap();
        assert!(decoded.iter().all(|byte| *byte == 0));
    }
}
