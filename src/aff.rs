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
//! Data pages are named `page0`, `page1`, …, `pageN` and may be zlib-compressed
//! (indicated by a non-zero flag).  Metadata segments such as `pagesize`,
//! `imagesize`, and `sectorsize` carry acquisition parameters.

use flate2::read::ZlibDecoder;
use log::info;
use std::cmp::min;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
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

/// Default sector size.
const AFF_DEFAULT_SECTOR_SIZE: u16 = 512;

// ---- Helper: read big-endian u32 --------------------------------------------

fn read_be_u32(file: &mut File) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    file.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

// ---- Helper: decode an `aff_quad` (64-bit value stored as two BE u32) -------

/// Decode an `aff_quad` from 8 bytes.  The encoding is `low_u32_be` followed by
/// `high_u32_be`, both in network (big-endian) byte order.
fn decode_aff_quad(data: &[u8]) -> u64 {
    assert!(data.len() >= 8, "aff_quad requires 8 bytes");
    let low = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64;
    let high = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as u64;
    (high << 32) | low
}

// ---- Per-page descriptor ----------------------------------------------------

/// Points to a single data page inside the AFF file.
#[derive(Clone, Debug)]
struct AffPage {
    /// Absolute file offset where the page *data* begins.
    data_offset: u64,
    /// Length of the (possibly compressed) data payload in bytes.
    data_len: u32,
    /// Segment flag – non-zero ⇒ the payload is zlib-compressed.
    flag: u32,
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
            // Try to read segment head magic.
            let mut seg_magic = [0u8; 4];
            match file.read_exact(&mut seg_magic) {
                Ok(()) => {}
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(format!("Error reading segment head: {}", e)),
            }

            if seg_magic != AFF_SEG_HEAD_MAGIC {
                // Not a valid segment head – end of segment chain.
                break;
            }

            // Read fixed header fields (all big-endian u32).
            let name_len = read_be_u32(&mut file)
                .map_err(|e| format!("Error reading segment name_len: {}", e))?;
            let data_len = read_be_u32(&mut file)
                .map_err(|e| format!("Error reading segment data_len: {}", e))?;
            let flag =
                read_be_u32(&mut file).map_err(|e| format!("Error reading segment flag: {}", e))?;

            // Read segment name.
            let mut name_buf = vec![0u8; name_len as usize];
            file.read_exact(&mut name_buf)
                .map_err(|e| format!("Error reading segment name: {}", e))?;
            let name = String::from_utf8_lossy(&name_buf).to_string();

            // Record position of the data payload.
            let data_offset = file
                .stream_position()
                .map_err(|e| format!("Error getting data offset: {}", e))?;

            // Read (or skip) the data payload.
            let data = if data_len > 0 {
                // For metadata segments we need the bytes; for pages we just
                // record offsets, but small metadata segments are fine to
                // buffer fully.  Pages can be huge so we only fully read
                // metadata segments (name does NOT start with "page").
                if name.starts_with("page") && name[4..].parse::<usize>().is_ok() {
                    // Data page – skip the payload, just record the offset.
                    file.seek(SeekFrom::Current(data_len as i64))
                        .map_err(|e| format!("Error skipping page data: {}", e))?;
                    None
                } else {
                    let mut buf = vec![0u8; data_len as usize];
                    file.read_exact(&mut buf)
                        .map_err(|e| format!("Error reading segment data: {}", e))?;
                    Some(buf)
                }
            } else {
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

            // ---- Interpret known segment names ----
            if let Some(page_num) = name
                .strip_prefix("page")
                .and_then(|s| s.parse::<usize>().ok())
            {
                pages_map.insert(
                    page_num,
                    AffPage {
                        data_offset,
                        data_len,
                        flag,
                    },
                );
            } else if name == "pagesize" {
                if let Some(ref d) = data {
                    if d.len() >= 4 {
                        page_size = Some(u32::from_be_bytes([d[0], d[1], d[2], d[3]]));
                    }
                }
            } else if name == "imagesize" {
                if let Some(ref d) = data {
                    if d.len() >= 8 {
                        image_size = Some(decode_aff_quad(d));
                    }
                }
            } else if name == "sectorsize" {
                if let Some(ref d) = data {
                    if d.len() >= 4 {
                        let v = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
                        sector_size = Some(v as u16);
                    }
                }
            }
        }

        // Build ordered page vector.
        let max_page = pages_map.keys().copied().max().unwrap_or(0);
        let mut pages = Vec::with_capacity(max_page + 1);
        for i in 0..=max_page {
            match pages_map.remove(&i) {
                Some(p) => pages.push(p),
                None => {
                    return Err(format!(
                        "AFF image is missing page{} (have {} pages total)",
                        i,
                        pages_map.len() + pages.len()
                    ));
                }
            }
        }

        let ps = page_size.unwrap_or(AFF_DEFAULT_PAGE_SIZE);
        let is = image_size.unwrap_or_else(|| pages.len() as u64 * ps as u64);

        info!(
            "AFF: parsed {} pages, pagesize={}, imagesize={}",
            pages.len(),
            ps,
            is
        );

        Ok(AFF {
            file,
            path: file_path.to_string(),
            position: 0,
            image_size: is,
            page_size: ps,
            sector_size: sector_size.unwrap_or(AFF_DEFAULT_SECTOR_SIZE),
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

    // ---- Internal page reading ----------------------------------------------

    /// Read and (if necessary) decompress a single page into memory.
    fn read_page(&mut self, page_num: usize) -> io::Result<Vec<u8>> {
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

        let page = &self.pages[page_num];
        let data_offset = page.data_offset;
        let data_len = page.data_len as usize;
        let flag = page.flag;

        // Read raw payload from disk.
        self.file.seek(SeekFrom::Start(data_offset))?;
        let mut raw = vec![0u8; data_len];
        self.file.read_exact(&mut raw)?;

        if flag != 0 {
            // Zlib-compressed page.
            let mut decoder = ZlibDecoder::new(&raw[..]);
            let mut decompressed = Vec::with_capacity(self.page_size as usize);
            decoder.read_to_end(&mut decompressed).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to decompress page{}: {}", page_num, e),
                )
            })?;
            Ok(decompressed)
        } else {
            // Uncompressed page.
            Ok(raw)
        }
    }

    /// Ensure that `cache_data` contains the decompressed content for `page_num`.
    fn ensure_cached(&mut self, page_num: usize) -> io::Result<()> {
        if self.cache_page == Some(page_num) {
            return Ok(());
        }
        let data = self.read_page(page_num)?;
        self.cache_page = Some(page_num);
        self.cache_data = data;
        Ok(())
    }
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
