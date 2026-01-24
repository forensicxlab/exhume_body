//! **EWF (Expert Witness Format) reader utilities**
//!
//! This module provides all the data-structures and helper functions required to
//! parse, inspect and stream data from a multi-segment **EWF / EnCase** forensic
//! image (`.E01`, `.L01`, …).

use flate2::read::ZlibDecoder;
use log::{debug, error, info};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Header located at the very beginning of every *segment* (E01, E02 …).
///
/// The header starts with an 8-byte signature followed by some small control
/// fields. Only the *segment number* is currently exposed – the remainder is
/// preserved for integrity checks but never interpreted by the library.
#[derive(Default, Clone)]
struct EwfHeader {
    /// Either `EVF` / `MVF` signature depending on the EWF **flavour**.
    _signature: [u8; 8],
    /// Logical position of the segment in the multi-part image (starts at `1`).
    segment_number: u16,
}

/// Generic *section descriptor* that precedes **every** section in the format
/// (header, volume, table, data, …). It tells where to find the section and how
/// large it is.
///
/// Refer to the official specification <https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc#31-section-descriptor>
#[derive(Clone)]
struct EwfSectionDescriptor {
    /// NUL-padded ASCII section kind (e.g. `header`, `table`, `done`).
    section_type_def: String,
    /// Offset **from the beginning of the segment** to the *next* section
    /// descriptor.
    next_section_offset: u64,
    /// Raw size (in bytes) of the described section.
    section_size: u64,
    /// CRC-32 of the section header – currently ignored but kept for future
    /// verification.
    _checksum: u32,
}

/// Compressed *header* section — contains acquisition metadata (case number,
/// examiner name, hashes, …). The structure is kept opaque for the moment.
#[derive(Default, Clone)]
struct EwfHeaderSection {
    /// Inflated Zlib payload.
    _data: Vec<u8>,
    /// Parsed tab-separated key/value fields (identifier → value).
    metadata: HashMap<String, String>,
}

/// *Volume* section – describes geometry of the acquired medium.
#[derive(Default, Clone)]
struct EwfVolumeSection {
    /// How many *chunks* (compressed or raw) build the whole image.
    chunk_count: u32,
    /// Number of 512-byte sectors packed into a single *chunk*.
    sector_per_chunk: u32,
    /// Logical sector size in bytes (usually **512**).
    bytes_per_sector: u32,
    /// Overall amount of sectors in the original evidence.
    total_sector_count: u32,
}

/// Lightweight descriptor of a single *chunk*.
#[derive(Clone)]
struct Chunk {
    /// Whether this chunk is zlib-deflated.
    compressed: bool,
    /// Absolute offset (within the segment) to the start of the chunk payload.
    data_offset: u64,
    /// Chunk index **from the beginning of image**, not just its segment.
    chunk_number: usize,
}

/// In-memory cache so repeated `read()` / `seek()` calls do not hammer the IO
/// layer. It always stores **exactly one** chunk.
#[derive(Clone)]
struct ChunkCache {
    /// Chunk global index (starting at 0).
    number: usize,
    /// Owning segment index (starting at 1, to match EWF convention).
    segment: usize,
    /// Current read pointer *inside* the cached chunk.
    ptr: usize,
    /// Decompressed data of the cached chunk.
    data: Vec<u8>,
}

impl Default for ChunkCache {
    fn default() -> Self {
        ChunkCache {
            number: 0,
            segment: 1,
            ptr: 0,
            data: Vec::new(),
        }
    }
}

/// Public façade – implements the `Read` / `Seek` traits over an entire multi-
/// segment EWF image just like a `File` on the original evidence.
#[derive(Default)]
pub struct EWF {
    /// File descriptors for every segment (ordered).
    segments: Vec<File>,
    /// Segment header (from the *last* parsed segment).
    ewf_header: EwfHeader,
    /// All discovered section descriptors of the currently processed segment.
    sections: Vec<EwfSectionDescriptor>,
    /// Global header (only one is expected per image even in multi-segment).
    header: EwfHeaderSection,
    /// Geometry / layout information.
    volume: EwfVolumeSection,
    /// Mapping `segment → [list of chunks]`.
    chunks: HashMap<usize, Vec<Chunk>>,
    /// Map `segment → offset` of the *sectors* section tail – helps delimitate
    /// the last compressed chunk.
    end_of_sectors: HashMap<usize, u64>,
    /// Small read-ahead cache.
    cached_chunk: ChunkCache,
    /// Running counter while parsing tables.
    chunk_count: usize,
    /// Last absolute position after a `seek()` (needed for relative seeks).
    position: u64,
}

// ===== impl EwfVolumeSection =================================================
impl EwfVolumeSection {
    /// Parse and inflate a *volume* section located at `offset` within `file`.
    fn new(mut file: &File, offset: u64) -> Self {
        let mut chunk_count = [0u8; 4];
        let mut sector_per_chunk = [0u8; 4];
        let mut bytes_per_sector = [0u8; 4];
        let mut total_sector_count = [0u8; 4];

        file.seek(SeekFrom::Start(offset + 4)).unwrap();
        file.read(&mut chunk_count).unwrap();
        file.seek(SeekFrom::Start(offset + 8)).unwrap();
        file.read(&mut sector_per_chunk).unwrap();
        file.seek(SeekFrom::Start(offset + 12)).unwrap();
        file.read(&mut bytes_per_sector).unwrap();
        file.seek(SeekFrom::Start(offset + 16)).unwrap();
        file.read(&mut total_sector_count).unwrap();

        Self {
            chunk_count: u32::from_le_bytes(chunk_count),
            sector_per_chunk: u32::from_le_bytes(sector_per_chunk),
            bytes_per_sector: u32::from_le_bytes(bytes_per_sector),
            total_sector_count: u32::from_le_bytes(total_sector_count),
        }
    }

    /// Computed size (in **bytes**) of a single *chunk*.
    #[inline]
    fn chunk_size(&self) -> usize {
        self.sector_per_chunk as usize * self.bytes_per_sector as usize
    }

    /// Largest valid offset (`total_sector_count × bytes_per_sector`).
    #[inline]
    fn max_offset(&self) -> usize {
        self.total_sector_count as usize * self.bytes_per_sector as usize
    }
}

// ===== impl EwfHeader ========================================================
impl EwfHeader {
    /// Read and validate an `EwfHeader` from the **start** of `file`.
    ///
    /// The function ensures the 8-byte signature matches either the *L01* or
    /// *E01* flavour and validates a few sanity bytes that must follow.
    fn new(mut file: &File) -> Result<Self, String> {
        const EWF_L01_SIGNATURE: [u8; 8] = [0x4d, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
        const EWF_E01_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];

        let mut signature = [0u8; 8];
        file.read_exact(&mut signature).unwrap();

        if signature != EWF_L01_SIGNATURE && signature != EWF_E01_SIGNATURE {
            return Err("Invalid Signature.".into());
        }

        let mut one_byte = [0u8; 1];
        file.read_exact(&mut one_byte).unwrap();

        let mut segment_number = [0u8; 2];
        file.read_exact(&mut segment_number).unwrap();

        let mut zero_field = [0u8; 2];
        file.read_exact(&mut zero_field).unwrap();

        if one_byte[0] != 1 || zero_field != [0u8; 2] {
            return Err("Invalid Header Fields.".into());
        }

        Ok(Self {
            _signature: signature,
            segment_number: u16::from_le_bytes(segment_number),
        })
    }
}

// ===== impl EwfSectionDescriptor ============================================
impl EwfSectionDescriptor {
    /// Parse a **section descriptor** present at `offset` in `file`.
    fn new(mut file: &File, offset: u64) -> Self {
        let mut section_type_def = [0u8; 16];
        let mut next_section_offset = [0u8; 8];
        let mut section_size = [0u8; 8];
        let mut checksum = [0u8; 4];

        file.seek(SeekFrom::Start(offset)).unwrap();
        file.read(&mut section_type_def).unwrap();
        file.seek(SeekFrom::Start(offset + 16)).unwrap();
        file.read(&mut next_section_offset).unwrap();
        file.seek(SeekFrom::Start(offset + 24)).unwrap();
        file.read(&mut section_size).unwrap();
        file.seek(SeekFrom::Start(offset + 104)).unwrap();
        file.read(&mut checksum).unwrap();

        let mut section_type = String::from_utf8(section_type_def.to_vec()).unwrap();
        section_type.retain(|c| c != '\0');

        Self {
            section_type_def: section_type,
            next_section_offset: u64::from_le_bytes(next_section_offset),
            section_size: u64::from_le_bytes(section_size),
            _checksum: u32::from_le_bytes(checksum),
        }
    }
}

// ===== impl EwfHeaderSection ===============================================
impl EwfHeaderSection {
    /* ---------------------------------------------------------------- helpers */

    /// Decode raw bytes (`ASCII` first, then `UTF-16LE`) into a `String`.
    fn decode(raw: &[u8]) -> String {
        if let Ok(txt) = String::from_utf8(raw.to_vec()) {
            return txt;
        }
        if raw.len() % 2 == 0 {
            let utf16: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            if let Ok(txt) = String::from_utf16(&utf16) {
                return txt;
            }
        }
        String::new()
    }

    /// Build a map from a *key-row + value-row* pair (tab-separated).
    fn table_to_map(keys: &str, vals: &str) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for (k, v) in keys.split('\t').zip(vals.split('\t')) {
            map.insert(
                k.trim_matches('\0').to_string(),
                v.trim_matches('\0').to_string(),
            );
        }
        map
    }

    /// Robust parser that copes with:
    /// * optional BOM
    /// * optional blank line before the table
    /// * classic *“one entry per line”* fallback used in old images
    fn parse_metadata(raw: &[u8]) -> HashMap<String, String> {
        let txt = Self::decode(raw);
        let mut lines: Vec<&str> = txt
            .split(|c| c == '\n' || c == '\r')
            .filter(|l| !l.trim().is_empty())
            .collect();

        /* strip UTF-8 BOM if present */
        if let Some(first) = lines.first_mut() {
            *first = first.trim_start_matches('\u{FEFF}');
        }

        /* find the first two consecutive tabbed lines – those are the table */
        for i in 0..lines.len().saturating_sub(1) {
            if lines[i].contains('\t') && lines[i + 1].contains('\t') {
                return Self::table_to_map(lines[i], lines[i + 1]);
            }
        }

        /* fallback: id<TAB>value per line */
        let mut map = HashMap::new();
        for l in lines {
            if let Some((k, v)) = l.split_once('\t') {
                map.insert(
                    k.trim_matches('\0').to_string(),
                    v.trim_matches('\0').to_string(),
                );
            }
        }
        map
    }

    /// Inflate the compressed section and immediately parse its metadata.
    fn new(file: &File, offset: u64, section: &EwfSectionDescriptor) -> Result<Self, String> {
        let mut fd = file.try_clone().unwrap();
        fd.seek(SeekFrom::Start(offset)).unwrap();

        let mut compressed = vec![0; section.section_size as usize];
        fd.read_exact(&mut compressed).unwrap();

        let mut decoder = ZlibDecoder::new(&compressed[..]);
        let mut data = Vec::new();
        decoder
            .read_to_end(&mut data)
            .map_err(|_| "Could not decompress the header section".into())
            .map(|_| {
                let metadata = Self::parse_metadata(&data);
                Self {
                    _data: data,
                    metadata,
                }
            })
    }
}

// ===== impl EWF =============================================================
impl EWF {
    /// Create a new `EWF` reader from **any** file belonging to the image.
    ///
    /// *Example* – reading from the very first segment:
    /// ```no_run
    /// # use my_crate::EWF;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut ewf = EWF::new("/evidence/disk.E01")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(file_path: &str) -> Result<Self, String> {
        let fp = Path::new(file_path);
        let files = find_files(fp)?;

        let mut ewf = Self::default();

        // Iterate over every segment and merge their structures.
        for file in files {
            let fd = File::open(file).map_err(|e| e.to_string())?;
            ewf = ewf.parse_segment(fd)?;
        }

        Ok(ewf)
    }
    /// Ref: https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%202%20(EWF2).asciidoc
    /// Outputs a human-readable summary to the current `log` subscriber.
    pub fn print_info(&self) {
        info!("EWF File Information:");
        info!("Number of Segments: {}", self.segments.len());

        if !self.header.metadata.is_empty() {
            info!("Acquisition Metadata:");

            // canonical display order
            let order = [
                "c", "cn", "n", "en", "a", "e", "ex", "t", "nt", "av", "ov", "m", "u", "p", "r",
            ];

            /// Map identifier → human-readable label.
            fn pretty(id: &str) -> &str {
                match id {
                    "c" | "cn" => "Case Number",
                    "n" | "en" => "Evidence Number",
                    "a" => "Description",
                    "e" | "ex" => "Examiner",
                    "t" | "nt" => "Notes",
                    "av" => "Application Version",
                    "ov" => "OS Version",
                    "m" => "Acquisition Date",
                    "u" => "System Date",
                    "p" => "Password Hash",
                    "r" => "Reserved",
                    _ => id, // fall back to the caller’s borrow
                }
            }

            // first: well-known keys in a stable order
            for k in order {
                if let Some(v) = self.header.metadata.get(k) {
                    info!("  {}: {}", pretty(k), v);
                }
            }
            // then any non-standard fields
            for (k, v) in &self.header.metadata {
                if !order.contains(&k.as_str()) {
                    info!("  {}: {}", pretty(k), v);
                }
            }
        }
        info!("Volume Information:");
        info!("  Chunk Count: {}", self.volume.chunk_count);
        info!(
            "  Sectors Per Chunk: {} ({} bytes)",
            self.volume.sector_per_chunk,
            self.volume.chunk_size()
        );
        info!("  Bytes Per Sector: {}", self.volume.bytes_per_sector);
        info!("  Total Sector Count: {}", self.volume.total_sector_count);

        info!("Chunk Information:");
        for (segment_number, chunks) in &self.chunks {
            info!("  Segment Number: {}", segment_number);
            info!("  Number of Chunks: {}", chunks.len());
            for chunk in chunks {
                debug!(
                    "    Chunk Number: {} – Compressed: {} – Data Offset: 0x{:x}",
                    chunk.chunk_number, chunk.compressed, chunk.data_offset
                );
            }
        }
    }

    /// Returns the logical sector size declared in the volume section.
    #[inline]
    pub fn get_sector_size(&self) -> u16 {
        self.volume.bytes_per_sector as u16
    }

    // ---------------------------------------------------------------------
    // Internal helpers (parsing & IO glue). Nothing below this point is part
    // of the public API.
    // ---------------------------------------------------------------------

    /// Parse the *table* section and return a flat list of chunks.
    fn parse_table(&mut self, mut file: &File, offset: u64) -> Vec<Chunk> {
        // Reference: §3.9.1 of the official spec.
        let mut chunks = Vec::new();
        let mut buffer = [0u8; 4];
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.read(&mut buffer).unwrap();
        let entry_count = u32::from_le_bytes(buffer);

        let mut buffer_u64 = [0u8; 8];
        file.seek(SeekFrom::Start(offset + 8)).unwrap();
        file.read_exact(&mut buffer_u64).unwrap();
        let table_base_offset = u64::from_le_bytes(buffer_u64);

        file.read(&mut buffer).unwrap(); // checksum – ignored

        file.seek(SeekFrom::Start(offset + 24)).unwrap();
        let mut entry_buffer = vec![0u8; entry_count as usize * 4];
        file.read_exact(&mut entry_buffer).unwrap();

        for i in 0..entry_count as usize {
            let start = i * 4;
            let tentry = u32::from_le_bytes(entry_buffer[start..start + 4].try_into().unwrap());
            let msb = 0x8000_0000u32;
            let mut ptr = (tentry & 0x7FFF_FFFF) as u64;
            ptr += table_base_offset;

            chunks.push(Chunk {
                compressed: (tentry & msb) != 0,
                data_offset: ptr,
                chunk_number: self.chunk_count,
            });

            self.chunk_count = self
                .chunk_count
                .checked_add(1)
                .expect("Chunk count overflow");
        }
        chunks
    }

    /// Fully parse a single *segment* and merge its metadata into `self`.
    fn parse_segment(mut self, file: File) -> Result<Self, String> {
        self.ewf_header = EwfHeader::new(&file)?;

        // Position ourselves right *after* the header (13 bytes).
        let mut current_offset = 13u64;
        let ewf_section_descriptor_size = 0x4c;
        let mut extracted_chunks = Vec::new();

        loop {
            let section = EwfSectionDescriptor::new(&file, current_offset);
            let section_offset = section.next_section_offset;
            let section_size = section.section_size;
            let section_type = section.section_type_def.clone();
            self.sections.push(section);

            match section_type.as_str() {
                "header" | "header2" => {
                    let h = EwfHeaderSection::new(
                        &file,
                        current_offset + ewf_section_descriptor_size,
                        self.sections.last().unwrap(),
                    )?;
                    if self.header._data.is_empty() {
                        self.header = h;
                    } else {
                        // header2 values overwrite duplicates from header (UTF-16 beats ASCII)
                        self.header.metadata.extend(h.metadata);
                    }
                }
                "disk" | "volume" => {
                    self.volume =
                        EwfVolumeSection::new(&file, current_offset + ewf_section_descriptor_size);
                }
                "table" => {
                    extracted_chunks.extend(
                        self.parse_table(&file, current_offset + ewf_section_descriptor_size),
                    );
                }
                "sectors" => {
                    self.end_of_sectors.insert(
                        self.ewf_header.segment_number as usize,
                        current_offset + section_size,
                    );
                }
                _ => {}
            }

            if current_offset == section_offset || section_type == "done" {
                break;
            }
            current_offset = section_offset;
        }

        self.segments.push(file);
        self.chunks
            .insert(self.ewf_header.segment_number as usize, extracted_chunks);
        Ok(self)
    }

    /// Read and *optionally* inflate the `chunk_number` of `segment`.
    fn read_chunk(&self, segment: usize, chunk_number: usize) -> Vec<u8> {
        debug!(
            "Reading chunk number {} (segment {})",
            chunk_number, segment
        );

        if chunk_number >= self.chunks[&segment].len() {
            error!(
                "Could not read chunk number {} in segment {}",
                chunk_number, segment
            );
            std::process::exit(1);
        }

        let chunk = &self.chunks[&segment][chunk_number];
        let start_offset = chunk.data_offset;

        let mut file = self.segments[segment - 1].try_clone().unwrap();
        file.seek(SeekFrom::Start(start_offset)).unwrap();

        if !chunk.compressed {
            let mut data = vec![0u8; self.volume.chunk_size()];
            file.read_exact(&mut data).unwrap();
            return data;
        }

        // Compressed chunk – compute its length first (end offset varies).
        let end_offset = if chunk.data_offset == self.chunks[&segment].last().unwrap().data_offset {
            self.end_of_sectors[&segment]
        } else {
            self.chunks[&segment][chunk_number + 1].data_offset
        };
        let mut compressed_data = vec![0u8; (end_offset - start_offset) as usize];
        file.read_exact(&mut compressed_data).unwrap();

        let mut decoder = ZlibDecoder::new(&compressed_data[..]);
        let mut data = Vec::new();
        decoder.read_to_end(&mut data).unwrap();
        data
    }

    /// Copy `buf.len()` bytes from the image into `buf`, starting at the
    /// *current* offset (tracked by `self.cached_chunk`). Returns the amount of
    /// bytes actually copied (0 on EOF).
    fn ewf_read(&mut self, buf: &mut [u8]) -> usize {
        let mut total_bytes_read = 0;
        let mut remaining = buf.len();

        // Ensure we have something in cache.
        if self.cached_chunk.data.is_empty() {
            self.cached_chunk.data =
                self.read_chunk(self.cached_chunk.segment, self.cached_chunk.number);
        }

        // While there is still room in the caller buffer.
        while remaining > 0 {
            let current_chunk_size = self.volume.chunk_size();
            let available_in_chunk = current_chunk_size - self.cached_chunk.ptr;

            if available_in_chunk >= remaining {
                // Enough data available – just copy and return.
                buf[total_bytes_read..total_bytes_read + remaining].copy_from_slice(
                    &self.cached_chunk.data
                        [self.cached_chunk.ptr..self.cached_chunk.ptr + remaining],
                );
                self.cached_chunk.ptr += remaining;
                total_bytes_read += remaining;
                remaining = 0;
            } else {
                // Drain the rest of the current chunk.
                buf[total_bytes_read..total_bytes_read + available_in_chunk]
                    .copy_from_slice(&self.cached_chunk.data[self.cached_chunk.ptr..]);
                total_bytes_read += available_in_chunk;
                remaining -= available_in_chunk;
                self.cached_chunk.ptr = current_chunk_size; // EOF of chunk.

                // Move to **next** chunk (same segment or the following one).
                if self.cached_chunk.segment < self.segments.len()
                    || (self.cached_chunk.segment == self.segments.len()
                        && self.cached_chunk.number + 1
                            < self.chunks[&self.cached_chunk.segment].len())
                {
                    if self.cached_chunk.number + 1 < self.chunks[&self.cached_chunk.segment].len()
                    {
                        self.cached_chunk.number += 1;
                    } else {
                        self.cached_chunk.segment += 1;
                        self.cached_chunk.number = 0;
                    }

                    self.cached_chunk.data =
                        self.read_chunk(self.cached_chunk.segment, self.cached_chunk.number);
                    self.cached_chunk.ptr = 0;
                } else {
                    // No more data.
                    break;
                }
            }
        }
        total_bytes_read
    }

    /// Translate an absolute offset into the appropriate chunk and refresh the
    /// cache so that subsequent reads start from there.
    fn ewf_seek(&mut self, offset: usize) -> io::Result<()> {
        if offset > self.volume.max_offset() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Offset 0x{:x} is beyond image size (0x{:x})",
                    offset,
                    self.volume.max_offset()
                ),
            ));
        }

        let chunk_size = self.volume.chunk_size();
        let mut chunk_number = offset / chunk_size;
        if chunk_number >= self.volume.chunk_count as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Chunk number exceeds declared chunk_count",
            ));
        }

        // Locate the appropriate segment.
        let mut segment = 1;
        while segment < self.segments.len()
            && (self.chunks[&segment][0].chunk_number > chunk_number
                || chunk_number > self.chunks[&segment].last().unwrap().chunk_number)
        {
            segment += 1;
        }

        chunk_number -= self.chunks[&segment][0].chunk_number;

        // Populate cache.
        self.cached_chunk.data = self.read_chunk(segment, chunk_number);
        self.cached_chunk.number = chunk_number;
        self.cached_chunk.segment = segment;
        self.cached_chunk.ptr = offset % chunk_size;
        self.position = offset as u64;
        Ok(())
    }
}

// ===== Clone impl ===========================================================
impl Clone for EWF {
    fn clone(&self) -> Self {
        let segments = self
            .segments
            .iter()
            .map(|fd| fd.try_clone().expect("failed to duplicate segment FD"))
            .collect();

        Self {
            segments,
            ewf_header: self.ewf_header.clone(),
            sections: self.sections.clone(),
            header: self.header.clone(),
            volume: self.volume.clone(),
            chunks: self.chunks.clone(),
            end_of_sectors: self.end_of_sectors.clone(),
            cached_chunk: self.cached_chunk.clone(),
            chunk_count: self.chunk_count,
            position: self.position,
        }
    }
}

// ===== std::io trait implementations =======================================
impl Read for EWF {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes_read = self.ewf_read(buf);
        Ok(bytes_read)
    }
}

impl Seek for EWF {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_offset = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::Current(o) => self.position as i64 + o,
            SeekFrom::End(o) => self.volume.max_offset() as i64 + o,
        };

        if new_offset < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Seek before start of image",
            ));
        }

        let new_offset_usize = new_offset as usize;
        self.ewf_seek(new_offset_usize)?;
        Ok(new_offset as u64)
    }
}

// ===== helpers ==============================================================
/// Look for every segment belonging to the *same* multi-part image as `path`.
///
/// The function builds a glob pattern **in the parent directory** replacing the
/// numeric suffix with a wild-card (e.g. `image.E01` ⇒ `image.E??`) and returns
/// the sorted list of matching paths.
fn find_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    let path = path
        .canonicalize()
        .map_err(|_| "Invalid path".to_string())?;
    let filename = path.file_name().ok_or("Invalid file name")?;
    let filename_str = filename.to_str().ok_or("Invalid file name")?;

    if filename_str.len() < 2 {
        return Err("File name too short".into());
    }

    let base_filename = &filename_str[..filename_str.len() - 2];
    let parent = path.parent().ok_or("No parent directory")?;

    let mut pattern_path = PathBuf::from(parent);
    pattern_path.push(format!("{}??", base_filename));
    let pattern = pattern_path.to_str().ok_or("Invalid pattern")?.to_string();

    let files = glob::glob(&pattern).map_err(|e| format!("Glob error: {}", e))?;
    let mut paths: Vec<PathBuf> = files.filter_map(Result::ok).collect();
    paths.sort();

    Ok(paths)
}
