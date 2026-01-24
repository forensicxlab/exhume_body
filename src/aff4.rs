// src/aff4.rs

use log::{debug, error, info, warn};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

// --- Zip & Zip64 Constants & Signatures ---
const EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x05, 0x06]; // Legacy End of Central Directory
const ZIP64_LOCATOR_SIG: [u8; 4] = [0x50, 0x4b, 0x06, 0x07]; // Zip64 Locator
const ZIP64_EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x06, 0x06]; // Zip64 End of Central Directory Record
const CD_ENTRY_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02]; // Central Directory File Header

#[derive(Default)]
pub struct AFF4 {
    /// The handle to the physical .aff4 file (Zip container).
    file: Option<File>,

    /// The size of the reconstructed image (parsed from RDF).
    image_size: u64,

    /// The Map: A sorted list of intervals.
    /// When `read(offset)` is called, we binary_search this list.
    intervals: Vec<Aff4Interval>,

    /// The Zip Directory: Maps "URNs" to physical file offsets.
    zip_directory: BTreeMap<String, ZipEntry>,

    /// Cache to avoid re-inflating Deflate streams constantly.
    cache: Aff4Cache,

    /// Current virtual cursor position (for Seek/Read).
    position: u64,
}

/// Represents a single mapping interval from the AFF4 Map.
/// From logical byte X to Y, go read physical data at Z.
#[derive(Clone, Debug)]
struct Aff4Interval {
    /// The starting offset in the **Virtual Image**.
    virtual_offset: u64,
    /// The length of this run of data.
    length: u64,
    /// The name of the zip member where this data lives (e.g. "data/chunk_1.dat").
    target_urn: String,
    /// The offset inside that target zip member (usually 0).
    target_offset: u64,
}

/// Represents the "Table of Contents" of the Zip container.
/// We need this to quickly find where "data/chunk_1.dat" physically sits in the .aff4 file.
#[derive(Clone, Debug)]
pub struct ZipEntry {
    /// Physical offset in the .aff4 file where the Local File Header starts.
    /// Note: The actual data starts *after* the variable-length local header.
    pub header_offset: u64,
    /// Compressed size.
    pub compressed_size: u64,
    /// Uncompressed size.
    pub uncompressed_size: u64,
    /// Compression method (0 = Store, 8 = Deflate).
    pub compression_method: u16,
}

#[derive(Clone, Default)]
struct Aff4Cache {
    /// The URN of the cached chunk (e.g., "data/chunk_42").
    target_urn: String,
    /// The decompressed data.
    data: Vec<u8>,
    /// Current read pointer inside this cached chunk.
    ptr: usize,
}

impl AFF4 {
    pub fn new(path: &str) -> Result<Self, String> {
        let mut file = File::open(path).map_err(|e| e.to_string())?;

        // 1. Parse the Zip64 Footer & Central Directory (The Theory we covered)
        let zip_directory = Self::parse_zip_structure(&mut file)?;

        // 2. Extract "information.turtle"
        let turtle_data = Self::extract_metadata(&mut file, &zip_directory)?;

        // 3. Parse RDF to build the Interval Map
        let (intervals, image_size) = Self::parse_turtle_map(&turtle_data)?;

        Ok(Self {
            file: Some(file),
            image_size,
            intervals,
            zip_directory,
            cache: Aff4Cache::default(),
            position: 0,
        })
    }

    fn extract_metadata(
        file: &mut File,
        zip_directory: &BTreeMap<String, ZipEntry>,
    ) -> Result<String, String> {
        Ok("".to_string())
    }

    /// Scans the end of the file to find the Zip64 directory structures and
    /// builds a map of filenames to file locations.
    fn parse_zip_structure(file: &mut File) -> Result<BTreeMap<String, ZipEntry>, String> {
        // 1. Find the Legacy EOCD to handle trailing comments (e.g., from Digital Collector).
        // We scan the last 66KB (Max comment size + EOCD size).
        let eocd_offset = Self::find_legacy_eocd_offset(file)?;
        debug!("Found Legacy EOCD at offset: {}", eocd_offset);

        // 2. The Zip64 Locator must be exactly 20 bytes before the Legacy EOCD.
        let locator_offset = eocd_offset
            .checked_sub(20)
            .ok_or("File too small to contain Zip64 Locator")?;

        file.seek(SeekFrom::Start(locator_offset))
            .map_err(|e| e.to_string())?;

        // 3. Read and Validate the Zip64 Locator (20 bytes).
        let mut locator_buf = [0u8; 20];
        file.read_exact(&mut locator_buf)
            .map_err(|e| e.to_string())?;

        if locator_buf[0..4] != ZIP64_LOCATOR_SIG {
            return Err(format!(
                "Invalid Zip64 Locator signature at {}. Expected 504b0607, found {:x?}",
                locator_offset,
                &locator_buf[0..4]
            ));
        }

        // Bytes 8-16 contain the 64-bit absolute offset of the Zip64 EOCD Record.
        let eocd64_offset = u64::from_le_bytes(locator_buf[8..16].try_into().unwrap());
        debug!("Zip64 EOCD Record located at: {}", eocd64_offset);

        // 4. Jump to the Zip64 EOCD Record.
        file.seek(SeekFrom::Start(eocd64_offset))
            .map_err(|e| e.to_string())?;

        // Read the fixed part of the Zip64 EOCD (first 56 bytes are standard).
        let mut eocd64_buf = [0u8; 56];
        file.read_exact(&mut eocd64_buf)
            .map_err(|e| e.to_string())?;

        if eocd64_buf[0..4] != ZIP64_EOCD_SIG {
            return Err("Invalid Zip64 EOCD Record signature".to_string());
        }

        // Extract directory information:
        // Offset 24: Total entries (u64)
        // Offset 40: Size of Central Directory (u64)
        // Offset 48: Offset of Central Directory (u64)
        let total_entries = u64::from_le_bytes(eocd64_buf[32..40].try_into().unwrap());
        let _cd_size = u64::from_le_bytes(eocd64_buf[40..48].try_into().unwrap());
        let cd_start_offset = u64::from_le_bytes(eocd64_buf[48..56].try_into().unwrap());

        debug!(
            "Central Directory: {} entries starting at {}",
            total_entries, cd_start_offset
        );

        // 5. Parse the Central Directory.
        Self::parse_central_directory(file, cd_start_offset, total_entries)
    }

    /// Iterates through the Central Directory headers to build the file map.
    fn parse_central_directory(
        file: &mut File,
        offset: u64,
        count: u64,
    ) -> Result<BTreeMap<String, ZipEntry>, String> {
        let mut directory = BTreeMap::new();
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| e.to_string())?;

        for _ in 0..count {
            // Read fixed-size header (46 bytes)
            let mut buf = [0u8; 46];
            file.read_exact(&mut buf).map_err(|e| e.to_string())?;

            if buf[0..4] != CD_ENTRY_SIG {
                warn!("Central Directory signature mismatch. Stopping directory scan.");
                break;
            }

            let comp_method = u16::from_le_bytes(buf[10..12].try_into().unwrap());
            let name_len = u16::from_le_bytes(buf[28..30].try_into().unwrap()) as usize;
            let extra_len = u16::from_le_bytes(buf[30..32].try_into().unwrap()) as usize;
            let comment_len = u16::from_le_bytes(buf[32..34].try_into().unwrap()) as usize;

            // Read variable length filename
            let mut name_buf = vec![0u8; name_len];
            file.read_exact(&mut name_buf).map_err(|e| e.to_string())?;
            let filename = String::from_utf8_lossy(&name_buf).to_string();

            // Read Extra Field (Contains Zip64 64-bit sizes/offsets)
            let mut extra_buf = vec![0u8; extra_len];
            file.read_exact(&mut extra_buf).map_err(|e| e.to_string())?;

            // Read Comment (Discard)
            file.seek(SeekFrom::Current(comment_len as i64))
                .map_err(|e| e.to_string())?;

            // ---------------------------------------------------------
            // ZIP64 Parsing Logic for Sizes
            // ---------------------------------------------------------
            // We need to parse the Extra Field to find the Zip64 Extended Information (Tag 0x0001)
            // This is required because standard fields are only 32-bit.

            let mut real_comp_size = u32::from_le_bytes(buf[20..24].try_into().unwrap()) as u64;
            let mut real_uncomp_size = u32::from_le_bytes(buf[24..28].try_into().unwrap()) as u64;
            let mut real_offset = u32::from_le_bytes(buf[42..46].try_into().unwrap()) as u64;

            // Simple Extra Field Parser
            let mut i = 0;
            while i + 4 <= extra_buf.len() {
                let tag = u16::from_le_bytes(extra_buf[i..i + 2].try_into().unwrap());
                let size = u16::from_le_bytes(extra_buf[i + 2..i + 4].try_into().unwrap()) as usize;

                if tag == 0x0001 {
                    // Zip64 Tag
                    // Format depends on which values were -1 (0xFFFFFFFF) in main header.
                    // Usually: [Uncomp Size (8)] [Comp Size (8)] [Offset (8)] [Disk Start (4)]
                    // But strictly, they only appear if the header value was 0xFFFFFFFF.
                    // For simplicity in AFF4 (huge files), we assume they are present if tag exists.

                    let mut data_ptr = i + 4;

                    if real_uncomp_size == 0xFFFFFFFF && data_ptr + 8 <= extra_buf.len() {
                        real_uncomp_size = u64::from_le_bytes(
                            extra_buf[data_ptr..data_ptr + 8].try_into().unwrap(),
                        );
                        data_ptr += 8;
                    }
                    if real_comp_size == 0xFFFFFFFF && data_ptr + 8 <= extra_buf.len() {
                        real_comp_size = u64::from_le_bytes(
                            extra_buf[data_ptr..data_ptr + 8].try_into().unwrap(),
                        );
                        data_ptr += 8;
                    }
                    if real_offset == 0xFFFFFFFF && data_ptr + 8 <= extra_buf.len() {
                        real_offset = u64::from_le_bytes(
                            extra_buf[data_ptr..data_ptr + 8].try_into().unwrap(),
                        );
                    }
                }
                i += 4 + size;
            }
            debug!("Found {:?} in AFF4 Zip Central Directory", filename);
            if filename == "version.txt" {
                info!("version.txt file found at offset 0x{:x}.", real_offset);
            }
            if filename == "information.turtle" {
                info!(
                    "information.turtle file found at offset 0x{:x}.",
                    real_offset
                );
            }
            directory.insert(
                filename,
                ZipEntry {
                    header_offset: real_offset,
                    compressed_size: real_comp_size,
                    uncompressed_size: real_uncomp_size,
                    compression_method: comp_method,
                },
            );
        }

        Ok(directory)
    }

    /// Scans the file backwards from the end until it finds the first Legacy EOCD signature.
    /// This handles variable comment lengths without arbitrary size limits.
    fn find_legacy_eocd_offset(file: &mut File) -> Result<u64, String> {
        let file_len = file.metadata().map_err(|e| e.to_string())?.len();

        // We start scanning from the very end of the file.
        let mut cursor = file_len;

        // This should be large enought to cover the comments i've seens some commercial tools are putting in the end of the AFF4.
        let chunk_size = 4096;

        while cursor > 0 {
            // Determine the start of the read.
            // If cursor is 1000 and chunk_size is 4096, start is 0.
            let start_pos = if cursor > chunk_size {
                cursor - chunk_size
            } else {
                0
            };

            let read_len = (cursor - start_pos) as usize;

            // 1. Seek and Read the chunk
            file.seek(SeekFrom::Start(start_pos))
                .map_err(|e| e.to_string())?;
            let mut buffer = vec![0u8; read_len];
            file.read_exact(&mut buffer).map_err(|e| e.to_string())?;

            // 2. Scan the buffer BACKWARDS
            // rposition returns the index of the *start* of the match.
            if let Some(offset_in_chunk) = buffer
                .windows(EOCD_SIGNATURE.len())
                .rposition(|window| window == EOCD_SIGNATURE)
            {
                // Found it! Calculate absolute offset.
                return Ok(start_pos + offset_in_chunk as u64);
            }

            // 3. Prepare for next iteration
            if start_pos == 0 {
                break; // Reached start of file, not found.
            }

            // CRITICAL: Overlap Logic
            // If the signature is 4 bytes [PK 05 06], it might be split across the chunk boundary.
            // (e.g., PK at the start of this chunk, 05 06 at the end of the previous chunk).
            // To catch this, we reset the cursor to `start_pos + 3`.
            // This ensures the next read includes the first 3 bytes of the current chunk
            // at the end of its buffer, allowing the window to match across the seam.
            cursor = start_pos + (EOCD_SIGNATURE.len() as u64 - 1);
        }

        Err("Could not find Legacy EOCD signature".to_string())
    }

    fn parse_turtle_map(turtle: &str) -> Result<(Vec<Aff4Interval>, u64), String> {
        // TODO: Use Rio or Regex to parse the Map intervals
        Ok((Vec::new(), 0))
    }

    // --- The Read Logic ---

    /// Find which interval covers the current virtual offset.
    fn find_interval(&self, offset: u64) -> Option<&Aff4Interval> {
        // Binary search logic here.
        // If no interval is found, it means we are in a "Sparse Gap" (Zeros).
        self.intervals
            .iter()
            .find(|i| offset >= i.virtual_offset && offset < i.virtual_offset + i.length)
    }

    fn read_from_interval(&mut self, interval: &Aff4Interval, buf: &mut [u8]) -> usize {
        // 1. Check if data is in cache.
        // 2. If not, look up interval.target_urn in self.zip_directory.
        // 3. Seek to physical offset, read compressed bytes, inflate.
        // 4. Copy to buf.
        0 // placeholder
    }

    pub fn print_info(&self) {
        println!("TODO!");
    }

    pub fn get_sector_size(&self) -> u16 {
        512
    }
}

// In src/aff4.rs

impl Clone for AFF4 {
    fn clone(&self) -> Self {
        // We must manually clone the File handle using try_clone().
        // This creates a new file descriptor pointing to the same file.
        let file = self
            .file
            .as_ref()
            .map(|f| f.try_clone().expect("Failed to clone AFF4 file handle"));

        Self {
            file,
            // These fields implement Clone automatically (u64, Vec, BTreeMap, etc.)
            image_size: self.image_size,
            intervals: self.intervals.clone(),
            zip_directory: self.zip_directory.clone(),
            // The cache is cloned as-is. The new reader inherits the cache state,
            // which is fine since it's just a buffer of data.
            cache: self.cache.clone(),
            position: self.position,
        }
    }
}

impl Read for AFF4 {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.image_size {
            return Ok(0);
        }

        let mut read_len = 0;
        let mut remaining = buf.len();

        while remaining > 0 && self.position < self.image_size {
            // 1. Where are we?
            match self.find_interval(self.position) {
                Some(interval) => {
                    // We are in data. Read from the Zip stream.
                    // (Logic similar to EWF::ewf_read but resolving the map first)
                    let chunk_read =
                        self.read_from_interval(&interval.clone(), &mut buf[read_len..]);
                    read_len += chunk_read;
                    remaining -= chunk_read;
                    self.position += chunk_read as u64;

                    // Boundary check: if we hit end of interval, loop continues to next one.
                }
                None => {
                    // We are in a GAP (Sparse Data).
                    // The Map has no entry for this, so it is virtually ZERO.
                    // We need to find the START of the NEXT interval to know how many zeros to write.
                    let next_start = self
                        .intervals
                        .iter()
                        .find(|i| i.virtual_offset > self.position)
                        .map(|i| i.virtual_offset)
                        .unwrap_or(self.image_size);

                    let gap_size = next_start - self.position;
                    let to_fill = std::cmp::min(gap_size, remaining as u64) as usize;

                    // Zero out the buffer
                    buf[read_len..read_len + to_fill].fill(0);

                    read_len += to_fill;
                    remaining -= to_fill;
                    self.position += to_fill as u64;
                }
            }
        }
        Ok(read_len)
    }
}

impl Seek for AFF4 {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::Current(o) => self.position as i64 + o,
            SeekFrom::End(o) => self.image_size as i64 + o,
        };

        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Seek before start",
            ));
        }

        // AFF4 Seek is cheap: just update the cursor.
        // The Map resolution happens lazily during Read.
        self.position = new_pos as u64;
        Ok(self.position)
    }
}
