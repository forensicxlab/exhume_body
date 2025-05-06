use flate2::read::ZlibDecoder;
use log::{debug, error, info};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[derive(Default, Clone)]
struct EwfHeader {
    _signature: [u8; 8], // 8 bytes
    segment_number: u16, // 2 bytes
}

#[derive(Clone)]
struct EwfSectionDescriptor {
    // Ref : https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc#31-section-descriptor
    section_type_def: String, // 16 bytes
    next_section_offset: u64, // 8 bytes
    section_size: u64,        // 8 bytes
    _checksum: u32,           // 4 bytes
}

#[derive(Default, Clone)]
struct EwfHeaderSection {
    // Ref: https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc#34-header-section
    _data: Vec<u8>,
}

#[derive(Default, Clone)]
struct EwfVolumeSection {
    // Ref : https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc#35-volume-section
    chunk_count: u32,
    sector_per_chunk: u32,
    bytes_per_sector: u32,
    total_sector_count: u32,
}

#[derive(Clone)]
struct Chunk {
    compressed: bool,    // Am I compressed ?
    data_offset: u64,    // Where are my data starting ?
    chunk_number: usize, // What is my chunk number (absolute) ?
}

#[derive(Clone)]
struct ChunkCache {
    number: usize,
    segment: usize,
    ptr: usize,
    data: Vec<u8>,
}

#[derive(Default)]
pub struct EWF {
    segments: Vec<File>,
    ewf_header: EwfHeader,
    sections: Vec<EwfSectionDescriptor>,
    header: EwfHeaderSection,
    volume: EwfVolumeSection,
    chunks: HashMap<usize, Vec<Chunk>>,
    end_of_sectors: HashMap<usize, u64>,
    cached_chunk: ChunkCache,
    chunk_count: usize,
    position: u64,
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

impl EwfVolumeSection {
    fn new(mut file: &File, offset: u64) -> EwfVolumeSection {
        let mut chunk_count: [u8; 4] = [0; 4];
        let mut sector_per_chunk: [u8; 4] = [0; 4];
        let mut bytes_per_sector: [u8; 4] = [0; 4];
        let mut total_sector_count: [u8; 4] = [0; 4];
        file.seek(SeekFrom::Start(offset + 4)).unwrap();
        file.read(&mut chunk_count).unwrap();
        file.seek(SeekFrom::Start(offset + 8)).unwrap();
        file.read(&mut sector_per_chunk).unwrap();
        file.seek(SeekFrom::Start(offset + 12)).unwrap();
        file.read(&mut bytes_per_sector).unwrap();
        file.seek(SeekFrom::Start(offset + 16)).unwrap();
        file.read(&mut total_sector_count).unwrap();

        return EwfVolumeSection {
            chunk_count: u32::from_le_bytes(chunk_count),
            sector_per_chunk: u32::from_le_bytes(sector_per_chunk),
            bytes_per_sector: u32::from_le_bytes(bytes_per_sector),
            total_sector_count: u32::from_le_bytes(total_sector_count),
        };
    }

    fn chunk_size(&self) -> usize {
        return self.sector_per_chunk as usize * self.bytes_per_sector as usize;
    }

    fn max_offset(&self) -> usize {
        return self.total_sector_count as usize * self.bytes_per_sector as usize;
    }
}

impl EwfHeader {
    fn new(mut file: &File) -> Result<EwfHeader, String> {
        let ewf_l01_signature = [0x4d, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];
        let ewf_e01_signature = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];

        let mut signature: [u8; 8] = [0u8; 8];
        file.read_exact(&mut signature).unwrap();

        if (ewf_l01_signature != signature) && (signature != ewf_e01_signature) {
            return Err("Invalid Signature.".to_string());
        }

        let mut one_byte: [u8; 1] = [0u8; 1];
        file.read_exact(&mut one_byte).unwrap();

        let mut segment_number: [u8; 2] = [0u8; 2];
        file.read_exact(&mut segment_number).unwrap();

        let mut zero_field: [u8; 2] = [0u8; 2];
        file.read_exact(&mut zero_field).unwrap();

        if one_byte[0] != 1 || zero_field != [0u8; 2] {
            return Err("Invalid Header Fields.".to_string());
        }

        Ok(EwfHeader {
            _signature: signature,
            segment_number: u16::from_le_bytes(segment_number),
        })
    }
}

impl EwfSectionDescriptor {
    fn new(mut file: &File, offset: u64) -> EwfSectionDescriptor {
        let mut section_type_def = [0; 16];
        let mut next_section_offset: [u8; 8] = [0; 8];
        let mut section_size: [u8; 8] = [0; 8];
        let mut checksum: [u8; 4] = [0; 4];

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

        return EwfSectionDescriptor {
            section_type_def: section_type,
            next_section_offset: u64::from_le_bytes(next_section_offset),
            section_size: u64::from_le_bytes(section_size),
            _checksum: u32::from_le_bytes(checksum),
        };
    }
}

impl EwfHeaderSection {
    fn new(
        mut file: &File,
        offset: u64,
        section: &EwfSectionDescriptor,
    ) -> Result<EwfHeaderSection, String> {
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut compressed_data = vec![0; section.section_size as usize];
        file.read(&mut compressed_data).unwrap();
        let mut decoder = ZlibDecoder::new(&compressed_data[..]);
        let mut data = Vec::new();

        match decoder.read_to_end(&mut data) {
            Ok(_) => return Ok(EwfHeaderSection { _data: data }),
            Err(_) => return Err("Could not decompress the header section".to_string()),
        }
    }
}

impl EWF {
    pub fn new(file_path: &str) -> Result<EWF, String> {
        let fp: &Path = Path::new(file_path);
        //let entries = fs::read_dir(parent_dir).unwrap();
        let files = match find_files(fp) {
            Ok(fp) => fp,
            Err(m) => return Err(m),
        };

        let mut ewf: EWF = EWF::default();

        //Go through all of the segments and parse them.

        for file in files {
            let fd = match File::open(file) {
                Ok(file) => file,
                Err(m) => return Err(m.to_string()),
            };

            ewf = match ewf.parse_segment(fd) {
                Ok(ewf) => ewf,
                Err(m) => return Err(m),
            };
        }
        return Ok(ewf);
    }

    /// Print useful information about the EWF file
    pub fn print_info(&self) {
        info!("EWF File Information:");

        // Print number of segments
        info!("Number of Segments: {}", self.segments.len());

        // Print volume information
        info!("Volume Information:");
        info!("  Chunk Count: {}", self.volume.chunk_count);
        info!("  Sectors Per Chunk: {}", self.volume.sector_per_chunk);
        info!("  Bytes Per Sector: {}", self.volume.bytes_per_sector);
        info!("  Total Sector Count: {}", self.volume.total_sector_count);

        // Print each segment with its associated chunks
        info!("Chunk Information:");
        for (segment_number, chunks) in &self.chunks {
            info!("  Segment Number: {}", segment_number);
            info!("  Number of Chunks: {}", chunks.len());
            for chunk in chunks {
                debug!(
                    "    Chunk Number: {} - Compressed: {} - Data Offset: {}",
                    chunk.chunk_number, chunk.compressed, chunk.data_offset
                );
            }
        }
    }

    pub fn get_sector_size(&self) -> u16 {
        return self.volume.bytes_per_sector as u16;
    }

    fn parse_table(&mut self, mut file: &File, offset: u64) -> Vec<Chunk> {
        // Ref: https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc#391-ewf-specification
        let mut chunks: Vec<Chunk> = Vec::new();
        let mut buffer: [u8; 4] = [0; 4];
        file.seek(SeekFrom::Start(offset)).unwrap();

        file.read(&mut buffer).unwrap();
        let entry_count = u32::from_le_bytes(buffer);

        let mut buffer_u64: [u8; 8] = [0; 8];
        file.seek(SeekFrom::Start(offset + 8)).unwrap();
        file.read_exact(&mut buffer_u64).unwrap();
        let table_base_offset = u64::from_le_bytes(buffer_u64);

        file.read(&mut buffer).unwrap();
        let _checksum = u32::from_le_bytes(buffer); // Not used yet.

        file.seek(SeekFrom::Start(offset + 24)).unwrap(); // We place ourself at the beginning of the first table entry.

        let mut entry_buffer = vec![0u8; entry_count as usize * 4];
        file.read_exact(&mut entry_buffer).unwrap();

        for i in 0..entry_count as usize {
            let start = i * 4;
            let tentry = u32::from_le_bytes(entry_buffer[start..start + 4].try_into().unwrap());
            let msb: u32 = 0x80000000;
            let mut ptr = (tentry & 0x7FFFFFFF) as u64;
            ptr += table_base_offset;

            chunks.push(Chunk {
                compressed: (tentry & msb) != 0,
                data_offset: ptr,
                chunk_number: self.chunk_count,
            });

            self.chunk_count = self
                .chunk_count
                .checked_add(1)
                .ok_or("Chunk count overflow")
                .unwrap();
        }
        return chunks;
    }

    fn parse_segment(mut self, file: File) -> Result<EWF, String> {
        self.ewf_header = match EwfHeader::new(&file) {
            Ok(header) => header,
            Err(m) => return Err(m),
        };

        // Then, we place our pointer after the header section
        let mut current_offset = 13; //We place our self just after the EWFHeaderSection.
        let ewf_section_descriptor_size = 0x4c; // Each section descriptor size is 0x4c.
        let mut extracted_chunks: Vec<Chunk> = Vec::new();

        loop {
            let section: EwfSectionDescriptor = EwfSectionDescriptor::new(&file, current_offset);
            let section_offset = section.next_section_offset.clone();
            let section_size = section.section_size.clone();
            let section_type = section.section_type_def.clone();
            self.sections.push(section);

            if section_type == "header" || section_type == "header2" {
                // We save the header, it contains information about the acquired media.
                self.header = match EwfHeaderSection::new(
                    &file,
                    current_offset + ewf_section_descriptor_size,
                    self.sections.last().unwrap(),
                ) {
                    Ok(header) => header,
                    Err(m) => return Err(m),
                };
            }

            if section_type == "disk" || section_type == "volume" {
                self.volume =
                    EwfVolumeSection::new(&file, current_offset + ewf_section_descriptor_size);
                // We keep the volume because it has information about the acquired media.
            }

            if section_type == "table" {
                extracted_chunks
                    .extend(self.parse_table(&file, current_offset + ewf_section_descriptor_size));
            }

            if section_type == "sectors" {
                self.end_of_sectors.insert(
                    self.ewf_header.segment_number.clone() as usize,
                    current_offset + section_size,
                );
            }

            if current_offset == section_offset || section_type == "done" {
                break;
            }
            current_offset = section_offset;
        }

        self.segments.push(file);
        self.chunks.insert(
            self.ewf_header.segment_number.clone() as usize,
            extracted_chunks,
        );
        return Ok(self);
    }

    fn read_chunk(&self, segment: usize, chunk_number: usize) -> Vec<u8> {
        debug!(
            "Reading chunk number {:?}, segment {:?}",
            chunk_number, segment
        );
        if chunk_number >= self.chunks.get(&segment).unwrap().len() {
            error!(
                "Could not read chunk number {:?} in segment number {:?}",
                chunk_number, segment
            );
            std::process::exit(1);
        }
        let mut data: Vec<u8>;
        let chunk = &self.chunks[&segment][chunk_number];

        let end_offset: u64;
        let start_offset: u64 = chunk.data_offset as u64;

        self.segments
            .get(segment as usize - 1)
            .unwrap()
            .seek(SeekFrom::Start(start_offset))
            .unwrap();

        if !chunk.compressed {
            data = vec![0; self.volume.chunk_size()];
            self.segments
                .get(segment as usize - 1)
                .unwrap()
                .read(&mut data)
                .unwrap();
        } else {
            if chunk.data_offset == self.chunks[&segment].last().unwrap().data_offset {
                end_offset = self.end_of_sectors[&segment];
            } else {
                end_offset = self.chunks[&segment][chunk_number + 1].data_offset as u64;
            }
            let mut compressed_data = vec![0; (end_offset - start_offset) as usize];
            self.segments
                .get(segment as usize - 1)
                .unwrap()
                .read(&mut compressed_data)
                .unwrap();
            let mut decoder = ZlibDecoder::new(&compressed_data[..]);
            data = Vec::new();
            decoder.read_to_end(&mut data).unwrap();
        }
        return data;
    }

    fn ewf_read(&mut self, buf: &mut [u8]) -> usize {
        let mut total_bytes_read = 0;
        let mut remaining = buf.len();

        if self.cached_chunk.data.is_empty() {
            self.cached_chunk.data =
                self.read_chunk(self.cached_chunk.segment, self.cached_chunk.number);
        }

        // While there is still space in our buffer.
        while remaining > 0 {
            let current_chunk = self.volume.chunk_size();
            let available_in_chunk = current_chunk - self.cached_chunk.ptr;

            // When the current chunk holds enough bytes to satisfy the remainder of the buffer.
            if available_in_chunk >= remaining {
                buf[total_bytes_read..total_bytes_read + remaining].copy_from_slice(
                    &self.cached_chunk.data
                        [self.cached_chunk.ptr..self.cached_chunk.ptr + remaining],
                );
                self.cached_chunk.ptr += remaining;
                total_bytes_read += remaining;
                remaining = 0;
            } else {
                // Otherwise, copy what is available.
                buf[total_bytes_read..total_bytes_read + available_in_chunk]
                    .copy_from_slice(&self.cached_chunk.data[self.cached_chunk.ptr..]);
                total_bytes_read += available_in_chunk;
                remaining -= available_in_chunk;
                self.cached_chunk.ptr = current_chunk; // Now pointer at the end of the chunk.

                // Now move to the next chunk if it exists.
                if self.cached_chunk.segment < self.segments.len()
                    || (self.cached_chunk.segment == self.segments.len()
                        && self.cached_chunk.number + 1
                            < self.chunks[&self.cached_chunk.segment].len())
                {
                    // Determine the next chunk.
                    if self.cached_chunk.number + 1 < self.chunks[&self.cached_chunk.segment].len()
                    {
                        self.cached_chunk.number += 1;
                    } else {
                        if self.cached_chunk.segment + 1 <= self.segments.len() {
                            self.cached_chunk.segment += 1;
                            self.cached_chunk.number = 0;
                        } else {
                            // No further chunk can be read.
                            break;
                        }
                    }
                    // Read in the next chunk.
                    self.cached_chunk.data =
                        self.read_chunk(self.cached_chunk.segment, self.cached_chunk.number);
                    self.cached_chunk.ptr = 0;
                } else {
                    // No more data available.
                    break;
                }
            }
        }
        total_bytes_read
    }

    fn ewf_seek(&mut self, offset: usize) -> io::Result<()> {
        if offset > self.volume.max_offset() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Could not seek to the requested offset: 0x{:x}, the offset is higher than the volume's maximum offset",
                    offset
                ),
            ));
        }

        let chunk_size = self.volume.chunk_size();
        // Calculate the global chunk number
        let mut chunk_number = offset / chunk_size;
        if chunk_number >= self.volume.chunk_count as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Error: the requested chunk number ({:?}) is higher than the total number of chunks ({:?}).",
                    chunk_number, self.volume.chunk_count
                ),
            ));
        }

        // Determine which segment contains this chunk.
        let mut segment = 1;
        while segment < self.segments.len()
            && (self.chunks[&segment][0].chunk_number > chunk_number
                || chunk_number > self.chunks[&segment].last().unwrap().chunk_number)
        {
            segment += 1;
        }

        // Adjust the chunk number relative to the chosen segment.
        chunk_number = chunk_number - self.chunks[&segment][0].chunk_number;

        // Read the new chunk and update the cached chunk state.
        self.cached_chunk.data = self.read_chunk(segment, chunk_number);
        self.cached_chunk.number = chunk_number;
        self.cached_chunk.segment = segment;
        self.cached_chunk.ptr = offset % chunk_size;

        // Update the current position for later reference if needed.
        self.position = offset as u64;
        Ok(())
    }
}

impl Clone for EWF {
    fn clone(&self) -> Self {
        let segments = self
            .segments
            .iter()
            .map(|fd| {
                fd.try_clone()
                    .expect("failed to duplicate segment descriptor")
            })
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

impl Read for EWF {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes_read = self.ewf_read(buf);
        if bytes_read == 0 {
            Ok(0)
        } else {
            Ok(bytes_read)
        }
    }
}

impl Seek for EWF {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Determine new absolute offset based on the current position and pos parameter.
        let new_offset: i64 = match pos {
            SeekFrom::Start(offset) => offset as i64,
            SeekFrom::Current(offset) => self.position as i64 + offset,
            SeekFrom::End(offset) => self.volume.max_offset() as i64 + offset,
        };

        // Check for negative seeking.
        if new_offset < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid seek to a negative position",
            ));
        }

        // Convert to usize after checking that new_offset is non-negative.
        let new_offset_usize = new_offset as usize;
        self.ewf_seek(new_offset_usize)?;
        Ok(new_offset as u64)
    }
}

fn find_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    let path = path
        .canonicalize()
        .map_err(|_| "Invalid path".to_string())?;
    let filename = path
        .file_name()
        .ok_or_else(|| "Invalid file name".to_string())?;
    let filename_str = filename
        .to_str()
        .ok_or_else(|| "Invalid file name".to_string())?;

    if filename_str.len() < 2 {
        return Err("File name too short".to_string());
    }

    let base_filename = &filename_str[..filename_str.len() - 2];
    let parent = path
        .parent()
        .ok_or_else(|| "No parent directory".to_string())?;

    // Construct the pattern using PathBuf and OsString for cross-platform compatibility
    let mut pattern_path = PathBuf::from(parent);
    pattern_path.push(format!("{}??", base_filename));

    // Convert PathBuf to string for glob
    let pattern = pattern_path
        .to_str()
        .ok_or_else(|| "Invalid pattern".to_string())?
        .to_string();

    let files = glob::glob(&pattern).map_err(|e| format!("Glob error: {}", e))?;
    let mut paths: Vec<PathBuf> = files.filter_map(Result::ok).collect();
    paths.sort();

    Ok(paths)
}
