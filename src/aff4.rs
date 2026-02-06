use flate2::read::DeflateDecoder;
use log::{debug, info, warn};
use rio_api::model::{Literal, Term};
use rio_api::parser::TriplesParser;
use rio_turtle::TurtleParser;

use lz4_flex::block;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};

// -----------------------------
// ZIP constants
// -----------------------------
const EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x05, 0x06]; // End of Central Directory
const ZIP64_LOCATOR_SIG: [u8; 4] = [0x50, 0x4b, 0x06, 0x07]; // Zip64 Locator
const ZIP64_EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x06, 0x06]; // Zip64 EOCD Record
const CD_ENTRY_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02]; // Central Dir File Header
const LOCAL_FILE_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];

// -----------------------------
// Error handling
// -----------------------------
#[derive(Debug)]
pub enum Aff4Error {
    Io(io::Error),
    Format(String),
    Unsupported(String),
    Missing(String),
}

impl From<io::Error> for Aff4Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for Aff4Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Aff4Error::Io(e) => write!(f, "io error: {}", e),
            Aff4Error::Format(s) => write!(f, "format error: {}", s),
            Aff4Error::Unsupported(s) => write!(f, "unsupported: {}", s),
            Aff4Error::Missing(s) => write!(f, "missing: {}", s),
        }
    }
}

impl std::error::Error for Aff4Error {}

type Aff4Result<T> = Result<T, Aff4Error>;

// -----------------------------
// Public types
// -----------------------------

/// Supported AFF4 compression methods (inside segments/chunks).
#[derive(Clone, Debug, PartialEq)]
pub enum CompressionMethod {
    None,
    Lz4,
    Snappy,
    Zlib,
    Unknown,
}

impl Default for CompressionMethod {
    fn default() -> Self {
        CompressionMethod::None
    }
}

/// Central directory entry we care about.
#[derive(Clone, Debug)]
pub struct ZipEntry {
    pub header_offset: u64,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub compression_method: u16, // 0=store, 8=deflate
}

/// One mapping run: virtual bytes -> (target urn + offset).
#[derive(Clone, Debug)]
struct Aff4Interval {
    virtual_offset: u64,
    length: u64,
    target_urn: String,
    target_offset: u64,
}

/// Cache holds the last decoded chunk (simple, effective).
#[derive(Clone, Default)]
struct ChunkCache {
    member: String,
    chunk_index: u32,
    data: Vec<u8>,
}

// -----------------------------
// Small helper structs
// -----------------------------

/// Metadata extracted from information.turtle.
#[derive(Debug, Clone)]
struct Aff4Metadata {
    image_size: u64,
    chunk_size: u64,
    chunks_in_segment: u64,
    compression: CompressionMethod,
    data_base_path: String, // e.g. "aff4%3A%2F%2F.../data"
    // stored_urn currently unused in this codepath, keep if you need it later:
    #[allow(dead_code)]
    stored_urn: Option<String>,
}

/// ZIP access helper. Owns no state besides a file handle clone + directory.
struct ZipReader {
    file: File,
    dir: BTreeMap<String, ZipEntry>,
}

impl ZipReader {
    fn new(file: &File, dir: BTreeMap<String, ZipEntry>) -> Aff4Result<Self> {
        Ok(Self {
            file: file.try_clone()?,
            dir,
        })
    }

    fn directory(&self) -> &BTreeMap<String, ZipEntry> {
        &self.dir
    }

    fn entry(&self, name: &str) -> Aff4Result<&ZipEntry> {
        self.dir
            .get(name)
            .ok_or_else(|| Aff4Error::Missing(format!("ZIP member not found: {}", name)))
    }

    /// Computes the payload start (after local header + filename + extra).
    fn payload_offset(&mut self, header_offset: u64) -> Aff4Result<u64> {
        self.file.seek(SeekFrom::Start(header_offset))?;

        let mut fixed = [0u8; 30];
        self.file.read_exact(&mut fixed)?;

        if fixed[0..4] != LOCAL_FILE_SIG {
            return Err(Aff4Error::Format(format!(
                "invalid local header signature at 0x{:x}",
                header_offset
            )));
        }

        let name_len = u16::from_le_bytes([fixed[26], fixed[27]]) as u64;
        let extra_len = u16::from_le_bytes([fixed[28], fixed[29]]) as u64;

        Ok(header_offset + 30 + name_len + extra_len)
    }

    /// Reads the raw compressed payload bytes for a member.
    fn read_member_compressed(&mut self, name: &str) -> Aff4Result<Vec<u8>> {
        let e = self.entry(name)?.clone();
        let payload = self.payload_offset(e.header_offset)?;

        self.file.seek(SeekFrom::Start(payload))?;
        let mut buf = vec![0u8; e.compressed_size as usize];
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Reads & decompresses a ZIP member (supports STORE and DEFLATE).
    fn read_member(&mut self, name: &str) -> Aff4Result<Vec<u8>> {
        let e = self.entry(name)?.clone();
        let compressed = self.read_member_compressed(name)?;

        match e.compression_method {
            0 => Ok(compressed),
            8 => {
                let mut decoder = DeflateDecoder::new(&compressed[..]);
                let mut decoded = Vec::with_capacity(e.uncompressed_size as usize);
                decoder.read_to_end(&mut decoded).map_err(|err| {
                    Aff4Error::Format(format!("deflate decode failed for {}: {}", name, err))
                })?;
                Ok(decoded)
            }
            other => Err(Aff4Error::Unsupported(format!(
                "ZIP compression method {} for member {}",
                other, name
            ))),
        }
    }

    /// Range read inside STORE member payload (fast path).
    fn read_store_range(
        &mut self,
        name: &str,
        offset_in_member: u64,
        out: &mut [u8],
    ) -> Aff4Result<()> {
        let e = self.entry(name)?.clone();
        if e.compression_method != 0 {
            return Err(Aff4Error::Unsupported(format!(
                "range read requires STORE(0); {} uses {}",
                name, e.compression_method
            )));
        }

        let payload = self.payload_offset(e.header_offset)?;
        let needed = out.len() as u64;

        if offset_in_member.checked_add(needed).unwrap_or(u64::MAX) > e.compressed_size {
            return Err(Aff4Error::Format(format!(
                "range read past end: {} off=0x{:x} len=0x{:x} member_len=0x{:x}",
                name, offset_in_member, needed, e.compressed_size
            )));
        }

        self.file
            .seek(SeekFrom::Start(payload + offset_in_member))?;
        self.file.read_exact(out)?;
        Ok(())
    }
}

// -----------------------------
// AFF4 main reader
// -----------------------------
#[derive(Default)]
pub struct AFF4 {
    file: Option<File>, // backing .aff4
    image_size: u64,

    intervals: Vec<Aff4Interval>,

    chunk_size: u64,
    chunks_in_segment: u64,
    compression: CompressionMethod,

    zip_directory: BTreeMap<String, ZipEntry>,
    cache: ChunkCache,

    position: u64,
}

impl AFF4 {
    pub fn new(path: &str) -> Result<Self, String> {
        // Keep your public signature, but internally use Aff4Error.
        match Self::new_impl(path) {
            Ok(v) => Ok(v),
            Err(e) => Err(e.to_string()),
        }
    }

    fn new_impl(path: &str) -> Aff4Result<Self> {
        let mut file = File::open(path)?;
        let zip_directory = Self::parse_zip_structure(&mut file)?;

        let mut zip = ZipReader::new(&file, zip_directory.clone())?;

        // Read metadata
        let turtle_bytes = zip.read_member("information.turtle")?;
        let turtle_content = String::from_utf8(turtle_bytes)
            .map_err(|e| Aff4Error::Format(format!("information.turtle not utf-8: {}", e)))?;
        let meta = Self::parse_metadata(&turtle_content)?;

        // Locate map and idx based on your current strategy: "{data_base_path}/map"
        let map_member = format!("{}/map", meta.data_base_path);
        if !zip.directory().contains_key(&map_member) {
            return Err(Aff4Error::Missing(format!(
                "no binary map found at expected {}",
                map_member
            )));
        }

        let intervals = Self::parse_map_stream_with_idx(&mut zip, &map_member, meta.image_size)?;

        Ok(Self {
            file: Some(file),
            image_size: meta.image_size,
            chunk_size: meta.chunk_size,
            chunks_in_segment: meta.chunks_in_segment,
            compression: meta.compression,
            intervals,
            zip_directory,
            cache: ChunkCache::default(),
            position: 0,
        })
    }

    pub fn print_info(&self) {
        info!(
            "AFF4 image_size=0x{:x}, chunk_size=0x{:x}, chunks_in_segment={}, compression={:?}, intervals={}",
            self.image_size,
            self.chunk_size,
            self.chunks_in_segment,
            self.compression,
            self.intervals.len()
        );
    }

    pub fn get_sector_size(&self) -> u16 {
        512
    }
}

// -----------------------------
// Zip64 parsing
// -----------------------------
impl AFF4 {
    fn parse_zip_structure(file: &mut File) -> Aff4Result<BTreeMap<String, ZipEntry>> {
        let eocd_offset = Self::find_legacy_eocd_offset(file)?;
        debug!("Found Legacy EOCD at offset: {}", eocd_offset);

        let locator_offset = eocd_offset
            .checked_sub(20)
            .ok_or_else(|| Aff4Error::Format("file too small for zip64 locator".into()))?;

        file.seek(SeekFrom::Start(locator_offset))?;
        let mut locator_buf = [0u8; 20];
        file.read_exact(&mut locator_buf)?;

        if locator_buf[0..4] != ZIP64_LOCATOR_SIG {
            return Err(Aff4Error::Format(format!(
                "invalid zip64 locator signature at 0x{:x}",
                locator_offset
            )));
        }

        let eocd64_offset = u64::from_le_bytes(locator_buf[8..16].try_into().unwrap());
        info!("Zip64 EOCD Record located at: 0x{:x}", eocd64_offset);

        file.seek(SeekFrom::Start(eocd64_offset))?;
        let mut eocd64_buf = [0u8; 56];
        file.read_exact(&mut eocd64_buf)?;
        if eocd64_buf[0..4] != ZIP64_EOCD_SIG {
            return Err(Aff4Error::Format("invalid zip64 eocd signature".into()));
        }

        let total_entries = u64::from_le_bytes(eocd64_buf[32..40].try_into().unwrap());
        let _cd_size = u64::from_le_bytes(eocd64_buf[40..48].try_into().unwrap());
        let cd_start_offset = u64::from_le_bytes(eocd64_buf[48..56].try_into().unwrap());

        info!("Central Directory Total Entries: 0x{:x}", total_entries);
        info!("Central Directory Size: 0x{:x}", _cd_size);
        info!(
            "Central Directory: {} entries starting at 0x{:x}",
            total_entries, cd_start_offset
        );

        Self::parse_central_directory(file, cd_start_offset, total_entries)
    }

    fn parse_central_directory(
        file: &mut File,
        offset: u64,
        count: u64,
    ) -> Aff4Result<BTreeMap<String, ZipEntry>> {
        let mut directory = BTreeMap::new();
        file.seek(SeekFrom::Start(offset))?;

        for _ in 0..count {
            let mut buf = [0u8; 46];
            file.read_exact(&mut buf)?;

            if buf[0..4] != CD_ENTRY_SIG {
                warn!("Central Directory signature mismatch. Stopping scan.");
                break;
            }

            let comp_method = u16::from_le_bytes(buf[10..12].try_into().unwrap());
            let name_len = u16::from_le_bytes(buf[28..30].try_into().unwrap()) as usize;
            let extra_len = u16::from_le_bytes(buf[30..32].try_into().unwrap()) as usize;
            let comment_len = u16::from_le_bytes(buf[32..34].try_into().unwrap()) as usize;

            let mut name_buf = vec![0u8; name_len];
            file.read_exact(&mut name_buf)?;
            let filename = String::from_utf8_lossy(&name_buf).to_string();

            let mut extra_buf = vec![0u8; extra_len];
            file.read_exact(&mut extra_buf)?;

            if comment_len > 0 {
                file.seek(SeekFrom::Current(comment_len as i64))?;
            }

            // default 32-bit fields
            let mut real_comp_size = u32::from_le_bytes(buf[20..24].try_into().unwrap()) as u64;
            let mut real_uncomp_size = u32::from_le_bytes(buf[24..28].try_into().unwrap()) as u64;
            let mut real_offset = u32::from_le_bytes(buf[42..46].try_into().unwrap()) as u64;

            // Zip64 extra field (tag 0x0001)
            let mut i = 0;
            while i + 4 <= extra_buf.len() {
                let tag = u16::from_le_bytes(extra_buf[i..i + 2].try_into().unwrap());
                let size = u16::from_le_bytes(extra_buf[i + 2..i + 4].try_into().unwrap()) as usize;
                let data_start = i + 4;
                let data_end = data_start.saturating_add(size);

                if data_end > extra_buf.len() {
                    break; // malformed extra, stop parsing
                }

                if tag == 0x0001 {
                    // Only read fields that were 0xFFFFFFFF in header, per spec.
                    let mut p = data_start;

                    if real_uncomp_size == 0xFFFF_FFFF && p + 8 <= data_end {
                        real_uncomp_size =
                            u64::from_le_bytes(extra_buf[p..p + 8].try_into().unwrap());
                        p += 8;
                    }
                    if real_comp_size == 0xFFFF_FFFF && p + 8 <= data_end {
                        real_comp_size =
                            u64::from_le_bytes(extra_buf[p..p + 8].try_into().unwrap());
                        p += 8;
                    }
                    if real_offset == 0xFFFF_FFFF && p + 8 <= data_end {
                        real_offset = u64::from_le_bytes(extra_buf[p..p + 8].try_into().unwrap());
                    }
                }

                i = data_end;
            }

            debug!(
                "CentralDir member={:?} comp_method=0x{:x} comp=0x{:x} uncomp=0x{:x} hdr_off=0x{:x}",
                filename, comp_method, real_comp_size, real_uncomp_size, real_offset
            );

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

    fn find_legacy_eocd_offset(file: &mut File) -> Aff4Result<u64> {
        let file_len = file.metadata()?.len();
        let mut cursor = file_len;

        // scan backwards in chunks, with seam overlap
        let chunk = 4096;

        while cursor > 0 {
            let start_pos = if cursor > chunk { cursor - chunk } else { 0 };
            let read_len = (cursor - start_pos) as usize;

            file.seek(SeekFrom::Start(start_pos))?;
            let mut buffer = vec![0u8; read_len];
            file.read_exact(&mut buffer)?;

            if let Some(off) = buffer
                .windows(EOCD_SIGNATURE.len())
                .rposition(|w| w == EOCD_SIGNATURE)
            {
                return Ok(start_pos + off as u64);
            }

            if start_pos == 0 {
                break;
            }

            cursor = start_pos + (EOCD_SIGNATURE.len() as u64 - 1);
        }

        Err(Aff4Error::Format(
            "could not find legacy EOCD signature".into(),
        ))
    }
}

// -----------------------------
// Metadata parsing
// -----------------------------
impl AFF4 {
    fn parse_metadata(turtle_content: &str) -> Aff4Result<Aff4Metadata> {
        let mut total_size: Option<u64> = None;
        let mut chunk_size: Option<u64> = None;
        let mut chunks_in_segment: Option<u64> = None;
        let mut compression = CompressionMethod::None;
        let mut stored_urn: Option<String> = None;
        let mut data_urn: Option<String> = None;

        let turtle_bytes = turtle_content.as_bytes();
        let mut parser = TurtleParser::new(Cursor::new(turtle_bytes), None);

        parser
            .parse_all(&mut |t| {
                let predicate = t.predicate.iri;
                let object = t.object;

                // Optional log: show only AFF4-related keys
                if predicate.contains("aff4.org") || predicate.contains("blackbagtech.com") {
                    let value_display = match object {
                        Term::Literal(lit) => match lit {
                            Literal::Simple { value } => value.to_string(),
                            Literal::LanguageTaggedString { value, .. } => value.to_string(),
                            Literal::Typed { value, .. } => value.to_string(),
                        },
                        Term::NamedNode(node) => node.iri.to_string(),
                        Term::BlankNode(node) => format!("_:{}", node.id),
                        _ => "??".to_string(),
                    };
                    let short_pred = predicate.rsplit('#').next().unwrap_or(predicate);
                    info!("Metadata: {:<24} = {}", short_pred, value_display);
                }

                let pred_lower = predicate.to_lowercase();

                // Helpers: extract literal string if present
                let lit_value = |o: Term<'_>| -> Option<String> {
                    if let Term::Literal(lit) = o {
                        let v = match lit {
                            Literal::Simple { value } => value,
                            Literal::LanguageTaggedString { value, .. } => value,
                            Literal::Typed { value, .. } => value,
                        };
                        Some(v.to_string())
                    } else {
                        None
                    }
                };

                if pred_lower.ends_with("schema#size") {
                    if let Some(v) = lit_value(object) {
                        if let Ok(n) = v.parse::<u64>() {
                            if n > total_size.unwrap_or(0) {
                                total_size = Some(n);
                            }
                        }
                    }
                } else if pred_lower.ends_with("schema#stored") {
                    if let Term::NamedNode(node) = object {
                        stored_urn = Some(node.iri.to_string());
                    }
                } else if pred_lower.ends_with("schema#datastream") {
                    if let Term::NamedNode(node) = object {
                        data_urn = Some(node.iri.to_string());
                    }
                } else if pred_lower.ends_with("schema#chunksize") {
                    if let Some(v) = lit_value(object) {
                        if let Ok(n) = v.parse::<u64>() {
                            chunk_size = Some(n);
                        }
                    }
                } else if pred_lower.ends_with("schema#chunksinsegment") {
                    if let Some(v) = lit_value(object) {
                        if let Ok(n) = v.parse::<u64>() {
                            chunks_in_segment = Some(n);
                        }
                    }
                } else if pred_lower.ends_with("compressionmethod") {
                    let method = match object {
                        Term::NamedNode(n) => n.iri,
                        _ => "",
                    };
                    if method.contains("lz4") {
                        compression = CompressionMethod::Lz4;
                    } else if method.contains("snappy") {
                        compression = CompressionMethod::Snappy;
                    } else if method.contains("zlib") {
                        compression = CompressionMethod::Zlib;
                    } else if method.contains("none") {
                        compression = CompressionMethod::None;
                    } else {
                        compression = CompressionMethod::Unknown;
                    }
                }

                Ok(()) as Result<(), Box<dyn std::error::Error>>
            })
            .map_err(|e| Aff4Error::Format(format!("turtle parse error: {}", e)))?;

        let image_size =
            total_size.ok_or_else(|| Aff4Error::Missing("no image size found".into()))?;
        let chunk_size = chunk_size.unwrap_or(32768);
        let chunks_in_segment = chunks_in_segment.unwrap_or(1024);

        // Convert "aff4://..." into the zip member base path encoding used by your producers.
        let data_base_path = if let Some(urn) = data_urn {
            urn.replace("://", "%3A%2F%2F")
        } else {
            "data".to_string()
        };

        Ok(Aff4Metadata {
            image_size,
            chunk_size,
            chunks_in_segment,
            compression,
            data_base_path,
            stored_urn,
        })
    }
}

// -----------------------------
// Map + idx parsing
// -----------------------------
impl AFF4 {
    fn parse_idx_table(idx_bytes: &[u8]) -> Aff4Result<Vec<String>> {
        let mut out = Vec::new();

        for part in idx_bytes.split(|b| *b == 0u8) {
            if part.is_empty() {
                continue;
            }
            let s = String::from_utf8(part.to_vec())
                .map_err(|e| Aff4Error::Format(format!("idx table invalid utf-8: {}", e)))?;
            let cleaned = s.trim().to_string();
            if !cleaned.is_empty() {
                out.push(cleaned);
            }
        }

        if out.is_empty() {
            return Err(Aff4Error::Format("idx table parsed to zero strings".into()));
        }
        Ok(out)
    }

    fn aff4_uri_to_zip_base(uri: &str) -> String {
        // "aff4://uuid/path" -> "aff4%3A%2F%2Fuuid/path"
        if let Some(pos) = uri.find("://") {
            let (scheme, rest) = uri.split_at(pos);
            let rest = &rest[3..];
            format!("{}%3A%2F%2F{}", scheme, rest)
        } else {
            uri.to_string()
        }
    }

    fn parse_map_stream_with_idx(
        zip: &mut ZipReader,
        map_member: &str,
        image_size: u64,
    ) -> Aff4Result<Vec<Aff4Interval>> {
        info!("--- Parsing Binary Map Stream: {} ---", map_member);

        let map_bytes = zip.read_member(map_member)?;

        // locate idx next to map
        let idx_candidate = map_member
            .strip_suffix("/map")
            .map(|base| format!("{}/idx", base))
            .unwrap_or_else(|| format!("{}/idx", map_member));

        let idx_member = if zip.directory().contains_key(&idx_candidate) {
            idx_candidate
        } else {
            return Err(Aff4Error::Missing(format!(
                "no idx table found next to map (tried {})",
                idx_candidate
            )));
        };

        info!("Using idx table member: {}", idx_member);
        let idx_bytes = zip.read_member(&idx_member)?;
        let targets = Self::parse_idx_table(&idx_bytes)?;
        info!("idx table contains {} target strings", targets.len());

        const REC_SIZE: usize = 28;
        if map_bytes.len() % REC_SIZE != 0 {
            return Err(Aff4Error::Format(format!(
                "map size {} not divisible by {}",
                map_bytes.len(),
                REC_SIZE
            )));
        }

        let mut records: Vec<(u64, u64, u64, u32)> = Vec::with_capacity(map_bytes.len() / REC_SIZE);
        for (i, chunk) in map_bytes.chunks_exact(REC_SIZE).enumerate() {
            let v_off = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
            let extent_len = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
            let target_off = u64::from_le_bytes(chunk[16..24].try_into().unwrap());
            let index = u32::from_le_bytes(chunk[24..28].try_into().unwrap());

            if extent_len == 0 {
                continue; // sentinel/hole marker
            }

            // Basic sanity
            if v_off >= image_size {
                return Err(Aff4Error::Format(format!(
                    "map record {} virtual_off 0x{:x} >= image_size 0x{:x}",
                    i, v_off, image_size
                )));
            }

            // Prevent overflow on v_off+extent_len checks
            if v_off.checked_add(extent_len).is_none() {
                return Err(Aff4Error::Format(format!(
                    "map record {} overflows virtual range",
                    i
                )));
            }

            records.push((v_off, extent_len, target_off, index));
        }

        if records.is_empty() {
            return Err(Aff4Error::Format("no usable records found in map".into()));
        }

        records.sort_by_key(|r| r.0);

        let mut intervals: Vec<Aff4Interval> = Vec::with_capacity(records.len());
        for (i, (v_off, extent_len, target_off, index)) in records.into_iter().enumerate() {
            let idx = index as usize;
            if idx >= targets.len() {
                return Err(Aff4Error::Format(format!(
                    "map record {} target index {} out of range (idx size {})",
                    i,
                    index,
                    targets.len()
                )));
            }

            let target_uri = &targets[idx];
            let target_zip = Self::aff4_uri_to_zip_base(target_uri);

            intervals.push(Aff4Interval {
                virtual_offset: v_off,
                length: extent_len,
                target_urn: target_zip,
                target_offset: target_off,
            });
        }

        // Merge contiguous intervals to reduce binary-search & boundaries
        intervals.sort_by_key(|iv| iv.virtual_offset);
        let mut merged: Vec<Aff4Interval> = Vec::with_capacity(intervals.len());
        for iv in intervals {
            if let Some(last) = merged.last_mut() {
                let last_end = last.virtual_offset + last.length;
                let contiguous_virtual = last_end == iv.virtual_offset;
                let same_target = last.target_urn == iv.target_urn;
                let contiguous_target = (last.target_offset + last.length) == iv.target_offset;

                if contiguous_virtual && same_target && contiguous_target {
                    last.length += iv.length;
                    continue;
                }
            }
            merged.push(iv);
        }

        info!(
            "Built {} merged intervals. First v_off=0x{:x}",
            merged.len(),
            merged[0].virtual_offset
        );

        Ok(merged)
    }
}

// -----------------------------
// Interval helpers + segment resolution
// -----------------------------
impl AFF4 {
    fn find_interval_index(&self, pos: u64) -> Option<usize> {
        if self.intervals.is_empty() {
            return None;
        }
        match self
            .intervals
            .binary_search_by_key(&pos, |iv| iv.virtual_offset)
        {
            Ok(i) => Some(i),
            Err(0) => None,
            Err(i) => Some(i - 1),
        }
    }

    fn interval_covers(&self, idx: usize, pos: u64) -> bool {
        let iv = &self.intervals[idx];
        pos >= iv.virtual_offset && pos < (iv.virtual_offset + iv.length)
    }

    fn next_interval_start(&self, pos: u64) -> Option<u64> {
        let needle = pos.saturating_add(1);
        let i = match self
            .intervals
            .binary_search_by_key(&needle, |iv| iv.virtual_offset)
        {
            Ok(i) => i,
            Err(i) => i,
        };
        self.intervals.get(i).map(|iv| iv.virtual_offset)
    }

    /// Cellebrite segments appear as ".../data/00001078" (8-digit decimal)
    fn resolve_segment_member(&self, base_stream: &str, logical_off: u64) -> Option<(String, u64)> {
        let seg_size = self.chunk_size.saturating_mul(self.chunks_in_segment);
        if seg_size == 0 {
            return None;
        }

        let seg_index = logical_off / seg_size;
        let off_in_seg = logical_off % seg_size;

        let m_dec8 = format!("{}/{:08}", base_stream, seg_index);
        if self.zip_directory.contains_key(&m_dec8) {
            return Some((m_dec8, off_in_seg));
        }

        // fallbacks
        let m_hex8 = format!("{}/{:08x}", base_stream, seg_index);
        if self.zip_directory.contains_key(&m_hex8) {
            return Some((m_hex8, off_in_seg));
        }

        let m_dec = format!("{}/{}", base_stream, seg_index);
        if self.zip_directory.contains_key(&m_dec) {
            return Some((m_dec, off_in_seg));
        }

        None
    }
}

// -----------------------------
// Read/Seek implementations
// -----------------------------
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
                "seek before start",
            ));
        }

        self.position = new_pos as u64;
        Ok(self.position)
    }
}

impl Read for AFF4 {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.image_size {
            return Ok(0);
        }

        let max_can_read = (self.image_size - self.position) as usize;
        let want_total = buf.len().min(max_can_read);

        let mut written = 0usize;

        while written < want_total && self.position < self.image_size {
            let pos = self.position;

            // Which interval covers current virtual position?
            let idx_opt = self.find_interval_index(pos);
            let in_interval = idx_opt.filter(|&i| self.interval_covers(i, pos));

            // Hole -> zero fill until next interval or EOF
            if in_interval.is_none() {
                let next = self.next_interval_start(pos).unwrap_or(self.image_size);
                let hole_len = next.saturating_sub(pos) as usize;
                let can = hole_len.min(want_total - written);

                debug!("READ hole: v=0x{:x} len=0x{:x}", pos, can);

                buf[written..written + can].fill(0);
                written += can;
                self.position += can as u64;
                continue;
            }

            let iv_idx = in_interval.unwrap();
            let iv = &self.intervals[iv_idx];

            let within_iv = pos - iv.virtual_offset;
            let remain_iv = iv.length - within_iv;
            let can_iv = (remain_iv as usize).min(want_total - written);

            // Logical offset into the target stream
            let logical_off = iv.target_offset + within_iv;

            // Resolve base stream ".../data" to a concrete segment member ".../data/00001078"
            let (member, seg_off) = self
                .resolve_segment_member(&iv.target_urn, logical_off)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "cannot resolve segment: base={:?} logical_off=0x{:x}",
                            iv.target_urn, logical_off
                        ),
                    )
                })?;

            // Determine chunk index and offset inside chunk
            let chunk_index = (seg_off / self.chunk_size) as u32;
            let within_chunk = (seg_off % self.chunk_size) as usize;

            if written == 0 {
                debug!(
                    "READ pos=0x{:x} iv[{}] member={:?} seg_off=0x{:x} chunk={} within_chunk=0x{:x}",
                    pos, iv_idx, member, seg_off, chunk_index, within_chunk
                );
            }

            // Load/decode chunk into cache (compression-aware)
            self.load_chunk_into_cache(&member, chunk_index)?;

            if within_chunk >= self.cache.data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "within_chunk=0x{:x} beyond decoded chunk size=0x{:x}",
                        within_chunk,
                        self.cache.data.len()
                    ),
                ));
            }

            let available = self.cache.data.len() - within_chunk;
            let take = available.min(can_iv);

            buf[written..written + take]
                .copy_from_slice(&self.cache.data[within_chunk..within_chunk + take]);

            written += take;
            self.position += take as u64;
        }

        Ok(written)
    }
}

// -----------------------------
// Chunk loading: index -> compressed slice -> decode
// -----------------------------
#[derive(Debug, Clone, Copy)]
struct IndexEntry {
    c_off: u64,
    c_len: u32,
}

impl AFF4 {
    fn read_index_entry(
        &mut self,
        zip: &mut ZipReader,
        index_member: &str,
        idx: u32,
    ) -> io::Result<IndexEntry> {
        let z = zip.directory().get(index_member).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("missing index member {:?}", index_member),
            )
        })?;

        if z.compression_method != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "index member {:?} is ZIP-compressed (unexpected)",
                    index_member
                ),
            ));
        }

        let off = (idx as u64) * 12;
        if off + 12 > z.compressed_size {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "index entry {} out of range: {:?} size=0x{:x}",
                    idx, index_member, z.compressed_size
                ),
            ));
        }

        let mut raw = [0u8; 12];
        zip.read_store_range(index_member, off, &mut raw)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let lo = u32::from_le_bytes(raw[0..4].try_into().unwrap());
        let hi = u32::from_le_bytes(raw[4..8].try_into().unwrap());
        let len = u32::from_le_bytes(raw[8..12].try_into().unwrap());

        Ok(IndexEntry {
            c_off: (lo as u64) | ((hi as u64) << 32),
            c_len: len,
        })
    }
}

impl AFF4 {
    fn load_chunk_into_cache(&mut self, member: &str, chunk_index: u32) -> io::Result<()> {
        if self.cache.member == member
            && self.cache.chunk_index == chunk_index
            && !self.cache.data.is_empty()
        {
            return Ok(());
        }

        // Use a ZipReader clone for safe member reads.
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "AFF4 file is closed"))?;
        let mut zip = ZipReader::new(file, self.zip_directory.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let index_member = format!("{}.index", member);

        let ent = self.read_index_entry(&mut zip, &index_member, chunk_index)?;

        let member_len = self
            .zip_directory
            .get(member)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("missing data member {:?}", member),
                )
            })?
            .compressed_size;

        let c_off = ent.c_off;
        let c_len = ent.c_len as u64;

        if c_len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "index says chunk {} has zero length (member {:?})",
                    chunk_index, member
                ),
            ));
        }
        if c_off + c_len > member_len {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "index out of bounds: chunk {} c_off=0x{:x} c_len=0x{:x} member_len=0x{:x}",
                    chunk_index, c_off, c_len, member_len
                ),
            ));
        }

        let mut compressed = vec![0u8; ent.c_len as usize];
        zip.read_store_range(member, c_off, &mut compressed)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        // Decode according to AFF4 layer-2 compression declared by metadata.
        let decoded = match self.compression {
            CompressionMethod::None => compressed,
            CompressionMethod::Lz4 => {
                if ent.c_len as u64 == self.chunk_size {
                    // common optimization: store raw chunk when incompressible
                    compressed
                } else {
                    let mut out = vec![0u8; self.chunk_size as usize];
                    block::decompress_into(&compressed, &mut out).map_err(|err| {
                        let magic = compressed.get(0..4).unwrap_or(&compressed);
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!(
                                "lz4 block decompress failed for chunk {}: {} (first4={:02x?})",
                                chunk_index, err, magic
                            ),
                        )
                    })?;
                    out
                }
            }
            CompressionMethod::Snappy => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "snappy not implemented yet",
                ))
            }
            CompressionMethod::Zlib => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "zlib not implemented yet",
                ))
            }
            CompressionMethod::Unknown => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unknown compression method",
                ))
            }
        };

        self.cache.member = member.to_string();
        self.cache.chunk_index = chunk_index;
        self.cache.data = decoded;

        Ok(())
    }
}

// -----------------------------
// Correct Clone implementation
// -----------------------------
impl Clone for AFF4 {
    fn clone(&self) -> Self {
        let file = self
            .file
            .as_ref()
            .map(|f| f.try_clone().expect("Failed to clone AFF4 file handle"));

        Self {
            file,
            image_size: self.image_size,
            intervals: self.intervals.clone(),
            chunk_size: self.chunk_size,
            chunks_in_segment: self.chunks_in_segment, // FIXED BUG
            zip_directory: self.zip_directory.clone(),
            compression: self.compression.clone(),
            cache: self.cache.clone(),
            position: self.position,
        }
    }
}
