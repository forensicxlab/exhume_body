//! QCOW2 (QEMU Copy-On-Write, version 2 and 3) image reader.
//!
//! This module exposes the active guest view of a QCOW2 image as a seekable
//! byte stream. It supports:
//!
//! - version 2 and version 3 headers, including header extensions,
//! - standard clusters, zlib-compressed clusters, and the version 3
//!   "all zeroes" cluster flag,
//! - extended L2 entries (subcluster allocation bitmaps),
//! - external data files,
//! - backing-file chains made of raw or QCOW2 images.
//!
//! Refcount tables are never consulted: the reader trusts the L1/L2 mapping
//! only, which is what a forensic reader wants when the refcounts of a
//! crashed guest are inconsistent (dirty bit set).
//!
//! # Known Limitations
//!
//! - Encrypted images (AES or LUKS) are rejected.
//! - zstd-compressed clusters are rejected; only zlib is supported.
//! - Internal snapshots are listed by [`QCOW2::print_info`] but their content
//!   cannot be selected for reading yet. Only the active L1 table is exposed.
//! - Persistent dirty bitmaps are ignored.

use std::{
    cmp::min,
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::utils::{
    be_u16, be_u32, be_u64, checked_offset, invalid_data, read_exact_at, read_zero_padded_at,
};
use flate2::read::DeflateDecoder;

use log::{debug, info, warn};

const QCOW2_MAGIC: [u8; 4] = [b'Q', b'F', b'I', 0xfb];
const SECTOR_SIZE: u16 = 512;
/// Size of the version 2 header. Version 3 headers carry their own length.
const V2_HEADER_LENGTH: u32 = 72;
/// Minimum size of a version 3 header (up to and including `header_length`).
const V3_MIN_HEADER_LENGTH: u32 = 104;
const MIN_CLUSTER_BITS: u32 = 9;
const MAX_CLUSTER_BITS: u32 = 21;
/// Minimum cluster size when extended L2 entries are in use (QEMU: 16 KiB).
const MIN_EXTENDED_L2_CLUSTER_BITS: u32 = 14;
/// Largest refcount order accepted by QEMU (64-bit refcounts).
const MAX_REFCOUNT_ORDER: u32 = 6;
/// QEMU refuses L1 tables larger than 32 MiB.
const MAX_L1_ENTRIES: u64 = (32 << 20) / 8;
const MAX_SNAPSHOTS: u32 = 65536;
const MAX_BACKING_DEPTH: usize = 16;
/// Number of L2 tables kept in memory per image.
const L2_CACHE_TABLES: usize = 32;
const COMPRESSED_SECTOR_SIZE: u64 = 512;
const SUBCLUSTERS_PER_CLUSTER: u32 = 32;

/// Mask of the offset bits shared by L1 and standard L2 entries.
const OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const L2_FLAG_COPIED: u64 = 1 << 63;
const L2_FLAG_COMPRESSED: u64 = 1 << 62;
const L2_FLAG_ZERO: u64 = 1;

const INCOMPATIBLE_DIRTY: u64 = 1 << 0;
const INCOMPATIBLE_CORRUPT: u64 = 1 << 1;
const INCOMPATIBLE_DATA_FILE: u64 = 1 << 2;
const INCOMPATIBLE_COMPRESSION_TYPE: u64 = 1 << 3;
const INCOMPATIBLE_EXTENDED_L2: u64 = 1 << 4;
const KNOWN_INCOMPATIBLE_FEATURES: u64 = INCOMPATIBLE_DIRTY
    | INCOMPATIBLE_CORRUPT
    | INCOMPATIBLE_DATA_FILE
    | INCOMPATIBLE_COMPRESSION_TYPE
    | INCOMPATIBLE_EXTENDED_L2;
const COMPATIBLE_LAZY_REFCOUNTS: u64 = 1 << 0;
const AUTOCLEAR_BITMAPS: u64 = 1 << 0;
const AUTOCLEAR_RAW_DATA_FILE: u64 = 1 << 1;

const COMPRESSION_ZLIB: u8 = 0;
const COMPRESSION_ZSTD: u8 = 1;

const HEADER_EXT_END: u32 = 0;
const HEADER_EXT_BACKING_FORMAT: u32 = 0xe279_2aca;
const HEADER_EXT_FEATURE_NAME_TABLE: u32 = 0x6803_f857;
const HEADER_EXT_BITMAPS: u32 = 0x2385_2875;
const HEADER_EXT_CRYPTO_HEADER: u32 = 0x0537_be77;
const HEADER_EXT_DATA_FILE: u32 = 0x4441_5441;
const FEATURE_NAME_ENTRY_SIZE: usize = 48;

/// Decoded fixed-size part of a QCOW2 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qcow2Header {
    pub version: u32,
    pub backing_file_offset: u64,
    pub backing_file_size: u32,
    pub cluster_bits: u32,
    /// Virtual disk size in bytes.
    pub size: u64,
    pub crypt_method: u32,
    pub l1_size: u32,
    pub l1_table_offset: u64,
    pub refcount_table_offset: u64,
    pub refcount_table_clusters: u32,
    pub nb_snapshots: u32,
    pub snapshots_offset: u64,
    pub incompatible_features: u64,
    pub compatible_features: u64,
    pub autoclear_features: u64,
    pub refcount_order: u32,
    pub header_length: u32,
    pub compression_type: u8,
}

impl Qcow2Header {
    /// Parse the fixed header fields from the beginning of the image.
    pub fn parse(data: &[u8]) -> Result<Qcow2Header, String> {
        if data.len() < V2_HEADER_LENGTH as usize {
            return Err(format!(
                "file is too small to hold a QCOW2 header ({} bytes)",
                data.len()
            ));
        }
        if data[0..4] != QCOW2_MAGIC {
            return Err("invalid QCOW2 magic".to_owned());
        }
        let version = be_u32(data, 4)?;
        if version != 2 && version != 3 {
            return Err(format!("unsupported QCOW2 version {version}"));
        }

        let mut header = Qcow2Header {
            version,
            backing_file_offset: be_u64(data, 8)?,
            backing_file_size: be_u32(data, 16)?,
            cluster_bits: be_u32(data, 20)?,
            size: be_u64(data, 24)?,
            crypt_method: be_u32(data, 32)?,
            l1_size: be_u32(data, 36)?,
            l1_table_offset: be_u64(data, 40)?,
            refcount_table_offset: be_u64(data, 48)?,
            refcount_table_clusters: be_u32(data, 56)?,
            nb_snapshots: be_u32(data, 60)?,
            snapshots_offset: be_u64(data, 64)?,
            incompatible_features: 0,
            compatible_features: 0,
            autoclear_features: 0,
            refcount_order: 4,
            header_length: V2_HEADER_LENGTH,
            compression_type: COMPRESSION_ZLIB,
        };

        if version == 3 {
            if data.len() < V3_MIN_HEADER_LENGTH as usize {
                return Err("truncated QCOW2 version 3 header".to_owned());
            }
            header.incompatible_features = be_u64(data, 72)?;
            header.compatible_features = be_u64(data, 80)?;
            header.autoclear_features = be_u64(data, 88)?;
            header.refcount_order = be_u32(data, 96)?;
            header.header_length = be_u32(data, 100)?;
            if header.header_length < V3_MIN_HEADER_LENGTH {
                return Err(format!(
                    "QCOW2 header length {} is smaller than the minimum of {}",
                    header.header_length, V3_MIN_HEADER_LENGTH
                ));
            }
            if !header.header_length.is_multiple_of(8) {
                return Err(format!(
                    "QCOW2 header length {} is not a multiple of 8",
                    header.header_length
                ));
            }
            // QEMU rejects refcount widths above 64 bits (order 6).
            if header.refcount_order > MAX_REFCOUNT_ORDER {
                return Err(format!(
                    "QCOW2 refcount order {} is larger than the maximum of {MAX_REFCOUNT_ORDER}",
                    header.refcount_order
                ));
            }
            if header.header_length > V3_MIN_HEADER_LENGTH {
                if data.len() <= V3_MIN_HEADER_LENGTH as usize {
                    return Err("truncated QCOW2 version 3 header".to_owned());
                }
                header.compression_type = data[V3_MIN_HEADER_LENGTH as usize];
            }
        }

        if !(MIN_CLUSTER_BITS..=MAX_CLUSTER_BITS).contains(&header.cluster_bits) {
            return Err(format!(
                "unsupported QCOW2 cluster_bits {} (expected {MIN_CLUSTER_BITS}..={MAX_CLUSTER_BITS})",
                header.cluster_bits
            ));
        }
        if header.header_length as u64 > header.cluster_size() {
            return Err("QCOW2 header is larger than a cluster".to_owned());
        }

        Ok(header)
    }

    pub fn cluster_size(&self) -> u64 {
        1u64 << self.cluster_bits
    }

    pub fn has_extended_l2(&self) -> bool {
        self.incompatible_features & INCOMPATIBLE_EXTENDED_L2 != 0
    }

    pub fn has_external_data_file(&self) -> bool {
        self.incompatible_features & INCOMPATIBLE_DATA_FILE != 0
    }

    /// Size in bytes of one L2 table entry (8, or 16 with extended L2).
    pub fn l2_entry_size(&self) -> u64 {
        if self.has_extended_l2() {
            16
        } else {
            8
        }
    }

    /// Number of entries in one L2 table.
    pub fn l2_entries(&self) -> u64 {
        self.cluster_size() / self.l2_entry_size()
    }

    pub fn l2_bits(&self) -> u32 {
        self.l2_entries().trailing_zeros()
    }

    /// Number of L1 entries required to map the whole virtual disk.
    pub fn required_l1_entries(&self) -> u64 {
        let span = self.cluster_size() << self.l2_bits();
        self.size.div_ceil(span)
    }
}

/// A named feature bit advertised by the feature name table extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qcow2FeatureName {
    /// 0 = incompatible, 1 = compatible, 2 = autoclear.
    pub kind: u8,
    pub bit: u8,
    pub name: String,
}

/// Decoded header extensions.
#[derive(Debug, Clone, Default)]
pub struct Qcow2HeaderExtensions {
    pub backing_format: Option<String>,
    pub data_file_name: Option<String>,
    pub feature_names: Vec<Qcow2FeatureName>,
    pub has_bitmaps_extension: bool,
    pub has_crypto_header: bool,
    /// Extension types this reader does not understand.
    pub unknown_types: Vec<u32>,
}

impl Qcow2HeaderExtensions {
    fn parse(first_cluster: &[u8], header: &Qcow2Header) -> Qcow2HeaderExtensions {
        let mut extensions = Qcow2HeaderExtensions::default();
        let mut offset = header.header_length as usize;

        while offset + 8 <= first_cluster.len() {
            let (Ok(ext_type), Ok(ext_len)) = (
                be_u32(first_cluster, offset),
                be_u32(first_cluster, offset + 4),
            ) else {
                break;
            };
            let ext_len = ext_len as usize;
            offset += 8;
            if ext_type == HEADER_EXT_END {
                break;
            }
            let Some(end) = offset.checked_add(ext_len) else {
                warn!("QCOW2 header extension {ext_type:#x} overflows the first cluster");
                break;
            };
            if end > first_cluster.len() {
                warn!(
                    "QCOW2 header extension {ext_type:#x} ({ext_len} bytes) runs past the first cluster"
                );
                break;
            }
            let data = &first_cluster[offset..end];
            match ext_type {
                HEADER_EXT_BACKING_FORMAT => {
                    extensions.backing_format = Some(
                        String::from_utf8_lossy(data)
                            .trim_end_matches('\0')
                            .to_owned(),
                    );
                }
                HEADER_EXT_DATA_FILE => {
                    extensions.data_file_name = Some(
                        String::from_utf8_lossy(data)
                            .trim_end_matches('\0')
                            .to_owned(),
                    );
                }
                HEADER_EXT_FEATURE_NAME_TABLE => {
                    for entry in data.chunks_exact(FEATURE_NAME_ENTRY_SIZE) {
                        let name_end = entry[2..].iter().position(|b| *b == 0).unwrap_or(46);
                        extensions.feature_names.push(Qcow2FeatureName {
                            kind: entry[0],
                            bit: entry[1],
                            name: String::from_utf8_lossy(&entry[2..2 + name_end]).into_owned(),
                        });
                    }
                }
                HEADER_EXT_BITMAPS => extensions.has_bitmaps_extension = true,
                HEADER_EXT_CRYPTO_HEADER => extensions.has_crypto_header = true,
                other => extensions.unknown_types.push(other),
            }
            // Extension payloads are padded to a multiple of 8 bytes.
            offset = end.div_ceil(8) * 8;
        }

        extensions
    }

    fn feature_name(&self, kind: u8, bit: u8) -> Option<&str> {
        self.feature_names
            .iter()
            .find(|f| f.kind == kind && f.bit == bit)
            .map(|f| f.name.as_str())
    }
}

/// Metadata of an internal snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qcow2Snapshot {
    pub id: String,
    pub name: String,
    pub l1_table_offset: u64,
    pub l1_size: u32,
    /// Creation time, seconds since the Unix epoch (host clock).
    pub date_sec: u32,
    pub date_nsec: u32,
    pub vm_state_size: u64,
    /// Virtual disk size at snapshot time, when recorded.
    pub disk_size: Option<u64>,
}

fn parse_snapshots(file: &mut File, header: &Qcow2Header) -> io::Result<Vec<Qcow2Snapshot>> {
    const FIXED_PART: usize = 40;
    let count = min(header.nb_snapshots, MAX_SNAPSHOTS);
    let mut snapshots = Vec::with_capacity(count as usize);
    if count == 0 {
        return Ok(snapshots);
    }
    if header.snapshots_offset == 0
        || !header
            .snapshots_offset
            .is_multiple_of(header.cluster_size())
    {
        return Err(invalid_data(format!(
            "snapshot table offset {:#x} is not cluster aligned",
            header.snapshots_offset
        )));
    }

    let mut offset = header.snapshots_offset;
    for _ in 0..count {
        let mut fixed = [0u8; FIXED_PART];
        read_exact_at(file, offset, &mut fixed)?;
        let l1_table_offset = be_u64(&fixed, 0)?;
        let l1_size = be_u32(&fixed, 8)?;
        let id_str_size = be_u16(&fixed, 12)? as usize;
        let name_size = be_u16(&fixed, 14)? as usize;
        let date_sec = be_u32(&fixed, 16)?;
        let date_nsec = be_u32(&fixed, 20)?;
        // Bytes 24..32 hold the guest clock (vm_clock_nsec), unused here.
        let mut vm_state_size = be_u32(&fixed, 32)? as u64;
        let extra_data_size = be_u32(&fixed, 36)? as usize;
        if extra_data_size > 1024 {
            return Err(invalid_data(format!(
                "snapshot extra data size {extra_data_size} is unreasonably large"
            )));
        }

        let mut variable = vec![0u8; extra_data_size + id_str_size + name_size];
        read_exact_at(file, offset + FIXED_PART as u64, &mut variable)?;
        let extra = &variable[..extra_data_size];
        let mut disk_size = None;
        if extra.len() >= 8 {
            vm_state_size = be_u64(extra, 0)?;
        }
        if extra.len() >= 16 {
            disk_size = Some(be_u64(extra, 8)?);
        }
        let id = String::from_utf8_lossy(&variable[extra_data_size..extra_data_size + id_str_size])
            .into_owned();
        let name = String::from_utf8_lossy(&variable[extra_data_size + id_str_size..]).into_owned();

        snapshots.push(Qcow2Snapshot {
            id,
            name,
            l1_table_offset,
            l1_size,
            date_sec,
            date_nsec,
            vm_state_size,
            disk_size,
        });

        let entry_len = (FIXED_PART + variable.len()) as u64;
        offset += entry_len.div_ceil(8) * 8;
    }

    Ok(snapshots)
}

/// Where unallocated guest clusters of an overlay are read from.
enum Qcow2Backing {
    Qcow2(Box<QCOW2>),
    Raw { path: PathBuf, file: File, len: u64 },
}

impl Qcow2Backing {
    /// Open a backing file.
    ///
    /// The format declared by the backing-format header extension wins: a raw
    /// backing whose guest data happens to start with a QCOW2 magic must stay
    /// raw (this is the classic format-probing confusion). Only when the
    /// overlay does not declare a format is the backing probed by content.
    fn open(
        path: PathBuf,
        declared_format: Option<&str>,
        depth: usize,
        visited: &mut HashSet<PathBuf>,
    ) -> Result<Self, String> {
        let mut file = File::open(&path)
            .map_err(|error| format!("cannot open backing file {}: {error}", path.display()))?;
        let has_magic = QCOW2::has_magic(&mut file);
        let open_as_qcow2 = match declared_format {
            Some("qcow2") => {
                if !has_magic {
                    return Err(format!(
                        "backing file {} is declared as qcow2 but has no QCOW2 magic",
                        path.display()
                    ));
                }
                true
            }
            Some("raw") => false,
            Some(other) => {
                return Err(format!(
                    "backing file {} uses unsupported format '{other}' (only raw and qcow2)",
                    path.display()
                ));
            }
            None => {
                warn!(
                    "QCOW2 overlay does not declare the format of its backing file {}; probing its content",
                    path.display()
                );
                has_magic
            }
        };
        if open_as_qcow2 {
            return QCOW2::open_with_depth(&path, depth, visited)
                .map(|image| Qcow2Backing::Qcow2(Box::new(image)));
        }
        let len = file
            .metadata()
            .map_err(|error| format!("cannot stat backing file {}: {error}", path.display()))?
            .len();
        Ok(Qcow2Backing::Raw { path, file, len })
    }

    fn describe(&self) -> &'static str {
        match self {
            Qcow2Backing::Qcow2(_) => "qcow2",
            Qcow2Backing::Raw { .. } => "raw",
        }
    }

    fn len(&self) -> u64 {
        match self {
            Qcow2Backing::Qcow2(image) => image.get_image_size(),
            Qcow2Backing::Raw { len, .. } => *len,
        }
    }

    fn backing_paths(&self) -> Vec<PathBuf> {
        match self {
            Qcow2Backing::Qcow2(image) => image.backing_paths(),
            Qcow2Backing::Raw { path, .. } => vec![path.clone()],
        }
    }

    /// Read `buf.len()` bytes at guest offset `pos`, zero-filling beyond the
    /// end of the backing image.
    fn read_at(&mut self, pos: u64, buf: &mut [u8]) -> io::Result<()> {
        let len = self.len();
        if pos >= len {
            buf.fill(0);
            return Ok(());
        }
        let available = min((len - pos) as usize, buf.len());
        let (head, tail) = buf.split_at_mut(available);
        match self {
            Qcow2Backing::Raw { file, .. } => {
                read_zero_padded_at(file, pos, head)?;
            }
            Qcow2Backing::Qcow2(image) => {
                image.seek(SeekFrom::Start(pos))?;
                image.read_exact(head)?;
            }
        }
        tail.fill(0);
        Ok(())
    }
}

impl Clone for Qcow2Backing {
    fn clone(&self) -> Self {
        match self {
            Qcow2Backing::Qcow2(image) => Qcow2Backing::Qcow2(image.clone()),
            Qcow2Backing::Raw { path, file, len } => Qcow2Backing::Raw {
                path: path.clone(),
                file: file.try_clone().unwrap_or_else(|error| {
                    panic!("failed to clone backing file {}: {error}", path.display())
                }),
                len: *len,
            },
        }
    }
}

/// How one guest cluster (or subcluster) maps onto host storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClusterMapping {
    /// Not allocated in this image; read from the backing file or zeroes.
    Unallocated,
    /// Reads as zeroes regardless of any backing file.
    Zero,
    /// Stored uncompressed at this host offset (in the data file).
    Standard(u64),
    /// Stored compressed; the raw L2 entry describes where.
    Compressed(u64),
}

/// A QCOW2 image opened for reading.
pub struct QCOW2 {
    path: PathBuf,
    file: File,
    header: Qcow2Header,
    extensions: Qcow2HeaderExtensions,
    backing_file_name: Option<String>,
    backing: Option<Qcow2Backing>,
    /// External data file holding the guest clusters, when the feature is on.
    data_file: Option<(PathBuf, File)>,
    snapshots: Vec<Qcow2Snapshot>,
    l1: Arc<Vec<u64>>,
    /// L2 tables keyed by their host offset.
    l2_cache: HashMap<u64, Arc<Vec<u64>>>,
    /// Last decompressed cluster, keyed by its raw L2 entry.
    compressed_cache: Option<(u64, Arc<Vec<u8>>)>,
    position: u64,
}

impl std::fmt::Debug for QCOW2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QCOW2")
            .field("path", &self.path)
            .field("header", &self.header)
            .field("backing_file_name", &self.backing_file_name)
            .field("data_file", &self.data_file.as_ref().map(|(path, _)| path))
            .field("snapshots", &self.snapshots.len())
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

impl Clone for QCOW2 {
    fn clone(&self) -> Self {
        let file = self.file.try_clone().unwrap_or_else(|error| {
            panic!(
                "failed to clone QCOW2 file handle {}: {error}",
                self.path.display()
            )
        });
        let data_file = self.data_file.as_ref().map(|(path, file)| {
            let file = file.try_clone().unwrap_or_else(|error| {
                panic!(
                    "failed to clone QCOW2 data file handle {}: {error}",
                    path.display()
                )
            });
            (path.clone(), file)
        });
        Self {
            path: self.path.clone(),
            file,
            header: self.header.clone(),
            extensions: self.extensions.clone(),
            backing_file_name: self.backing_file_name.clone(),
            backing: self.backing.clone(),
            data_file,
            snapshots: self.snapshots.clone(),
            l1: Arc::clone(&self.l1),
            l2_cache: self.l2_cache.clone(),
            compressed_cache: self.compressed_cache.clone(),
            position: self.position,
        }
    }
}

impl QCOW2 {
    /// Open a QCOW2 image, resolving its backing chain and external data file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file is not a QCOW2 image, uses a feature this
    /// reader does not support (encryption, zstd compression, unknown
    /// incompatible feature bits), or references files that cannot be opened.
    pub fn new(file_path: &str) -> Result<QCOW2, String> {
        let mut visited = HashSet::new();
        Self::open_with_depth(Path::new(file_path), 0, &mut visited)
    }

    /// Whether the file starts with the QCOW2 magic. Cheap: reads four bytes.
    ///
    /// Format auto-detection uses this so that a file that *is* a QCOW2 image
    /// but cannot be opened (missing backing file, encryption, ...) surfaces
    /// its real error instead of silently falling through to another format.
    pub fn probe(file_path: &str) -> bool {
        File::open(file_path)
            .map(|mut file| Self::has_magic(&mut file))
            .unwrap_or(false)
    }

    fn has_magic(file: &mut File) -> bool {
        let mut magic = [0u8; 4];
        file.seek(SeekFrom::Start(0)).is_ok()
            && file.read_exact(&mut magic).is_ok()
            && magic == QCOW2_MAGIC
    }

    fn open_with_depth(
        path: &Path,
        depth: usize,
        visited: &mut HashSet<PathBuf>,
    ) -> Result<QCOW2, String> {
        if depth > MAX_BACKING_DEPTH {
            return Err(format!(
                "QCOW2 backing chain is deeper than {MAX_BACKING_DEPTH} levels"
            ));
        }
        let mut file = File::open(path)
            .map_err(|error| format!("cannot open QCOW2 image {}: {error}", path.display()))?;
        let canonical = path
            .canonicalize()
            .map_err(|error| format!("cannot resolve QCOW2 path {}: {error}", path.display()))?;
        if !visited.insert(canonical.clone()) {
            return Err(format!(
                "QCOW2 backing chain loops back to {}",
                canonical.display()
            ));
        }
        let file_len = file
            .metadata()
            .map_err(|error| format!("cannot stat {}: {error}", path.display()))?
            .len();

        // Fixed header first, then the whole first cluster for the extensions.
        let mut fixed = vec![0u8; min(file_len, 512) as usize];
        read_exact_at(&mut file, 0, &mut fixed).map_err(|error| error.to_string())?;
        let header = Qcow2Header::parse(&fixed)?;
        let mut first_cluster = vec![0u8; min(file_len, header.cluster_size()) as usize];
        read_exact_at(&mut file, 0, &mut first_cluster).map_err(|error| error.to_string())?;
        let extensions = Qcow2HeaderExtensions::parse(&first_cluster, &header);

        Self::check_supported(&header, &extensions)?;

        let backing_file_name = if header.backing_file_offset != 0 && header.backing_file_size != 0
        {
            let start = header.backing_file_offset as usize;
            let end = start.saturating_add(header.backing_file_size as usize);
            if header.backing_file_offset >= first_cluster.len() as u64 || end > first_cluster.len()
            {
                return Err("QCOW2 backing file name lies outside the first cluster".to_owned());
            }
            Some(String::from_utf8_lossy(&first_cluster[start..end]).into_owned())
        } else {
            None
        };

        let l1 = Self::load_l1(&mut file, &header)?;

        let snapshots = match parse_snapshots(&mut file, &header) {
            Ok(snapshots) => snapshots,
            Err(error) => {
                warn!("cannot parse QCOW2 snapshot table: {error}");
                Vec::new()
            }
        };

        // Like QEMU, resolve relative names against the image path as given,
        // not against its canonical (symlink-resolved) location.
        let base_dir = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));

        let data_file = if header.has_external_data_file() {
            let name = extensions
                .data_file_name
                .as_deref()
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    "QCOW2 image uses an external data file but does not name it".to_owned()
                })?;
            let data_path = resolve_relative(&base_dir, name);
            let data = File::open(&data_path).map_err(|error| {
                format!(
                    "cannot open QCOW2 external data file {}: {error}",
                    data_path.display()
                )
            })?;
            let data_path = data_path.canonicalize().unwrap_or(data_path);
            Some((data_path, data))
        } else {
            None
        };

        let backing = match &backing_file_name {
            Some(name) => {
                let backing_path = resolve_relative(&base_dir, name);
                debug!(
                    "QCOW2 {} has backing file {} (format: {})",
                    path.display(),
                    backing_path.display(),
                    extensions
                        .backing_format
                        .as_deref()
                        .unwrap_or("unspecified")
                );
                Some(Qcow2Backing::open(
                    backing_path,
                    extensions.backing_format.as_deref(),
                    depth + 1,
                    visited,
                )?)
            }
            None => None,
        };

        Ok(QCOW2 {
            path: canonical,
            file,
            header,
            extensions,
            backing_file_name,
            backing,
            data_file,
            snapshots,
            l1: Arc::new(l1),
            l2_cache: HashMap::new(),
            compressed_cache: None,
            position: 0,
        })
    }

    fn check_supported(
        header: &Qcow2Header,
        extensions: &Qcow2HeaderExtensions,
    ) -> Result<(), String> {
        if header.crypt_method != 0 || extensions.has_crypto_header {
            let method = match header.crypt_method {
                1 => "AES".to_owned(),
                2 => "LUKS".to_owned(),
                other => format!("method {other}"),
            };
            return Err(format!(
                "encrypted QCOW2 images are not supported ({method})"
            ));
        }

        let unknown = header.incompatible_features & !KNOWN_INCOMPATIBLE_FEATURES;
        if unknown != 0 {
            let names: Vec<String> = (0..64)
                .filter(|bit| unknown & (1u64 << bit) != 0)
                .map(|bit| match extensions.feature_name(0, bit as u8) {
                    Some(name) => format!("{name} (bit {bit})"),
                    None => format!("bit {bit}"),
                })
                .collect();
            return Err(format!(
                "QCOW2 image uses unsupported incompatible features: {}",
                names.join(", ")
            ));
        }

        let has_compression_type_bit =
            header.incompatible_features & INCOMPATIBLE_COMPRESSION_TYPE != 0;
        if has_compression_type_bit && header.header_length <= V3_MIN_HEADER_LENGTH {
            return Err(
                "QCOW2 compression type feature is set but the header has no compression_type field"
                    .to_owned(),
            );
        }
        if !has_compression_type_bit && header.compression_type != COMPRESSION_ZLIB {
            return Err(format!(
                "QCOW2 compression_type is {} but the compression type feature bit is not set",
                header.compression_type
            ));
        }
        if header.compression_type != COMPRESSION_ZLIB {
            let name = match header.compression_type {
                COMPRESSION_ZSTD => "zstd".to_owned(),
                other => format!("type {other}"),
            };
            return Err(format!(
                "QCOW2 compression {name} is not supported (only zlib)"
            ));
        }

        if header.has_extended_l2() && header.cluster_bits < MIN_EXTENDED_L2_CLUSTER_BITS {
            return Err(format!(
                "QCOW2 extended L2 entries require clusters of at least {} bytes",
                1u64 << MIN_EXTENDED_L2_CLUSTER_BITS
            ));
        }

        if header.has_external_data_file() && header.version < 3 {
            return Err("QCOW2 version 2 images cannot use an external data file".to_owned());
        }

        if header.incompatible_features & INCOMPATIBLE_CORRUPT != 0 {
            warn!("QCOW2 image is flagged as corrupt by QEMU; reads may be unreliable");
        }
        if header.incompatible_features & INCOMPATIBLE_DIRTY != 0 {
            warn!(
                "QCOW2 image was not cleanly closed (dirty bit set); refcounts are ignored anyway"
            );
        }

        Ok(())
    }

    fn load_l1(file: &mut File, header: &Qcow2Header) -> Result<Vec<u64>, String> {
        let cluster_size = header.cluster_size();
        let l1_size = header.l1_size as u64;
        if l1_size > MAX_L1_ENTRIES {
            return Err(format!("QCOW2 L1 table has too many entries ({l1_size})"));
        }
        if l1_size == 0 {
            return Ok(Vec::new());
        }
        if header.l1_table_offset == 0 || !header.l1_table_offset.is_multiple_of(cluster_size) {
            return Err(format!(
                "QCOW2 L1 table offset {:#x} is not cluster aligned",
                header.l1_table_offset
            ));
        }
        let required = header.required_l1_entries();
        if l1_size < required {
            warn!(
                "QCOW2 L1 table has {l1_size} entries but {required} are needed to map the whole disk; the unmapped tail reads as unallocated"
            );
        }

        let mut raw = vec![0u8; (l1_size * 8) as usize];
        read_exact_at(file, header.l1_table_offset, &mut raw)
            .map_err(|error| format!("cannot read QCOW2 L1 table: {error}"))?;
        let l1: Vec<u64> = raw
            .chunks_exact(8)
            .map(|c| be_u64(c, 0))
            .collect::<Result<_, _>>()?;
        for (index, entry) in l1.iter().enumerate() {
            let offset = entry & OFFSET_MASK;
            if !offset.is_multiple_of(cluster_size) {
                return Err(format!(
                    "QCOW2 L1 entry {index} points to unaligned L2 table offset {offset:#x}"
                ));
            }
        }
        Ok(l1)
    }

    /// Fetch (and cache) the L2 table stored at `offset`.
    fn l2_table(&mut self, offset: u64) -> io::Result<Arc<Vec<u64>>> {
        if let Some(table) = self.l2_cache.get(&offset) {
            return Ok(Arc::clone(table));
        }
        let mut raw = vec![0u8; self.header.cluster_size() as usize];
        // QEMU's block layer zero-fills metadata reads past the end of a
        // truncated container, so the clusters of a cut-off L2 table read as
        // unallocated. Do the same, but say so.
        let read = read_zero_padded_at(&mut self.file, offset, &mut raw).map_err(|error| {
            invalid_data(format!(
                "cannot read QCOW2 L2 table at {offset:#x}: {error}"
            ))
        })?;
        if read < raw.len() {
            warn!(
                "QCOW2 L2 table at {offset:#x} is truncated ({read} of {} bytes present); missing entries read as unallocated",
                raw.len()
            );
        }
        let table: Arc<Vec<u64>> = Arc::new(
            raw.chunks_exact(8)
                .map(|c| be_u64(c, 0))
                .collect::<Result<_, _>>()?,
        );
        if self.l2_cache.len() >= L2_CACHE_TABLES {
            self.l2_cache.clear();
        }
        self.l2_cache.insert(offset, Arc::clone(&table));
        Ok(table)
    }

    /// Resolve the L2 entry (and subcluster bitmap, if any) for guest offset `pos`.
    fn l2_entry(&mut self, pos: u64) -> io::Result<Option<(u64, u64)>> {
        let cluster_bits = self.header.cluster_bits;
        let l2_bits = self.header.l2_bits();
        let l1_index = (pos >> (cluster_bits + l2_bits)) as usize;
        let l2_index = ((pos >> cluster_bits) & ((1u64 << l2_bits) - 1)) as usize;

        let Some(l1_entry) = self.l1.get(l1_index) else {
            return Ok(None);
        };
        let l2_offset = l1_entry & OFFSET_MASK;
        if l2_offset == 0 {
            return Ok(None);
        }
        let table = self.l2_table(l2_offset)?;
        let words_per_entry = (self.header.l2_entry_size() / 8) as usize;
        let base = l2_index * words_per_entry;
        let entry = table[base];
        let bitmap = if words_per_entry == 2 {
            table[base + 1]
        } else {
            0
        };
        Ok(Some((entry, bitmap)))
    }

    fn classify(&self, entry: u64) -> io::Result<ClusterMapping> {
        if entry & L2_FLAG_COMPRESSED != 0 {
            if self.header.has_external_data_file() {
                return Err(invalid_data(
                    "compressed cluster in a QCOW2 image with an external data file".to_owned(),
                ));
            }
            return Ok(ClusterMapping::Compressed(entry));
        }
        let host = entry & OFFSET_MASK;
        if !host.is_multiple_of(self.header.cluster_size()) {
            return Err(invalid_data(format!(
                "QCOW2 L2 entry {entry:#x} points to an unaligned cluster offset"
            )));
        }
        if !self.header.has_extended_l2() && entry & L2_FLAG_ZERO != 0 {
            // The zero flag only exists from version 3 on; QEMU refuses it in
            // version 2 images ("Zero cluster entry found in pre-v3 image").
            if self.header.version < 3 {
                return Err(invalid_data(format!(
                    "QCOW2 L2 entry {entry:#x} has the zero flag set in a version 2 image"
                )));
            }
            return Ok(ClusterMapping::Zero);
        }
        if host == 0 {
            // With an external data file, host offsets equal guest offsets, so
            // the very first cluster legitimately lives at offset 0. QEMU tells
            // it apart from an unallocated entry by the COPIED flag.
            if self.header.has_external_data_file() && entry & L2_FLAG_COPIED != 0 {
                return Ok(ClusterMapping::Standard(0));
            }
            return Ok(ClusterMapping::Unallocated);
        }
        Ok(ClusterMapping::Standard(host))
    }

    fn decompress_cluster(&mut self, entry: u64) -> io::Result<Arc<Vec<u8>>> {
        if let Some((cached_entry, data)) = &self.compressed_cache {
            if *cached_entry == entry {
                return Ok(Arc::clone(data));
            }
        }
        let cluster_bits = self.header.cluster_bits;
        let csize_shift = 62 - (cluster_bits - 8);
        let csize_mask = (1u64 << (cluster_bits - 8)) - 1;
        let offset_mask = (1u64 << csize_shift) - 1;
        let coffset = entry & offset_mask;
        let nb_csectors = ((entry >> csize_shift) & csize_mask) + 1;
        let csize = nb_csectors * COMPRESSED_SECTOR_SIZE - (coffset % COMPRESSED_SECTOR_SIZE);

        // QEMU zero-fills reads past the end of the container, so a compressed
        // cluster at the very end of the file may be shorter than `csize`.
        let mut compressed = vec![0u8; csize as usize];
        read_zero_padded_at(&mut self.file, coffset, &mut compressed)?;

        let mut cluster = vec![0u8; self.header.cluster_size() as usize];
        let mut decoder = DeflateDecoder::new(&compressed[..]);
        decoder.read_exact(&mut cluster).map_err(|error| {
            invalid_data(format!(
                "cannot inflate QCOW2 compressed cluster at {coffset:#x}: {error}"
            ))
        })?;
        let cluster = Arc::new(cluster);
        self.compressed_cache = Some((entry, Arc::clone(&cluster)));
        Ok(cluster)
    }

    /// Read guest bytes `[pos, pos + buf.len())` that all fall inside the
    /// cluster containing `pos`.
    fn read_within_cluster(&mut self, pos: u64, buf: &mut [u8]) -> io::Result<()> {
        let cluster_size = self.header.cluster_size();
        let in_cluster = pos % cluster_size;
        debug_assert!(in_cluster + buf.len() as u64 <= cluster_size);

        let Some((entry, bitmap)) = self.l2_entry(pos)? else {
            return self.read_unallocated(pos, buf);
        };

        let mapping = self.classify(entry)?;
        // With an external data file the host offset must equal the guest
        // offset; QEMU treats any other value as corruption.
        if let ClusterMapping::Standard(host) = mapping {
            let guest_cluster = pos - in_cluster;
            if self.header.has_external_data_file() && host != guest_cluster {
                return Err(invalid_data(format!(
                    "QCOW2 external data file host cluster offset {host:#x} does not match guest cluster offset {guest_cluster:#x}"
                )));
            }
        }

        match mapping {
            ClusterMapping::Unallocated if !self.header.has_extended_l2() => {
                self.read_unallocated(pos, buf)
            }
            ClusterMapping::Zero => {
                buf.fill(0);
                Ok(())
            }
            ClusterMapping::Compressed(entry) => {
                let cluster = self.decompress_cluster(entry)?;
                let start = in_cluster as usize;
                buf.copy_from_slice(&cluster[start..start + buf.len()]);
                Ok(())
            }
            ClusterMapping::Standard(host) if !self.header.has_extended_l2() => {
                self.read_host(host + in_cluster, buf)
            }
            // Extended L2: standard or unallocated clusters are decided per subcluster.
            ClusterMapping::Standard(host) => self.read_subclusters(pos, Some(host), bitmap, buf),
            ClusterMapping::Unallocated => self.read_subclusters(pos, None, bitmap, buf),
        }
    }

    /// Extended L2 read: consult the allocation and zero bitmaps per subcluster.
    fn read_subclusters(
        &mut self,
        pos: u64,
        host: Option<u64>,
        bitmap: u64,
        buf: &mut [u8],
    ) -> io::Result<()> {
        let cluster_size = self.header.cluster_size();
        let subcluster_size = cluster_size / SUBCLUSTERS_PER_CLUSTER as u64;
        let alloc_bits = bitmap as u32;
        let zero_bits = (bitmap >> 32) as u32;

        // QEMU validates the whole bitmap, not just the subclusters being read:
        // a subcluster that is both allocated and zero, or an allocation bit in
        // an unallocated cluster, makes the entire cluster invalid.
        if alloc_bits & zero_bits != 0 || (host.is_none() && alloc_bits != 0) {
            return Err(invalid_data(format!(
                "QCOW2 guest cluster {:#x} has an invalid subcluster bitmap {bitmap:#018x}",
                pos - pos % cluster_size
            )));
        }

        let mut done = 0usize;
        while done < buf.len() {
            let current = pos + done as u64;
            let in_cluster = current % cluster_size;
            let index = (in_cluster / subcluster_size) as u32;
            let in_sub = in_cluster % subcluster_size;
            let chunk = min((subcluster_size - in_sub) as usize, buf.len() - done);
            let out = &mut buf[done..done + chunk];

            let allocated = alloc_bits & (1 << index) != 0;
            let zero = zero_bits & (1 << index) != 0;
            match (host, allocated, zero) {
                (_, true, true) | (None, true, false) => {
                    return Err(invalid_data(format!(
                        "QCOW2 subcluster {index} of guest cluster {:#x} has an invalid allocation state",
                        current - in_cluster
                    )));
                }
                (_, false, true) => out.fill(0),
                (Some(host), true, false) => self.read_host(host + in_cluster, out)?,
                (_, false, false) => self.read_unallocated(current, out)?,
            }
            done += chunk;
        }
        Ok(())
    }

    /// Read from the file that stores guest clusters (the image or its data file).
    fn read_host(&mut self, host_offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let file = match &mut self.data_file {
            Some((_, data)) => data,
            None => &mut self.file,
        };
        read_zero_padded_at(file, host_offset, buf)?;
        Ok(())
    }

    fn read_unallocated(&mut self, pos: u64, buf: &mut [u8]) -> io::Result<()> {
        match &mut self.backing {
            Some(backing) => backing.read_at(pos, buf),
            None => {
                buf.fill(0);
                Ok(())
            }
        }
    }

    pub fn get_sector_size(&self) -> u16 {
        SECTOR_SIZE
    }

    /// Logical (virtual disk) size in bytes.
    pub fn get_image_size(&self) -> u64 {
        self.header.size
    }

    pub fn header(&self) -> &Qcow2Header {
        &self.header
    }

    pub fn snapshots(&self) -> &[Qcow2Snapshot] {
        &self.snapshots
    }

    pub fn backing_file_name(&self) -> Option<&str> {
        self.backing_file_name.as_deref()
    }

    /// Canonical paths of every file this image reads from: the image itself,
    /// its external data file, and the whole backing chain.
    pub fn backing_paths(&self) -> Vec<PathBuf> {
        let mut paths = vec![self.path.clone()];
        if let Some((data_path, _)) = &self.data_file {
            paths.push(data_path.clone());
        }
        if let Some(backing) = &self.backing {
            paths.extend(backing.backing_paths());
        }
        paths.sort();
        paths.dedup();
        paths
    }

    pub fn print_info(&self) {
        let h = &self.header;
        info!("QCOW2 Disk Information:");
        info!("  Version: {}", h.version);
        info!(
            "  Virtual size: {} bytes ({:.2} GiB)",
            h.size,
            h.size as f64 / (1u64 << 30) as f64
        );
        info!("  Cluster size: {} bytes", h.cluster_size());
        info!(
            "  L1 entries: {} (table at {:#x})",
            h.l1_size, h.l1_table_offset
        );
        info!(
            "  Refcount order: {} ({} bits)",
            h.refcount_order,
            1u32 << h.refcount_order
        );
        if h.version >= 3 {
            let compression = match h.compression_type {
                COMPRESSION_ZLIB => "zlib",
                COMPRESSION_ZSTD => "zstd",
                _ => "unknown",
            };
            info!("  Compression type: {compression}");
            info!("  Extended L2 entries: {}", h.has_extended_l2());
            info!(
                "  Lazy refcounts: {}",
                h.compatible_features & COMPATIBLE_LAZY_REFCOUNTS != 0
            );
            info!(
                "  Dirty: {}",
                h.incompatible_features & INCOMPATIBLE_DIRTY != 0
            );
            info!(
                "  Corrupt: {}",
                h.incompatible_features & INCOMPATIBLE_CORRUPT != 0
            );
            if h.autoclear_features & AUTOCLEAR_BITMAPS != 0
                || self.extensions.has_bitmaps_extension
            {
                info!("  Persistent dirty bitmaps: present (ignored)");
            }
        }
        match &self.data_file {
            Some((path, _)) => info!(
                "  External data file: {} (raw: {})",
                path.display(),
                h.autoclear_features & AUTOCLEAR_RAW_DATA_FILE != 0
            ),
            None => info!("  External data file: none"),
        }
        match (&self.backing_file_name, &self.backing) {
            (Some(name), Some(backing)) => {
                info!(
                    "  Backing file: {} (declared format: {}, detected: {})",
                    name,
                    self.extensions
                        .backing_format
                        .as_deref()
                        .unwrap_or("unspecified"),
                    backing.describe()
                );
            }
            _ => info!("  Backing file: none"),
        }
        info!("  Internal snapshots: {}", h.nb_snapshots);
        for snapshot in &self.snapshots {
            info!(
                "    - id {} name '{}' date {}.{:09} (unix) vm state {} bytes{}",
                snapshot.id,
                snapshot.name,
                snapshot.date_sec,
                snapshot.date_nsec,
                snapshot.vm_state_size,
                snapshot
                    .disk_size
                    .map(|size| format!(" disk size {size} bytes"))
                    .unwrap_or_default()
            );
        }
        if !self.extensions.unknown_types.is_empty() {
            let types: Vec<String> = self
                .extensions
                .unknown_types
                .iter()
                .map(|t| format!("{t:#x}"))
                .collect();
            info!("  Unknown header extensions: {}", types.join(", "));
        }
    }
}

fn resolve_relative(base_dir: &Path, name: &str) -> PathBuf {
    let candidate = Path::new(name);
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base_dir.join(candidate)
    }
}

impl Read for QCOW2 {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.header.size;
        if self.position >= size || buf.is_empty() {
            return Ok(0);
        }
        let total = min(buf.len() as u64, size - self.position) as usize;
        let cluster_size = self.header.cluster_size();

        let mut done = 0usize;
        while done < total {
            let pos = self.position + done as u64;
            let in_cluster = pos % cluster_size;
            let chunk = min((cluster_size - in_cluster) as usize, total - done);
            self.read_within_cluster(pos, &mut buf[done..done + chunk])?;
            done += chunk;
        }
        self.position += done as u64;
        Ok(done)
    }
}

impl Seek for QCOW2 {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let size = self.header.size;
        let target = match pos {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::Current(offset) => checked_offset(self.position, offset).ok(),
            SeekFrom::End(offset) => checked_offset(size, offset).ok(),
        };
        match target {
            Some(target) if target <= size => {
                self.position = target;
                Ok(target)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek position is outside the QCOW2 virtual disk",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::fs;
    use std::io::Write;

    const COPIED: u64 = L2_FLAG_COPIED;

    /// Builds small synthetic images: header in cluster 0, L1 in cluster 1,
    /// (unused) refcount table in cluster 2, L2 table in cluster 3, data after.
    struct ImageBuilder {
        version: u32,
        cluster_bits: u32,
        size: u64,
        extended_l2: bool,
        external_data_file: Option<String>,
        backing: Option<(String, Option<String>)>,
        incompatible_extra: u64,
        crypt_method: u32,
        compression_type: u8,
        refcount_order: u32,
        /// Override of the written header_length (version 3 only).
        header_length: Option<u32>,
        /// Override of the compression-type feature bit (None = derived).
        compression_bit: Option<bool>,
        l2: Vec<(u64, u64)>,
        file: Vec<u8>,
        data_file: Vec<u8>,
    }

    impl ImageBuilder {
        fn new(version: u32, cluster_bits: u32, size: u64) -> Self {
            let cluster_size = 1usize << cluster_bits;
            let mut builder = Self {
                version,
                cluster_bits,
                size,
                extended_l2: false,
                external_data_file: None,
                backing: None,
                incompatible_extra: 0,
                crypt_method: 0,
                compression_type: COMPRESSION_ZLIB,
                refcount_order: 4,
                header_length: None,
                compression_bit: None,
                l2: Vec::new(),
                file: vec![0u8; cluster_size * 4],
                data_file: Vec::new(),
            };
            builder.l2 = vec![(0, 0); builder.l2_entries()];
            builder
        }

        fn cluster_size(&self) -> usize {
            1usize << self.cluster_bits
        }

        fn l2_entries(&self) -> usize {
            self.cluster_size() / if self.extended_l2 { 16 } else { 8 }
        }

        fn extended(mut self) -> Self {
            self.extended_l2 = true;
            self.l2 = vec![(0, 0); self.l2_entries()];
            self
        }

        fn with_backing(mut self, name: &str, format: Option<&str>) -> Self {
            self.backing = Some((name.to_owned(), format.map(str::to_owned)));
            self
        }

        fn with_external_data_file(mut self, name: &str) -> Self {
            self.external_data_file = Some(name.to_owned());
            self
        }

        /// Append a cluster-aligned data cluster and return its host offset.
        fn append_cluster(&mut self, data: &[u8]) -> u64 {
            let cluster_size = self.cluster_size();
            assert!(data.len() <= cluster_size);
            let target = if self.external_data_file.is_some() {
                &mut self.data_file
            } else {
                &mut self.file
            };
            let offset = target.len();
            target.extend_from_slice(data);
            target.resize(offset + cluster_size, 0);
            offset as u64
        }

        fn set_standard(&mut self, index: usize, data: &[u8]) {
            let host = self.append_cluster(data);
            self.l2[index] = (host | COPIED, 0);
        }

        fn set_zero(&mut self, index: usize) {
            self.l2[index] = (L2_FLAG_ZERO, 0);
        }

        fn set_compressed(&mut self, index: usize, data: &[u8]) {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
            encoder.write_all(data).unwrap();
            let compressed = encoder.finish().unwrap();
            // Place compressed data at an odd sector offset to exercise the
            // `coffset % 512` adjustment.
            let coffset = self.file.len() as u64 + 100;
            let csize_shift = 62 - (self.cluster_bits - 8);
            let end = coffset + compressed.len() as u64;
            let nb_csectors = end.div_ceil(512) - coffset / 512;
            self.file.resize(coffset as usize, 0);
            self.file.extend_from_slice(&compressed);
            let padded = self.file.len().div_ceil(self.cluster_size()) * self.cluster_size();
            self.file.resize(padded, 0);
            let entry = L2_FLAG_COMPRESSED | ((nb_csectors - 1) << csize_shift) | coffset;
            self.l2[index] = (entry, 0);
        }

        /// Extended L2: allocate a cluster and set the subcluster bitmaps.
        fn set_extended(&mut self, index: usize, data: Option<&[u8]>, alloc: u32, zero: u32) {
            let entry = match data {
                Some(data) => self.append_cluster(data) | COPIED,
                None => 0,
            };
            self.l2[index] = (entry, ((zero as u64) << 32) | alloc as u64);
        }

        fn header_bytes(&self) -> Vec<u8> {
            let cluster_size = self.cluster_size() as u64;
            let mut incompatible = self.incompatible_extra;
            if self.extended_l2 {
                incompatible |= INCOMPATIBLE_EXTENDED_L2;
            }
            if self.external_data_file.is_some() {
                incompatible |= INCOMPATIBLE_DATA_FILE;
            }
            let compression_bit = self
                .compression_bit
                .unwrap_or(self.compression_type != COMPRESSION_ZLIB);
            if compression_bit {
                incompatible |= INCOMPATIBLE_COMPRESSION_TYPE;
            }
            let header_length: u32 = if self.version == 2 {
                72
            } else {
                self.header_length.unwrap_or(112)
            };

            // Extensions and backing file name follow the header.
            let mut tail = Vec::new();
            let push_ext = |tail: &mut Vec<u8>, ext_type: u32, data: &[u8]| {
                tail.extend_from_slice(&ext_type.to_be_bytes());
                tail.extend_from_slice(&(data.len() as u32).to_be_bytes());
                tail.extend_from_slice(data);
                let padded = data.len().div_ceil(8) * 8;
                tail.resize(tail.len() + padded - data.len(), 0);
            };
            if let Some((_, Some(format))) = &self.backing {
                push_ext(&mut tail, HEADER_EXT_BACKING_FORMAT, format.as_bytes());
            }
            if let Some(name) = &self.external_data_file {
                push_ext(&mut tail, HEADER_EXT_DATA_FILE, name.as_bytes());
            }
            let mut feature_table = Vec::new();
            for (kind, bit, name) in [(0u8, 0u8, "dirty bit"), (0, 7, "fancy future feature")] {
                let mut entry = vec![kind, bit];
                entry.extend_from_slice(name.as_bytes());
                entry.resize(FEATURE_NAME_ENTRY_SIZE, 0);
                feature_table.extend_from_slice(&entry);
            }
            push_ext(&mut tail, HEADER_EXT_FEATURE_NAME_TABLE, &feature_table);
            push_ext(&mut tail, HEADER_EXT_END, &[]);

            let (backing_offset, backing_size) = match &self.backing {
                Some((name, _)) => {
                    let offset = header_length as u64 + tail.len() as u64;
                    tail.extend_from_slice(name.as_bytes());
                    (offset, name.len() as u32)
                }
                None => (0, 0),
            };

            let mut h = Vec::new();
            h.extend_from_slice(&QCOW2_MAGIC);
            h.extend_from_slice(&self.version.to_be_bytes());
            h.extend_from_slice(&backing_offset.to_be_bytes());
            h.extend_from_slice(&backing_size.to_be_bytes());
            h.extend_from_slice(&self.cluster_bits.to_be_bytes());
            h.extend_from_slice(&self.size.to_be_bytes());
            h.extend_from_slice(&self.crypt_method.to_be_bytes());
            h.extend_from_slice(&1u32.to_be_bytes()); // l1_size
            h.extend_from_slice(&cluster_size.to_be_bytes()); // l1_table_offset
            h.extend_from_slice(&(2 * cluster_size).to_be_bytes()); // refcount_table_offset
            h.extend_from_slice(&1u32.to_be_bytes()); // refcount_table_clusters
            h.extend_from_slice(&0u32.to_be_bytes()); // nb_snapshots
            h.extend_from_slice(&0u64.to_be_bytes()); // snapshots_offset
            if self.version == 3 {
                h.extend_from_slice(&incompatible.to_be_bytes());
                h.extend_from_slice(&COMPATIBLE_LAZY_REFCOUNTS.to_be_bytes());
                h.extend_from_slice(&0u64.to_be_bytes());
                h.extend_from_slice(&self.refcount_order.to_be_bytes());
                h.extend_from_slice(&header_length.to_be_bytes());
                if header_length > 104 {
                    h.push(self.compression_type);
                }
                h.resize(header_length as usize, 0);
            }
            h.extend_from_slice(&tail);
            assert!(h.len() <= self.cluster_size(), "header overflows cluster 0");
            h
        }

        fn write(mut self, dir: &Path, name: &str) -> PathBuf {
            let cluster_size = self.cluster_size();
            let header = self.header_bytes();
            self.file[..header.len()].copy_from_slice(&header);
            // L1: single entry pointing at the L2 table in cluster 3.
            let l1_entry = (3 * cluster_size as u64) | COPIED;
            self.file[cluster_size..cluster_size + 8].copy_from_slice(&l1_entry.to_be_bytes());
            let mut l2_bytes = Vec::new();
            for (entry, bitmap) in &self.l2 {
                l2_bytes.extend_from_slice(&entry.to_be_bytes());
                if self.extended_l2 {
                    l2_bytes.extend_from_slice(&bitmap.to_be_bytes());
                }
            }
            self.file[3 * cluster_size..4 * cluster_size].copy_from_slice(&l2_bytes);

            let path = dir.join(name);
            fs::write(&path, &self.file).unwrap();
            if let Some(data_name) = &self.external_data_file {
                fs::write(dir.join(data_name), &self.data_file).unwrap();
            }
            path
        }
    }

    fn pattern(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| seed.wrapping_add((i % 251) as u8))
            .collect()
    }

    fn read_all(image: &mut QCOW2) -> Vec<u8> {
        image.seek(SeekFrom::Start(0)).unwrap();
        let mut out = Vec::new();
        image.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn header_parse_rejects_garbage() {
        assert!(Qcow2Header::parse(&[0u8; 16]).is_err());
        let mut bad_magic = vec![0u8; 104];
        bad_magic[..4].copy_from_slice(b"KDMV");
        assert!(Qcow2Header::parse(&bad_magic)
            .unwrap_err()
            .contains("magic"));

        let mut bad_version = vec![0u8; 104];
        bad_version[..4].copy_from_slice(&QCOW2_MAGIC);
        bad_version[4..8].copy_from_slice(&1u32.to_be_bytes());
        bad_version[20..24].copy_from_slice(&16u32.to_be_bytes());
        assert!(Qcow2Header::parse(&bad_version)
            .unwrap_err()
            .contains("version"));

        let mut bad_cluster_bits = bad_version.clone();
        bad_cluster_bits[4..8].copy_from_slice(&3u32.to_be_bytes());
        bad_cluster_bits[20..24].copy_from_slice(&22u32.to_be_bytes());
        bad_cluster_bits[100..104].copy_from_slice(&104u32.to_be_bytes());
        assert!(Qcow2Header::parse(&bad_cluster_bits)
            .unwrap_err()
            .contains("cluster_bits"));
    }

    #[test]
    fn reads_standard_zero_and_unallocated_clusters() {
        let dir = tempfile::tempdir().unwrap();
        let cluster = 4096usize;
        let mut builder = ImageBuilder::new(3, 12, 4 * cluster as u64 + 100);
        let a = pattern(0x10, cluster);
        let d = pattern(0x40, cluster);
        builder.set_standard(0, &a);
        // cluster 1 left unallocated
        builder.set_zero(2);
        builder.set_standard(3, &d);
        // cluster 4 (the trailing 100 bytes) unallocated
        let path = builder.write(dir.path(), "disk.qcow2");

        let mut image = QCOW2::new(path.to_str().unwrap()).unwrap();
        assert_eq!(image.get_image_size(), 4 * cluster as u64 + 100);
        assert_eq!(image.get_sector_size(), 512);
        assert_eq!(image.header().version, 3);
        assert!(image.backing_file_name().is_none());

        let mut expected = Vec::new();
        expected.extend_from_slice(&a);
        expected.extend(std::iter::repeat_n(0u8, cluster));
        expected.extend(std::iter::repeat_n(0u8, cluster));
        expected.extend_from_slice(&d);
        expected.extend(std::iter::repeat_n(0u8, 100));
        assert_eq!(read_all(&mut image), expected);

        // A read straddling three clusters, starting mid-cluster.
        let start = cluster as u64 - 10;
        image.seek(SeekFrom::Start(start)).unwrap();
        let mut buf = vec![0u8; 2 * cluster + 20];
        image.read_exact(&mut buf).unwrap();
        assert_eq!(buf, expected[start as usize..start as usize + buf.len()]);

        // Seek semantics.
        assert_eq!(image.seek(SeekFrom::End(-100)).unwrap(), 4 * cluster as u64);
        let mut tail = Vec::new();
        assert_eq!(image.read_to_end(&mut tail).unwrap(), 100);
        assert_eq!(image.read(&mut buf).unwrap(), 0);
        assert!(image.seek(SeekFrom::End(1)).is_err());
        assert!(image
            .seek(SeekFrom::Current(-(5 * cluster as i64)))
            .is_err());

        assert_eq!(image.backing_paths(), vec![path.canonicalize().unwrap()]);
    }

    #[test]
    fn reads_version_2_images() {
        let dir = tempfile::tempdir().unwrap();
        let cluster = 4096usize;
        let mut builder = ImageBuilder::new(2, 12, 2 * cluster as u64);
        let b = pattern(0x22, cluster);
        builder.set_standard(1, &b);
        let path = builder.write(dir.path(), "v2.qcow2");

        let mut image = QCOW2::new(path.to_str().unwrap()).unwrap();
        assert_eq!(image.header().version, 2);
        assert_eq!(image.header().header_length, 72);
        let mut expected = vec![0u8; cluster];
        expected.extend_from_slice(&b);
        assert_eq!(read_all(&mut image), expected);
    }

    #[test]
    fn reads_compressed_clusters() {
        let dir = tempfile::tempdir().unwrap();
        let cluster = 4096usize;
        let mut builder = ImageBuilder::new(3, 12, 3 * cluster as u64);
        let a = pattern(0x01, cluster);
        let c = pattern(0x99, cluster);
        builder.set_compressed(0, &a);
        builder.set_standard(1, &pattern(0x55, cluster));
        builder.set_compressed(2, &c);
        let path = builder.write(dir.path(), "compressed.qcow2");

        let mut image = QCOW2::new(path.to_str().unwrap()).unwrap();
        let all = read_all(&mut image);
        assert_eq!(&all[..cluster], &a[..]);
        assert_eq!(&all[cluster..2 * cluster], &pattern(0x55, cluster)[..]);
        assert_eq!(&all[2 * cluster..], &c[..]);

        // Partial reads inside a compressed cluster hit the cache.
        image
            .seek(SeekFrom::Start(2 * cluster as u64 + 17))
            .unwrap();
        let mut small = [0u8; 5];
        image.read_exact(&mut small).unwrap();
        assert_eq!(small, c[17..22]);
    }

    #[test]
    fn overlay_reads_unallocated_clusters_from_raw_backing() {
        let dir = tempfile::tempdir().unwrap();
        let cluster = 4096usize;
        // Backing is shorter than the overlay: the tail must read as zeroes.
        let base = pattern(0x77, 2 * cluster + 50);
        fs::write(dir.path().join("base.raw"), &base).unwrap();

        let mut builder =
            ImageBuilder::new(3, 12, 4 * cluster as u64).with_backing("base.raw", Some("raw"));
        let over = pattern(0xaa, cluster);
        builder.set_standard(1, &over);
        builder.set_zero(3);
        let path = builder.write(dir.path(), "overlay.qcow2");

        let mut image = QCOW2::new(path.to_str().unwrap()).unwrap();
        assert_eq!(image.backing_file_name(), Some("base.raw"));

        let mut expected = base.clone();
        expected.resize(4 * cluster, 0);
        expected[cluster..2 * cluster].copy_from_slice(&over);
        assert_eq!(read_all(&mut image), expected);

        let mut paths = vec![
            path.canonicalize().unwrap(),
            dir.path().join("base.raw").canonicalize().unwrap(),
        ];
        paths.sort();
        assert_eq!(image.backing_paths(), paths);
    }

    #[test]
    fn overlay_chain_reads_through_qcow2_backing() {
        let dir = tempfile::tempdir().unwrap();
        let cluster = 4096usize;
        let base_data = pattern(0x05, cluster);
        let mut base = ImageBuilder::new(3, 12, 3 * cluster as u64);
        base.set_standard(0, &base_data);
        base.set_standard(2, &pattern(0x06, cluster));
        base.write(dir.path(), "base.qcow2");

        let mid_data = pattern(0x50, cluster);
        let mut mid =
            ImageBuilder::new(3, 12, 3 * cluster as u64).with_backing("base.qcow2", Some("qcow2"));
        mid.set_standard(2, &mid_data);
        mid.write(dir.path(), "mid.qcow2");

        let top_data = pattern(0xf0, cluster);
        let mut top = ImageBuilder::new(3, 12, 3 * cluster as u64).with_backing("mid.qcow2", None);
        top.set_standard(1, &top_data);
        let path = top.write(dir.path(), "top.qcow2");

        let mut image = QCOW2::new(path.to_str().unwrap()).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&base_data);
        expected.extend_from_slice(&top_data);
        expected.extend_from_slice(&mid_data);
        assert_eq!(read_all(&mut image), expected);
        assert_eq!(image.backing_paths().len(), 3);
    }

    #[test]
    fn backing_loop_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        ImageBuilder::new(3, 12, 4096)
            .with_backing("b.qcow2", None)
            .write(dir.path(), "a.qcow2");
        let b = ImageBuilder::new(3, 12, 4096)
            .with_backing("a.qcow2", None)
            .write(dir.path(), "b.qcow2");
        let error = QCOW2::new(b.to_str().unwrap()).unwrap_err();
        assert!(error.contains("loops"), "{error}");
    }

    #[test]
    fn missing_backing_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = ImageBuilder::new(3, 12, 4096)
            .with_backing("gone.raw", Some("raw"))
            .write(dir.path(), "orphan.qcow2");
        let error = QCOW2::new(path.to_str().unwrap()).unwrap_err();
        assert!(error.contains("gone.raw"), "{error}");
    }

    #[test]
    fn reads_extended_l2_subclusters() {
        let dir = tempfile::tempdir().unwrap();
        let cluster = 16384usize;
        let sub = cluster / 32;
        let base = pattern(0x33, 2 * cluster);
        fs::write(dir.path().join("base.raw"), &base).unwrap();

        let mut builder = ImageBuilder::new(3, 14, 2 * cluster as u64)
            .extended()
            .with_backing("base.raw", Some("raw"));
        let data = pattern(0xcc, cluster);
        // Cluster 0 allocated: subclusters 0 and 5 allocated, 1 and 2 zero,
        // the rest come from the backing file.
        builder.set_extended(0, Some(&data), 0b10_0001, 0b110);
        // Cluster 1 unallocated: subcluster 31 is a plain zero subcluster.
        builder.set_extended(1, None, 0, 1 << 31);
        let path = builder.write(dir.path(), "ext.qcow2");

        let mut image = QCOW2::new(path.to_str().unwrap()).unwrap();
        assert!(image.header().has_extended_l2());
        let all = read_all(&mut image);
        let mut expected = base.clone();
        expected[..sub].copy_from_slice(&data[..sub]);
        expected[sub..3 * sub].fill(0);
        expected[5 * sub..6 * sub].copy_from_slice(&data[5 * sub..6 * sub]);
        expected[cluster + 31 * sub..].fill(0);
        assert_eq!(all, expected);

        // Read a window crossing a zero / backing boundary.
        image.seek(SeekFrom::Start(3 * sub as u64 - 7)).unwrap();
        let mut window = [0u8; 14];
        image.read_exact(&mut window).unwrap();
        assert_eq!(window, expected[3 * sub - 7..3 * sub + 7]);
    }

    #[test]
    fn extended_l2_invalid_subcluster_state_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = ImageBuilder::new(3, 14, 16384).extended();
        // Allocated and zero at the same time.
        builder.set_extended(0, Some(&pattern(1, 16384)), 1, 1);
        let path = builder.write(dir.path(), "bad.qcow2");
        let mut image = QCOW2::new(path.to_str().unwrap()).unwrap();
        let mut buf = [0u8; 16];
        let error = image.read_exact(&mut buf).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn reads_clusters_from_external_data_file() {
        let dir = tempfile::tempdir().unwrap();
        let cluster = 4096usize;
        let mut builder =
            ImageBuilder::new(3, 12, 2 * cluster as u64).with_external_data_file("disk.data");
        let a = pattern(0x12, cluster);
        builder.set_standard(0, &a);
        let path = builder.write(dir.path(), "disk.qcow2");

        let mut image = QCOW2::new(path.to_str().unwrap()).unwrap();
        let mut expected = a.clone();
        expected.resize(2 * cluster, 0);
        assert_eq!(read_all(&mut image), expected);
        assert_eq!(image.backing_paths().len(), 2);

        fs::remove_file(dir.path().join("disk.data")).unwrap();
        let error = QCOW2::new(path.to_str().unwrap()).unwrap_err();
        assert!(error.contains("external data file"), "{error}");
    }

    #[test]
    fn unsupported_images_are_rejected_with_a_reason() {
        let dir = tempfile::tempdir().unwrap();

        let mut encrypted = ImageBuilder::new(3, 12, 4096);
        encrypted.crypt_method = 2;
        let path = encrypted.write(dir.path(), "enc.qcow2");
        let error = QCOW2::new(path.to_str().unwrap()).unwrap_err();
        assert!(
            error.contains("encrypted") && error.contains("LUKS"),
            "{error}"
        );

        let mut zstd = ImageBuilder::new(3, 12, 4096);
        zstd.compression_type = COMPRESSION_ZSTD;
        let path = zstd.write(dir.path(), "zstd.qcow2");
        let error = QCOW2::new(path.to_str().unwrap()).unwrap_err();
        assert!(error.contains("zstd"), "{error}");

        let mut future = ImageBuilder::new(3, 12, 4096);
        future.incompatible_extra = 1 << 7;
        let path = future.write(dir.path(), "future.qcow2");
        let error = QCOW2::new(path.to_str().unwrap()).unwrap_err();
        assert!(error.contains("fancy future feature (bit 7)"), "{error}");

        fs::write(dir.path().join("not.qcow2"), b"nope").unwrap();
        assert!(QCOW2::new(dir.path().join("not.qcow2").to_str().unwrap()).is_err());
    }

    #[test]
    fn dirty_images_still_open() {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = ImageBuilder::new(3, 12, 4096);
        builder.incompatible_extra = INCOMPATIBLE_DIRTY | INCOMPATIBLE_CORRUPT;
        builder.set_standard(0, &pattern(9, 4096));
        let path = builder.write(dir.path(), "dirty.qcow2");
        let mut image = QCOW2::new(path.to_str().unwrap()).unwrap();
        assert_eq!(read_all(&mut image), pattern(9, 4096));
    }

    #[test]
    fn cloned_image_keeps_an_independent_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let cluster = 4096usize;
        let mut builder = ImageBuilder::new(3, 12, 2 * cluster as u64);
        let a = pattern(0xa1, cluster);
        let b = pattern(0xb2, cluster);
        builder.set_standard(0, &a);
        builder.set_compressed(1, &b);
        let path = builder.write(dir.path(), "clone.qcow2");

        let mut original = QCOW2::new(path.to_str().unwrap()).unwrap();
        original.seek(SeekFrom::Start(cluster as u64)).unwrap();
        let mut cloned = original.clone();
        cloned.seek(SeekFrom::Start(0)).unwrap();

        let mut from_original = [0u8; 8];
        let mut from_clone = [0u8; 8];
        original.read_exact(&mut from_original).unwrap();
        cloned.read_exact(&mut from_clone).unwrap();
        assert_eq!(from_original, b[..8]);
        assert_eq!(from_clone, a[..8]);
        assert_eq!(original.position, cluster as u64 + 8);
        assert_eq!(cloned.position, 8);
    }

    #[test]
    fn body_autodetects_qcow2() {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = ImageBuilder::new(3, 12, 8192);
        builder.set_standard(1, &pattern(0x42, 4096));
        let path = builder.write(dir.path(), "auto.qcow2");

        let mut body = crate::Body::try_new(path.to_string_lossy().into_owned(), "auto").unwrap();
        assert!(matches!(body.format, crate::BodyFormat::QCOW2 { .. }));
        assert_eq!(body.get_image_size(), 8192);
        body.seek(SeekFrom::Start(4096)).unwrap();
        let mut buf = [0u8; 4];
        body.read_exact(&mut buf).unwrap();
        assert_eq!(buf, pattern(0x42, 4)[..]);

        let explicit = crate::Body::try_new(path.to_string_lossy().into_owned(), "qcow2").unwrap();
        assert_eq!(
            explicit.format_description(),
            "QCOW2 (QEMU Copy-On-Write) image"
        );
    }

    /// End-to-end check against images produced by qemu-img. Ignored by
    /// default because it needs `qemu-img` and `qemu-io` on the PATH.
    #[test]
    #[ignore]
    fn matches_qemu_img_output() {
        use std::process::Command;

        fn run(cmd: &mut Command) {
            let output = cmd.output().expect("qemu tools must be installed");
            assert!(
                output.status.success(),
                "{:?} failed: {}",
                cmd,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let size = 8u64 << 20;
        let mut reference = vec![0u8; size as usize];
        // Sparse content: data in some 1 MiB regions, holes elsewhere.
        for region in [0usize, 2, 5, 7] {
            let start = region << 20;
            reference[start..start + (1 << 20)]
                .copy_from_slice(&pattern(region as u8 + 1, 1 << 20));
        }
        let raw_path = dir.join("reference.raw");
        fs::write(&raw_path, &reference).unwrap();

        let variants: &[(&str, &[&str], bool)] = &[
            ("plain.qcow2", &["-o", "cluster_size=65536"], false),
            (
                "compressed.qcow2",
                &["-c", "-o", "cluster_size=65536"],
                false,
            ),
            ("small.qcow2", &["-o", "cluster_size=4096"], false),
            ("v2.qcow2", &["-o", "compat=0.10"], false),
            (
                "extended.qcow2",
                &["-o", "extended_l2=on,cluster_size=131072"],
                false,
            ),
            ("datafile.qcow2", &[], true),
        ];
        for (name, options, external_data) in variants {
            let out = dir.join(name);
            let mut cmd = Command::new("qemu-img");
            cmd.args(["convert", "-f", "raw", "-O", "qcow2"]);
            cmd.args(*options);
            if *external_data {
                cmd.args([
                    "-o",
                    &format!("data_file={}", dir.join("disk.data").display()),
                ]);
            }
            cmd.arg(&raw_path).arg(&out);
            run(&mut cmd);

            let mut image = QCOW2::new(out.to_str().unwrap()).unwrap();
            assert_eq!(image.get_image_size(), size, "{name}");
            assert_eq!(read_all(&mut image), reference, "{name} content differs");
        }

        // Overlay with its own writes and a zero-cluster, backed by the plain image.
        let overlay = dir.join("overlay.qcow2");
        run(Command::new("qemu-img").args([
            "create",
            "-f",
            "qcow2",
            "-b",
            "plain.qcow2",
            "-F",
            "qcow2",
            overlay.to_str().unwrap(),
        ]));
        run(Command::new("qemu-io").args([
            "-c",
            "write -P 0xee 3M 64k",
            "-c",
            "write -z 0 64k",
            "-c",
            "write -c -P 0x11 6M 128k",
            overlay.to_str().unwrap(),
        ]));
        let mut expected = reference.clone();
        expected[3 << 20..(3 << 20) + 65536].fill(0xee);
        expected[..65536].fill(0);
        expected[6 << 20..(6 << 20) + 131072].fill(0x11);

        let mut image = QCOW2::new(overlay.to_str().unwrap()).unwrap();
        assert_eq!(image.backing_file_name(), Some("plain.qcow2"));
        assert_eq!(read_all(&mut image), expected);

        // Internal snapshot metadata is listed.
        run(Command::new("qemu-img").args([
            "snapshot",
            "-c",
            "before-incident",
            overlay.to_str().unwrap(),
        ]));
        let image = QCOW2::new(overlay.to_str().unwrap()).unwrap();
        assert_eq!(image.snapshots().len(), 1);
        assert_eq!(image.snapshots()[0].name, "before-incident");
        assert_eq!(image.snapshots()[0].disk_size, Some(size));
    }

    /// Tiny deterministic generator so the mutation tests need no extra crate.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 11
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound
        }
    }

    /// Open and fully read an image, ignoring errors: the point is that nothing
    /// panics on a corrupted file.
    fn exercise(path: &Path) -> bool {
        match QCOW2::new(path.to_str().unwrap()) {
            Ok(mut image) => {
                let mut sink = vec![0u8; 1 << 16];
                let mut total = 0u64;
                loop {
                    match image.read(&mut sink) {
                        Ok(0) => break,
                        Ok(n) => total += n as u64,
                        Err(_) => break,
                    }
                    // Mutated headers may claim an enormous virtual size.
                    if total > (64 << 20) {
                        break;
                    }
                }
                let _ = image.seek(SeekFrom::End(0));
                let _ = image.seek(SeekFrom::Start(0));
                image.print_info();
                let _ = image.backing_paths();
                let _ = image.clone();
                true
            }
            Err(_) => false,
        }
    }

    /// Returns the number of mutants for which the image still opened.
    fn mutate_and_exercise(original: &[u8], dir: &Path, seed: u64, rounds: usize) -> usize {
        let mut rng = Lcg(seed);
        let mut opened = 0;
        let target = dir.join("mutant.qcow2");
        for round in 0..rounds {
            let mut mutant = original.to_vec();
            match round % 4 {
                // Truncation anywhere in the file.
                0 => {
                    let len = rng.below(original.len() as u64) as usize;
                    mutant.truncate(len);
                }
                // A burst of random bytes in the metadata area (first 4 clusters).
                1 => {
                    let span = original.len().min(4 * 65536);
                    let count = 1 + rng.below(8) as usize;
                    for _ in 0..count {
                        let at = rng.below(span as u64) as usize;
                        mutant[at] = rng.next() as u8;
                    }
                }
                // Overwrite a whole aligned 8-byte word (an L1/L2 entry or header field).
                2 => {
                    let span = original.len().min(4 * 65536) / 8;
                    let at = rng.below(span as u64) as usize * 8;
                    let word = match rng.below(4) {
                        0 => u64::MAX,
                        1 => rng.next(),
                        2 => 1u64 << rng.below(64),
                        _ => rng.below(original.len() as u64 * 2),
                    };
                    mutant[at..at + 8].copy_from_slice(&word.to_be_bytes());
                }
                // Random bytes anywhere.
                _ => {
                    let count = 1 + rng.below(32) as usize;
                    for _ in 0..count {
                        let at = rng.below(original.len() as u64) as usize;
                        mutant[at] = rng.next() as u8;
                    }
                }
            }
            fs::write(&target, &mutant).unwrap();
            if exercise(&target) {
                opened += 1;
            }
        }
        opened
    }

    #[test]
    fn corrupted_synthetic_images_never_panic() {
        let dir = tempfile::tempdir().unwrap();
        let cluster = 4096usize;
        fs::write(dir.path().join("base.raw"), pattern(0x33, 2 * cluster)).unwrap();

        let mut plain =
            ImageBuilder::new(3, 12, 6 * cluster as u64).with_backing("base.raw", Some("raw"));
        plain.set_standard(0, &pattern(1, cluster));
        plain.set_compressed(1, &pattern(2, cluster));
        plain.set_zero(2);
        plain.set_standard(4, &pattern(3, cluster));
        let plain = fs::read(plain.write(dir.path(), "plain.qcow2")).unwrap();

        let mut extended = ImageBuilder::new(3, 14, 2 * 16384).extended();
        extended.set_extended(0, Some(&pattern(4, 16384)), 0b1010, 0b0101);
        extended.set_extended(1, None, 0, 1);
        let extended = fs::read(extended.write(dir.path(), "ext.qcow2")).unwrap();

        let mut v2 = ImageBuilder::new(2, 12, 3 * cluster as u64);
        v2.set_standard(2, &pattern(5, cluster));
        let v2 = fs::read(v2.write(dir.path(), "v2.qcow2")).unwrap();

        let mut opened = 0;
        for (seed, image) in [(1u64, &plain), (2, &extended), (3, &v2)] {
            opened += mutate_and_exercise(image, dir.path(), seed, 400);
        }
        // Sanity check that the mutations are not all fatal, otherwise the
        // read paths would not be exercised at all.
        assert!(opened > 100, "only {opened} mutants opened");
    }

    /// Mutation run over real qemu-img images. Ignored: needs qemu-img.
    #[test]
    #[ignore]
    fn corrupted_qemu_images_never_panic() {
        use std::process::Command;

        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join("ref.raw");
        let mut reference = vec![0u8; 2 << 20];
        reference[..65536].copy_from_slice(&pattern(1, 65536));
        reference[(1 << 20)..(1 << 20) + 65536].copy_from_slice(&pattern(2, 65536));
        fs::write(&raw, &reference).unwrap();

        let variants: &[(&str, &[&str])] = &[
            ("plain.qcow2", &[]),
            ("compressed.qcow2", &["-c"]),
            ("extended.qcow2", &["-o", "extended_l2=on"]),
            ("v2.qcow2", &["-o", "compat=0.10"]),
        ];
        let mut opened = 0;
        for (index, (name, options)) in variants.iter().enumerate() {
            let out = dir.path().join(name);
            let status = Command::new("qemu-img")
                .args(["convert", "-f", "raw", "-O", "qcow2"])
                .args(*options)
                .arg(&raw)
                .arg(&out)
                .status()
                .expect("qemu-img must be installed");
            assert!(status.success());
            let bytes = fs::read(&out).unwrap();
            opened += mutate_and_exercise(&bytes, dir.path(), 100 + index as u64, 500);
        }
        assert!(opened > 100, "only {opened} mutants opened");
    }

    #[test]
    fn declared_backing_format_wins_over_content_probing() {
        let dir = tempfile::tempdir().unwrap();
        let cluster = 4096usize;
        // A raw backing whose *content* is a complete QCOW2 image.
        let mut inner = ImageBuilder::new(3, 12, 2 * cluster as u64);
        inner.set_standard(0, &pattern(0x5a, cluster));
        let inner_path = inner.write(dir.path(), "base.raw");
        let inner_bytes = fs::read(&inner_path).unwrap();

        // Declared raw: the overlay must expose the raw bytes (QCOW2 header first).
        let path = ImageBuilder::new(3, 12, inner_bytes.len() as u64)
            .with_backing("base.raw", Some("raw"))
            .write(dir.path(), "over_raw.qcow2");
        let mut image = QCOW2::new(path.to_str().unwrap()).unwrap();
        let all = read_all(&mut image);
        assert_eq!(&all[..4], &QCOW2_MAGIC);
        assert_eq!(all, inner_bytes);

        // Declared qcow2: the overlay reads the inner image's guest view.
        let path = ImageBuilder::new(3, 12, 2 * cluster as u64)
            .with_backing("base.raw", Some("qcow2"))
            .write(dir.path(), "over_qcow2.qcow2");
        let mut image = QCOW2::new(path.to_str().unwrap()).unwrap();
        assert_eq!(
            &read_all(&mut image)[..cluster],
            &pattern(0x5a, cluster)[..]
        );

        // Declared qcow2 but the file has no magic: refuse, like QEMU.
        fs::write(dir.path().join("plain.raw"), pattern(1, cluster)).unwrap();
        let path = ImageBuilder::new(3, 12, cluster as u64)
            .with_backing("plain.raw", Some("qcow2"))
            .write(dir.path(), "bad_decl.qcow2");
        let error = QCOW2::new(path.to_str().unwrap()).unwrap_err();
        assert!(error.contains("no QCOW2 magic"), "{error}");

        // Declared as something we cannot read.
        let path = ImageBuilder::new(3, 12, cluster as u64)
            .with_backing("plain.raw", Some("vmdk"))
            .write(dir.path(), "bad_fmt.qcow2");
        let error = QCOW2::new(path.to_str().unwrap()).unwrap_err();
        assert!(error.contains("unsupported format 'vmdk'"), "{error}");
    }

    #[test]
    fn header_sanity_checks_follow_qemu() {
        let dir = tempfile::tempdir().unwrap();

        let mut refcount = ImageBuilder::new(3, 12, 4096);
        refcount.refcount_order = 7;
        let path = refcount.write(dir.path(), "refcount.qcow2");
        let error = QCOW2::new(path.to_str().unwrap()).unwrap_err();
        assert!(error.contains("refcount order 7"), "{error}");

        let mut hostile = ImageBuilder::new(3, 12, 4096);
        hostile.refcount_order = u32::MAX;
        let path = hostile.write(dir.path(), "refcount_max.qcow2");
        assert!(QCOW2::new(path.to_str().unwrap()).is_err());

        let mut unaligned = ImageBuilder::new(3, 12, 4096);
        unaligned.header_length = Some(108);
        let path = unaligned.write(dir.path(), "unaligned.qcow2");
        let error = QCOW2::new(path.to_str().unwrap()).unwrap_err();
        assert!(error.contains("not a multiple of 8"), "{error}");

        // Compression type bit set but the header stops at 104 bytes.
        let mut short = ImageBuilder::new(3, 12, 4096);
        short.header_length = Some(104);
        short.compression_bit = Some(true);
        let path = short.write(dir.path(), "short.qcow2");
        let error = QCOW2::new(path.to_str().unwrap()).unwrap_err();
        assert!(error.contains("no compression_type field"), "{error}");

        // compression_type != 0 without the feature bit.
        let mut inconsistent = ImageBuilder::new(3, 12, 4096);
        inconsistent.compression_type = COMPRESSION_ZSTD;
        inconsistent.compression_bit = Some(false);
        let path = inconsistent.write(dir.path(), "inconsistent.qcow2");
        let error = QCOW2::new(path.to_str().unwrap()).unwrap_err();
        assert!(error.contains("feature bit is not set"), "{error}");

        // A 104-byte header with the bit clear is the common pre-5.1 layout.
        let mut old = ImageBuilder::new(3, 12, 4096);
        old.header_length = Some(104);
        let path = old.write(dir.path(), "old.qcow2");
        assert_eq!(
            QCOW2::new(path.to_str().unwrap())
                .unwrap()
                .header()
                .header_length,
            104
        );
    }

    #[test]
    fn truncated_l2_table_reads_as_unallocated_like_qemu() {
        let dir = tempfile::tempdir().unwrap();
        let cluster = 4096usize;
        let mut builder = ImageBuilder::new(3, 12, 2 * cluster as u64);
        builder.set_standard(0, &pattern(7, cluster));
        let path = builder.write(dir.path(), "cut.qcow2");
        // Keep header, L1 and refcount table; cut the L2 table and the data.
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, &bytes[..3 * cluster]).unwrap();

        let mut image = QCOW2::new(path.to_str().unwrap()).unwrap();
        assert_eq!(read_all(&mut image), vec![0u8; 2 * cluster]);
    }

    #[test]
    fn corruptions_qemu_refuses_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let cluster = 4096usize;

        // Zero flag in a version 2 image.
        let mut v2 = ImageBuilder::new(2, 12, cluster as u64);
        v2.set_zero(0);
        let path = v2.write(dir.path(), "v2zero.qcow2");
        let mut image = QCOW2::new(path.to_str().unwrap()).unwrap();
        let mut buf = [0u8; 16];
        let error = image.read_exact(&mut buf).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");

        // External data file: host offset of guest cluster 0 pointing at cluster 1.
        let mut data =
            ImageBuilder::new(3, 12, 2 * cluster as u64).with_external_data_file("d.data");
        data.set_standard(0, &pattern(1, cluster));
        data.set_standard(1, &pattern(2, cluster));
        data.l2[0] = (cluster as u64 | COPIED, 0);
        let path = data.write(dir.path(), "mismatch.qcow2");
        let mut image = QCOW2::new(path.to_str().unwrap()).unwrap();
        let error = image.read_exact(&mut buf).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match guest cluster offset"),
            "{error}"
        );
        // Cluster 1 itself is consistent and still readable.
        image.seek(SeekFrom::Start(cluster as u64)).unwrap();
        image.read_exact(&mut buf).unwrap();
        assert_eq!(buf, pattern(2, 16)[..]);

        // Extended L2: an invalid bitmap anywhere in the cluster poisons the
        // whole cluster, even when the subcluster being read looks fine.
        let mut ext = ImageBuilder::new(3, 14, 16384).extended();
        ext.set_extended(0, Some(&pattern(3, 16384)), 1 | (1 << 5), 1 << 5);
        let path = ext.write(dir.path(), "extbad.qcow2");
        let mut image = QCOW2::new(path.to_str().unwrap()).unwrap();
        let error = image.read_exact(&mut buf).unwrap_err();
        assert!(
            error.to_string().contains("invalid subcluster bitmap"),
            "{error}"
        );
    }

    #[test]
    fn autodetect_reports_qcow2_open_errors_instead_of_falling_back_to_raw() {
        let dir = tempfile::tempdir().unwrap();
        let path = ImageBuilder::new(3, 12, 4096)
            .with_backing("missing.raw", Some("raw"))
            .write(dir.path(), "orphan.qcow2");
        let error = match crate::Body::try_new(path.to_string_lossy().into_owned(), "auto") {
            Ok(_) => panic!("an orphan QCOW2 must not open as RAW"),
            Err(error) => error,
        };
        assert!(
            error.contains("QCOW2") && error.contains("missing.raw"),
            "{error}"
        );
        assert!(QCOW2::probe(path.to_str().unwrap()));
        assert!(!QCOW2::probe(dir.path().join("absent").to_str().unwrap()));
    }

    #[test]
    fn relative_backing_name_resolves_against_the_path_as_given() {
        let dir = tempfile::tempdir().unwrap();
        let cluster = 4096usize;
        let real = dir.path().join("real");
        let link_dir = dir.path().join("linked");
        fs::create_dir_all(&real).unwrap();
        fs::create_dir_all(&link_dir).unwrap();
        // Two different backings with the same name in the two directories.
        fs::write(real.join("base.raw"), pattern(0x11, cluster)).unwrap();
        fs::write(link_dir.join("base.raw"), pattern(0x22, cluster)).unwrap();
        let image_path = ImageBuilder::new(3, 12, cluster as u64)
            .with_backing("base.raw", Some("raw"))
            .write(&real, "disk.qcow2");
        let link = link_dir.join("disk.qcow2");
        if std::os::unix::fs::symlink(&image_path, &link).is_err() {
            return; // filesystem without symlinks: nothing to test
        }
        // Through the symlink, QEMU picks linked/base.raw; so do we.
        let mut image = QCOW2::new(link.to_str().unwrap()).unwrap();
        assert_eq!(read_all(&mut image), pattern(0x22, cluster));
        let mut image = QCOW2::new(image_path.to_str().unwrap()).unwrap();
        assert_eq!(read_all(&mut image), pattern(0x11, cluster));
    }
}
