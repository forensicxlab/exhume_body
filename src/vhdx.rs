//! VHDX (Hyper-V Virtual Hard Disk, version 2) image reader.
//!
//! This module exposes the guest view of a VHDX image as a seekable byte
//! stream, following the MS-VHDX specification:
//!
//! - file type identifier, the two headers (CRC32C-validated, the one with
//!   the highest sequence number wins) and the two region tables;
//! - the metadata region: file parameters, virtual disk size, virtual disk
//!   ID, logical and physical sector sizes, parent locator;
//! - the block allocation table (BAT) with interleaved sector bitmap entries;
//! - fixed and dynamic disks, and differencing disks whose parent chain is
//!   made of VHDX files reachable from the parent locator;
//! - partially present blocks, read sector by sector through the sector
//!   bitmap.
//!
//! # Known Limitations
//!
//! - An image whose log must be replayed (non-zero `LogGuid`, the disk was
//!   not cleanly detached) is refused: replaying would mean reconstructing
//!   metadata from the log, and the evidence must not be modified. Replay it
//!   on a copy with a tool that can write the format (e.g. `qemu-img convert`)
//!   and read the copy.
//! - Parents are located through `relative_path`, `absolute_win32_path` and
//!   `volume_path`; Windows volume GUID paths cannot be resolved on other
//!   systems.
//! - Encrypted (BitLocker-in-guest) content is passed through untouched, as
//!   for every other format.

use std::{
    cmp::min,
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::utils::{
    checked_offset, invalid_data, le_u16, le_u32, le_u64, read_exact_at, read_zero_padded_at,
};

use log::{debug, info, warn};

const MIB: u64 = 1 << 20;
const FILE_TYPE_SIGNATURE: &[u8; 8] = b"vhdxfile";
const HEADER_SIGNATURE: &[u8; 4] = b"head";
const REGION_TABLE_SIGNATURE: &[u8; 4] = b"regi";
const METADATA_TABLE_SIGNATURE: &[u8; 8] = b"metadata";
const HEADER_OFFSETS: [u64; 2] = [64 * 1024, 128 * 1024];
const REGION_TABLE_OFFSETS: [u64; 2] = [192 * 1024, 256 * 1024];
const HEADER_SIZE: usize = 4096;
const REGION_TABLE_SIZE: usize = 64 * 1024;
const METADATA_TABLE_SIZE: usize = 64 * 1024;
const REGION_ENTRY_SIZE: usize = 32;
const METADATA_ENTRY_SIZE: usize = 32;
const MAX_REGION_ENTRIES: u32 = 2047;
const MAX_METADATA_ENTRIES: u16 = 2047;
const MIN_BLOCK_SIZE: u32 = 1 << 20;
const MAX_BLOCK_SIZE: u32 = 256 << 20;
const SECTOR_BITMAP_BLOCK_SIZE: u64 = MIB;
/// Largest BAT this reader loads in memory (256 MiB of entries).
const MAX_BAT_BYTES: u64 = 256 * MIB;
/// Largest metadata item this reader loads.
const MAX_METADATA_ITEM_BYTES: u32 = 64 << 20;
const MAX_PARENT_DEPTH: usize = 16;
const SECTOR_BITMAP_CACHE_BLOCKS: usize = 8;

const BAT_STATE_MASK: u64 = 0x7;
const BAT_OFFSET_MASK: u64 = 0xffff_ffff_fff0_0000;
const PAYLOAD_BLOCK_NOT_PRESENT: u64 = 0;
const PAYLOAD_BLOCK_UNDEFINED: u64 = 1;
const PAYLOAD_BLOCK_ZERO: u64 = 2;
const PAYLOAD_BLOCK_UNMAPPED: u64 = 3;
const PAYLOAD_BLOCK_FULLY_PRESENT: u64 = 6;
const PAYLOAD_BLOCK_PARTIALLY_PRESENT: u64 = 7;
const SB_BLOCK_PRESENT: u64 = 6;

const FILE_PARAMETERS_LEAVE_BLOCKS_ALLOCATED: u32 = 1 << 0;
const FILE_PARAMETERS_HAS_PARENT: u32 = 1 << 1;
const METADATA_FLAG_IS_USER: u32 = 1 << 0;
const METADATA_FLAG_IS_VIRTUAL_DISK: u32 = 1 << 1;
const METADATA_FLAG_IS_REQUIRED: u32 = 1 << 2;
const REGION_FLAG_REQUIRED: u32 = 1 << 0;

/// GUID in on-disk (mixed-endian) byte order.
pub type Guid = [u8; 16];

/// Build the on-disk byte layout of a GUID written in its textual form.
const fn guid(d1: u32, d2: u16, d3: u16, d4: u16, d5: u64) -> Guid {
    let a = d1.to_le_bytes();
    let b = d2.to_le_bytes();
    let c = d3.to_le_bytes();
    let d = d4.to_be_bytes();
    let e = d5.to_be_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], e[2], e[3], e[4], e[5], e[6],
        e[7],
    ]
}

const REGION_BAT: Guid = guid(0x2dc2_7766, 0xf623, 0x4200, 0x9d64, 0x115e_9bfd_4a08);
const REGION_METADATA: Guid = guid(0x8b7c_a206, 0x4790, 0x4b9a, 0xb8fe, 0x575f_050f_886e);
const ITEM_FILE_PARAMETERS: Guid = guid(0xcaa1_6737, 0xfa36, 0x4d43, 0xb3b6, 0x33f0_aa44_e76b);
const ITEM_VIRTUAL_DISK_SIZE: Guid = guid(0x2fa5_4224, 0xcd1b, 0x4876, 0xb211, 0x5dbe_d83b_f4b8);
const ITEM_VIRTUAL_DISK_ID: Guid = guid(0xbeca_12ab, 0xb2e6, 0x4523, 0x93ef, 0xc309_e000_c746);
const ITEM_LOGICAL_SECTOR_SIZE: Guid = guid(0x8141_bf1d, 0xa96f, 0x4709, 0xba47, 0xf233_a8fa_ab5f);
const ITEM_PHYSICAL_SECTOR_SIZE: Guid = guid(0xcda3_48c7, 0x445d, 0x4471, 0x9cc9, 0xe988_5251_c556);
const ITEM_PARENT_LOCATOR: Guid = guid(0xa8d3_5f2d, 0xb30b, 0x454d, 0xabf7, 0xd3d8_4834_ab0c);
const PARENT_LOCATOR_TYPE_VHDX: Guid = guid(0xb04a_efb7, 0xd19e, 0x4a81, 0xb789, 0x25b8_e944_5913);

/// Textual form of an on-disk GUID.
pub fn format_guid(g: &Guid) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

const fn crc32c_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82f6_3b78
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

const CRC32C_TABLE: [u32; 256] = crc32c_table();

/// CRC-32C (Castagnoli), as used by every VHDX checksum.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc = CRC32C_TABLE[((crc ^ byte as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

/// Checksum of a structure whose own checksum field (4 bytes at `field`) is
/// taken as zero.
fn crc32c_with_zeroed_field(data: &[u8], field: usize) -> u32 {
    let mut copy = data.to_vec();
    copy[field..field + 4].fill(0);
    crc32c(&copy)
}

fn read_guid(data: &[u8], offset: usize) -> Guid {
    let mut g = [0u8; 16];
    g.copy_from_slice(&data[offset..offset + 16]);
    g
}

fn decode_utf16le(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let end = units.iter().position(|u| *u == 0).unwrap_or(units.len());
    char::decode_utf16(units[..end].iter().copied())
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// One of the two VHDX headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VhdxHeader {
    /// 0 or 1: which of the two header slots this was read from.
    pub slot: usize,
    pub sequence_number: u64,
    pub file_write_guid: Guid,
    pub data_write_guid: Guid,
    pub log_guid: Guid,
    pub log_version: u16,
    pub version: u16,
    pub log_length: u32,
    pub log_offset: u64,
}

impl VhdxHeader {
    fn parse(data: &[u8], slot: usize) -> Result<VhdxHeader, String> {
        if data.len() < HEADER_SIZE {
            return Err("truncated header".to_owned());
        }
        if &data[0..4] != HEADER_SIGNATURE {
            return Err("missing 'head' signature".to_owned());
        }
        let stored = le_u32(data, 4)?;
        let computed = crc32c_with_zeroed_field(&data[..HEADER_SIZE], 4);
        if stored != computed {
            return Err(format!(
                "checksum mismatch (stored {stored:#010x}, computed {computed:#010x})"
            ));
        }
        let header = VhdxHeader {
            slot,
            sequence_number: le_u64(data, 8)?,
            file_write_guid: read_guid(data, 16),
            data_write_guid: read_guid(data, 32),
            log_guid: read_guid(data, 48),
            log_version: le_u16(data, 64)?,
            version: le_u16(data, 66)?,
            log_length: le_u32(data, 68)?,
            log_offset: le_u64(data, 72)?,
        };
        if header.version != 1 {
            return Err(format!(
                "unsupported VHDX header version {}",
                header.version
            ));
        }
        Ok(header)
    }

    /// Whether the log holds entries that must be replayed before the
    /// metadata can be trusted.
    pub fn log_needs_replay(&self) -> bool {
        self.log_guid != [0u8; 16]
    }
}

/// One region table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VhdxRegion {
    pub guid: Guid,
    pub file_offset: u64,
    pub length: u32,
    pub required: bool,
}

fn parse_region_table(data: &[u8]) -> Result<Vec<VhdxRegion>, String> {
    if data.len() < REGION_TABLE_SIZE {
        return Err("truncated region table".to_owned());
    }
    if &data[0..4] != REGION_TABLE_SIGNATURE {
        return Err("missing 'regi' signature".to_owned());
    }
    let stored = le_u32(data, 4)?;
    let computed = crc32c_with_zeroed_field(&data[..REGION_TABLE_SIZE], 4);
    if stored != computed {
        return Err(format!(
            "checksum mismatch (stored {stored:#010x}, computed {computed:#010x})"
        ));
    }
    let count = le_u32(data, 8)?;
    if count > MAX_REGION_ENTRIES {
        return Err(format!("region table declares {count} entries"));
    }
    let mut regions = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let base = 16 + index * REGION_ENTRY_SIZE;
        let region = VhdxRegion {
            guid: read_guid(data, base),
            file_offset: le_u64(data, base + 16)?,
            length: le_u32(data, base + 24)?,
            required: le_u32(data, base + 28)? & REGION_FLAG_REQUIRED != 0,
        };
        if region.file_offset < MIB || !region.file_offset.is_multiple_of(MIB) {
            return Err(format!(
                "region {} has an invalid file offset {:#x}",
                format_guid(&region.guid),
                region.file_offset
            ));
        }
        if region.length == 0 || !(region.length as u64).is_multiple_of(MIB) {
            return Err(format!(
                "region {} has an invalid length {:#x}",
                format_guid(&region.guid),
                region.length
            ));
        }
        regions.push(region);
    }
    Ok(regions)
}

/// One metadata table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VhdxMetadataEntry {
    pub item_id: Guid,
    /// Offset of the item, relative to the start of the metadata region.
    pub offset: u32,
    pub length: u32,
    pub is_user: bool,
    pub is_virtual_disk: bool,
    pub is_required: bool,
}

fn parse_metadata_table(data: &[u8], region_length: u32) -> Result<Vec<VhdxMetadataEntry>, String> {
    if data.len() < METADATA_TABLE_SIZE {
        return Err("truncated metadata table".to_owned());
    }
    if &data[0..8] != METADATA_TABLE_SIGNATURE {
        return Err("missing 'metadata' signature".to_owned());
    }
    let count = le_u16(data, 10)?;
    if count > MAX_METADATA_ENTRIES {
        return Err(format!("metadata table declares {count} entries"));
    }
    let mut entries = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let base = 32 + index * METADATA_ENTRY_SIZE;
        let flags = le_u32(data, base + 24)?;
        let entry = VhdxMetadataEntry {
            item_id: read_guid(data, base),
            offset: le_u32(data, base + 16)?,
            length: le_u32(data, base + 20)?,
            is_user: flags & METADATA_FLAG_IS_USER != 0,
            is_virtual_disk: flags & METADATA_FLAG_IS_VIRTUAL_DISK != 0,
            is_required: flags & METADATA_FLAG_IS_REQUIRED != 0,
        };
        // Items live after the 64 KiB table, inside the region.
        if entry.length != 0 {
            if entry.offset < METADATA_TABLE_SIZE as u32 {
                return Err(format!(
                    "metadata item {} overlaps the metadata table",
                    format_guid(&entry.item_id)
                ));
            }
            let end = entry.offset as u64 + entry.length as u64;
            if end > region_length as u64 {
                return Err(format!(
                    "metadata item {} runs past the metadata region",
                    format_guid(&entry.item_id)
                ));
            }
            if entry.length > MAX_METADATA_ITEM_BYTES {
                return Err(format!(
                    "metadata item {} is unreasonably large ({} bytes)",
                    format_guid(&entry.item_id),
                    entry.length
                ));
            }
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// The File Parameters metadata item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VhdxFileParameters {
    pub block_size: u32,
    /// Fixed disk: every block is allocated up front.
    pub leave_blocks_allocated: bool,
    /// Differencing disk: unallocated blocks come from the parent.
    pub has_parent: bool,
}

/// The Parent Locator metadata item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VhdxParentLocator {
    pub locator_type: Guid,
    pub entries: Vec<(String, String)>,
}

impl VhdxParentLocator {
    fn parse(data: &[u8]) -> Result<VhdxParentLocator, String> {
        if data.len() < 20 {
            return Err("parent locator is too short".to_owned());
        }
        let locator_type = read_guid(data, 0);
        let count = le_u16(data, 18)? as usize;
        let mut entries = Vec::with_capacity(count);
        for index in 0..count {
            let base = 20 + index * 12;
            if base + 12 > data.len() {
                return Err("parent locator entry table is truncated".to_owned());
            }
            let key_offset = le_u32(data, base)? as usize;
            let value_offset = le_u32(data, base + 4)? as usize;
            let key_length = le_u16(data, base + 8)? as usize;
            let value_length = le_u16(data, base + 10)? as usize;
            let key_end = key_offset.checked_add(key_length);
            let value_end = value_offset.checked_add(value_length);
            match (key_end, value_end) {
                (Some(k), Some(v)) if k <= data.len() && v <= data.len() => {
                    entries.push((
                        decode_utf16le(&data[key_offset..k]),
                        decode_utf16le(&data[value_offset..v]),
                    ));
                }
                _ => return Err("parent locator entry points outside the item".to_owned()),
            }
        }
        Ok(VhdxParentLocator {
            locator_type,
            entries,
        })
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }
}

/// How one payload block (or sector of it) maps onto storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockMapping {
    /// Read from the parent, or zeroes without one.
    NotPresent,
    Zero,
    /// Stored in this file at the given offset.
    Present(u64),
    /// Decided sector by sector through the chunk's sector bitmap.
    Partial(u64),
}

/// A VHDX image opened for reading.
pub struct VHDX {
    path: PathBuf,
    file: File,
    creator: String,
    header: VhdxHeader,
    regions: Vec<VhdxRegion>,
    metadata_entries: Vec<VhdxMetadataEntry>,
    parameters: VhdxFileParameters,
    disk_size: u64,
    virtual_disk_id: Guid,
    logical_sector_size: u32,
    physical_sector_size: u32,
    parent_locator: Option<VhdxParentLocator>,
    parent: Option<Box<VHDX>>,
    bat: Arc<Vec<u64>>,
    chunk_ratio: u64,
    /// Sector bitmap blocks keyed by chunk index.
    bitmap_cache: HashMap<u64, Arc<Vec<u8>>>,
    position: u64,
    /// Set once a payload read hit the end of a truncated container.
    truncation_reported: bool,
}

impl std::fmt::Debug for VHDX {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VHDX")
            .field("path", &self.path)
            .field("creator", &self.creator)
            .field("header", &self.header)
            .field("parameters", &self.parameters)
            .field("disk_size", &self.disk_size)
            .field("logical_sector_size", &self.logical_sector_size)
            .field("parent", &self.parent.as_ref().map(|p| &p.path))
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

impl Clone for VHDX {
    fn clone(&self) -> Self {
        let file = self.file.try_clone().unwrap_or_else(|error| {
            panic!(
                "failed to clone VHDX file handle {}: {error}",
                self.path.display()
            )
        });
        Self {
            path: self.path.clone(),
            file,
            creator: self.creator.clone(),
            header: self.header.clone(),
            regions: self.regions.clone(),
            metadata_entries: self.metadata_entries.clone(),
            parameters: self.parameters,
            disk_size: self.disk_size,
            virtual_disk_id: self.virtual_disk_id,
            logical_sector_size: self.logical_sector_size,
            physical_sector_size: self.physical_sector_size,
            parent_locator: self.parent_locator.clone(),
            parent: self.parent.clone(),
            bat: Arc::clone(&self.bat),
            chunk_ratio: self.chunk_ratio,
            bitmap_cache: self.bitmap_cache.clone(),
            position: self.position,
            truncation_reported: self.truncation_reported,
        }
    }
}

impl VHDX {
    /// Open a VHDX image and its parent chain.
    ///
    /// # Errors
    ///
    /// Returns an error if the file is not a VHDX image, if both headers or
    /// both region tables are corrupt, if the log must be replayed, if a
    /// required region or metadata item is unknown, or if a parent cannot be
    /// found.
    pub fn new(file_path: &str) -> Result<VHDX, String> {
        let mut visited = HashSet::new();
        Self::open_with_depth(Path::new(file_path), 0, &mut visited)
    }

    /// Whether the file starts with the VHDX file type identifier. Cheap.
    pub fn probe(file_path: &str) -> bool {
        File::open(file_path)
            .map(|mut file| Self::has_signature(&mut file))
            .unwrap_or(false)
    }

    fn has_signature(file: &mut File) -> bool {
        let mut magic = [0u8; 8];
        file.seek(SeekFrom::Start(0)).is_ok()
            && file.read_exact(&mut magic).is_ok()
            && &magic == FILE_TYPE_SIGNATURE
    }

    fn open_with_depth(
        path: &Path,
        depth: usize,
        visited: &mut HashSet<PathBuf>,
    ) -> Result<VHDX, String> {
        if depth > MAX_PARENT_DEPTH {
            return Err(format!(
                "VHDX parent chain is deeper than {MAX_PARENT_DEPTH} levels"
            ));
        }
        let mut file = File::open(path)
            .map_err(|error| format!("cannot open VHDX image {}: {error}", path.display()))?;
        let canonical = path
            .canonicalize()
            .map_err(|error| format!("cannot resolve VHDX path {}: {error}", path.display()))?;
        if !visited.insert(canonical.clone()) {
            return Err(format!(
                "VHDX parent chain loops back to {}",
                canonical.display()
            ));
        }

        // File type identifier: signature + UTF-16LE creator.
        let mut identifier = vec![0u8; 8 + 512];
        read_exact_at(&mut file, 0, &mut identifier)
            .map_err(|error| format!("cannot read VHDX file type identifier: {error}"))?;
        if &identifier[0..8] != FILE_TYPE_SIGNATURE {
            return Err("invalid VHDX signature".to_owned());
        }
        let creator = decode_utf16le(&identifier[8..]);

        let header = Self::read_headers(&mut file)?;
        if header.log_needs_replay() {
            return Err(format!(
                "VHDX log must be replayed (LogGuid {}): the disk was not cleanly detached and the log may hold metadata updates. \
                 Replay it on a copy with a tool that can write VHDX (e.g. `qemu-img convert`) and read the copy",
                format_guid(&header.log_guid)
            ));
        }
        let regions = Self::read_region_table(&mut file)?;
        for region in &regions {
            if region.required && region.guid != REGION_BAT && region.guid != REGION_METADATA {
                return Err(format!(
                    "VHDX image has an unknown required region {}",
                    format_guid(&region.guid)
                ));
            }
        }
        let bat_region = regions
            .iter()
            .find(|r| r.guid == REGION_BAT)
            .cloned()
            .ok_or_else(|| "VHDX image has no BAT region".to_owned())?;
        let metadata_region = regions
            .iter()
            .find(|r| r.guid == REGION_METADATA)
            .cloned()
            .ok_or_else(|| "VHDX image has no metadata region".to_owned())?;

        let mut table = vec![0u8; METADATA_TABLE_SIZE];
        read_exact_at(&mut file, metadata_region.file_offset, &mut table)
            .map_err(|error| format!("cannot read VHDX metadata table: {error}"))?;
        let metadata_entries = parse_metadata_table(&table, metadata_region.length)
            .map_err(|error| format!("invalid VHDX metadata table: {error}"))?;

        let mut parameters = None;
        let mut disk_size = None;
        let mut virtual_disk_id = None;
        let mut logical_sector_size = None;
        let mut physical_sector_size = None;
        let mut parent_locator = None;
        for entry in &metadata_entries {
            let known = [
                ITEM_FILE_PARAMETERS,
                ITEM_VIRTUAL_DISK_SIZE,
                ITEM_VIRTUAL_DISK_ID,
                ITEM_LOGICAL_SECTOR_SIZE,
                ITEM_PHYSICAL_SECTOR_SIZE,
                ITEM_PARENT_LOCATOR,
            ]
            .contains(&entry.item_id);
            if !known {
                if entry.is_required {
                    return Err(format!(
                        "VHDX image has an unknown required metadata item {}",
                        format_guid(&entry.item_id)
                    ));
                }
                continue;
            }
            let mut item = vec![0u8; entry.length as usize];
            read_exact_at(
                &mut file,
                metadata_region.file_offset + entry.offset as u64,
                &mut item,
            )
            .map_err(|error| {
                format!(
                    "cannot read VHDX metadata item {}: {error}",
                    format_guid(&entry.item_id)
                )
            })?;
            let too_short = |what: &str| format!("VHDX {what} metadata item is too short");
            match entry.item_id {
                ITEM_FILE_PARAMETERS => {
                    if item.len() < 8 {
                        return Err(too_short("file parameters"));
                    }
                    let flags = le_u32(&item, 4)?;
                    parameters = Some(VhdxFileParameters {
                        block_size: le_u32(&item, 0)?,
                        leave_blocks_allocated: flags & FILE_PARAMETERS_LEAVE_BLOCKS_ALLOCATED != 0,
                        has_parent: flags & FILE_PARAMETERS_HAS_PARENT != 0,
                    });
                }
                ITEM_VIRTUAL_DISK_SIZE => {
                    if item.len() < 8 {
                        return Err(too_short("virtual disk size"));
                    }
                    disk_size = Some(le_u64(&item, 0)?);
                }
                ITEM_VIRTUAL_DISK_ID => {
                    if item.len() < 16 {
                        return Err(too_short("virtual disk ID"));
                    }
                    virtual_disk_id = Some(read_guid(&item, 0));
                }
                ITEM_LOGICAL_SECTOR_SIZE => {
                    if item.len() < 4 {
                        return Err(too_short("logical sector size"));
                    }
                    logical_sector_size = Some(le_u32(&item, 0)?);
                }
                ITEM_PHYSICAL_SECTOR_SIZE => {
                    if item.len() < 4 {
                        return Err(too_short("physical sector size"));
                    }
                    physical_sector_size = Some(le_u32(&item, 0)?);
                }
                ITEM_PARENT_LOCATOR => {
                    parent_locator = Some(
                        VhdxParentLocator::parse(&item)
                            .map_err(|error| format!("invalid VHDX parent locator: {error}"))?,
                    );
                }
                _ => unreachable!("filtered above"),
            }
        }

        let parameters =
            parameters.ok_or_else(|| "VHDX image has no file parameters item".to_owned())?;
        let disk_size =
            disk_size.ok_or_else(|| "VHDX image has no virtual disk size item".to_owned())?;
        let virtual_disk_id =
            virtual_disk_id.ok_or_else(|| "VHDX image has no virtual disk ID item".to_owned())?;
        let logical_sector_size = logical_sector_size
            .ok_or_else(|| "VHDX image has no logical sector size item".to_owned())?;
        let physical_sector_size = physical_sector_size.unwrap_or_else(|| {
            warn!("VHDX image has no physical sector size item (required by the specification); assuming the logical size");
            logical_sector_size
        });

        if !parameters.block_size.is_power_of_two()
            || !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&parameters.block_size)
        {
            return Err(format!(
                "VHDX block size {} is not a power of two between 1 MiB and 256 MiB",
                parameters.block_size
            ));
        }
        if logical_sector_size != 512 && logical_sector_size != 4096 {
            return Err(format!(
                "VHDX logical sector size {logical_sector_size} is neither 512 nor 4096"
            ));
        }
        if physical_sector_size != 512 && physical_sector_size != 4096 {
            return Err(format!(
                "VHDX physical sector size {physical_sector_size} is neither 512 nor 4096"
            ));
        }
        if disk_size == 0 || !disk_size.is_multiple_of(logical_sector_size as u64) {
            return Err(format!(
                "VHDX virtual disk size {disk_size} is not a positive multiple of the sector size"
            ));
        }

        // Payload blocks per chunk; one sector bitmap entry follows each chunk.
        let chunk_ratio =
            ((1u64 << 23) * logical_sector_size as u64) / parameters.block_size as u64;
        let blocks = disk_size.div_ceil(parameters.block_size as u64);
        let chunks = blocks.div_ceil(chunk_ratio);
        let needed_entries = (blocks - 1) + (blocks - 1) / chunk_ratio + 1;
        let available_entries = min(bat_region.length as u64 / 8, chunks * (chunk_ratio + 1));
        if available_entries < needed_entries {
            return Err(format!(
                "VHDX BAT region holds {available_entries} entries but {needed_entries} are needed for a {disk_size}-byte disk"
            ));
        }
        if available_entries * 8 > MAX_BAT_BYTES {
            return Err(format!(
                "VHDX BAT is larger than this reader supports ({} bytes)",
                available_entries * 8
            ));
        }
        let mut raw_bat = vec![0u8; (available_entries * 8) as usize];
        let read = read_zero_padded_at(&mut file, bat_region.file_offset, &mut raw_bat)
            .map_err(|error| format!("cannot read VHDX BAT: {error}"))?;
        if (read as u64) < needed_entries * 8 {
            return Err(format!(
                "VHDX BAT is truncated: {read} of {} bytes present",
                needed_entries * 8
            ));
        }
        let bat: Vec<u64> = raw_bat
            .chunks_exact(8)
            .map(|c| le_u64(c, 0))
            .collect::<Result<_, _>>()?;

        let parent = if parameters.has_parent {
            let locator = parent_locator
                .as_ref()
                .ok_or_else(|| "VHDX differencing disk has no parent locator item".to_owned())?;
            if locator.locator_type != PARENT_LOCATOR_TYPE_VHDX {
                return Err(format!(
                    "VHDX parent locator type {} is not supported",
                    format_guid(&locator.locator_type)
                ));
            }
            let base_dir = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."));
            let parent_path = Self::resolve_parent_path(locator, &base_dir)?;
            debug!(
                "VHDX {} has parent {}",
                path.display(),
                parent_path.display()
            );
            let parent = Self::open_with_depth(&parent_path, depth + 1, visited)?;
            if let Some(linkage) = locator.get("parent_linkage") {
                let expected = linkage
                    .trim_matches(|c| c == '{' || c == '}')
                    .to_ascii_lowercase();
                let actual = format_guid(&parent.header.data_write_guid);
                if expected != actual {
                    warn!(
                        "VHDX parent {} was modified after the child was created (parent_linkage {expected}, parent DataWriteGuid {actual}); the child's view may be inconsistent",
                        parent_path.display()
                    );
                }
            }
            Some(Box::new(parent))
        } else {
            None
        };

        Ok(VHDX {
            path: canonical,
            file,
            creator,
            header,
            regions,
            metadata_entries,
            parameters,
            disk_size,
            virtual_disk_id,
            logical_sector_size,
            physical_sector_size,
            parent_locator,
            parent,
            bat: Arc::new(bat),
            chunk_ratio,
            bitmap_cache: HashMap::new(),
            position: 0,
            truncation_reported: false,
        })
    }

    /// Read both header slots and keep the valid one with the highest
    /// sequence number.
    fn read_headers(file: &mut File) -> Result<VhdxHeader, String> {
        let mut best: Option<VhdxHeader> = None;
        let mut errors = Vec::new();
        for (slot, offset) in HEADER_OFFSETS.iter().enumerate() {
            let mut buf = vec![0u8; HEADER_SIZE];
            match read_exact_at(file, *offset, &mut buf) {
                Ok(()) => match VhdxHeader::parse(&buf, slot) {
                    Ok(header) => {
                        if best
                            .as_ref()
                            .is_none_or(|b| header.sequence_number > b.sequence_number)
                        {
                            best = Some(header);
                        }
                    }
                    Err(error) => errors.push(format!("header {}: {error}", slot + 1)),
                },
                Err(error) => errors.push(format!("header {}: {error}", slot + 1)),
            }
        }
        match best {
            Some(header) => {
                if !errors.is_empty() {
                    warn!(
                        "VHDX: using header {} only ({})",
                        header.slot + 1,
                        errors.join("; ")
                    );
                }
                Ok(header)
            }
            None => Err(format!(
                "both VHDX headers are invalid: {}",
                errors.join("; ")
            )),
        }
    }

    fn read_region_table(file: &mut File) -> Result<Vec<VhdxRegion>, String> {
        let mut errors = Vec::new();
        for (slot, offset) in REGION_TABLE_OFFSETS.iter().enumerate() {
            let mut buf = vec![0u8; REGION_TABLE_SIZE];
            match read_exact_at(file, *offset, &mut buf) {
                Ok(()) => match parse_region_table(&buf) {
                    Ok(regions) => {
                        if !errors.is_empty() {
                            warn!(
                                "VHDX: using region table {} only ({})",
                                slot + 1,
                                errors.join("; ")
                            );
                        }
                        return Ok(regions);
                    }
                    Err(error) => errors.push(format!("region table {}: {error}", slot + 1)),
                },
                Err(error) => errors.push(format!("region table {}: {error}", slot + 1)),
            }
        }
        Err(format!(
            "both VHDX region tables are invalid: {}",
            errors.join("; ")
        ))
    }

    /// Turn the parent locator entries into a path that exists.
    fn resolve_parent_path(
        locator: &VhdxParentLocator,
        base_dir: &Path,
    ) -> Result<PathBuf, String> {
        let mut candidates = Vec::new();
        if let Some(relative) = locator.get("relative_path") {
            let relative = relative.trim_start_matches(".\\").replace('\\', "/");
            let candidate = Path::new(&relative);
            candidates.push(if candidate.is_absolute() {
                candidate.to_path_buf()
            } else {
                base_dir.join(candidate)
            });
        }
        for key in ["absolute_win32_path", "volume_path"] {
            if let Some(value) = locator.get(key) {
                let cleaned = value
                    .trim_start_matches("\\\\?\\")
                    .trim_start_matches("\\??\\")
                    .replace('\\', "/");
                candidates.push(PathBuf::from(&cleaned));
                // A Windows path like C:/dir/x.vhdx is useless here, but the
                // file may sit next to the child under the same name.
                if let Some(name) = Path::new(&cleaned).file_name() {
                    candidates.push(base_dir.join(name));
                }
            }
        }
        for candidate in &candidates {
            if candidate.is_file() {
                return Ok(candidate.clone());
            }
        }
        let tried: Vec<String> = candidates.iter().map(|c| c.display().to_string()).collect();
        Err(format!(
            "cannot resolve VHDX parent: none of the locator paths exist ({})",
            if tried.is_empty() {
                "no path in the locator".to_owned()
            } else {
                tried.join(", ")
            }
        ))
    }

    fn bat_entry(&self, index: u64) -> u64 {
        self.bat.get(index as usize).copied().unwrap_or(0)
    }

    fn mapping(&self, block: u64) -> io::Result<BlockMapping> {
        let entry = self.bat_entry(block + block / self.chunk_ratio);
        let state = entry & BAT_STATE_MASK;
        let offset = entry & BAT_OFFSET_MASK;
        let check_offset = |offset: u64| -> io::Result<u64> {
            if offset < MIB {
                return Err(invalid_data(format!(
                    "VHDX BAT entry for block {block} points inside the header area ({offset:#x})"
                )));
            }
            Ok(offset)
        };
        match state {
            PAYLOAD_BLOCK_NOT_PRESENT => Ok(BlockMapping::NotPresent),
            PAYLOAD_BLOCK_UNDEFINED | PAYLOAD_BLOCK_ZERO | PAYLOAD_BLOCK_UNMAPPED => {
                Ok(BlockMapping::Zero)
            }
            PAYLOAD_BLOCK_FULLY_PRESENT => Ok(BlockMapping::Present(check_offset(offset)?)),
            PAYLOAD_BLOCK_PARTIALLY_PRESENT => Ok(BlockMapping::Partial(check_offset(offset)?)),
            other => Err(invalid_data(format!(
                "VHDX BAT entry for block {block} has reserved state {other}"
            ))),
        }
    }

    /// Fetch (and cache) the sector bitmap block of a chunk.
    fn sector_bitmap(&mut self, chunk: u64) -> io::Result<Arc<Vec<u8>>> {
        if let Some(bitmap) = self.bitmap_cache.get(&chunk) {
            return Ok(Arc::clone(bitmap));
        }
        let entry = self.bat_entry(chunk * (self.chunk_ratio + 1) + self.chunk_ratio);
        let state = entry & BAT_STATE_MASK;
        let offset = entry & BAT_OFFSET_MASK;
        if state != SB_BLOCK_PRESENT || offset < MIB {
            return Err(invalid_data(format!(
                "VHDX chunk {chunk} has a partially present block but no sector bitmap (entry state {state})"
            )));
        }
        let mut bitmap = vec![0u8; SECTOR_BITMAP_BLOCK_SIZE as usize];
        read_zero_padded_at(&mut self.file, offset, &mut bitmap)?;
        let bitmap = Arc::new(bitmap);
        if self.bitmap_cache.len() >= SECTOR_BITMAP_CACHE_BLOCKS {
            self.bitmap_cache.clear();
        }
        self.bitmap_cache.insert(chunk, Arc::clone(&bitmap));
        Ok(bitmap)
    }

    /// Read guest bytes `[pos, pos + buf.len())` that all fall inside one block.
    fn read_within_block(&mut self, pos: u64, buf: &mut [u8]) -> io::Result<()> {
        let block_size = self.parameters.block_size as u64;
        let block = pos / block_size;
        let in_block = pos % block_size;
        debug_assert!(in_block + buf.len() as u64 <= block_size);

        match self.mapping(block)? {
            BlockMapping::NotPresent => self.read_from_parent(pos, buf),
            BlockMapping::Zero => {
                buf.fill(0);
                Ok(())
            }
            BlockMapping::Present(offset) => {
                let read = read_zero_padded_at(&mut self.file, offset + in_block, buf)?;
                self.report_truncation(read, buf.len(), offset + in_block);
                Ok(())
            }
            BlockMapping::Partial(offset) => {
                let chunk = block / self.chunk_ratio;
                let bitmap = self.sector_bitmap(chunk)?;
                let sector = self.logical_sector_size as u64;
                let sectors_per_block = block_size / sector;
                let first_bit = (block % self.chunk_ratio) * sectors_per_block;
                let mut done = 0usize;
                while done < buf.len() {
                    let current = pos + done as u64;
                    let in_sector = current % sector;
                    let chunk_len = min((sector - in_sector) as usize, buf.len() - done);
                    let sector_index = (current % block_size) / sector;
                    let bit = first_bit + sector_index;
                    let present = bitmap[(bit / 8) as usize] & (1 << (bit % 8)) != 0;
                    let out = &mut buf[done..done + chunk_len];
                    if present {
                        let host = offset + (current % block_size);
                        let read = read_zero_padded_at(&mut self.file, host, out)?;
                        self.report_truncation(read, out.len(), host);
                    } else {
                        self.read_from_parent(current, out)?;
                    }
                    done += chunk_len;
                }
                Ok(())
            }
        }
    }

    /// A payload block that extends past the end of the file reads as zeroes
    /// (like QEMU); say so once, because it means the container is truncated.
    fn report_truncation(&mut self, read: usize, wanted: usize, host_offset: u64) {
        if read < wanted && !self.truncation_reported {
            self.truncation_reported = true;
            warn!(
                "VHDX container {} is truncated: only {read} of {wanted} bytes present at {host_offset:#x}; missing data reads as zeroes",
                self.path.display()
            );
        }
    }

    fn read_from_parent(&mut self, pos: u64, buf: &mut [u8]) -> io::Result<()> {
        match &mut self.parent {
            Some(parent) => {
                let len = parent.get_image_size();
                if pos >= len {
                    buf.fill(0);
                    return Ok(());
                }
                let available = min((len - pos) as usize, buf.len());
                let (head, tail) = buf.split_at_mut(available);
                parent.seek(SeekFrom::Start(pos))?;
                parent.read_exact(head)?;
                tail.fill(0);
                Ok(())
            }
            None => {
                buf.fill(0);
                Ok(())
            }
        }
    }

    pub fn get_sector_size(&self) -> u16 {
        self.logical_sector_size as u16
    }

    /// Virtual disk size in bytes.
    pub fn get_image_size(&self) -> u64 {
        self.disk_size
    }

    pub fn header(&self) -> &VhdxHeader {
        &self.header
    }

    pub fn parameters(&self) -> &VhdxFileParameters {
        &self.parameters
    }

    pub fn creator(&self) -> &str {
        &self.creator
    }

    pub fn virtual_disk_id(&self) -> &Guid {
        &self.virtual_disk_id
    }

    pub fn parent_locator(&self) -> Option<&VhdxParentLocator> {
        self.parent_locator.as_ref()
    }

    /// Canonical paths of the image and its whole parent chain.
    pub fn backing_paths(&self) -> Vec<PathBuf> {
        let mut paths = vec![self.path.clone()];
        if let Some(parent) = &self.parent {
            paths.extend(parent.backing_paths());
        }
        paths.sort();
        paths.dedup();
        paths
    }

    /// Count of payload blocks per BAT state.
    fn block_state_summary(&self) -> Vec<(u64, u64)> {
        let blocks = self.disk_size.div_ceil(self.parameters.block_size as u64);
        let mut counts: HashMap<u64, u64> = HashMap::new();
        for block in 0..blocks {
            let state = self.bat_entry(block + block / self.chunk_ratio) & BAT_STATE_MASK;
            *counts.entry(state).or_default() += 1;
        }
        let mut summary: Vec<(u64, u64)> = counts.into_iter().collect();
        summary.sort();
        summary
    }

    pub fn print_info(&self) {
        info!("VHDX Disk Information:");
        info!("  Creator: {}", self.creator);
        info!(
            "  Active header: slot {} (sequence {})",
            self.header.slot + 1,
            self.header.sequence_number
        );
        info!(
            "  File write GUID: {}",
            format_guid(&self.header.file_write_guid)
        );
        info!(
            "  Data write GUID: {}",
            format_guid(&self.header.data_write_guid)
        );
        info!(
            "  Log: offset {:#x}, length {} bytes, replay needed: {}",
            self.header.log_offset,
            self.header.log_length,
            self.header.log_needs_replay()
        );
        info!(
            "  Virtual size: {} bytes ({:.2} GiB)",
            self.disk_size,
            self.disk_size as f64 / (1u64 << 30) as f64
        );
        info!("  Virtual disk ID: {}", format_guid(&self.virtual_disk_id));
        info!("  Block size: {} bytes", self.parameters.block_size);
        info!(
            "  Logical / physical sector size: {} / {} bytes",
            self.logical_sector_size, self.physical_sector_size
        );
        let kind = match (
            self.parameters.has_parent,
            self.parameters.leave_blocks_allocated,
        ) {
            (true, _) => "differencing",
            (false, true) => "fixed",
            (false, false) => "dynamic",
        };
        info!("  Disk type: {kind}");
        for (state, count) in self.block_state_summary() {
            let name = match state {
                PAYLOAD_BLOCK_NOT_PRESENT => "not present",
                PAYLOAD_BLOCK_UNDEFINED => "undefined",
                PAYLOAD_BLOCK_ZERO => "zero",
                PAYLOAD_BLOCK_UNMAPPED => "unmapped",
                PAYLOAD_BLOCK_FULLY_PRESENT => "fully present",
                PAYLOAD_BLOCK_PARTIALLY_PRESENT => "partially present",
                _ => "reserved",
            };
            info!("    blocks {name}: {count}");
        }
        info!("  Regions: {}", self.regions.len());
        for region in &self.regions {
            let name = match region.guid {
                REGION_BAT => "BAT",
                REGION_METADATA => "metadata",
                _ => "unknown",
            };
            info!(
                "    - {} ({name}) at {:#x}, {} bytes{}",
                format_guid(&region.guid),
                region.file_offset,
                region.length,
                if region.required { ", required" } else { "" }
            );
        }
        let unknown_items: Vec<String> = self
            .metadata_entries
            .iter()
            .filter(|e| {
                ![
                    ITEM_FILE_PARAMETERS,
                    ITEM_VIRTUAL_DISK_SIZE,
                    ITEM_VIRTUAL_DISK_ID,
                    ITEM_LOGICAL_SECTOR_SIZE,
                    ITEM_PHYSICAL_SECTOR_SIZE,
                    ITEM_PARENT_LOCATOR,
                ]
                .contains(&e.item_id)
            })
            .map(|e| {
                format!(
                    "{}{}",
                    format_guid(&e.item_id),
                    if e.is_user { " (user)" } else { "" }
                )
            })
            .collect();
        if !unknown_items.is_empty() {
            info!("  Unknown metadata items: {}", unknown_items.join(", "));
        }
        match (&self.parent_locator, &self.parent) {
            (Some(locator), parent) => {
                info!("  Parent locator:");
                for (key, value) in &locator.entries {
                    info!("    {key} = {value}");
                }
                match parent {
                    Some(parent) => info!("  Parent resolved to: {}", parent.path.display()),
                    None => info!("  Parent: locator present but the disk has no parent flag"),
                }
            }
            (None, _) => info!("  Parent: none"),
        }
    }
}

impl Read for VHDX {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.disk_size;
        if self.position >= size || buf.is_empty() {
            return Ok(0);
        }
        let total = min(buf.len() as u64, size - self.position) as usize;
        let block_size = self.parameters.block_size as u64;

        let mut done = 0usize;
        while done < total {
            let pos = self.position + done as u64;
            let in_block = pos % block_size;
            let chunk = min((block_size - in_block) as usize, total - done);
            self.read_within_block(pos, &mut buf[done..done + chunk])?;
            done += chunk;
        }
        self.position += done as u64;
        Ok(done)
    }
}

impl Seek for VHDX {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let size = self.disk_size;
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
                "seek position is outside the VHDX virtual disk",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const TEST_DATA_WRITE_GUID: Guid = guid(0x1111_2222, 0x3333, 0x4444, 0x5555, 0x6666_7777_8888);

    /// Builds synthetic VHDX files: identifier at 0, headers at 64/128 KiB,
    /// region tables at 192/256 KiB, log at 1 MiB, BAT at 2 MiB, metadata at
    /// 3 MiB, payload and bitmap blocks from 4 MiB.
    struct VhdxBuilder {
        block_size: u32,
        disk_size: u64,
        logical_sector_size: u32,
        has_parent: bool,
        leave_blocks_allocated: bool,
        parent_locator: Vec<(String, String)>,
        locator_type: Guid,
        data_write_guid: Guid,
        log_guid: Guid,
        header_sequences: [u64; 2],
        corrupt_header: [bool; 2],
        corrupt_region_table: [bool; 2],
        extra_region: Option<(Guid, bool)>,
        extra_metadata: Option<(Guid, bool)>,
        bat_region_mib: u32,
        bat: Vec<u64>,
        data: Vec<u8>,
        data_start: u64,
    }

    impl VhdxBuilder {
        fn new(block_size: u32, disk_size: u64) -> Self {
            let bat_region_mib = 1;
            let data_start = 4 * MIB + (bat_region_mib as u64 - 1) * MIB;
            Self {
                block_size,
                disk_size,
                logical_sector_size: 512,
                has_parent: false,
                leave_blocks_allocated: false,
                parent_locator: Vec::new(),
                locator_type: PARENT_LOCATOR_TYPE_VHDX,
                data_write_guid: TEST_DATA_WRITE_GUID,
                log_guid: [0u8; 16],
                header_sequences: [1, 2],
                corrupt_header: [false, false],
                corrupt_region_table: [false, false],
                extra_region: None,
                extra_metadata: None,
                bat_region_mib,
                bat: Vec::new(),
                data: Vec::new(),
                data_start,
            }
        }

        fn chunk_ratio(&self) -> u64 {
            ((1u64 << 23) * self.logical_sector_size as u64) / self.block_size as u64
        }

        fn payload_index(&self, block: u64) -> usize {
            (block + block / self.chunk_ratio()) as usize
        }

        fn bitmap_index(&self, chunk: u64) -> usize {
            (chunk * (self.chunk_ratio() + 1) + self.chunk_ratio()) as usize
        }

        fn set_entry(&mut self, index: usize, value: u64) {
            if self.bat.len() <= index {
                self.bat.resize(index + 1, 0);
            }
            self.bat[index] = value;
        }

        /// Reserve a MiB-aligned block of `size` bytes holding `data` at its
        /// start and return its file offset.
        fn append(&mut self, data: &[u8], size: u64) -> u64 {
            assert!(data.len() as u64 <= size);
            let relative = self.data.len() as u64;
            let offset = self.data_start + relative;
            self.data.extend_from_slice(data);
            let end = (relative + size).div_ceil(MIB) * MIB;
            self.data.resize(end as usize, 0);
            offset
        }

        fn with_parent(mut self, relative_path: &str, linkage: &Guid) -> Self {
            self.has_parent = true;
            self.parent_locator = vec![
                (
                    "parent_linkage".to_owned(),
                    format!("{{{}}}", format_guid(linkage)),
                ),
                ("relative_path".to_owned(), relative_path.replace('/', "\\")),
                (
                    "absolute_win32_path".to_owned(),
                    format!("\\\\?\\C:\\images\\{}", relative_path.replace('/', "\\")),
                ),
                (
                    "volume_path".to_owned(),
                    "\\\\?\\Volume{deadbeef-0000-0000-0000-000000000000}\\images\\x.vhdx"
                        .to_owned(),
                ),
            ];
            self
        }

        fn set_full(&mut self, block: u64, data: &[u8]) {
            let offset = self.append(data, self.block_size as u64);
            let index = self.payload_index(block);
            self.set_entry(index, offset | PAYLOAD_BLOCK_FULLY_PRESENT);
        }

        fn set_state(&mut self, block: u64, state: u64) {
            let index = self.payload_index(block);
            self.set_entry(index, state);
        }

        /// Partially present block: `present_sectors` are the sector indexes
        /// (inside the block) stored in this file.
        fn set_partial(&mut self, block: u64, data: &[u8], present_sectors: &[u64]) {
            let offset = self.append(data, self.block_size as u64);
            let index = self.payload_index(block);
            self.set_entry(index, offset | PAYLOAD_BLOCK_PARTIALLY_PRESENT);

            let chunk = block / self.chunk_ratio();
            let bitmap_index = self.bitmap_index(chunk);
            let existing = self.bat.get(bitmap_index).copied().unwrap_or(0);
            let bitmap_offset = if existing & BAT_STATE_MASK == SB_BLOCK_PRESENT {
                existing & BAT_OFFSET_MASK
            } else {
                let offset = self.append(&[], SECTOR_BITMAP_BLOCK_SIZE);
                self.set_entry(bitmap_index, offset | SB_BLOCK_PRESENT);
                offset
            };
            let sectors_per_block = self.block_size as u64 / self.logical_sector_size as u64;
            let first_bit = (block % self.chunk_ratio()) * sectors_per_block;
            for sector in present_sectors {
                let bit = first_bit + sector;
                let byte = (bitmap_offset - self.data_start + bit / 8) as usize;
                self.data[byte] |= 1 << (bit % 8);
            }
        }

        fn header_bytes(&self, slot: usize) -> Vec<u8> {
            let mut h = vec![0u8; HEADER_SIZE];
            h[0..4].copy_from_slice(HEADER_SIGNATURE);
            h[8..16].copy_from_slice(&self.header_sequences[slot].to_le_bytes());
            h[16..32].copy_from_slice(&guid(0xaaaa_bbbb, 0xcccc, 0xdddd, 0xeeee, 0xffff_0000_1111));
            h[32..48].copy_from_slice(&self.data_write_guid);
            h[48..64].copy_from_slice(&self.log_guid);
            h[64..66].copy_from_slice(&0u16.to_le_bytes());
            h[66..68].copy_from_slice(&1u16.to_le_bytes());
            h[68..72].copy_from_slice(&(MIB as u32).to_le_bytes());
            h[72..80].copy_from_slice(&MIB.to_le_bytes());
            let crc = crc32c(&h);
            h[4..8].copy_from_slice(&crc.to_le_bytes());
            if self.corrupt_header[slot] {
                h[100] ^= 0xff;
            }
            h
        }

        fn region_table_bytes(&self, slot: usize) -> Vec<u8> {
            let mut t = vec![0u8; REGION_TABLE_SIZE];
            t[0..4].copy_from_slice(REGION_TABLE_SIGNATURE);
            let mut entries: Vec<(Guid, u64, u32, bool)> = vec![
                (REGION_BAT, 2 * MIB, self.bat_region_mib * MIB as u32, true),
                (
                    REGION_METADATA,
                    3 * MIB + (self.bat_region_mib as u64 - 1) * MIB,
                    MIB as u32,
                    true,
                ),
            ];
            if let Some((guid, required)) = self.extra_region {
                let offset = self.data_start + self.data.len() as u64;
                entries.push((guid, offset, MIB as u32, required));
            }
            t[8..12].copy_from_slice(&(entries.len() as u32).to_le_bytes());
            for (i, (guid, offset, length, required)) in entries.iter().enumerate() {
                let base = 16 + i * REGION_ENTRY_SIZE;
                t[base..base + 16].copy_from_slice(guid);
                t[base + 16..base + 24].copy_from_slice(&offset.to_le_bytes());
                t[base + 24..base + 28].copy_from_slice(&length.to_le_bytes());
                t[base + 28..base + 32].copy_from_slice(&(*required as u32).to_le_bytes());
            }
            let crc = crc32c(&t);
            t[4..8].copy_from_slice(&crc.to_le_bytes());
            if self.corrupt_region_table[slot] {
                t[20] ^= 0x01;
            }
            t
        }

        fn metadata_region_bytes(&self) -> Vec<u8> {
            let mut region = vec![0u8; MIB as usize];
            region[0..8].copy_from_slice(METADATA_TABLE_SIGNATURE);
            let mut items: Vec<(Guid, Vec<u8>, u32)> = Vec::new();
            let mut flags = 0u32;
            if self.leave_blocks_allocated {
                flags |= FILE_PARAMETERS_LEAVE_BLOCKS_ALLOCATED;
            }
            if self.has_parent {
                flags |= FILE_PARAMETERS_HAS_PARENT;
            }
            let mut params = Vec::new();
            params.extend_from_slice(&self.block_size.to_le_bytes());
            params.extend_from_slice(&flags.to_le_bytes());
            items.push((ITEM_FILE_PARAMETERS, params, METADATA_FLAG_IS_REQUIRED));
            items.push((
                ITEM_VIRTUAL_DISK_SIZE,
                self.disk_size.to_le_bytes().to_vec(),
                METADATA_FLAG_IS_REQUIRED | METADATA_FLAG_IS_VIRTUAL_DISK,
            ));
            items.push((
                ITEM_VIRTUAL_DISK_ID,
                guid(0x0bad_cafe, 0x0001, 0x0002, 0x0003, 0x0000_0000_0004).to_vec(),
                METADATA_FLAG_IS_REQUIRED | METADATA_FLAG_IS_VIRTUAL_DISK,
            ));
            items.push((
                ITEM_LOGICAL_SECTOR_SIZE,
                self.logical_sector_size.to_le_bytes().to_vec(),
                METADATA_FLAG_IS_REQUIRED | METADATA_FLAG_IS_VIRTUAL_DISK,
            ));
            items.push((
                ITEM_PHYSICAL_SECTOR_SIZE,
                4096u32.to_le_bytes().to_vec(),
                METADATA_FLAG_IS_REQUIRED | METADATA_FLAG_IS_VIRTUAL_DISK,
            ));
            if !self.parent_locator.is_empty() {
                let mut item = Vec::new();
                item.extend_from_slice(&self.locator_type);
                item.extend_from_slice(&0u16.to_le_bytes());
                item.extend_from_slice(&(self.parent_locator.len() as u16).to_le_bytes());
                let table_len = 20 + 12 * self.parent_locator.len();
                let mut strings = Vec::new();
                let mut table = Vec::new();
                for (key, value) in &self.parent_locator {
                    let k: Vec<u8> = key.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
                    let v: Vec<u8> = value.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
                    let key_offset = table_len + strings.len();
                    strings.extend_from_slice(&k);
                    let value_offset = table_len + strings.len();
                    strings.extend_from_slice(&v);
                    table.extend_from_slice(&(key_offset as u32).to_le_bytes());
                    table.extend_from_slice(&(value_offset as u32).to_le_bytes());
                    table.extend_from_slice(&(k.len() as u16).to_le_bytes());
                    table.extend_from_slice(&(v.len() as u16).to_le_bytes());
                }
                item.extend_from_slice(&table);
                item.extend_from_slice(&strings);
                items.push((
                    ITEM_PARENT_LOCATOR,
                    item,
                    METADATA_FLAG_IS_REQUIRED | METADATA_FLAG_IS_VIRTUAL_DISK,
                ));
            }
            if let Some((guid, required)) = self.extra_metadata {
                let flags = METADATA_FLAG_IS_USER
                    | if required {
                        METADATA_FLAG_IS_REQUIRED
                    } else {
                        0
                    };
                items.push((guid, vec![0x42; 16], flags));
            }
            region[10..12].copy_from_slice(&(items.len() as u16).to_le_bytes());
            let mut cursor = METADATA_TABLE_SIZE;
            for (i, (id, payload, flags)) in items.iter().enumerate() {
                let base = 32 + i * METADATA_ENTRY_SIZE;
                region[base..base + 16].copy_from_slice(id);
                region[base + 16..base + 20].copy_from_slice(&(cursor as u32).to_le_bytes());
                region[base + 20..base + 24].copy_from_slice(&(payload.len() as u32).to_le_bytes());
                region[base + 24..base + 28].copy_from_slice(&flags.to_le_bytes());
                region[cursor..cursor + payload.len()].copy_from_slice(payload);
                cursor = (cursor + payload.len()).div_ceil(8) * 8;
            }
            region
        }

        fn bytes(&self) -> Vec<u8> {
            let mut file = vec![0u8; self.data_start as usize];
            file[0..8].copy_from_slice(FILE_TYPE_SIGNATURE);
            let creator: Vec<u8> = "exhume synthetic"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect();
            file[8..8 + creator.len()].copy_from_slice(&creator);
            for slot in 0..2 {
                let o = HEADER_OFFSETS[slot] as usize;
                file[o..o + HEADER_SIZE].copy_from_slice(&self.header_bytes(slot));
                let o = REGION_TABLE_OFFSETS[slot] as usize;
                file[o..o + REGION_TABLE_SIZE].copy_from_slice(&self.region_table_bytes(slot));
            }
            let bat_start = (2 * MIB) as usize;
            for (i, entry) in self.bat.iter().enumerate() {
                let o = bat_start + i * 8;
                assert!(
                    o + 8 <= bat_start + (self.bat_region_mib as usize) * MIB as usize,
                    "BAT overflows its region"
                );
                file[o..o + 8].copy_from_slice(&entry.to_le_bytes());
            }
            let meta_start = (3 * MIB + (self.bat_region_mib as u64 - 1) * MIB) as usize;
            file[meta_start..meta_start + MIB as usize]
                .copy_from_slice(&self.metadata_region_bytes());
            file.extend_from_slice(&self.data);
            if self.extra_region.is_some() {
                file.resize(file.len() + MIB as usize, 0);
            }
            file
        }

        fn write(&self, dir: &Path, name: &str) -> PathBuf {
            let path = dir.join(name);
            fs::write(&path, self.bytes()).unwrap();
            path
        }
    }

    fn pattern(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| seed.wrapping_add((i % 251) as u8))
            .collect()
    }

    fn read_all(image: &mut VHDX) -> Vec<u8> {
        image.seek(SeekFrom::Start(0)).unwrap();
        let mut out = Vec::new();
        image.read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn crc32c_matches_known_vectors() {
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8a91_36aa);
    }

    #[test]
    fn guid_layout_and_formatting() {
        assert_eq!(
            format_guid(&REGION_BAT),
            "2dc27766-f623-4200-9d64-115e9bfd4a08"
        );
        // Bytes as they appear on disk in a qemu-img file.
        assert_eq!(
            REGION_BAT,
            [
                0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0x00, 0x42, 0x9d, 0x64, 0x11, 0x5e, 0x9b, 0xfd,
                0x4a, 0x08
            ]
        );
        assert_eq!(
            format_guid(&ITEM_FILE_PARAMETERS),
            "caa16737-fa36-4d43-b3b6-33f0aa44e76b"
        );
    }

    #[test]
    fn reads_dynamic_disk_block_states() {
        let dir = tempfile::tempdir().unwrap();
        let block = MIB as usize;
        let mut b = VhdxBuilder::new(block as u32, 6 * MIB + 512);
        let a = pattern(1, block);
        let f = pattern(6, block);
        b.set_full(0, &a);
        // block 1: not present -> zeros (no parent)
        b.set_state(2, PAYLOAD_BLOCK_UNDEFINED);
        b.set_state(3, PAYLOAD_BLOCK_ZERO);
        b.set_state(4, PAYLOAD_BLOCK_UNMAPPED);
        b.set_full(5, &f);
        b.set_full(6, &pattern(7, 512));
        let path = b.write(dir.path(), "dyn.vhdx");

        let mut image = VHDX::new(path.to_str().unwrap()).unwrap();
        assert_eq!(image.get_image_size(), 6 * MIB + 512);
        assert_eq!(image.get_sector_size(), 512);
        assert_eq!(image.creator(), "exhume synthetic");
        assert_eq!(
            image.header().slot,
            1,
            "header 2 has the higher sequence number"
        );
        assert!(!image.parameters().has_parent);

        let mut expected = Vec::new();
        expected.extend_from_slice(&a);
        expected.extend(std::iter::repeat_n(0u8, 4 * block));
        expected.extend_from_slice(&f);
        expected.extend_from_slice(&pattern(7, 512));
        assert_eq!(read_all(&mut image), expected);

        // Read crossing several blocks from an odd offset.
        let start = block as u64 - 100;
        image.seek(SeekFrom::Start(start)).unwrap();
        let mut buf = vec![0u8; 4 * block + 300];
        image.read_exact(&mut buf).unwrap();
        assert_eq!(buf, expected[start as usize..start as usize + buf.len()]);

        assert_eq!(image.seek(SeekFrom::End(-512)).unwrap(), 6 * MIB);
        let mut tail = Vec::new();
        assert_eq!(image.read_to_end(&mut tail).unwrap(), 512);
        assert!(image.seek(SeekFrom::End(1)).is_err());
        assert_eq!(image.backing_paths(), vec![path.canonicalize().unwrap()]);
    }

    #[test]
    fn header_with_highest_sequence_wins_and_corrupt_headers_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = VhdxBuilder::new(MIB as u32, MIB);
        b.set_full(0, &pattern(1, 10));
        b.header_sequences = [9, 3];
        let path = b.write(dir.path(), "seq.vhdx");
        assert_eq!(VHDX::new(path.to_str().unwrap()).unwrap().header().slot, 0);

        b.corrupt_header = [true, false];
        let path = b.write(dir.path(), "h1bad.vhdx");
        let image = VHDX::new(path.to_str().unwrap()).unwrap();
        assert_eq!(image.header().slot, 1);
        assert_eq!(image.header().sequence_number, 3);

        b.corrupt_header = [true, true];
        let path = b.write(dir.path(), "bothbad.vhdx");
        let error = VHDX::new(path.to_str().unwrap()).unwrap_err();
        assert!(error.contains("both VHDX headers are invalid"), "{error}");
        assert!(error.contains("checksum mismatch"), "{error}");

        b.corrupt_header = [false, false];
        b.corrupt_region_table = [true, false];
        let path = b.write(dir.path(), "rt1bad.vhdx");
        assert!(VHDX::new(path.to_str().unwrap()).is_ok());
        b.corrupt_region_table = [true, true];
        let path = b.write(dir.path(), "rtbothbad.vhdx");
        let error = VHDX::new(path.to_str().unwrap()).unwrap_err();
        assert!(
            error.contains("both VHDX region tables are invalid"),
            "{error}"
        );
    }

    #[test]
    fn pending_log_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = VhdxBuilder::new(MIB as u32, MIB);
        b.log_guid = guid(1, 2, 3, 4, 5);
        let path = b.write(dir.path(), "log.vhdx");
        let error = VHDX::new(path.to_str().unwrap()).unwrap_err();
        assert!(error.contains("log must be replayed"), "{error}");
        assert!(
            error.contains("00000001-0002-0003-0004-000000000005"),
            "{error}"
        );
    }

    #[test]
    fn unknown_required_region_or_item_is_refused_but_optional_ones_are_listed() {
        let dir = tempfile::tempdir().unwrap();
        let unknown = guid(0xdead_beef, 1, 2, 3, 4);

        let mut b = VhdxBuilder::new(MIB as u32, MIB);
        b.extra_region = Some((unknown, true));
        let path = b.write(dir.path(), "req_region.vhdx");
        let error = VHDX::new(path.to_str().unwrap()).unwrap_err();
        assert!(
            error.contains("unknown required region deadbeef-0001-0002-0003-000000000004"),
            "{error}"
        );

        b.extra_region = Some((unknown, false));
        let path = b.write(dir.path(), "opt_region.vhdx");
        let image = VHDX::new(path.to_str().unwrap()).unwrap();
        assert_eq!(image.regions.len(), 3);
        image.print_info();

        let mut b = VhdxBuilder::new(MIB as u32, MIB);
        b.extra_metadata = Some((unknown, true));
        let path = b.write(dir.path(), "req_item.vhdx");
        let error = VHDX::new(path.to_str().unwrap()).unwrap_err();
        assert!(error.contains("unknown required metadata item"), "{error}");

        b.extra_metadata = Some((unknown, false));
        let path = b.write(dir.path(), "opt_item.vhdx");
        assert_eq!(
            VHDX::new(path.to_str().unwrap())
                .unwrap()
                .metadata_entries
                .len(),
            6
        );
    }

    #[test]
    fn invalid_parameters_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        for (block_size, disk_size, needle) in [
            (3 * MIB as u32, MIB, "power of two"),
            (512 * 1024, MIB, "power of two"),
            (MIB as u32, 0, "positive multiple"),
            (MIB as u32, MIB + 100, "positive multiple"),
        ] {
            let b = VhdxBuilder::new(block_size, disk_size);
            let path = b.write(dir.path(), "bad.vhdx");
            let error = VHDX::new(path.to_str().unwrap()).unwrap_err();
            assert!(error.contains(needle), "{block_size}/{disk_size}: {error}");
        }
        let mut b = VhdxBuilder::new(MIB as u32, MIB);
        b.logical_sector_size = 1024;
        let path = b.write(dir.path(), "sector.vhdx");
        assert!(VHDX::new(path.to_str().unwrap())
            .unwrap_err()
            .contains("neither 512 nor 4096"));

        // BAT region too small for the disk.
        let b = VhdxBuilder::new(MIB as u32, 200 * 1024 * MIB);
        let path = b.write(dir.path(), "smallbat.vhdx");
        let error = VHDX::new(path.to_str().unwrap()).unwrap_err();
        assert!(error.contains("BAT region holds"), "{error}");

        let mut not = vec![0u8; 1024];
        not[..8].copy_from_slice(b"vhdxfilx");
        fs::write(dir.path().join("not.vhdx"), &not).unwrap();
        let error = VHDX::new(dir.path().join("not.vhdx").to_str().unwrap()).unwrap_err();
        assert!(error.contains("signature"), "{error}");
        fs::write(dir.path().join("tiny.vhdx"), b"vhdxfile").unwrap();
        assert!(VHDX::new(dir.path().join("tiny.vhdx").to_str().unwrap()).is_err());
    }

    #[test]
    fn bat_entry_in_header_area_or_reserved_state_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = VhdxBuilder::new(MIB as u32, 2 * MIB);
        let index = b.payload_index(0);
        b.set_entry(index, (512 * 1024) | PAYLOAD_BLOCK_FULLY_PRESENT);
        b.set_state(1, 5);
        let path = b.write(dir.path(), "badbat.vhdx");
        let mut image = VHDX::new(path.to_str().unwrap()).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(
            image.read_exact(&mut buf).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        image.seek(SeekFrom::Start(MIB)).unwrap();
        let error = image.read_exact(&mut buf).unwrap_err();
        assert!(error.to_string().contains("reserved state 5"), "{error}");
    }

    #[test]
    fn differencing_disk_reads_through_parent_and_sector_bitmap() {
        let dir = tempfile::tempdir().unwrap();
        let block = MIB as usize;
        let mut parent = VhdxBuilder::new(block as u32, 4 * MIB);
        let p0 = pattern(0x10, block);
        let p1 = pattern(0x11, block);
        let p2 = pattern(0x12, block);
        parent.set_full(0, &p0);
        parent.set_full(1, &p1);
        parent.set_full(2, &p2);
        // block 3 of the parent not present -> zeros
        parent.write(dir.path(), "parent.vhdx");

        let mut child = VhdxBuilder::new(block as u32, 4 * MIB)
            .with_parent("parent.vhdx", &TEST_DATA_WRITE_GUID);
        let c1 = pattern(0xc1, block);
        let c2 = pattern(0xc2, block);
        child.set_full(1, &c1);
        // block 2: sectors 0, 1 and 100 from the child, the rest from the parent.
        child.set_partial(2, &c2, &[0, 1, 100]);
        child.set_state(3, PAYLOAD_BLOCK_ZERO);
        let path = child.write(dir.path(), "child.vhdx");

        let mut image = VHDX::new(path.to_str().unwrap()).unwrap();
        assert!(image.parameters().has_parent);
        assert_eq!(
            image.parent_locator().unwrap().get("RELATIVE_PATH"),
            Some("parent.vhdx")
        );
        assert_eq!(image.backing_paths().len(), 2);

        let mut expected = Vec::new();
        expected.extend_from_slice(&p0);
        expected.extend_from_slice(&c1);
        let mut mixed = p2.clone();
        for sector in [0usize, 1, 100] {
            mixed[sector * 512..(sector + 1) * 512]
                .copy_from_slice(&c2[sector * 512..(sector + 1) * 512]);
        }
        expected.extend_from_slice(&mixed);
        expected.extend(std::iter::repeat_n(0u8, block));
        assert_eq!(read_all(&mut image), expected);

        // A read straddling a present/absent sector boundary inside the partial block.
        image.seek(SeekFrom::Start(2 * MIB + 2 * 512 - 7)).unwrap();
        let mut window = [0u8; 14];
        image.read_exact(&mut window).unwrap();
        assert_eq!(window, expected[2 * block + 1017..2 * block + 1031]);
        image.print_info();
    }

    #[test]
    fn differencing_disk_without_reachable_parent_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let child =
            VhdxBuilder::new(MIB as u32, MIB).with_parent("gone.vhdx", &TEST_DATA_WRITE_GUID);
        let path = child.write(dir.path(), "orphan.vhdx");
        let error = VHDX::new(path.to_str().unwrap()).unwrap_err();
        assert!(
            error.contains("cannot resolve VHDX parent") && error.contains("gone.vhdx"),
            "{error}"
        );

        // Loop: a disk that names itself as parent.
        let selfish =
            VhdxBuilder::new(MIB as u32, MIB).with_parent("selfish.vhdx", &TEST_DATA_WRITE_GUID);
        let path = selfish.write(dir.path(), "selfish.vhdx");
        let error = VHDX::new(path.to_str().unwrap()).unwrap_err();
        assert!(error.contains("loops back"), "{error}");

        // Partially present block but no sector bitmap -> read error, not panic.
        VhdxBuilder::new(MIB as u32, MIB).write(dir.path(), "p.vhdx");
        let mut bad =
            VhdxBuilder::new(MIB as u32, MIB).with_parent("p.vhdx", &TEST_DATA_WRITE_GUID);
        let offset = bad.append(&pattern(1, 512), MIB);
        let index = bad.payload_index(0);
        bad.set_entry(index, offset | PAYLOAD_BLOCK_PARTIALLY_PRESENT);
        let path = bad.write(dir.path(), "nobitmap.vhdx");
        let mut image = VHDX::new(path.to_str().unwrap()).unwrap();
        let mut buf = [0u8; 16];
        let error = image.read_exact(&mut buf).unwrap_err();
        assert!(error.to_string().contains("no sector bitmap"), "{error}");
    }

    #[test]
    fn parent_found_through_absolute_path_file_name_fallback() {
        let dir = tempfile::tempdir().unwrap();
        VhdxBuilder::new(MIB as u32, MIB).write(dir.path(), "base.vhdx");
        let mut child =
            VhdxBuilder::new(MIB as u32, MIB).with_parent("base.vhdx", &TEST_DATA_WRITE_GUID);
        // Only a Windows absolute path, as a Hyper-V host would record it.
        child
            .parent_locator
            .retain(|(k, _)| k == "parent_linkage" || k == "absolute_win32_path");
        let path = child.write(dir.path(), "child.vhdx");
        let image = VHDX::new(path.to_str().unwrap()).unwrap();
        assert_eq!(image.backing_paths().len(), 2);
    }

    #[test]
    fn multiple_chunks_use_interleaved_bitmap_entries() {
        // 1 MiB blocks and 512-byte sectors: 4096 blocks per chunk, so a
        // 5 GiB disk spans two chunks. The file stays small (sparse BAT).
        let dir = tempfile::tempdir().unwrap();
        let block = MIB as usize;
        let mut parent = VhdxBuilder::new(block as u32, 5 * 1024 * MIB);
        let p = pattern(0x33, block);
        parent.set_full(4100, &p);
        parent.write(dir.path(), "bigparent.vhdx");
        let mut child = VhdxBuilder::new(block as u32, 5 * 1024 * MIB)
            .with_parent("bigparent.vhdx", &TEST_DATA_WRITE_GUID);
        let c = pattern(0x44, block);
        child.set_partial(4100, &c, &[5]);
        child.set_full(4095, &pattern(0x55, block));
        child.set_full(4096, &pattern(0x66, block));
        let path = child.write(dir.path(), "bigchild.vhdx");

        let mut image = VHDX::new(path.to_str().unwrap()).unwrap();
        assert_eq!(image.chunk_ratio, 4096);
        let mut buf = vec![0u8; block];
        image.seek(SeekFrom::Start(4100 * MIB)).unwrap();
        image.read_exact(&mut buf).unwrap();
        let mut expected = p.clone();
        expected[5 * 512..6 * 512].copy_from_slice(&c[5 * 512..6 * 512]);
        assert_eq!(buf, expected);
        image.seek(SeekFrom::Start(4095 * MIB + 10)).unwrap();
        let mut two = vec![0u8; 2 * block - 20];
        image.read_exact(&mut two).unwrap();
        assert_eq!(&two[..block - 10], &pattern(0x55, block)[10..]);
        assert_eq!(&two[block - 10..], &pattern(0x66, block)[..block - 10]);
        // Unallocated area in the second chunk reads as zeros from both levels.
        image.seek(SeekFrom::Start(4500 * MIB)).unwrap();
        image.read_exact(&mut buf).unwrap();
        assert!(buf.iter().all(|b| *b == 0));
    }

    #[test]
    fn fixed_disk_and_4k_sectors() {
        let dir = tempfile::tempdir().unwrap();
        let block = MIB as usize;
        let mut b = VhdxBuilder::new(block as u32, 2 * MIB);
        b.leave_blocks_allocated = true;
        b.logical_sector_size = 4096;
        b.set_full(0, &pattern(1, block));
        b.set_full(1, &pattern(2, block));
        let path = b.write(dir.path(), "fixed.vhdx");
        let mut image = VHDX::new(path.to_str().unwrap()).unwrap();
        assert_eq!(image.get_sector_size(), 4096);
        assert_eq!(image.chunk_ratio, 32768);
        let mut expected = pattern(1, block);
        expected.extend_from_slice(&pattern(2, block));
        assert_eq!(read_all(&mut image), expected);
        image.print_info();
    }

    #[test]
    fn cloned_image_keeps_an_independent_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let block = MIB as usize;
        let mut b = VhdxBuilder::new(block as u32, 2 * MIB);
        let a = pattern(0xa1, block);
        let c = pattern(0xb2, block);
        b.set_full(0, &a);
        b.set_full(1, &c);
        let path = b.write(dir.path(), "clone.vhdx");
        let mut original = VHDX::new(path.to_str().unwrap()).unwrap();
        original.seek(SeekFrom::Start(MIB)).unwrap();
        let mut cloned = original.clone();
        cloned.seek(SeekFrom::Start(0)).unwrap();
        let mut from_original = [0u8; 8];
        let mut from_clone = [0u8; 8];
        original.read_exact(&mut from_original).unwrap();
        cloned.read_exact(&mut from_clone).unwrap();
        assert_eq!(from_original, c[..8]);
        assert_eq!(from_clone, a[..8]);
        assert_eq!(original.position, MIB + 8);
        assert_eq!(cloned.position, 8);
    }

    #[test]
    fn body_autodetects_vhdx_and_reports_open_errors() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = VhdxBuilder::new(MIB as u32, 2 * MIB);
        b.set_full(1, &pattern(0x42, 4096));
        let path = b.write(dir.path(), "auto.vhdx");
        let mut body = crate::Body::try_new(path.to_string_lossy().into_owned(), "auto").unwrap();
        assert!(matches!(body.format, crate::BodyFormat::VHDX { .. }));
        assert_eq!(body.get_image_size(), 2 * MIB);
        body.seek(SeekFrom::Start(MIB)).unwrap();
        let mut buf = [0u8; 4];
        body.read_exact(&mut buf).unwrap();
        assert_eq!(buf, pattern(0x42, 4)[..]);
        let explicit = crate::Body::try_new(path.to_string_lossy().into_owned(), "vhdx").unwrap();
        assert_eq!(
            explicit.format_description(),
            "VHDX (Hyper-V Virtual Hard Disk v2) image"
        );

        let orphan =
            VhdxBuilder::new(MIB as u32, MIB).with_parent("missing.vhdx", &TEST_DATA_WRITE_GUID);
        let path = orphan.write(dir.path(), "orphan.vhdx");
        let error = match crate::Body::try_new(path.to_string_lossy().into_owned(), "auto") {
            Ok(_) => panic!("an orphan VHDX must not open as RAW"),
            Err(error) => error,
        };
        assert!(
            error.contains("VHDX") && error.contains("missing.vhdx"),
            "{error}"
        );
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

    fn exercise(path: &Path) -> bool {
        match VHDX::new(path.to_str().unwrap()) {
            Ok(mut image) => {
                let mut sink = vec![0u8; 1 << 16];
                let mut total = 0u64;
                loop {
                    match image.read(&mut sink) {
                        Ok(0) => break,
                        Ok(n) => total += n as u64,
                        Err(_) => break,
                    }
                    if total > (64 << 20) {
                        break;
                    }
                }
                let _ = image.seek(SeekFrom::End(0));
                image.print_info();
                let _ = image.backing_paths();
                let _ = image.clone();
                true
            }
            Err(_) => false,
        }
    }

    /// Mutates the metadata area (first 4 MiB) and the whole file; returns
    /// how many mutants still opened.
    fn mutate_and_exercise(original: &[u8], dir: &Path, seed: u64, rounds: usize) -> usize {
        let mut rng = Lcg(seed);
        let mut opened = 0;
        let target = dir.join("mutant.vhdx");
        let meta_span = original.len().min(4 * MIB as usize);
        for round in 0..rounds {
            let mut mutant = original.to_vec();
            match round % 4 {
                0 => {
                    let len = rng.below(original.len() as u64) as usize;
                    mutant.truncate(len);
                }
                1 => {
                    let count = 1 + rng.below(8) as usize;
                    for _ in 0..count {
                        let at = rng.below(meta_span as u64) as usize;
                        mutant[at] = rng.next() as u8;
                    }
                }
                2 => {
                    // Overwrite an aligned 8-byte word in a BAT or table and
                    // fix the header/region checksums so the change is "valid".
                    let at = rng.below(meta_span as u64 / 8) as usize * 8;
                    let word = match rng.below(4) {
                        0 => u64::MAX,
                        1 => rng.next(),
                        2 => 1u64 << rng.below(64),
                        _ => {
                            (rng.below(original.len() as u64 * 2) & BAT_OFFSET_MASK) | rng.below(8)
                        }
                    };
                    mutant[at..at + 8].copy_from_slice(&word.to_le_bytes());
                    for offset in HEADER_OFFSETS {
                        let o = offset as usize;
                        let crc = crc32c_with_zeroed_field(&mutant[o..o + HEADER_SIZE], 4);
                        mutant[o + 4..o + 8].copy_from_slice(&crc.to_le_bytes());
                    }
                    for offset in REGION_TABLE_OFFSETS {
                        let o = offset as usize;
                        let crc = crc32c_with_zeroed_field(&mutant[o..o + REGION_TABLE_SIZE], 4);
                        mutant[o + 4..o + 8].copy_from_slice(&crc.to_le_bytes());
                    }
                }
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
        let block = MIB as usize;
        let mut parent = VhdxBuilder::new(block as u32, 3 * MIB);
        parent.set_full(0, &pattern(1, block));
        parent.write(dir.path(), "parent.vhdx");
        let mut child = VhdxBuilder::new(block as u32, 3 * MIB)
            .with_parent("parent.vhdx", &TEST_DATA_WRITE_GUID);
        child.set_full(1, &pattern(2, block));
        child.set_partial(2, &pattern(3, block), &[1, 2, 3]);
        let child = child.bytes();
        let mut plain = VhdxBuilder::new(block as u32, 4 * MIB);
        plain.set_full(0, &pattern(4, block));
        plain.set_state(1, PAYLOAD_BLOCK_ZERO);
        plain.set_full(3, &pattern(5, block));
        let plain = plain.bytes();

        let mut opened = 0;
        for (seed, image) in [(1u64, &plain), (2, &child)] {
            opened += mutate_and_exercise(image, dir.path(), seed, 300);
        }
        assert!(opened > 50, "only {opened} mutants opened");
    }

    /// End-to-end check against qemu-img. Ignored: needs qemu-img and qemu-io.
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
        let size = 24u64 << 20;
        let mut reference = vec![0u8; size as usize];
        for region in [0usize, 3, 4, 9, 22] {
            let start = region << 20;
            reference[start..start + (1 << 20)]
                .copy_from_slice(&pattern(region as u8 + 1, 1 << 20));
        }
        let raw_path = dir.join("reference.raw");
        fs::write(&raw_path, &reference).unwrap();

        let variants: &[(&str, &[&str])] = &[
            ("dynamic.vhdx", &[]),
            ("fixed.vhdx", &["-o", "subformat=fixed"]),
            ("small.vhdx", &["-o", "block_size=1M,block_state_zero=off"]),
            ("big.vhdx", &["-o", "block_size=16M,log_size=2M"]),
        ];
        for (name, options) in variants {
            let out = dir.join(name);
            let mut cmd = Command::new("qemu-img");
            cmd.args(["convert", "-f", "raw", "-O", "vhdx"]);
            cmd.args(*options);
            cmd.arg(&raw_path).arg(&out);
            run(&mut cmd);
            let mut image = VHDX::new(out.to_str().unwrap()).unwrap();
            assert_eq!(image.get_image_size(), size, "{name}");
            assert_eq!(
                image.creator(),
                format!("QEMU v{}", qemu_version()),
                "{name}"
            );
            assert_eq!(read_all(&mut image), reference, "{name} content differs");
        }

        // An image written with qemu-io: data, zero writes and a hole.
        let written = dir.join("written.vhdx");
        run(Command::new("qemu-img").args([
            "create",
            "-q",
            "-f",
            "vhdx",
            "-o",
            "block_size=1M",
            written.to_str().unwrap(),
            "8M",
        ]));
        run(Command::new("qemu-io").args([
            "-c",
            "write -P 0xab 1M 1M",
            "-c",
            "write -P 0xcd 2M 4k",
            "-c",
            "write -z 1M 64k",
            "-c",
            "write -P 0xef 7M 512",
            written.to_str().unwrap(),
        ]));
        let mut expected = vec![0u8; 8 << 20];
        expected[1 << 20..2 << 20].fill(0xab);
        expected[2 << 20..(2 << 20) + 4096].fill(0xcd);
        expected[1 << 20..(1 << 20) + 65536].fill(0);
        expected[7 << 20..(7 << 20) + 512].fill(0xef);
        let mut image = VHDX::new(written.to_str().unwrap()).unwrap();
        assert_eq!(read_all(&mut image), expected);
        image.print_info();

        // Large sparse disk spanning several chunks (1 MiB blocks, 4096 per chunk).
        let large = dir.join("large.vhdx");
        run(Command::new("qemu-img").args([
            "create",
            "-q",
            "-f",
            "vhdx",
            "-o",
            "block_size=1M",
            large.to_str().unwrap(),
            "5G",
        ]));
        run(Command::new("qemu-io").args([
            "-c",
            "write -P 0x5a 4600M 1M",
            "-c",
            "write -P 0x6b 4095M 2M",
            large.to_str().unwrap(),
        ]));
        let mut image = VHDX::new(large.to_str().unwrap()).unwrap();
        let mut buf = vec![0u8; 1 << 20];
        image.seek(SeekFrom::Start(4600 << 20)).unwrap();
        image.read_exact(&mut buf).unwrap();
        assert!(buf.iter().all(|b| *b == 0x5a));
        image.seek(SeekFrom::Start((4095 << 20) + 100)).unwrap();
        let mut two = vec![0u8; (2 << 20) - 200];
        image.read_exact(&mut two).unwrap();
        assert!(two.iter().all(|b| *b == 0x6b));
        image.seek(SeekFrom::Start(4601 << 20)).unwrap();
        image.read_exact(&mut buf).unwrap();
        assert!(buf.iter().all(|b| *b == 0));
    }

    #[cfg(test)]
    fn qemu_version() -> String {
        let output = std::process::Command::new("qemu-img")
            .arg("--version")
            .output()
            .expect("qemu-img");
        let text = String::from_utf8_lossy(&output.stdout);
        text.split_whitespace()
            .nth(2)
            .unwrap_or_default()
            .to_owned()
    }

    /// Mutation run over qemu-img images. Ignored: needs qemu-img.
    #[test]
    #[ignore]
    fn corrupted_qemu_images_never_panic() {
        use std::process::Command;
        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join("ref.raw");
        let mut reference = vec![0u8; 4 << 20];
        reference[..65536].copy_from_slice(&pattern(1, 65536));
        reference[(2 << 20)..(2 << 20) + 65536].copy_from_slice(&pattern(2, 65536));
        fs::write(&raw, &reference).unwrap();
        let variants: &[(&str, &[&str])] = &[
            ("dynamic.vhdx", &["-o", "block_size=1M"]),
            ("fixed.vhdx", &["-o", "subformat=fixed,block_size=1M"]),
        ];
        let mut opened = 0;
        for (index, (name, options)) in variants.iter().enumerate() {
            let out = dir.path().join(name);
            let status = Command::new("qemu-img")
                .args(["convert", "-f", "raw", "-O", "vhdx"])
                .args(*options)
                .arg(&raw)
                .arg(&out)
                .status()
                .expect("qemu-img must be installed");
            assert!(status.success());
            let bytes = fs::read(&out).unwrap();
            opened += mutate_and_exercise(&bytes, dir.path(), 100 + index as u64, 400);
        }
        assert!(opened > 50, "only {opened} mutants opened");
    }
}
