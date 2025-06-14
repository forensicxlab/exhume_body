//! This module contains functionality for reading VMDK volumes.
//!
//! Currently VMDK files using Flat and Sparse (compressed of not) extents are supported. COWD files (used on ESXi) are not at this stage.
//! Note that this module does not support reading snapshots and any VMDK disk that requires referring to a parent VMDK.
//!
//! # Known Limitations
//!
//! For the moment VMDK descriptor files not written in UTF-8 encoding are not supported.

use std::{
    cmp::min,
    collections::HashMap,
    ffi::OsStr,
    fs::{self, File},
    io::{self, BufReader, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    str::FromStr,
    sync::LazyLock,
    u64,
};

use flate2::bufread::ZlibDecoder;
use log::{debug, info, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};

const SECTOR_SIZE: u64 = 512;
const DESCRIPTOR_FILE_SIGNATURE: &str = "# Disk DescriptorFile";
const DESCRIPTOR_FILE_EXTENT_SECTION_SIGNATURE: &str = "# Extent description";
const DESCRIPTOR_FILE_CHANGE_TRACKING_SECTION_SIGNATURE: &str = "# Change Tracking File";
const DESCRIPTOR_FILE_DISK_DATABASE_SECTION_SIGNATURE: &str = "# The Disk Data Base";

// Flags used in sparse extent file headers.
const _FLAG_VALID_NEWLINE_DETECTION_TEST: u32 = 0x00000001;
const FLAG_USE_SECONDARY_GRAIN_DIRECTORY: u32 = 0x00000002;
const _FLAG_USE_ZEROED_GRAIN_TABLE: u32 = 0x00000004;
const FLAG_HAS_COMPRESSED_GRAIN_DATA: u32 = 0x00010000;
const _FLAG_HAS_METADATA: u32 = 0x00020000;

/// Represents the character encoding used for the descriptor file.
///
/// See also: https://github.com/libyal/libvmdk/blame/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#211-encodings
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
enum VMDKEncoding {
    /// UTF-8 encoding
    #[serde(rename = "UTF-8")]
    Utf8,
    /// Big5 assumed to be equivalent to Windows codepage 950
    #[serde(rename = "Big5")]
    Big5,
    /// GBK assumed to be equivalent to Windows codepage 936
    /// Seen in VMware editions used for Windows Chinese editions
    #[serde(rename = "GBK")]
    Gbk,
    /// Shift_JIS assumed to be equivalent to Windows codepage 932
    /// Seen in VMWare Workstation for Windows, Japanese edition
    #[serde(rename = "Shift_JIS")]
    ShiftJis,
    /// Windows codepage 1252
    /// Seen in VMWare Player 9 descriptor file uncertain when this was introduced.
    #[serde(rename = "windows-1252")]
    Windows1252,
}

/// Represents a VMDK header section in a VMDK descriptor file.
///
/// See also: https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#21-header
#[derive(Clone, Debug, Serialize, Deserialize)]
struct VMDKHeader {
    /// The VMDK version number, must be 1, 2 or 3.
    version: u8,
    /// Encoding of the descriptor file
    encoding: VMDKEncoding,
    /// Content identifier _ A random 32-bit value updated the first time the content of the virtual disk is modified after the virtual disk is opened.
    cid: u32,
    /// The content identifier of the parent.
    /// A 32-bit value identifying the parent content. A value of 'ffffffff' (-1) represents no parent content.
    parent_cid: u32,
    /// Only seen values are "no"
    is_native_snapshot: Option<bool>,
    /// The disk type
    create_type: VMDKDiskType,
    /// Contains the path to the parent image.
    /// This value is only present if the image is a differential image (delta link).
    parent_file_name_hint: Option<String>,
}

impl TryFrom<HashMap<String, String>> for VMDKHeader {
    type Error = String;

    fn try_from(value: HashMap<String, String>) -> Result<Self, Self::Error> {
        // Error handling here may be too strict, consider more flexible parsing with warnings instead.
        // In our use case, only the information related to the extent is really needed.
        // Just replace error mapping with a default.
        let version = value
            .get("version")
            .ok_or("version not found in header")?
            .parse()
            .map_err(|_| "invalid version in header")?;
        let encoding_str = value
            .get("encoding")
            .unwrap_or(&String::from("UTF-8"))
            .to_string();
        let encoding = serde_json::from_value(serde_json::Value::String(encoding_str))
            .map_err(|_| "invalid encoding in header")?;
        let cid = u32::from_str_radix(
            value.get("CID").ok_or("CID not found in header")?.as_str(),
            16,
        )
        .map_err(|_| "invalid CID in header")?;
        let parent_cid = u32::from_str_radix(
            value
                .get("parentCID")
                .ok_or("parentCID not found in header")?
                .as_str(),
            16,
        )
        .map_err(|_| "invalid parent CID in header")?;
        let is_native_snapshot = value.get("isNativeSnapshot").map(|s| s.as_str() == "yes");
        let create_type_str = value
            .get("createType")
            .ok_or("createType not found in header")?
            .to_string();
        let create_type = serde_json::from_value(serde_json::Value::String(create_type_str))
            .map_err(|_| "invalid createType in header")?;
        let parent_file_name_hint = value.get("parentFileNameHint").map(|s| s.to_string());

        Ok(VMDKHeader {
            version,
            encoding,
            cid,
            parent_cid,
            is_native_snapshot,
            create_type,
            parent_file_name_hint,
        })
    }
}

/// Access mode for an extent.
///
/// See also: https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#222-extent-access-mode
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "UPPERCASE")]
enum VMDKExtentAccessMode {
    /// No access
    NoAccess,
    /// Read-only access
    RdOnly,
    /// Read-write access
    Rw,
}

/// Represents the disk type for an extent file.
///
/// See also: https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#223-extent-type
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "UPPERCASE")]
enum VMDKExtentType {
    /// RAW extent data file
    /// Seen in VMWare Player 9 to be also used for devices on Windows
    Flat,
    /// VMDK sparse extent data file
    Sparse,
    /// Sparse extent that consists of 0-byte values
    Zero,
    /// RAW extent data file
    Vmfs,
    /// COWD sparse extent data file
    VmfsSparse,
    VmfsRdm,
    VmfsRaw,
}

/// The extent descriptor allows to locate data within the extent files of the virtual disk.
///
/// See also: https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#22-extent-descriptions
#[derive(Clone, Debug, Serialize, Deserialize)]
struct VMDKExtentDescriptor {
    /// Access mode for the extent
    access_mode: VMDKExtentAccessMode,
    /// Number of sectors in the extent
    sector_number: u64,
    /// The type of the extent
    extent_type: VMDKExtentType,
    /// The name of the extent file. Specified if the extent type is different from flat
    extent_file_name: Option<String>,
    /// The start sector of the extent in the parent image. Optional and defaults to 0.
    extent_start_sector: Option<u64>,
    /// Only specified in some cases regarding Windows systems
    partition_uuid: Option<String>,
    /// Only specified in some cases regarding Windows systems
    device_identifier: Option<String>,
}

impl VMDKExtentDescriptor {
    /// Sets the path of the extent file.
    fn set_path(&mut self, path: &str) -> () {
        self.extent_file_name = Some(path.to_string());
    }
}

impl FromStr for VMDKExtentDescriptor {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // We use a LazyLock cell to ensure that the regex is compiled only once, ensuring better performance in a thread-safe manner
        // (required to be inserted into a static variable).
        static EXTENT_DESCRIPTOR_REGEX: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r#"^(\w+)\s+(\d+)\s+(\w+)\s*"?([\w\-\.\/ ]+)?"?\s*(\d+)?\s*([\w\-\.\/ ]+)?\s*([\w\-\.\/ ]+)?$"#).unwrap()
        });
        let captures = EXTENT_DESCRIPTOR_REGEX
            .captures(s)
            .ok_or_else(|| format!("Invalid extent descriptor format: {}", s))?;
        let access_mode_str =
            serde_json::Value::String(captures.get(1).unwrap().as_str().to_string());
        let extent_type_str =
            serde_json::Value::String(captures.get(3).unwrap().as_str().to_string());
        let extent_start_sector = captures.get(5).map(|m| match m.as_str().parse::<u64>() {
            Ok(n) => n,
            Err(_) => {
                warn!(
                    "Invalid extent start sector in extent description: {}",
                    m.as_str()
                );
                0
            }
        });
        Ok(Self {
            // Match group 1 to 3 will always contain a value at this stage, we can safely unwrap these values.
            access_mode: serde_json::from_value(access_mode_str).map_err(|_| {
                format!(
                    "Invalid access mode in extent description: {}",
                    captures.get(1).unwrap().as_str()
                )
            })?,
            sector_number: captures.get(2).unwrap().as_str().parse().map_err(|_| {
                format!(
                    "Invalid sector number in extent description: {}",
                    captures.get(2).unwrap().as_str()
                )
            })?,
            extent_type: serde_json::from_value(extent_type_str).map_err(|_| {
                format!(
                    "Invalid extent type in extent description: {}",
                    captures.get(3).unwrap().as_str()
                )
            })?,
            extent_file_name: captures.get(4).map(|m| m.as_str().to_string()),
            extent_start_sector,
            partition_uuid: captures.get(6).map(|m| m.as_str().to_string()),
            device_identifier: captures.get(7).map(|m| m.as_str().to_string()),
        })
    }
}

/// The change tracking file section was introduced in version 3 and seems to allow definition of a file log of changes made to the virtual disk.
///
/// See also: https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#23-change-tracking-file-section
#[derive(Clone, Debug, Serialize, Deserialize)]
struct VMDKChangeTrackingSection {
    /// Path of the change tracking file.
    change_track_path: String,
}

/// The adapter type for a disk.
///
/// See also: https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#242-the-disk-adapter-type
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
enum VMDKDiskAdapterType {
    #[serde(rename = "ide")]
    Ide,
    #[serde(rename = "buslogic")]
    BusLogic,
    #[serde(rename = "lsilogic")]
    LSILogic,
    #[serde(rename = "legacyESX")]
    LegacyESX,
}

/// The disk database section contains various information about the virtual disk.
///
/// See also: https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#24-disk-database
#[derive(Clone, Debug, Serialize, Deserialize)]
struct VMDKDiskDatabase {
    /// Most encountered value is true
    ddb_deletable: Option<bool>,
    /// The virtual hardware version
    /// For VMWare Player and Workstation this seems to correspond with the application version
    ddb_virtual_hw_version: Option<String>,
    /// The long content identifier
    /// 128-bit base16 encoded value, without spaces
    ddb_long_content_id: Option<String>,
    /// Unique identifier
    /// 128-bit base16 encoded value, with spaces between bytes
    ddb_uuid: Option<String>,
    /// The number of cylinders
    ddb_geometry_cylinders: Option<u64>,
    /// The number of heads
    ddb_geometry_heads: Option<u64>,
    /// The number of sectors
    ddb_geometry_sectors: Option<u64>,
    /// The number of cylinders as reported by the BIOS
    ddb_geometry_bios_cylinders: Option<u64>,
    /// The number of heads as reported by the BIOS
    ddb_geometry_bios_heads: Option<u64>,
    /// The number of sectors as reported by the BIOS
    ddb_geometry_bios_sectors: Option<u64>,
    /// The disk adapter type
    ddb_adapter_type: Option<VMDKDiskAdapterType>,
    /// String containing the version of the installed VMWare tools
    ddb_tools_version: Option<String>,
    /// Generally set to "1"
    ddb_thin_provisioned: Option<bool>,
}

impl TryFrom<HashMap<String, String>> for VMDKDiskDatabase {
    type Error = String;

    fn try_from(value: HashMap<String, String>) -> Result<Self, Self::Error> {
        let ddb_deletable = value.get("ddb.deletable").map(|s| s == "true");
        let ddb_virtual_hw_version = value.get("ddb.virtualHWVersion").map(|s| s.to_string());
        let ddb_long_content_id = value.get("ddb.longContentId").map(|s| s.to_string());
        let ddb_uuid = value.get("ddb.uuid").map(|s| s.to_string());
        let ddb_geometry_cylinders = value
            .get("ddb.geometry.cylinders")
            .map(|s| s.parse().unwrap_or(0));
        let ddb_geometry_heads = value
            .get("ddb.geometry.heads")
            .map(|s| s.parse().unwrap_or(0));
        let ddb_geometry_sectors = value
            .get("ddb.geometry.sectors")
            .map(|s| s.parse().unwrap_or(0));
        let ddb_geometry_bios_cylinders = value
            .get("ddb.geometry.biosCylinders")
            .map(|s| s.parse().unwrap_or(0));
        let ddb_geometry_bios_heads = value
            .get("ddb.geometry.biosHeads")
            .map(|s| s.parse().unwrap_or(0));
        let ddb_geometry_bios_sectors = value
            .get("ddb.geometry.biosSectors")
            .map(|s| s.parse().unwrap_or(0));
        let ddb_adapter_type = if let Some(s) = value.get("ddb.adapterType") {
            let adapter_type = serde_json::Value::String(s.to_string());
            serde_json::from_value(adapter_type)
                .map_err(|_| format!("Invalid adapter type: {}", s))?
        } else {
            None
        };
        let ddb_tools_version = value.get("ddb.toolsVersion").map(|s| s.to_string());
        let ddb_thin_provisioned = value.get("ddb.thinProvisioned").map(|s| s == "true");
        Ok(Self {
            ddb_deletable,
            ddb_virtual_hw_version,
            ddb_long_content_id,
            ddb_uuid,
            ddb_geometry_cylinders,
            ddb_geometry_heads,
            ddb_geometry_sectors,
            ddb_geometry_bios_cylinders,
            ddb_geometry_bios_heads,
            ddb_geometry_bios_sectors,
            ddb_adapter_type,
            ddb_tools_version,
            ddb_thin_provisioned,
        })
    }
}

/// Represents a VMDK descriptor file.
///
/// See also: https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#2-the-descriptor-file
#[derive(Clone, Debug, Serialize, Deserialize)]
struct VMDKDescriptorFile {
    /// The VMDK header read from the descriptor file.
    header: VMDKHeader,
    /// The VMDK extent descriptions read from the descriptor file.
    extent_descriptions: Vec<VMDKExtentDescriptor>,
    /// The VMDK change tracking file read from the descriptor file.
    change_tracking_file: Option<VMDKChangeTrackingSection>,
    /// The VMDK disk database file read from the descriptor file.
    disk_database: Option<VMDKDiskDatabase>,
}

/// Returns a keyword related to the section mention from the line recovered from the descriptor file.
///
/// Possible values returned are:
/// * "header" if the line starts VMDK header
/// * "extent" if the line starts VMDK extent section
/// * "ddb" if the line starts VMDK disk database section
/// * "change_tracking" if the line starts VMDK change tracking section
/// * None if the line does not correspond to any known section type
fn get_descriptor_section(line: &str) -> Option<&'static str> {
    if line.starts_with("#") {
        match line {
            DESCRIPTOR_FILE_SIGNATURE => return Some("header"),
            DESCRIPTOR_FILE_EXTENT_SECTION_SIGNATURE => return Some("extent"),
            DESCRIPTOR_FILE_DISK_DATABASE_SECTION_SIGNATURE => return Some("ddb"),
            DESCRIPTOR_FILE_CHANGE_TRACKING_SECTION_SIGNATURE => return Some("change_tracking"),
            _ => return None,
        }
    }
    None
}

/// Parses a key-value pair from the given line.
///
/// Returns None if the line does not match the expected key-value format.
fn parse_key_value_pair(line: &str) -> Option<(&str, &str)> {
    // We use a LazyLock cell to ensure that the regex is compiled only once, ensuring better performance in a thread-safe manner
    // (required to be inserted into a static variable).
    static KEY_VALUE_REGEX: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"^([\w\.]+)\s*=\s*"?([^"]*)"?$"#).unwrap());
    let captures = KEY_VALUE_REGEX.captures(line);
    if let Some(captures) = captures {
        Some((
            captures.get(1).unwrap().as_str(),
            captures.get(2).unwrap().as_str(),
        ))
    } else {
        None
    }
}

impl FromStr for VMDKDescriptorFile {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Iterate over the lines of the string slice
        let mut lines = s.lines();
        let mut line = lines.next();
        let mut current_section = "";
        let mut file_header_hashmap = HashMap::new();
        let mut extent_descriptions = Vec::new();
        let mut ddb_hashmap = HashMap::new();
        let mut change_track_path = None;

        // We have to look for sections specified as comments
        while line.is_some() {
            let unwrapped_line = line.unwrap().trim(); // This should be safe to unwrap here as we verified we have Some already
            if unwrapped_line.starts_with("#") {
                current_section = get_descriptor_section(unwrapped_line).unwrap_or(current_section);
            } else {
                match current_section {
                    "header" => {
                        let parsed_pair = parse_key_value_pair(unwrapped_line);
                        if let Some((key, value)) = parsed_pair {
                            file_header_hashmap.insert(key.to_string(), value.to_string());
                        }
                    }
                    "extent" => {
                        let extent_descriptor = unwrapped_line.parse();
                        if let Ok(extent_descriptor) = extent_descriptor {
                            extent_descriptions.push(extent_descriptor);
                        }
                    }
                    "ddb" => {
                        let parsed_pair = parse_key_value_pair(unwrapped_line);
                        if let Some((key, value)) = parsed_pair {
                            ddb_hashmap.insert(key.to_string(), value.to_string());
                        }
                    }
                    "change_tracking" => {
                        let parsed_pair = parse_key_value_pair(unwrapped_line);
                        if let Some((key, value)) = parsed_pair {
                            if key == "changeTrackPath" {
                                change_track_path = Some(value.to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
            line = lines.next();
        }

        Ok(VMDKDescriptorFile {
            header: VMDKHeader::try_from(file_header_hashmap)?,
            extent_descriptions,
            change_tracking_file: if let Some(change_track_path) = change_track_path {
                Some(VMDKChangeTrackingSection { change_track_path })
            } else {
                None
            },
            disk_database: VMDKDiskDatabase::try_from(ddb_hashmap).ok(),
        })
    }
}

/// Represents a VMDK disk type.
///
/// See also: https://github.com/libyal/libvmdk/blame/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#212-disk-type
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
enum VMDKDiskType {
    /// The disk is split into fixed-size extents of maximum 2 GB.
    /// The extents consists of RAW extent data files.
    ///
    /// The 2GbMaxExtentFlat (or twoGbMaxExtentFlat) disk image consists of:
    /// * a descriptor file
    /// * RAW data extent files (<name>-f.vmdk), where is contains a decimal value starting with 1.
    #[serde(rename = "2GbMaxExtentFlat")]
    TwoGbMaxExtentFlat,
    /// Same as TwoGbMaxExtentFlat, this exists to take into account the 2 possible names
    #[serde(rename = "twoGbMaxExtentFlat")]
    TwoGbMaxExtentFlatAlt,
    /// The disk is split into sparse (dynamic-size) extents of maximum 2 GB.
    /// The extents consists of VMDK sparse extent data files.
    ///
    /// The 2GbMaxExtentSparse (or twoGbMaxExtentSparse) disk image consists of:
    /// * a descriptor file
    /// * VMDK sparse data extent files (<name>-s.vmdk), where is contains a decimal value starting with 1.
    #[serde(rename = "2GbMaxExtentSparse")]
    TwoGbMaxExtentSparse,
    /// Same as TwoGbMaxExtentSparse, this exists to take into account the 2 possible names
    #[serde(rename = "twoGbMaxExtentSparse")]
    TwoGbMaxExtentSparseAlt,
    /// Descriptor file with arbitrary extents , used to mount v2i-format.
    Custom,
    /// The disk uses a full physical disk device.
    FullDevice,
    /// The disk is a single RAW extent data file.
    ///
    /// The monolithicFlat disk image consists of:
    /// * a descriptor file
    /// * RAW data extent file (<name>-f001.vmdk)
    MonolithicFlat,
    /// The disk is a single VMDK sparse extent data file.
    ///
    /// The monolithicSparse disk image consists of:
    /// * VMDK sparse data extent file (<name>.vmdk) also contains the descriptor file data.
    MonolithicSparse,
    /// The disk uses a full physical disk device, using access per partition.
    PartitionedDevice,
    /// The disk is a single compressed VMDK sparse extent data file.
    StreamOptimized,
    /// The disk is a single RAW extent data file.
    /// This is similar to the "monolithicFlat".
    ///
    /// The vmfs disk image consists of:
    /// * a descriptor file
    /// * RAW data extent file (<name>-flat.vmdk)
    Vmfs,
    /// The disk is a single RAW extent data file.
    /// The disk is pre‐allocated on VMFS, with all blocks zeroed when created.
    VmfsEagerZeroedThick,
    /// The disk is a single RAW extent data file. The disk is pre‐allocated on VMFS, with blocks zeroed on first use.
    VmfsPreallocated,
    /// The disk uses a full physical disk device.
    /// Special raw disk for ESXi hosts, pass through only mode.
    VmfsRaw,
    /// The disk uses a full physical disk device.
    /// Also referred to as Raw Device Map (RDM).
    #[serde(rename = "vmfsRDM")]
    VmfsRawDeviceMap,
    /// The disk uses a full physical disk device.
    /// Similar to the Raw Device Map (RDM), but sends SCSI commands to underlying hardware.
    #[serde(rename = "vmfsRDMP")]
    VmfsPassthroughRawDeviceMap,
    /// The disk is split into sparse (dynamic-size) extents.
    /// The extents consists of COWD sparse extent data files.
    /// Often used as a redo-log
    ///
    /// The vmfsSparse disk image consists of:
    /// * a descriptor file
    /// * COWD sparse data extent files (<name>-delta.vmdk)
    VmfsSparse,
    /// The disk is split into sparse (dynamic-size) extents.
    /// The extents consists of COWD sparse extent data files.
    VmfsThin,
}

/// Represents the state of a Sparse extent file, including the flattened grain directory
#[derive(Clone, Debug)]
struct VMDKSparseExtentMetadata {
    /// The header of the sparse extent file
    header: VMDKSparseFileHeader,
    /// The grain directory
    grain_directory: Vec<u32>,
}

impl VMDKSparseExtentMetadata {
    /// Takes a sparse extent file and reads its metadata to recover the grain directory and grain tables
    ///
    /// # Errors
    ///
    /// Errors if any IO error occurs while reading the file or if some metadata is invalid
    fn read_from_file(file: &mut File, header: &VMDKSparseFileHeader) -> Result<Self, String> {
        let mut grain_directory_entry_count: u64 =
            header.capacity / (header.number_of_grain_table_entries as u64 * header.grain_number);
        if header.capacity % (header.number_of_grain_table_entries as u64 * header.grain_number) > 0
        {
            grain_directory_entry_count += 1
        }
        debug!(
            "Grain directory entry count: {}",
            grain_directory_entry_count
        );
        let mut grain_directory = Vec::with_capacity(grain_directory_entry_count as usize);
        let active_grain_directory_sector = if header.flags & FLAG_USE_SECONDARY_GRAIN_DIRECTORY
            == FLAG_USE_SECONDARY_GRAIN_DIRECTORY
            || header.grain_directory_sector == -1
        {
            i64::try_from(header.secondary_grain_directory_sector).map_err(|e| {
                format!(
                    "Unable to convert secondary grain directory sector to i64: {}",
                    e
                )
            })?
        } else {
            header.grain_directory_sector
        };
        file.seek(io::SeekFrom::Start(
            u64::try_from(active_grain_directory_sector).unwrap() * SECTOR_SIZE,
        ))
        .map_err(|e| format!("Unable to navigate the sparse extent file: {}", e))?;
        for _ in 0..grain_directory_entry_count {
            let mut number_buf = [0u8; 4];
            file.read(&mut number_buf)
                .map_err(|e| format!("Error reading sparse extent file: {}", e))?;
            grain_directory.push(u32::from_le_bytes(number_buf));
        }
        let mut grain_table_entries = Vec::with_capacity(
            header.number_of_grain_table_entries as usize * grain_directory_entry_count as usize,
        );
        for entry in grain_directory {
            file.seek(SeekFrom::Start(u64::from(entry) * SECTOR_SIZE))
                .map_err(|e| format!("Unable to navigate the sparse extent file: {}", e))?;
            for _ in 0..header.number_of_grain_table_entries {
                let mut grain_buf = [0u8; 4];
                file.read(&mut grain_buf)
                    .map_err(|e| format!("Error reading sparse extent file: {}", e))?;
                grain_table_entries.push(u32::from_le_bytes(grain_buf));
            }
        }
        Ok(VMDKSparseExtentMetadata {
            header: header.clone(),
            grain_directory: grain_table_entries,
        })
    }
}

/// Reads data from a RAW type extent
///
/// This type of extent consists in a RAW data file and is the simplest to read from as it does not require any special handling and can be read byte by byte.
///
/// This function takes a handle to the RAW file we want to read from and the offset from which to start reading.
/// The data read from the RAW file is then stored in the provided buffer. An `io::Result<usize>` is returned indicating the number of bytes read.
fn read_raw_extent(file: &mut File, buf: &mut [u8], start_offset: u64) -> io::Result<usize> {
    file.seek(io::SeekFrom::Start(start_offset))?;
    file.read(buf)
}

/// Read data from a sparse extent
///
/// This type of extent contains data in grains. A grain regroup several sectors, usually 128 (for 64kB of data).
///
/// This function takes a handle to the sparse file we want to read from and the offset in a similar way that `read_raw_extend` does.
/// To do so, the sparse file is "flattened" to fill the buffer in a linear manner (as the sparse file stores data in a non-linear way).
/// An `io::Result<usize>` is returned indicating the number of bytes read.
fn read_sparse_extent(
    file: &mut File,
    buf: &mut [u8],
    start_offset: u64,
    sparse_metadata: &VMDKSparseExtentMetadata,
) -> io::Result<usize> {
    let grain_size_in_bytes = sparse_metadata.header.grain_number * SECTOR_SIZE;
    let first_grain = start_offset / grain_size_in_bytes;
    let last_grain = (start_offset + buf.len() as u64).div_ceil(grain_size_in_bytes);
    let grain_range = first_grain..last_grain;
    let mut read_size = 0;
    for grain in grain_range {
        let sector_number =
            *sparse_metadata
                .grain_directory
                .get(grain as usize)
                .ok_or(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Grain directory entry not found: {}", grain),
                ))?;
        if sector_number == 0 {
            // The grain is sparse
            let remaining_buffer_size = buf.len() - read_size;
            if grain == first_grain {
                let additional_offset = start_offset - (grain * grain_size_in_bytes);
                let upper_bound = min(
                    (grain_size_in_bytes - additional_offset) as usize,
                    remaining_buffer_size,
                );
                buf[read_size..read_size + upper_bound].fill(0);
                read_size += remaining_buffer_size;
            } else {
                let remaining_read = min(remaining_buffer_size, grain_size_in_bytes as usize);
                buf[read_size..read_size + remaining_read].fill(0);
                read_size += remaining_read;
            }
        } else {
            // The grain is not sparse, read the data from the file
            file.seek(io::SeekFrom::Start(sector_number as u64 * SECTOR_SIZE))?;

            let remaining_buffer_size = buf.len() - read_size;
            let mut upper_bound = min(remaining_buffer_size, grain_size_in_bytes as usize);
            if sparse_metadata.header.flags & FLAG_HAS_COMPRESSED_GRAIN_DATA
                == FLAG_HAS_COMPRESSED_GRAIN_DATA
            {
                // Grain data is compressed, uncompress it to read
                // We start in a grain marker
                // Skip the sector number and the compressed data size, at this stage we should know where we are
                // thanks to the grain table
                file.seek(SeekFrom::Current(8))?;
                let mut size_buf = [0u8; 4];
                file.read(&mut size_buf)?;
                let mut decoder = ZlibDecoder::new(BufReader::new(&mut *file));
                let mut decompressed_buf =
                    vec![0u8; (sparse_metadata.header.grain_number * SECTOR_SIZE) as usize];
                let bytes_read = decoder.read(&mut decompressed_buf[..])?;
                let additional_offset = if grain == first_grain {
                    let additional_offset = start_offset - (grain * grain_size_in_bytes);
                    if additional_offset + upper_bound as u64 > grain_size_in_bytes {
                        upper_bound = (grain_size_in_bytes - additional_offset) as usize;
                    }
                    additional_offset
                } else {
                    0
                };
                if upper_bound > bytes_read {
                    upper_bound = bytes_read;
                }
                buf[read_size + additional_offset as usize..read_size + upper_bound]
                    .copy_from_slice(&decompressed_buf[additional_offset as usize..upper_bound]);
                read_size += upper_bound - additional_offset as usize;
            } else {
                // Data in raw format, read directly
                if grain == first_grain {
                    let additional_offset = start_offset - (grain * grain_size_in_bytes);
                    // Panic shouldn't occur as it is highly unlikely that the additional offset exceeds the i64 bounds
                    file.seek(io::SeekFrom::Current(additional_offset.try_into().unwrap()))?;
                    if additional_offset + upper_bound as u64 > grain_size_in_bytes {
                        upper_bound = (grain_size_in_bytes - additional_offset) as usize;
                    }
                }
                read_size += file.read(&mut buf[read_size..read_size + upper_bound])?;
            }
        }
    }
    Ok(read_size)
}

/// Stores a VMDK extent file handle and the associated extent information for reading actual data.
///
/// This is a struct dedicated to maintain the state of read of a given extent file.
struct VMDKExtentFile {
    /// The extent description for this file
    extent_description: VMDKExtentDescriptor,
    /// The file handle for the extent file
    file: File,
    /// Metadata for sparse extent files, Some if this is a sparse extent file
    sparse_extent_metadata: Option<VMDKSparseExtentMetadata>,
}

impl VMDKExtentFile {
    /// Reads data in the range specified by the start and end positions (relative to the first sector defined for the extent file) and stores the data into the provided buffer.
    ///
    /// This function returns the actual data stored in the extent file after any parsing or decrompression if necessary.
    ///
    /// # Errors
    ///
    /// Errors if any IO error occurs while reading or if the provided range exceeds the extent file's limits. Also errors if the extent type is not supported.
    fn read_data(&mut self, start_pos: u64, buf: &mut [u8]) -> io::Result<usize> {
        match self.extent_description.extent_type {
            VMDKExtentType::Flat => read_raw_extent(&mut self.file, buf, start_pos),
            VMDKExtentType::Sparse => read_sparse_extent(
                &mut self.file,
                buf,
                start_pos,
                self.sparse_extent_metadata.as_ref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "No sparse extent metadata available",
                    )
                })?,
            ),
            VMDKExtentType::Zero => {
                // Zero out the buffer
                buf.fill(0);
                Ok(buf.len())
            }
            VMDKExtentType::Vmfs => read_raw_extent(&mut self.file, buf, start_pos),
            VMDKExtentType::VmfsSparse => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMFS Sparse extent type not yet supported",
            )),
            VMDKExtentType::VmfsRdm => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unsupported extent type VMFS RDM",
            )),
            VMDKExtentType::VmfsRaw => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unsupported extent type VMFS RAW",
            )),
        }
    }
}

/// Compression method used for data stored in VMDK sparse files
///
/// See also: https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#412-compression-method
#[derive(Debug, Clone, Serialize, Deserialize)]
enum VMDKCompressionMethod {
    /// No compression
    None,
    /// Zlib Deflate compression
    Deflate,
}

/// Structure representing a sparse file header.
///
/// Note that the bytes for the Magic Number are not included in the struct.
///
/// See also: https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#41-file-header
#[derive(Clone, Debug, Serialize, Deserialize)]
struct VMDKSparseFileHeader {
    /// Version of the VMDK Sparse format
    pub version: u32,
    /// Flags
    pub flags: u32,
    /// Maximum data number of sectors
    pub capacity: u64,
    /// Grain number of sectors
    /// The value must be a power of 2 and > 8
    pub grain_number: u64,
    /// The sector number of the embedded descriptor file. The value is relative from the start of the file or 0 if not set.
    pub embedded_descriptor_sector: u64,
    /// Descriptor number of sectors
    /// The number of sectors of the embedded descriptor in the extent data file.
    pub embedded_descriptor_sectors_count: u64,
    /// The number of grain table entries
    pub number_of_grain_table_entries: u32,
    /// Secondary (redundant) grain directory sector number
    /// The value is relative from the start of the file or 0 if not set.
    pub secondary_grain_directory_sector: u64,
    /// Grain directory sector number
    /// The value is relative from the start of the file or 0 if not set. This value can be -1
    pub grain_directory_sector: i64,
    /// Metadata (overhead) number of sectors
    pub number_of_sectors: u64,
    /// Is dirty
    /// Value to determine if the extent data file was cleanly closed.
    pub is_dirty: bool,
    /// Compression method
    pub compression_method: VMDKCompressionMethod,
}

impl VMDKSparseFileHeader {
    /// Parses a data buffer and tries to create a new VMDKSparseFileHeader object from the provided data buffer.
    ///
    /// # Errors
    ///
    /// Errors if the provided data buffer does not contain a valid VMDK sparse file header or if the header data is too short.
    fn parse_sparse_header(header_data: &[u8]) -> Result<Self, String> {
        if header_data.len() < 80 {
            return Err("Header data too short".to_string());
        }
        if &header_data[0..4] != b"KDMV" {
            return Err("Invalid VMDK magic number".to_string());
        }
        let compression_method =
            match u16::from_le_bytes(<[u8; 2]>::try_from(&header_data[77..79]).unwrap()) {
                0 => VMDKCompressionMethod::None,
                1 => VMDKCompressionMethod::Deflate,
                _ => return Err("Unsupported compression method".to_string()),
            };
        return Ok(Self {
            version: u32::from_le_bytes(<[u8; 4]>::try_from(&header_data[4..8]).unwrap()),
            flags: u32::from_le_bytes(<[u8; 4]>::try_from(&header_data[8..12]).unwrap()),
            capacity: u64::from_le_bytes(<[u8; 8]>::try_from(&header_data[12..20]).unwrap()),
            grain_number: u64::from_le_bytes(<[u8; 8]>::try_from(&header_data[20..28]).unwrap()),
            embedded_descriptor_sector: u64::from_le_bytes(
                <[u8; 8]>::try_from(&header_data[28..36]).unwrap(),
            ),
            embedded_descriptor_sectors_count: u64::from_le_bytes(
                <[u8; 8]>::try_from(&header_data[36..44]).unwrap(),
            ),
            number_of_grain_table_entries: u32::from_le_bytes(
                <[u8; 4]>::try_from(&header_data[44..48]).unwrap(),
            ),
            secondary_grain_directory_sector: u64::from_le_bytes(
                <[u8; 8]>::try_from(&header_data[48..56]).unwrap(),
            ),
            grain_directory_sector: i64::from_le_bytes(
                <[u8; 8]>::try_from(&header_data[56..64]).unwrap(),
            ),
            number_of_sectors: u64::from_le_bytes(
                <[u8; 8]>::try_from(&header_data[64..72]).unwrap(),
            ),
            is_dirty: header_data[72] & 0x01 == 1,
            compression_method,
        });
    }
}

/// Returns a VMDKDescriptorFile object from the provided sparse file and metadata.
///
/// # Errors
///
/// Errors on file read errors and if there is no embedded descriptor in the file.
fn get_descriptor_from_sparse(
    file: &mut File,
    header: &VMDKSparseFileHeader,
) -> Result<VMDKDescriptorFile, String> {
    if header.embedded_descriptor_sector == 0 || header.embedded_descriptor_sectors_count == 0 {
        return Err("No embedded descriptor file found".to_string());
    }
    let mut descriptor_buffer =
        vec![0u8; header.embedded_descriptor_sectors_count as usize * SECTOR_SIZE as usize];
    file.seek(io::SeekFrom::Start(
        header.embedded_descriptor_sector * SECTOR_SIZE as u64,
    ))
    .and_then(|_| file.read_exact(&mut descriptor_buffer))
    .map_err(|e| format!("Error reading embedded descriptor file: {}", e))?;
    let descriptor_string = String::from_utf8_lossy(&descriptor_buffer);
    let descriptor: VMDKDescriptorFile = descriptor_string.parse()?;
    return Ok(descriptor);
}

/// Represents a VMDK virtual disk in memory with the state of the file handles.
pub struct VMDK {
    /// The descriptor file for the volume
    descriptor_file: VMDKDescriptorFile,
    /// List of the extent files for the volume
    extent_files: Vec<VMDKExtentFile>,
    /// The position of the cursor on the disk
    position: u64,
    /// Working directory path
    descriptor_path: PathBuf,
}

impl Clone for VMDK {
    fn clone(&self) -> Self {
        let mut cloned_extent_files = Vec::new();
        for extent_file in &self.extent_files {
            if let Some(ref file_name) = extent_file.extent_description.extent_file_name {
                let extent_file_path = self
                    .descriptor_path
                    .parent()
                    .unwrap_or(Path::new(""))
                    .join(Path::new(file_name));
                let file = File::open(extent_file_path);
                // FIXME: even if it is highly unlikely that and error occurs, we should not silence it if it happens
                if let Ok(file) = file {
                    cloned_extent_files.push(VMDKExtentFile {
                        extent_description: extent_file.extent_description.clone(),
                        file,
                        sparse_extent_metadata: extent_file.sparse_extent_metadata.clone(),
                    });
                }
            }
        }
        Self {
            descriptor_file: self.descriptor_file.clone(),
            extent_files: cloned_extent_files,
            position: self.position.clone(),
            descriptor_path: self.descriptor_path.clone(),
        }
    }
}

impl VMDK {
    /// Attempts to create a new VMDK object from the given file path.
    /// The given file path must be a valid VMDK descriptor file.
    ///
    /// # Errors
    ///
    /// Throws an error if the file at the given path is not a valid VMDK descriptor file or if the specified extent files cannot be opened.
    /// May also throw an error if the encountered extend files are of unrecognized types.
    pub fn new(file_path: &str) -> Result<VMDK, String> {
        debug!("Opening and reading VMDK descriptor file: {}", file_path);

        // First, identify if we have a monolithic VMDK
        let mut vmdk_file =
            File::open(file_path).map_err(|e| format!("Error reading descriptor file: {}", e))?;
        let mut magic_buffer = [0u8; 4];
        let mut sparse_header = None;
        let mut descriptor_file = if vmdk_file
            .read(&mut magic_buffer)
            .map_err(|e| format!("Error reading descriptor file: {}", e))?
            == 4
            && &magic_buffer[..] == b"KDMV"
        {
            debug!("Monolithic Sparse VMDK detected, extracting descriptor information");
            vmdk_file
                .seek(SeekFrom::Start(0))
                .map_err(|e| format!("Error reading descriptor file: {}", e))?;
            let mut header_data = [0u8; 80];
            sparse_header = match vmdk_file.read(&mut header_data) {
                Ok(_) => Some(VMDKSparseFileHeader::parse_sparse_header(&header_data)?),
                Err(e) => return Err(format!("Error reading header in sparse file: {}", e)),
            };
            let descriptor =
                get_descriptor_from_sparse(&mut vmdk_file, sparse_header.as_ref().unwrap())?;
            descriptor
        } else {
            debug!("Trying to decode standalone descriptor file");
            let descriptor_file_contents = fs::read_to_string(file_path)
                .map_err(|e| format!("Error reading descriptor file: {}", e))?;
            let descriptor_file: VMDKDescriptorFile = descriptor_file_contents
                .parse()
                .map_err(|e| format!("Error parsing descriptor file: {}", e))?;
            descriptor_file
        };
        if descriptor_file.header.parent_cid != 0xffffffff {
            return Err("VMDK files having a parent CID (i.e. VMDK files representing a delta with another disk) are not supported".to_string());
        }

        //  Calculate implicit extent offsets
        //  When the "start-sector" column is omitted, the extent begins immediately after the previous one.
        let mut next_start = 0;
        for extent in &mut descriptor_file.extent_descriptions {
            if extent.extent_start_sector.is_none() {
                extent.extent_start_sector = Some(next_start);
            }
            next_start = extent
                .extent_start_sector
                .unwrap()
                .saturating_add(extent.sector_number);
        }

        if descriptor_file.extent_descriptions.len() == 1
            && (descriptor_file.header.create_type == VMDKDiskType::MonolithicSparse
                || descriptor_file.header.create_type == VMDKDiskType::StreamOptimized)
        {
            // There is no other extent file in these cases and the filename can be different from the one in the descriptor file
            // So we just make sure that the file path is set correctly
            for extent in &mut descriptor_file.extent_descriptions {
                extent.set_path(
                    Path::new(file_path)
                        .file_name()
                        .unwrap_or(OsStr::new(""))
                        .to_str()
                        .ok_or_else(|| "Invalid extent file name in descriptor file".to_string())?,
                );
            }
        }
        debug!("Parsed descriptor: {:?}", descriptor_file);

        debug!("Opening VMDK extent files if any");
        // Try to open all the identified extent files and add them to the VMDK object
        let extent_files: Vec<VMDKExtentFile> = descriptor_file
            .extent_descriptions
            .iter()
            .filter_map(|extent| {
                if let Some(ref extent_file_name) = extent.extent_file_name {
                    // Ensure the path read in the descriptor file is treated as a path relative to the descriptor file
                    // Note: the specification of VMDK does not prohibit absolute paths in the extent file name but this case is considered as
                    // unlikely and impractical in a forensic context. This code may be corrected if the case happens in the real world.
                    let extent_file_path = Path::new(file_path)
                        .parent()
                        .unwrap_or(Path::new(""))
                        .join(extent_file_name);
                    debug!("Opening extent file: {}", extent_file_path.display());
                    let mut file = File::open(extent_file_path).ok()?;
                    let sparse_extent_metadata = if extent.extent_type == VMDKExtentType::Sparse {
                        if sparse_header.is_none()
                            || descriptor_file.header.create_type == VMDKDiskType::StreamOptimized
                        {
                            if sparse_header.is_some()
                                && descriptor_file.header.create_type
                                    == VMDKDiskType::StreamOptimized
                                && sparse_header.as_ref().unwrap().grain_directory_sector == -1
                            {
                                // StreamOptimized disks usually have their header at the end of the file
                                file.seek(SeekFrom::End(-1024)).ok()?;
                            } else {
                                file.seek(SeekFrom::Start(0)).ok()?;
                            }
                            let mut header_data = [0u8; 80];
                            sparse_header = match file.read(&mut header_data) {
                                Ok(_) => Some(
                                    VMDKSparseFileHeader::parse_sparse_header(&header_data).ok()?,
                                ),
                                Err(_) => return None,
                            };
                        }
                        debug!("Parsed header: {:?}", sparse_header);
                        VMDKSparseExtentMetadata::read_from_file(&mut file, sparse_header.as_ref()?)
                            .ok()
                    } else {
                        None
                    };
                    Some(VMDKExtentFile {
                        extent_description: extent.clone(),
                        file: file,
                        sparse_extent_metadata,
                    })
                } else {
                    None
                }
            })
            .collect();

        let mut descriptor_path = PathBuf::new();
        descriptor_path.push(file_path);

        return Ok(VMDK {
            descriptor_file,
            extent_files,
            position: 0,
            descriptor_path,
        });
    }

    /// Reads data from the VMDK descriptor and prints metadata to the console.
    pub fn print_info(&self) {
        info!("VMDK Disk Information:");

        info!("  Disk Type: {:?}", self.descriptor_file.header.create_type);
        info!("  Extent list:");
        for extent in &self.descriptor_file.extent_descriptions {
            info!(
                "    - Extent file: {}, Number of sectors: {}, Start sector: {}",
                extent.extent_file_name.as_deref().unwrap_or("<unknown>"),
                extent.sector_number,
                extent.extent_start_sector.unwrap_or(0)
            );
        }
        info!("  Disk ID: {:x}", self.descriptor_file.header.cid);
        if let Some(ref disk_database) = self.descriptor_file.disk_database {
            if let Some(sectors) = disk_database.ddb_geometry_sectors {
                // Maybe we shouldn't rely on this information and rather use the number of sectors from the extent descriptions
                info!("  Disk sectors: {} sectors", sectors);
            }
            if let Some(ref tools) = disk_database.ddb_tools_version {
                info!("  Guest tools Version: {}", tools);
            }
            if let Some(thin_provisioned) = disk_database.ddb_thin_provisioned {
                info!("  Thin Provisioned: {}", thin_provisioned);
            }
        }
    }

    /// Reads data from the VMDK disk into the given buffer, starting from the current position.
    /// Advances the current position by the number of bytes read and returns the number of bytes read.
    ///
    /// # Errors
    ///
    /// Errors if IO errors occur while reading from the extent files. Also errors if trying to read data from unsupported extent types.
    pub fn vmdk_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // First, identify the extent file(s) that contains the data at the desired position
        let buf_len = buf.len() as u64;
        let mut extent_files = self.extent_files.iter_mut().filter(|e| {
            (
                // We want the file that contains the starting position
                self.position >= e.extent_description.extent_start_sector.unwrap_or(0) * SECTOR_SIZE
                    && self.position
                        < (e.extent_description.extent_start_sector.unwrap_or(0)
                            + e.extent_description.sector_number)
                            * SECTOR_SIZE
            ) || (
                // We also want the file that contains the ending position (starting position + length of the buffer)
                self.position + buf_len
                    >= e.extent_description.extent_start_sector.unwrap_or(0) * SECTOR_SIZE
                    && self.position + buf_len
                        < (e.extent_description.extent_start_sector.unwrap_or(0)
                            + e.extent_description.sector_number)
                            * SECTOR_SIZE
            ) || (
                // And we want all the files in between
                self.position < e.extent_description.extent_start_sector.unwrap_or(0) * SECTOR_SIZE
                    && self.position + buf_len
                        > (e.extent_description.extent_start_sector.unwrap_or(0)
                            + e.extent_description.sector_number)
                            * SECTOR_SIZE
            )
        });

        let mut total_read = 0;
        while let Some(extent) = extent_files.next() {
            // Find the relative position within the extent file we want depending on the structure of the extent files we recovered
            let end_of_extent = (extent.extent_description.extent_start_sector.unwrap_or(0)
                + extent.extent_description.sector_number)
                * SECTOR_SIZE;
            let start_of_extent =
                extent.extent_description.extent_start_sector.unwrap_or(0) * SECTOR_SIZE;
            let start_position = if self.position >= start_of_extent {
                self.position - start_of_extent
            } else {
                0
            };
            let end_position = if self.position + (buf.len() as u64) >= end_of_extent {
                end_of_extent - start_of_extent
            } else {
                self.position + (buf.len() as u64) - start_of_extent
            };
            // Now, read the data from the extent file and update the buffer
            let buffer_start = if start_of_extent <= self.position {
                0
            } else {
                start_of_extent - self.position
            };
            let buffer_end = (buffer_start + end_position - start_position) as usize;
            let buf_part = &mut buf[buffer_start as usize..buffer_end];
            let read_result = extent.read_data(start_position, buf_part);
            if let Ok(read_bytes) = read_result {
                total_read += read_bytes;
            } else {
                return read_result;
            }
        }
        self.position = self.position + total_read as u64;
        Ok(total_read)
    }

    /// Adds the given offset to the current position in the VMDK disk.
    /// Next call to `vmdk_read` will read from the updated position.
    ///
    /// # Errors
    ///
    /// Errors if the offset is out of bounds or if no extent file can cover the desired position.
    pub fn vmdk_seek(&mut self, offset: SeekFrom) -> io::Result<u64> {
        // First, check that the desired position is within the bounds of the disk as defined by the extent descriptions
        // If we are in the bounds, update the current position and return the new position
        if !self.descriptor_file.extent_descriptions.is_empty() {
            let total_sectors: u64 = self
                .descriptor_file
                .extent_descriptions
                .iter()
                .map(|e| e.sector_number)
                .sum();
            let total_bytes = total_sectors * SECTOR_SIZE;
            match offset {
                SeekFrom::Start(offset) => {
                    if offset <= total_bytes {
                        self.position = offset;
                        return Ok(offset);
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Offset is out of bounds",
                        ));
                    }
                }
                SeekFrom::Current(offset) => {
                    let new_position = self.position.checked_add_signed(offset);
                    if new_position.is_some() && new_position.unwrap_or(u64::MAX) <= total_bytes {
                        self.position = new_position.unwrap_or(0);
                        return Ok(self.position);
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Offset is out of bounds",
                        ));
                    }
                }
                SeekFrom::End(offset) => {
                    let new_position = total_bytes.checked_add_signed(offset);
                    if new_position.is_some() && new_position.unwrap_or(u64::MAX) <= total_bytes {
                        self.position = new_position.unwrap_or(0);
                        return Ok(self.position);
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Offset is out of bounds",
                        ));
                    }
                }
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No extent descriptions found",
            ));
        }
    }

    pub fn get_sector_size(&self) -> u64 {
        SECTOR_SIZE
    }
}

impl Read for VMDK {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.vmdk_read(buf)
    }
}

impl Seek for VMDK {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.vmdk_seek(pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key_value_pair() {
        assert_eq!(
            parse_key_value_pair("key1 = value1"),
            Some(("key1", "value1"))
        );
        assert_eq!(
            parse_key_value_pair("key2 = value2 with spaces"),
            Some(("key2", "value2 with spaces"))
        );
        assert_eq!(
            parse_key_value_pair("key3 = \"with quotes\""),
            Some(("key3", "with quotes"))
        );
        assert_eq!(
            parse_key_value_pair("key3 = \"with non-ascii çàù\""),
            Some(("key3", "with non-ascii çàù"))
        );
        assert_eq!(parse_key_value_pair("key4"), None);
        assert_eq!(
            parse_key_value_pair("key.with.periods = aaa"),
            Some(("key.with.periods", "aaa"))
        );
    }

    #[test]
    fn test_parse_descriptor_data() {
        let descriptor_data = r#"
# Disk DescriptorFile
version=1
CID=123a5678
parentCID=ffffffff
createType="2GbMaxExtentSparse"
encoding="UTF-8"
isNativeSnapshot="no"

# Extent description
RW 4192256 ZERO

# The Disk Data Base
# DDB

ddb.virtualHWVersion = "4"
ddb.geometry.cylinders = "16383"
ddb.geometry.heads = "16"
ddb.geometry.sectors = "63"
ddb.adapterType = "ide"
ddb.toolsVersion = "0"
"#;

        let descriptor = descriptor_data.parse::<VMDKDescriptorFile>();
        //assert_eq!(descriptor.err(), None);
        assert!(descriptor.is_ok());
        let descriptor = descriptor.unwrap();
        assert_eq!(
            descriptor.header.create_type,
            VMDKDiskType::TwoGbMaxExtentSparse
        );
        assert_eq!(descriptor.header.cid, 0x123a5678);
        assert_eq!(descriptor.header.parent_cid, 0xffffffff);
        assert_eq!(descriptor.header.is_native_snapshot, Some(false));
        assert_eq!(
            descriptor.extent_descriptions.get(0).unwrap().access_mode,
            VMDKExtentAccessMode::Rw
        );
        assert_eq!(
            descriptor.extent_descriptions.get(0).unwrap().sector_number,
            4192256
        );
        assert_eq!(
            descriptor.extent_descriptions.get(0).unwrap().extent_type,
            VMDKExtentType::Zero
        );
        assert_eq!(
            descriptor.disk_database.unwrap().ddb_geometry_cylinders,
            Some(16383)
        );
    }
}
