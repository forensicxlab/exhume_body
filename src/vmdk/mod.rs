//! This module contains functionality for reading VMDK volumes.
//! 
//! # Known Limitations
//! 
//! For the moment VMDK descriptor files not written in UTF-8 encoding are not supported.

use std::{collections::HashMap, fs::{self, File}, str::FromStr, sync::LazyLock};

use log::info;
use regex::Regex;
use strum::EnumString;

const SECTOR_SIZE: u32 = 512;
const DESCRIPTOR_FILE_SIGNATURE: &'static str = "# Disk DescriptorFile";
const DESCRIPTOR_FILE_EXTENT_SECTION_SIGNATURE: &'static str = "# Extent description";
const DESCRIPTOR_FILE_CHANGE_TRACKING_SECTION_SIGNATURE: &'static str  = "# Change Tracking File";
const DESCRIPTOR_FILE_DISK_DATABASE_SECTION_SIGNATURE: &'static str = "# The Disk Data Base";

/// Represents the character encoding used for the descriptor file.
/// 
/// See also: https://github.com/libyal/libvmdk/blame/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#211-encodings
#[derive(Debug, EnumString, PartialEq)]
enum VMDKEncoding {
    /// UTF-8 encoding
    #[strum(serialize = "UTF-8")]
    Utf8,
    /// Big5 assumed to be equivalent to Windows codepage 950
    #[strum(serialize = "Big5")]
    Big5,
    /// GBK assumed to be equivalent to Windows codepage 936
    /// Seen in VMware editions used for Windows Chinese editions
    #[strum(serialize = "GBK")]
    Gbk,
    /// Shift_JIS assumed to be equivalent to Windows codepage 932
    /// Seen in VMWare Workstation for Windows, Japanese edition
    #[strum(serialize = "Shift_JIS")]
    ShiftJis,
    /// Windows codepage 1252
    /// Seen in VMWare Player 9 descriptor file uncertain when this was introduced.
    #[strum(serialize = "windows-1252")]
    Windows1252,
}

/// Represents a VMDK header section in a VMDK descriptor file.
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
        let version = value.get("version")
            .ok_or("version not found in header")?.parse()
            .map_err(|_| "invalid version in header")?;
        let encoding = value.get("encoding")
            .ok_or("encoding not found in header")?.parse()
            .map_err(|_| "invalid encoding in header")?;
        let cid = u32::from_str_radix(
            value.get("CID").ok_or("CID not found in header")?.as_str(),
            16
        ).map_err(|_| "invalid CID in header")?;
        let parent_cid = u32::from_str_radix(
            value.get("parentCID").ok_or("parentCID not found in header")?.as_str(),
            16
        ).map_err(|_| "invalid parent CID in header")?;
        let is_native_snapshot = value.get("isNativeSnapshot")
            .map(|s| s.as_str() == "yes");
        let create_type = value.get("createType")
           .ok_or("createType not found in header")?.parse()
           .map_err(|_| "invalid createType in header")?;
        let parent_file_name_hint = value.get("parentFileNameHint")
           .map(|s| s.to_string());

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
#[derive(Debug, EnumString, PartialEq)]
#[strum(serialize_all = "UPPERCASE")]
enum VMDKExtentAccessMode {
    /// No access
    NoAccess,
    /// Read-only access
    RdOnly,
    /// Read-write access
    Rw,
}

#[derive(Debug, EnumString, PartialEq)]
#[strum(serialize_all = "UPPERCASE")]
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


impl FromStr for VMDKExtentDescriptor {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // We use a LazyLock cell to ensure that the regex is compiled only once, ensuring better performance in a thread-safe manner 
        // (required to be inserted into a static variable).
        static EXTENT_DESCRIPTOR_REGEX: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r#"^(\w+)\s+(\d+)\s+(\w+)\s*"?([\w\-\.\/ ]+)?"?\s*(\d+)?\s*([\w\-\.\/ ]+)?\s*([\w\-\.\/ ]+)?$"#).unwrap()
        });
        let captures = EXTENT_DESCRIPTOR_REGEX.captures(s).ok_or_else(|| {
            format!("Invalid extent descriptor format: {}", s)
        })?;
        Ok(Self {
            // Match group 1 to 3 will always contain a value at this stage, we can safely unwrap these values.
            access_mode: VMDKExtentAccessMode::from_str(captures.get(1).unwrap().as_str())
                .map_err(|_| format!("Invalid access mode in extent description: {}", captures.get(1).unwrap().as_str()))?, 
            sector_number: captures.get(2).unwrap().as_str().parse()
                .map_err(|_| format!("Invalid sector number in extent description: {}", captures.get(2).unwrap().as_str()))?,
            extent_type: VMDKExtentType::from_str(captures.get(3).unwrap().as_str())
                .map_err(|_| format!("Invalid extent type in extent description: {}", captures.get(3).unwrap().as_str()))?,
            extent_file_name: captures.get(4).map(|m| m.as_str().to_string()),
            // Maybe silently ignoring a parse error is not the best solution here
            extent_start_sector: captures.get(5).map(|m| m.as_str().parse::<u64>().unwrap_or(0)),
            partition_uuid: captures.get(6).map(|m| m.as_str().to_string()),
            device_identifier: captures.get(7).map(|m| m.as_str().to_string()),
        })
    }
}

/// The change tracking file section was introduced in version 3 and seems to allow definition of a file log of changes made to the virtual disk.
struct VMDKChangeTrackingSection {
    /// Path of the change tracking file.
    change_track_path: String,
}

#[derive(Debug, EnumString, PartialEq)]
enum VMDKDiskAdapterType {
    #[strum(serialize = "ide")]
    Ide,
    #[strum(serialize = "buslogic")]
    BusLogic,
    #[strum(serialize = "lsilogic")]
    LSILogic,
    #[strum(serialize = "legacyESX")]
    LegacyESX,
}

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
    ddb_geometry_cylinders: Option<u32>,
    /// The number of heads
    ddb_geometry_heads: Option<u32>,
    /// The number of sectors
    ddb_geometry_sectors: Option<u32>,
    /// The number of cylinders as reported by the BIOS
    ddb_geometry_bios_cylinders: Option<u32>,
    /// The number of heads as reported by the BIOS
    ddb_geometry_bios_heads: Option<u32>,
    /// The number of sectors as reported by the BIOS
    ddb_geometry_bios_sectors: Option<u32>,
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
        let ddb_geometry_cylinders = value.get("ddb.geometry.cylinders").map(|s| s.parse().unwrap_or(0));
        let ddb_geometry_heads = value.get("ddb.geometry.heads").map(|s| s.parse().unwrap_or(0));
        let ddb_geometry_sectors = value.get("ddb.geometry.sectors").map(|s| s.parse().unwrap_or(0));
        let ddb_geometry_bios_cylinders = value.get("ddb.geometry.biosCylinders").map(|s| s.parse().unwrap_or(0));
        let ddb_geometry_bios_heads = value.get("ddb.geometry.biosHeads").map(|s| s.parse().unwrap_or(0));
        let ddb_geometry_bios_sectors = value.get("ddb.geometry.biosSectors").map(|s| s.parse().unwrap_or(0));
        let ddb_adapter_type = if let Some(s) = value.get("ddb.adapterType") {
            VMDKDiskAdapterType::from_str(s).ok()
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
/// As defined at: https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#2-the-descriptor-file
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
    static KEY_VALUE_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^([\w\.]+)\s*=\s*"?([^"]*)"?$"#).unwrap());
    let captures = KEY_VALUE_REGEX.captures(line);
    if let Some(captures) = captures {
        Some((captures.get(1).unwrap().as_str(), captures.get(2).unwrap().as_str()))
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
                    },
                    "extent" => {
                        let extent_descriptor = unwrapped_line.parse();
                        if let Ok(extent_descriptor) = extent_descriptor {
                            extent_descriptions.push(extent_descriptor);
                        }
                    },
                    "ddb" => {
                        let parsed_pair = parse_key_value_pair(unwrapped_line);
                        if let Some((key, value)) = parsed_pair {
                            ddb_hashmap.insert(key.to_string(), value.to_string());
                        }
                    },
                    "change_tracking" => {
                        let parsed_pair = parse_key_value_pair(unwrapped_line);
                        if let Some((key, value)) = parsed_pair {
                            if key == "changeTrackPath" {
                                change_track_path = Some(value.to_string());
                            }
                        }
                    },
                    _ => {},
                }
            }
            line = lines.next();
        }

        Ok(VMDKDescriptorFile {
            header: VMDKHeader::try_from(file_header_hashmap)?,
            extent_descriptions,
            change_tracking_file: if let Some(change_track_path) = change_track_path {
                Some(VMDKChangeTrackingSection {
                    change_track_path,
                })
            } else {
                None
            },
            disk_database: VMDKDiskDatabase::try_from(ddb_hashmap).ok(),
        })
    }
}

/// Represents a VMDK disk type.
/// 
/// As defined at: https://github.com/libyal/libvmdk/blame/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#212-disk-type
#[derive(Debug, EnumString, PartialEq)]
#[strum(serialize_all = "camelCase")]
enum VMDKDiskType {
    /// The disk is split into fixed-size extents of maximum 2 GB.
    /// The extents consists of RAW extent data files.
    /// 
    /// The 2GbMaxExtentFlat (or twoGbMaxExtentFlat) disk image consists of:
    /// * a descriptor file
    /// * RAW data extent files (<name>-f.vmdk), where is contains a decimal value starting with 1.
    #[strum(serialize = "2GbMaxExtentFlat")]
    TwoGbMaxExtentFlat,
    /// The disk is split into sparse (dynamic-size) extents of maximum 2 GB.
    /// The extents consists of VMDK sparse extent data files.
    /// 
    /// The 2GbMaxExtentSparse (or twoGbMaxExtentSparse) disk image consists of:
    /// * a descriptor file
    /// * VMDK sparse data extent files (<name>-s.vmdk), where is contains a decimal value starting with 1.
    #[strum(serialize = "2GbMaxExtentSparse")]
    TwoGbMaxExtentSparse,
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
    #[strum(serialize = "vmfsRDM")]
    VmfsRawDeviceMap,
    /// The disk uses a full physical disk device.
    /// Similar to the Raw Device Map (RDM), but sends SCSI commands to underlying hardware.
    #[strum(serialize = "vmfsRDMP")]
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

/// Represents a VMDK virtual disk.
pub struct VMDK {
    /// The descriptor file for the volume
    descriptor_file: VMDKDescriptorFile,
    /// List of the extent files for the volume
    extent_files: Vec<File>,
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
        // Open the descriptor file and retrieve string contents
        let descriptor_file_contents = fs::read_to_string(file_path)
           .map_err(|e| format!("Error reading descriptor file: {}", e))?;

        // Parse the descriptor file into a VMDKDescriptorFile object
        let descriptor_file: VMDKDescriptorFile = descriptor_file_contents.parse()
           .map_err(|e| format!("Error parsing descriptor file: {}", e))?;
        
        // Try to open all the identified extent files and add them to the VMDK object
        let mut extent_files_iter = descriptor_file.extent_descriptions
            .iter()
            .filter_map(|extent| {
                if let Some(ref extent_file_name) = extent.extent_file_name {
                    Some(File::open(extent_file_name)
                    .map_err(|e| format!("Error opening extent file {}: {}", extent_file_name, e)))
                } else {
                    None
                }
            });
        
        if extent_files_iter.any(|e| e.is_err()) {
            let mut err = String::from("Error opening one or more extent files:");
            for err_msg in extent_files_iter.filter_map(|e| e.err()) {
                err.push_str(&format!("\n- {}", err_msg));
            }
            return Err(err);
        } else {
            // Unwrapping should be safe here as we eliminated None values and checked that no error occurred while opening extent files
            let extent_files = extent_files_iter.map(|f| f.unwrap()).collect();
            return Ok(VMDK {
                descriptor_file,
                extent_files,
            });
        }
    }

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
                info!("  Disk Size: {} sectors", sectors);
                info!("  Disk Size: {} bytes", sectors * SECTOR_SIZE);
            }
            if let Some(ref tools) = disk_database.ddb_tools_version {
                info!("  Guest tools Version: {}", tools);
            }
            if let Some(thin_provisioned) = disk_database.ddb_thin_provisioned {
                info!("  Thin Provisioned: {}", thin_provisioned);
            }
        }
    }

    pub fn get_sector_size(&self) -> u32 {
        SECTOR_SIZE
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
        assert_eq!(descriptor.header.create_type, VMDKDiskType::TwoGbMaxExtentSparse);
        assert_eq!(descriptor.header.cid, 0x123a5678);
        assert_eq!(descriptor.header.parent_cid, 0xffffffff);
        assert_eq!(descriptor.header.is_native_snapshot, Some(false));
        assert_eq!(descriptor.extent_descriptions.get(0).unwrap().access_mode, VMDKExtentAccessMode::Rw);
        assert_eq!(descriptor.extent_descriptions.get(0).unwrap().sector_number, 4192256);
        assert_eq!(descriptor.extent_descriptions.get(0).unwrap().extent_type, VMDKExtentType::Zero);
        assert_eq!(descriptor.disk_database.unwrap().ddb_geometry_cylinders, Some(16383));
    }
}