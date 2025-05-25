//! This module contains functionality for reading VMDK volumes.
//! 
//! # Known Limitations
//! 
//! For the moment VMDK descriptor files not written in UTF-8 encoding are not supported.

use std::{collections::HashMap, fs::{self, File}, io::{self, Read, Seek, SeekFrom}, path::Path, str::FromStr, sync::LazyLock, u64};

use log::{debug, error, info};
use regex::Regex;
use strum::EnumString;

const SECTOR_SIZE: u64 = 512;
const DESCRIPTOR_FILE_SIGNATURE: &'static str = "# Disk DescriptorFile";
const DESCRIPTOR_FILE_EXTENT_SECTION_SIGNATURE: &'static str = "# Extent description";
const DESCRIPTOR_FILE_CHANGE_TRACKING_SECTION_SIGNATURE: &'static str  = "# Change Tracking File";
const DESCRIPTOR_FILE_DISK_DATABASE_SECTION_SIGNATURE: &'static str = "# The Disk Data Base";

/// Represents the character encoding used for the descriptor file.
/// 
/// See also: https://github.com/libyal/libvmdk/blame/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#211-encodings
#[derive(Debug, EnumString, PartialEq, Clone)]
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
#[derive(Clone)]
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
#[derive(Debug, EnumString, PartialEq, Clone)]
#[strum(serialize_all = "UPPERCASE")]
enum VMDKExtentAccessMode {
    /// No access
    NoAccess,
    /// Read-only access
    RdOnly,
    /// Read-write access
    Rw,
}

#[derive(Debug, EnumString, PartialEq, Clone)]
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
#[derive(Clone)]
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
#[derive(Clone)]
struct VMDKChangeTrackingSection {
    /// Path of the change tracking file.
    change_track_path: String,
}

#[derive(Debug, EnumString, PartialEq, Clone)]
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


#[derive(Clone)]
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
#[derive(Clone)]
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
#[derive(Debug, EnumString, PartialEq, Clone)]
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

/// Stores a VMDK extent file handle and the associated extent information for reading actual data.
struct VMDKExtentFile {
    /// The extent description for this file
    extent_description: VMDKExtentDescriptor,
    /// The file handle for the extent file
    file: Result<File, io::Error>,
}

impl Clone for VMDKExtentFile {
    fn clone(&self) -> Self {
        let file = if self.file.is_ok() {
            self.file.as_ref().unwrap().try_clone()
        } else {
            let err = self.file.as_ref().err().unwrap();
            Err(io::Error::new(err.kind(), "Failed to clone file handle"))
        };
        Self { 
            extent_description: self.extent_description.clone(), 
            file
        }
    }
}

impl VMDKExtentFile {
    /// Reads data in the range specified by the start and end positions (relative to the first sector defined for the extent file) and stores the data into the provided buffer.
    /// 
    /// This function returns the actual data stored in the extent file after any parsing or decrompression if necessary.
    /// 
    /// # Errors
    /// 
    /// Errors if any IO error occurs while reading or if the provided range exceeds the extent file's limits.
    fn read_data(&mut self, start_pos: u64, end_pos: u64, buf: &mut [u8]) -> io::Result<usize> {
        match self.extent_description.extent_type {
            VMDKExtentType::Flat => {
                read_raw_extent(self.file.as_mut().map_err(|e| io::Error::new(e.kind(), "Error while opening file"))?, buf, start_pos)
            },
            VMDKExtentType::Sparse => todo!(),
            VMDKExtentType::Zero => {
                // Zero out the buffer
                buf.fill(0);
                Ok(buf.len())
            },
            VMDKExtentType::Vmfs => todo!(),
            VMDKExtentType::VmfsSparse => todo!(),
            VMDKExtentType::VmfsRdm => todo!(),
            VMDKExtentType::VmfsRaw => todo!(),
        }
    }
}

/// Represents a VMDK virtual disk.
#[derive(Clone)]
pub struct VMDK {
    /// The descriptor file for the volume
    descriptor_file: VMDKDescriptorFile,
    /// List of the extent files for the volume
    extent_files: Vec<VMDKExtentFile>,
    /// The position of the cursor on the disk
    position: u64,
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
        let mut vmdk_file = File::open(file_path).map_err(|e| format!("Error reading descriptor file: {}", e))?;
        let mut magic_buffer = [0u8; 4];
        let descriptor_file_contents = if vmdk_file.read(&mut magic_buffer).map_err(|e| format!("Error reading descriptor file: {}", e))? == 4
            && &magic_buffer[..] == b"KDMV" {
            debug!("Monolithic VMDK detected, extracting descriptor information");
            error!("Not implemented yet!");
            todo!();
            String::new()
        } else {
            debug!("Trying to decode standalone descriptor file");
            fs::read_to_string(file_path)
                .map_err(|e| format!("Error reading descriptor file: {}", e))?
        };

        // Parse the descriptor file into a VMDKDescriptorFile object
        let descriptor_file: VMDKDescriptorFile = descriptor_file_contents.parse()
           .map_err(|e| format!("Error parsing descriptor file: {}", e))?;
        
        debug!("Opening VMDK extent files if any");
        // Try to open all the identified extent files and add them to the VMDK object
        let extent_files: Vec<VMDKExtentFile> = descriptor_file.extent_descriptions
            .iter()
            .filter_map(|extent| {
                if let Some(ref extent_file_name) = extent.extent_file_name {
                    // Ensure the path read in the descriptor file is treated as a path relative to the descriptor file
                    // Note: the specification of VMDK does not prohibit absolute paths in the extent file name but this case is considered as 
                    // unlikely and impractical in a forensic context. This code may be corrected if the case happens in the real world.
                    let extent_file_path = Path::new(file_path).parent().unwrap_or(Path::new("")).join(extent_file_name);
                    let file = File::open(extent_file_path);
                    Some(VMDKExtentFile { 
                        extent_description: extent.clone(), 
                        file
                    })
                } else {
                    None
                }
            })
            .collect();
        
        let mut extent_files_iter = extent_files.iter();

        if extent_files_iter.any(|e| e.file.is_err()) {
            extent_files_iter = extent_files.iter();
            error!("Error opening one or more extent files:");
            for e in extent_files_iter.filter(|e| e.file.is_err()) {
                error!("- {} for {}", e.file.as_ref().err().unwrap(), e.extent_description.extent_file_name.as_ref().unwrap_or(&String::from("no name")));
            }
            return Err(String::from("Error opening one or more extent files"));
        } else {
            return Ok(VMDK {
                descriptor_file,
                extent_files,
                position: 0,
            });
        }
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
    pub fn vmdk_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // First, identify the extent file(s) that contains the data at the desired position
        let buf_len = buf.len() as u64;
        let mut extent_files = self.extent_files.iter_mut()
            .filter(|e| {
                (
                    // We want the file that contains the starting position
                    self.position >= e.extent_description.extent_start_sector.unwrap_or(0) * SECTOR_SIZE &&
                    self.position < (e.extent_description.extent_start_sector.unwrap_or(0) + e.extent_description.sector_number) * SECTOR_SIZE
                ) ||
                (
                    // We also want the file that contains the ending position (starting position + length of the buffer)
                    self.position + buf_len >= e.extent_description.extent_start_sector.unwrap_or(0) * SECTOR_SIZE &&
                    self.position + buf_len < (e.extent_description.extent_start_sector.unwrap_or(0) + e.extent_description.sector_number) * SECTOR_SIZE
                ) ||
                (
                    // And we want all the files in between
                    self.position < e.extent_description.extent_start_sector.unwrap_or(0) * SECTOR_SIZE &&
                    self.position + buf_len > (e.extent_description.extent_start_sector.unwrap_or(0) + e.extent_description.sector_number) * SECTOR_SIZE
                )
            });
        
        let mut total_read = 0;
        while let Some(extent) = extent_files.next() {
            // Find the relative position within the extent file we want depending on the structure of the extent files we recovered
            let end_of_extent = (extent.extent_description.extent_start_sector.unwrap_or(0) + extent.extent_description.sector_number) * SECTOR_SIZE;
            let start_of_extent = extent.extent_description.extent_start_sector.unwrap_or(0) * SECTOR_SIZE;
            let start_position = 
                if self.position >= start_of_extent {
                        self.position - start_of_extent
                } else {
                    0
                };
            let end_position =
                if self.position + (buf.len() as u64) >= end_of_extent {
                    end_of_extent - start_of_extent
                } else {
                    self.position + (buf.len() as u64) - start_of_extent
                };
            // Now, read the data from the extent file and update the buffer
            let buffer_start = 
                if start_of_extent <= self.position {
                    0
                } else {
                    start_of_extent - self.position
                }
                ;
            let buffer_end = (buffer_start + end_position - start_position) as usize;
            let buf_part = &mut buf[0..buffer_end];
            let read_result = extent.read_data(start_position, end_position, buf_part);
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
    pub fn vmdk_seek(&mut self, offset: SeekFrom) -> io::Result<u64> {
        // First, check that the desired position is within the bounds of the disk as defined by the extent descriptions
        // If we are in the bounds, update the current position and return the new position
        if !self.descriptor_file.extent_descriptions.is_empty() {
            let total_sectors: u64 = self.descriptor_file.extent_descriptions.iter().map(|e| e.sector_number).sum();
            let total_bytes = total_sectors * SECTOR_SIZE;
            match offset {
                SeekFrom::Start(offset) => {
                    if offset <= total_bytes {
                        self.position = offset;
                        return Ok(offset);
                    } else {
                        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Offset is out of bounds"));
                    }
                },
                SeekFrom::Current(offset) => {
                    let new_position = self.position.checked_add_signed(offset);
                    if new_position.is_some() && new_position.unwrap_or(u64::MAX) <= total_bytes {
                        self.position = new_position.unwrap_or(0);
                        return Ok(self.position);
                    } else {
                        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Offset is out of bounds"));
                    }
                },
                SeekFrom::End(offset) => {
                    let new_position = total_bytes.checked_add_signed(offset);
                    if new_position.is_some() && new_position.unwrap_or(u64::MAX) <= total_bytes {
                        self.position = new_position.unwrap_or(0);
                        return Ok(self.position);
                    } else {
                        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Offset is out of bounds"));
                    }
                },
            }
        } else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "No extent descriptions found"));
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