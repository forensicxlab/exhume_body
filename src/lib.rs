pub mod aff;
pub mod aff4;
pub mod ewf;
pub mod qcow2;
pub mod raw;
pub mod vmdk;

use aff::AFF;
use aff4::AFF4;
use ewf::EWF;
use log::{error, info};
use qcow2::QCOW2;
use raw::RAW;
use vmdk::VMDK;

use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;

/// A seekable, bounded block-volume view.
///
/// Implementations report their logical byte length and sector size without
/// requiring callers to probe the stream with `SeekFrom::End`.  This is the
/// lowest-level contract used by filesystem parsers, block transforms, and
/// streaming exporters.
pub trait VolumeReader: Read + Seek + Send {
    /// Logical length of this volume view in bytes.
    fn volume_len(&self) -> u64;

    /// Smallest addressable block size advertised by the source.
    fn sector_size(&self) -> u32;

    fn is_empty(&self) -> bool {
        self.volume_len() == 0
    }
}

#[derive(Clone)]
pub enum BodyFormat {
    RAW {
        image: raw::RAW,
        description: String,
    },
    EWF {
        image: ewf::EWF,
        description: String,
    },
    VMDK {
        image: vmdk::VMDK,
        description: String,
    },
    AFF {
        image: aff::AFF,
        description: String,
    },
    AFF4 {
        image: aff4::AFF4,
        description: String,
    },
    QCOW2 {
        image: qcow2::QCOW2,
        description: String,
    },
    // Other compatible image formats here.
}

#[derive(Clone)]
pub struct Body {
    pub path: String,
    pub format: BodyFormat,
}

impl Body {
    /// Create a new Body given a file path and a format.
    /// If the format string is "auto", the image format will be auto-detected.
    pub fn new(file_path: String, format: &str) -> Body {
        match Self::try_new(file_path, format) {
            Ok(body) => body,
            Err(err) => {
                error!("Error: {}", err);
                std::process::exit(1);
            }
        }
    }

    /// Try to create a new Body given a file path and a format.
    ///
    /// Unlike [`Body::new`], this function never terminates the calling process.
    /// It is intended for libraries and long-running applications that need to
    /// report missing, disconnected, or unreadable evidence back to their caller.
    /// If the format string is "auto", the image format will be auto-detected.
    pub fn try_new(file_path: String, format: &str) -> Result<Body, String> {
        if format == "auto" {
            return Ok(Body {
                path: file_path.clone(),
                format: Self::try_detect_format(&file_path)?,
            });
        }

        let body = match format {
            "ewf" => {
                let evidence = EWF::new(&file_path)
                    .map_err(|err| format!("failed to open EWF evidence '{file_path}': {err}"))?;
                Body {
                    path: file_path,
                    format: BodyFormat::EWF {
                        image: evidence,
                        description: "Expert Witness Compression Format".to_string(),
                    },
                }
            }
            "vmdk" => {
                let evidence = VMDK::new(&file_path)
                    .map_err(|err| format!("failed to open VMDK evidence '{file_path}': {err}"))?;
                Body {
                    path: file_path,
                    format: BodyFormat::VMDK {
                        image: evidence,
                        description: "VMDK (Virtual Machine Disk) file".to_string(),
                    },
                }
            }
            "raw" => {
                let evidence = RAW::new(&file_path)
                    .map_err(|err| format!("failed to open raw evidence '{file_path}': {err}"))?;
                Body {
                    path: file_path,
                    format: BodyFormat::RAW {
                        image: evidence,
                        description: "Raw image format".to_string(),
                    },
                }
            }
            "aff" => {
                let evidence = AFF::new(&file_path)
                    .map_err(|err| format!("failed to open AFF evidence '{file_path}': {err}"))?;
                Body {
                    path: file_path,
                    format: BodyFormat::AFF {
                        image: evidence,
                        description: "Advanced Forensics Format (AFF)".to_string(),
                    },
                }
            }
            "aff4" | "aff4l" => {
                let evidence = AFF4::new(&file_path)
                    .map_err(|err| format!("failed to open AFF4 evidence '{file_path}': {err}"))?;
                Body {
                    path: file_path,
                    format: BodyFormat::AFF4 {
                        image: evidence,
                        description: "AFF4 / AFF4-L (ImageStream)".to_string(),
                    },
                }
            }
            "qcow2" => {
                let evidence = QCOW2::new(&file_path)
                    .map_err(|err| format!("failed to open QCOW2 evidence '{file_path}': {err}"))?;
                Body {
                    path: file_path,
                    format: BodyFormat::QCOW2 {
                        image: evidence,
                        description: "QCOW2 (QEMU Copy-On-Write) image".to_string(),
                    },
                }
            }
            _ => {
                return Err(format!(
                    "invalid format '{format}'. Supported formats are 'raw', 'ewf', 'vmdk', 'aff', 'aff4', 'qcow2' or 'auto'"
                ));
            }
        };

        Ok(body)
    }

    pub fn new_from(file_path: String, format: &str, offset: Option<u64>) -> Body {
        let mut body = Body::new(file_path, format);
        if let Some(off) = offset {
            if let Err(e) = body.seek(SeekFrom::Start(off)) {
                error!("Error seeking to offset {}: {}", off, e);
                std::process::exit(1);
            }
        }
        body
    }

    pub fn print_info(&self) {
        info!("Evidence : {}", self.path);
        match &self.format {
            BodyFormat::EWF { image, .. } => image.print_info(),
            BodyFormat::VMDK { image, .. } => image.print_info(),
            BodyFormat::AFF { image, .. } => image.print_info(),
            BodyFormat::AFF4 { image, .. } => image.print_info(),
            BodyFormat::QCOW2 { image, .. } => image.print_info(),
            BodyFormat::RAW { .. } => (),
            // All other compatible formats are handled here.
        }
    }

    pub fn get_sector_size(&self) -> u16 {
        match &self.format {
            BodyFormat::EWF { image, .. } => image.get_sector_size(),
            BodyFormat::VMDK { image, .. } => image.get_sector_size() as u16,
            BodyFormat::AFF { image, .. } => image.get_sector_size(),
            BodyFormat::AFF4 { image, .. } => image.get_sector_size(),
            BodyFormat::QCOW2 { image, .. } => image.get_sector_size(),
            BodyFormat::RAW { .. } => 512,
            // All other compatible formats are handled here.
        }
    }

    /// Returns the logical (uncompressed) size of the disk image in bytes.
    ///
    /// For compressed formats (AFF4, EWF, AFF) this is the declared logical size from
    /// the image metadata, not the size of the container file on disk.
    pub fn get_image_size(&self) -> u64 {
        match &self.format {
            BodyFormat::EWF { image, .. } => image.get_image_size(),
            BodyFormat::VMDK { image, .. } => image.get_image_size(),
            BodyFormat::RAW { image, .. } => image.get_image_size(),
            BodyFormat::AFF { image, .. } => image.get_image_size(),
            BodyFormat::AFF4 { image, .. } => image.get_image_size(),
            BodyFormat::QCOW2 { image, .. } => image.get_image_size(),
        }
    }

    /// Returns a reference to the format description.
    pub fn format_description(&self) -> &str {
        match &self.format {
            BodyFormat::EWF { description, .. } => description,
            BodyFormat::VMDK { description, .. } => description,
            BodyFormat::RAW { description, .. } => description,
            BodyFormat::AFF { description, .. } => description,
            BodyFormat::AFF4 { description, .. } => description,
            BodyFormat::QCOW2 { description, .. } => description,
            // Handle additional formats here.
        }
    }

    /// Canonical paths of every file that backs this evidence stream.
    ///
    /// Multi-segment EWF images, descriptor-based VMDKs and QCOW2 images with a
    /// backing chain or an external data file can read files other than the
    /// path supplied to [`Body::try_new`]. Exporters must protect every
    /// returned path from output/staging collisions and bind resumable work to
    /// metadata for the complete set.
    pub fn backing_paths(&self) -> Result<Vec<PathBuf>, String> {
        let mut paths = match &self.format {
            BodyFormat::EWF { image, .. } => image.backing_paths().to_vec(),
            BodyFormat::VMDK { image, .. } => image.backing_paths(),
            BodyFormat::QCOW2 { image, .. } => image.backing_paths(),
            BodyFormat::RAW { .. } | BodyFormat::AFF { .. } | BodyFormat::AFF4 { .. } => {
                vec![PathBuf::from(&self.path).canonicalize().map_err(|error| {
                    format!(
                        "cannot resolve evidence backing path {}: {error}",
                        self.path
                    )
                })?]
            }
        };
        if paths.is_empty() {
            return Err("evidence body has no backing files".to_owned());
        }
        paths.sort();
        paths.dedup();
        Ok(paths)
    }

    /// Detect the image format by attempting to create each format.
    /// Currently, tries EWF first then falls back to RAW.
    fn try_detect_format(file_path: &str) -> Result<BodyFormat, String> {
        // Try EWF detection first.
        if let Ok(evidence) = EWF::new(file_path) {
            info!("Detected an EWF disk image.");
            return Ok(BodyFormat::EWF {
                image: evidence,
                description: "Expert Witness Compression Format (EWF)".to_string(),
            });
        }

        // Then try VMDK detection.
        if let Ok(evidence) = VMDK::new(file_path) {
            info!("Detected a VMDK disk image.");
            return Ok(BodyFormat::VMDK {
                image: evidence,
                description: "VMDK (Virtual Machine Disk) file".to_string(),
            });
        }

        // Then QCOW2. Its magic is unambiguous, so a file that carries it but
        // cannot be opened (missing backing file, encryption, ...) must report
        // that error rather than silently fall through to RAW.
        if QCOW2::probe(file_path) {
            let evidence = QCOW2::new(file_path)
                .map_err(|err| format!("failed to open QCOW2 evidence '{file_path}': {err}"))?;
            info!("Detected a QCOW2 disk image.");
            return Ok(BodyFormat::QCOW2 {
                image: evidence,
                description: "QCOW2 (QEMU Copy-On-Write) image".to_string(),
            });
        }

        // Then try AFF detection.
        if let Ok(evidence) = AFF::new(file_path) {
            info!("Detected an AFF disk image.");
            return Ok(BodyFormat::AFF {
                image: evidence,
                description: "Advanced Forensics Format (AFF)".to_string(),
            });
        }

        // Then try AFF4 detection.
        if let Ok(evidence) = AFF4::new(file_path) {
            info!("Detected an AFF4/AFF4-L volume (ImageStream).");
            return Ok(BodyFormat::AFF4 {
                image: evidence,
                description: "AFF4 / AFF4-L (ImageStream)".to_string(),
            });
        }

        // Default to RAW.
        match RAW::new(file_path) {
            Ok(evidence) => {
                info!("Detected RAW Data");
                Ok(BodyFormat::RAW {
                    image: evidence,
                    description: "Raw image format".to_string(),
                })
            }
            Err(err) => Err(format!("failed to open evidence '{file_path}': {err}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Body;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn missing_test_path() -> String {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "exhume-body-missing-{}-{unique}.raw",
                std::process::id()
            ))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn try_new_returns_an_error_for_a_missing_path() {
        let path = missing_test_path();
        let error = match Body::try_new(path.clone(), "auto") {
            Ok(_) => panic!("a missing evidence path must not open"),
            Err(error) => error,
        };

        assert!(error.contains(&path));
        assert!(error.contains("failed to open evidence"));
    }

    #[test]
    fn try_new_propagates_an_invalid_format_error() {
        let error = match Body::try_new(missing_test_path(), "unsupported") {
            Ok(_) => panic!("an unsupported evidence format must not open"),
            Err(error) => error,
        };

        assert!(error.contains("invalid format 'unsupported'"));
    }

    #[test]
    fn raw_body_reports_its_canonical_backing_path() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("evidence.raw");
        fs::write(&source, vec![0u8; 512]).unwrap();
        let body = Body::try_new(source.to_string_lossy().into_owned(), "raw").unwrap();

        assert_eq!(
            body.backing_paths().unwrap(),
            vec![source.canonicalize().unwrap()]
        );
    }
}

impl Read for Body {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.format {
            BodyFormat::EWF { image, .. } => image.read(buf),
            BodyFormat::VMDK { image, .. } => image.read(buf),
            BodyFormat::RAW { image, .. } => image.read(buf),
            BodyFormat::AFF { image, .. } => image.read(buf),
            BodyFormat::AFF4 { image, .. } => image.read(buf),
            BodyFormat::QCOW2 { image, .. } => image.read(buf),
            // TODO: Handle other compatible formats here.
        }
    }
}

impl Seek for Body {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match &mut self.format {
            BodyFormat::EWF { image, .. } => image.seek(pos),
            BodyFormat::VMDK { image, .. } => image.seek(pos),
            BodyFormat::RAW { image, .. } => image.seek(pos),
            BodyFormat::AFF { image, .. } => image.seek(pos),
            BodyFormat::AFF4 { image, .. } => image.seek(pos),
            BodyFormat::QCOW2 { image, .. } => image.seek(pos),
            // TODO: Handle other compatible formats here.
        }
    }
}

impl VolumeReader for Body {
    fn volume_len(&self) -> u64 {
        self.get_image_size()
    }

    fn sector_size(&self) -> u32 {
        u32::from(self.get_sector_size())
    }
}

pub struct BodySlice {
    body: Body,
    slice_start: u64,
    slice_len: u64,
    pos: u64,
}

impl BodySlice {
    pub fn new(src: &Body, slice_start: u64, slice_len: u64) -> io::Result<Self> {
        let slice_end = slice_start.checked_add(slice_len).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "slice start plus length overflows u64",
            )
        })?;
        let image_len = src.get_image_size();
        if slice_end > image_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("slice range {slice_start}..{slice_end} exceeds image length {image_len}"),
            ));
        }

        let mut body = src.clone();
        body.seek(SeekFrom::Start(slice_start))?;
        Ok(Self {
            body,
            slice_start,
            slice_len,
            pos: 0,
        })
    }

    /// Absolute byte offset of this slice in its parent image.
    pub fn start(&self) -> u64 {
        self.slice_start
    }

    /// Logical length of this slice in bytes.
    pub fn len(&self) -> u64 {
        self.slice_len
    }

    pub fn is_empty(&self) -> bool {
        self.slice_len == 0
    }

    /// Current cursor relative to the beginning of the slice.
    pub fn position(&self) -> u64 {
        self.pos
    }

    pub fn sector_size(&self) -> u32 {
        u32::from(self.body.get_sector_size())
    }
}

impl Read for BodySlice {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.slice_len {
            return Ok(0);
        }
        let max = std::cmp::min(buf.len() as u64, self.slice_len - self.pos) as usize;

        // Some image backends clone OS file handles whose physical cursor may
        // be shared. Reassert this slice's logical cursor before every read so
        // independently cloned slices cannot move one another unexpectedly.
        let absolute = self.slice_start.checked_add(self.pos).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "absolute read position overflow",
            )
        })?;
        self.body.seek(SeekFrom::Start(absolute))?;
        let n = self.body.read(&mut buf[..max])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for BodySlice {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(off) => off,
            SeekFrom::Current(off) => checked_offset(self.pos, off)?,
            SeekFrom::End(off) => checked_offset(self.slice_len, off)?,
        };

        if new_pos > self.slice_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek out of slice",
            ));
        }

        let absolute = self.slice_start.checked_add(new_pos).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "absolute seek position overflow",
            )
        })?;
        self.body.seek(SeekFrom::Start(absolute))?;
        self.pos = new_pos;
        Ok(self.pos)
    }
}

fn checked_offset(base: u64, offset: i64) -> io::Result<u64> {
    let target = if offset >= 0 {
        base.checked_add(offset as u64)
    } else {
        base.checked_sub(offset.unsigned_abs())
    };
    target.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "seek position is before start or overflows u64",
        )
    })
}

impl VolumeReader for BodySlice {
    fn volume_len(&self) -> u64 {
        self.slice_len
    }

    fn sector_size(&self) -> u32 {
        BodySlice::sector_size(self)
    }
}

impl Clone for BodySlice {
    fn clone(&self) -> Self {
        Self {
            body: self.body.clone(),
            slice_start: self.slice_start,
            slice_len: self.slice_len,
            pos: self.pos,
        }
    }
}

#[cfg(test)]
mod body_slice_tests {
    use super::{Body, BodySlice, VolumeReader};
    use std::fs;
    use std::io::{Read, Seek, SeekFrom};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestImage {
        path: String,
    }

    impl TestImage {
        fn new(bytes: &[u8]) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock before Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!(
                    "exhume-body-slice-{}-{unique}.raw",
                    std::process::id()
                ))
                .to_string_lossy()
                .into_owned();
            fs::write(&path, bytes).unwrap();
            Self { path }
        }
    }

    impl Drop for TestImage {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    #[test]
    fn slice_rejects_overflow_and_ranges_beyond_image() {
        let image = TestImage::new(&[0; 1024]);
        let body = Body::try_new(image.path.clone(), "raw").unwrap();

        assert!(BodySlice::new(&body, u64::MAX, 2).is_err());
        assert!(BodySlice::new(&body, 512, 513).is_err());
        assert!(BodySlice::new(&body, 1025, 0).is_err());
    }

    #[test]
    fn slice_reads_exact_bounds_and_supports_checked_seeks() {
        let bytes: Vec<u8> = (0..2048).map(|value| (value % 251) as u8).collect();
        let image = TestImage::new(&bytes);
        let body = Body::try_new(image.path.clone(), "raw").unwrap();
        let mut slice = BodySlice::new(&body, 512, 1024).unwrap();

        assert_eq!(slice.start(), 512);
        assert_eq!(slice.len(), 1024);
        assert_eq!(slice.volume_len(), 1024);
        assert_eq!(slice.sector_size(), 512);

        let mut output = Vec::new();
        slice.read_to_end(&mut output).unwrap();
        assert_eq!(output, bytes[512..1536]);
        assert_eq!(slice.position(), 1024);
        assert_eq!(slice.read(&mut [0; 1]).unwrap(), 0);

        assert_eq!(slice.seek(SeekFrom::End(-16)).unwrap(), 1008);
        assert!(slice.seek(SeekFrom::Current(-1009)).is_err());
        assert_eq!(slice.position(), 1008);
        assert!(slice.seek(SeekFrom::End(1)).is_err());
        assert_eq!(slice.position(), 1008);
    }

    #[test]
    fn cloned_slice_keeps_an_independent_cursor() {
        let bytes: Vec<u8> = (0..1024).map(|value| (value % 251) as u8).collect();
        let image = TestImage::new(&bytes);
        let body = Body::try_new(image.path.clone(), "raw").unwrap();
        let mut original = BodySlice::new(&body, 0, 1024).unwrap();
        original.seek(SeekFrom::Start(512)).unwrap();
        let mut cloned = original.clone();

        cloned.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(original.position(), 512);
        assert_eq!(cloned.position(), 0);

        let mut original_byte = [0_u8; 1];
        let mut cloned_byte = [0_u8; 1];
        original.read_exact(&mut original_byte).unwrap();
        cloned.read_exact(&mut cloned_byte).unwrap();
        assert_eq!(original_byte[0], bytes[512]);
        assert_eq!(cloned_byte[0], bytes[0]);
        assert_eq!(original.position(), 513);
        assert_eq!(cloned.position(), 1);
    }
}
