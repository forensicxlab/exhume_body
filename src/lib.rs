//#![no_std]

pub mod ewf;
pub mod raw;
use ewf::EWF;
use log::{error, info};
use raw::RAW;

use std::io::{self, Read, Seek, SeekFrom};

pub enum BodyFormat {
    RAW {
        image: raw::RAW,
        description: String,
    },
    EWF {
        image: ewf::EWF,
        description: String,
    },
    // Other compatible image formats here.
}

pub struct Body {
    pub path: String,
    pub format: BodyFormat,
}

impl Body {
    /// Create a new Body given a file path and a format.
    /// If the format string is "auto", the image format will be auto-detected.
    pub fn new(file_path: String, format: &str) -> Body {
        if format == "auto" {
            return Body {
                path: file_path.clone(),
                format: Self::detect_format(&file_path),
            };
        }

        match format {
            "ewf" => {
                let evidence = match EWF::new(&file_path) {
                    Ok(ewf) => ewf,
                    Err(err) => {
                        error!("Error: {}", err);
                        std::process::exit(1);
                    }
                };
                Body {
                    path: file_path,
                    format: BodyFormat::EWF {
                        image: evidence,
                        description: "Expert Witness Compression Format".to_string(),
                    },
                }
            }
            "raw" => {
                let evidence = match RAW::new(&file_path) {
                    Ok(evidence) => evidence,
                    Err(err) => {
                        error!("Error: {}", err);
                        std::process::exit(1);
                    }
                };
                Body {
                    path: file_path,
                    format: BodyFormat::RAW {
                        image: evidence,
                        description: "Raw image format".to_string(),
                    },
                }
            }
            _ => {
                error!(
                    "Error: Invalid format '{}'. Supported formats are 'raw', 'ewf', or 'auto'.",
                    format
                );
                std::process::exit(1);
            }
        }
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
            BodyFormat::RAW { .. } => (),
            // All other compatible formats will be handled here.
        }
    }

    pub fn get_sector_size(&self) -> u16 {
        match &self.format {
            BodyFormat::EWF { image, .. } => image.get_sector_size(),
            BodyFormat::RAW { .. } => 512,
            // All other compatible formats will be handled here.
        }
    }

    /// Returns a reference to the format description.
    pub fn format_description(&self) -> &str {
        match &self.format {
            BodyFormat::EWF { description, .. } => description,
            BodyFormat::RAW { description, .. } => description,
            // Handle additional formats here.
        }
    }

    /// Detect the image format by attempting to create each format.
    /// Currently, tries EWF first then falls back to RAW.
    fn detect_format(file_path: &str) -> BodyFormat {
        // Try EWF detection first.
        if let Ok(evidence) = EWF::new(file_path) {
            info!("Detected an EWF disk image.");
            return BodyFormat::EWF {
                image: evidence,
                description: "Expert Witness Compression Format (EWF)".to_string(),
            };
        }

        // Default to RAW.
        match RAW::new(file_path) {
            Ok(evidence) => {
                info!("Detected RAW Data");
                return BodyFormat::RAW {
                    image: evidence,
                    description: "Raw image format".to_string(),
                };
            }
            Err(err) => {
                error!("Error opening data: {}", err);
                std::process::exit(1);
            }
        };
    }
}

impl Read for Body {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.format {
            BodyFormat::EWF { image, .. } => image.read(buf),
            BodyFormat::RAW { image, .. } => image.read(buf),
            // TODO: Handle other compatible formats here.
        }
    }
}

impl Seek for Body {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match &mut self.format {
            BodyFormat::EWF { image, .. } => image.seek(pos),
            BodyFormat::RAW { image, .. } => image.seek(pos),
            // TODO: Handle other compatible formats here.
        }
    }
}

pub struct BodySlice<'a> {
    body: &'a mut Body,
    slice_start: u64,
    slice_len: u64,
    pos: u64, // relative position within the slice
}

impl<'a> BodySlice<'a> {
    /// Creates a new BodySlice starting at `slice_start` with length `slice_len`.
    /// Seeks the underlying Body to the starting offset.
    pub fn new(body: &'a mut Body, slice_start: u64, slice_len: u64) -> io::Result<BodySlice<'a>> {
        body.seek(SeekFrom::Start(slice_start))?;
        Ok(BodySlice {
            body,
            slice_start,
            slice_len,
            pos: 0,
        })
    }
}

impl<'a> Read for BodySlice<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.slice_len {
            return Ok(0); // End of slice
        }
        // Calculate how many bytes we can read without exceeding the slice limit
        let max = std::cmp::min(buf.len() as u64, self.slice_len - self.pos) as usize;
        let n = self.body.read(&mut buf[..max])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<'a> Seek for BodySlice<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(off) => off,
            SeekFrom::Current(off) => {
                let pos = self.pos as i64 + off;
                if pos < 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "negative seek"));
                }
                pos as u64
            }
            SeekFrom::End(off) => {
                let pos = self.slice_len as i64 + off;
                if pos < 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "negative seek"));
                }
                pos as u64
            }
        };

        if new_pos > self.slice_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek out of bounds",
            ));
        }
        // Move the underlying body to the new absolute position
        self.body
            .seek(SeekFrom::Start(self.slice_start + new_pos))?;
        self.pos = new_pos;
        Ok(new_pos)
    }
}
