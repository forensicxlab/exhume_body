//#![no_std]

pub mod ewf;
pub mod raw;
use ewf::EWF;
use log::{error, info};
use raw::RAW;

use std::io::{Read, Result, Seek, SeekFrom};

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
            return BodyFormat::EWF {
                image: evidence,
                description: "Expert Witness Compression Format (EWF)".to_string(),
            };
        }
        // More format detections can be added here in the future.

        // Default to RAW.
        let evidence = match RAW::new(file_path) {
            Ok(evidence) => evidence,
            Err(err) => {
                error!("Error opening RAW image: {}", err);
                std::process::exit(1);
            }
        };
        BodyFormat::RAW {
            image: evidence,
            description: "Raw image format".to_string(),
        }
    }
}

impl Read for Body {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match &mut self.format {
            BodyFormat::EWF { image, .. } => image.read(buf),
            BodyFormat::RAW { image, .. } => image.read(buf),
            // TODO: Handle other compatible formats here.
        }
    }
}

impl Seek for Body {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        match &mut self.format {
            BodyFormat::EWF { image, .. } => image.seek(pos),
            BodyFormat::RAW { image, .. } => image.seek(pos),
            // TODO: Handle other compatible formats here.
        }
    }
}
