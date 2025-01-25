pub mod ewf;
pub mod raw;

use ewf::EWF;
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
    }, // Other compatible image formats here
}
pub struct Body {
    path: String,
    format: BodyFormat,
}

impl Body {
    pub fn new(file_path: String, format: &str) -> Body {
        match format {
            "ewf" => {
                let evidence = match EWF::new(&file_path) {
                    Ok(ewf) => ewf,
                    Err(err) => {
                        eprintln!("Error: {}", err);
                        std::process::exit(1);
                    }
                };
                return Body {
                    path: file_path,
                    format: BodyFormat::EWF {
                        image: evidence,
                        description: "Expert Witness Compression Format".to_string(),
                    },
                };
            }
            "raw" => {
                let evidence = match RAW::new(&file_path) {
                    Ok(evidence) => evidence,
                    Err(err) => {
                        eprintln!("Error: {}", err);
                        std::process::exit(1);
                    }
                };

                return Body {
                    path: file_path,
                    format: BodyFormat::RAW {
                        image: evidence,
                        description: "Expert Witness Compression Format".to_string(),
                    },
                };
            }
            _ => {
                eprintln!(
                    "Error: Invalid format '{}'. Supported formats are 'raw' and 'ewf'.",
                    format
                );
                std::process::exit(1);
            }
        }
    }

    pub fn print_info(&self) {
        println!("Evidence : {}", self.path);
    }

    pub fn get_sector_size(&self) -> u16 {
        match &self.format {
            BodyFormat::EWF { image, .. } => image.get_sector_size(),
            BodyFormat::RAW { .. } => 512,
            // All other compatible formats will be handled here.
        }
    }
}

impl Read for Body {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match &mut self.format {
            BodyFormat::EWF { image, .. } => {
                let bytes_read = image.read(buf)?;
                println!(
                    "Read {} bytes using the EWF format method directly.",
                    bytes_read
                );
                Ok(bytes_read)
            }
            BodyFormat::RAW { image, .. } => image.read(buf),
            // Handle other compatible formats here.
            // BodyFormat::Other { image, .. } => image.read(buf),
        }
    }
}

impl Seek for Body {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        match &mut self.format {
            BodyFormat::EWF { image, .. } => {
                let new_pos = image.seek(pos)?;
                Ok(new_pos)
            }
            BodyFormat::RAW { image, .. } => image.seek(pos),
            // Handle other compatible formats here.
            // BodyFormat::Other { image, .. } => image.seek(pos),
        }
    }
}
