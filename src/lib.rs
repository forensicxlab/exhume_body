pub mod ewf;
pub mod raw;

use ewf::EWF;
use raw::RAW;

use std::io::{self, BufReader, Read, Seek, SeekFrom};

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

    pub fn read(&mut self, size: usize) -> Vec<u8> {
        let mut buffer = vec![0; size];
        match self.format {
            BodyFormat::EWF { ref mut image, .. } => {
                let bytes_read = image.read(&mut buffer).unwrap();
                println!(
                    "Read {} bytes using the EWF format method directly.",
                    bytes_read
                );
                buffer
            }
            BodyFormat::RAW { ref mut image, .. } => image.read(size),
            // All other compatible formats will be handled here.
        }
    }

    pub fn seek(&mut self, offset: u64) {
        match self.format {
            BodyFormat::EWF { ref mut image, .. } => {
                let u = image.seek(SeekFrom::Start(offset)).unwrap();
            }
            BodyFormat::RAW { ref mut image, .. } => image.seek(offset),
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
}
