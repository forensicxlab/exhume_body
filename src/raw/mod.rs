use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};
pub struct RAW {
    pub file: File,
    pub description: String,
}

impl RAW {
    pub fn new(file_path: &str) -> Result<RAW, String> {
        let file: &Path = Path::new(file_path);

        let fd = match File::open(file) {
            Ok(file) => file,
            Err(m) => return Err(m.to_string()),
        };

        return Ok(RAW {
            file: fd,
            description: "Reader for a RAW source file format.".to_string(),
        });
    }

    pub fn read(&mut self, size: usize) -> Vec<u8> {
        // Read data into the buffer in chunks
        let mut buffer = vec![0; size]; // Create a temporary buffer
        self.file.read_exact(&mut buffer).unwrap();
        return buffer;
    }

    pub fn seek(&mut self, offset: usize) {
        self.file.seek(SeekFrom::Start(offset as u64)).unwrap();
    }
}
