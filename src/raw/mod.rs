use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};
pub struct RAW {
    image: File,
    _description: String,
}

impl RAW {
    pub fn new(file_path: &str) -> Result<RAW, String> {
        let file: &Path = Path::new(file_path);

        let fd = match File::open(file) {
            Ok(file) => file,
            Err(m) => return Err(m.to_string()),
        };

        return Ok(RAW {
            image: fd,
            _description: "RAW image format".to_string(),
        });
    }

    pub fn read(&mut self, size: usize) -> Vec<u8> {
        // Read data into the buffer in chunks
        let mut buffer = vec![0; size]; // Create a temporary buffer
        self.image.read_exact(&mut buffer).unwrap();
        return buffer;
    }

    pub fn seek(&mut self, offset: usize) {
        self.image.seek(SeekFrom::Start(offset as u64)).unwrap();
    }
}
