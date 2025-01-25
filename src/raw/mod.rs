use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

pub struct RAW {
    pub file: File,
}

impl RAW {
    pub fn new(file_path: &str) -> Result<RAW, io::Error> {
        let path = Path::new(file_path);
        let file = File::open(path)?;
        Ok(RAW { file })
    }

    pub fn read_size(&mut self, size: usize) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0; size];
        let bytes_read = self.file.read(&mut buffer)?;
        buffer.truncate(bytes_read);
        Ok(buffer)
    }

    pub fn seek_from_start(&mut self, offset: u64) -> io::Result<u64> {
        self.file.seek(SeekFrom::Start(offset))
    }
}

impl Read for RAW {
    /// Reads data from the file into the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to read data into.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` indicating the number of bytes read.
    /// * `Err(io::Error)` if an I/O error occurs.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Seek for RAW {
    /// Seeks to an offset, in bytes, in the underlying file.
    ///
    /// # Arguments
    ///
    /// * `pos` - The position to seek to, defined by the `SeekFrom` enum.
    ///
    /// # Returns
    ///
    /// * `Ok(u64)` indicating the new position after seeking.
    /// * `Err(io::Error)` if an I/O error occurs.
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}
