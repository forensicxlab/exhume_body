//! RAW file abstraction
//!
//! This module provides the [`RAW`] struct, a thin wrapper around [`std::fs::File`]
//! that implements [`std::io::Read`] and [`std::io::Seek`].
//!

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::Path,
};

/// A simple, clonable wrapper around a [`File`] that represents a RAW binary stream.
///
/// This wrapper allows random access (`Seek`) and buffered reads (`Read`)
/// while also exposing convenience helpers to read fixed-size blocks and
/// to reposition the cursor.
///
/// Cloning a [`RAW`] duplicates the underlying file handle using
/// [`File::try_clone`], so both instances share the same file but maintain
/// independent cursors.
pub struct RAW {
    /// The underlying file handle.
    pub file: File,
}

impl RAW {
    /// Opens the file at `file_path` and returns a new [`RAW`] wrapper.
    ///
    /// # Errors
    ///
    /// Returns any [`io::Error`] produced by [`File::open`], e.g. when the
    /// path does not exist or the process lacks sufficient permissions.
    pub fn new(file_path: &str) -> Result<RAW, io::Error> {
        let path = Path::new(file_path);
        let file = File::open(path)?;
        Ok(RAW { file })
    }

    /// Reads exactly `size` bytes (or until EOF) from the current cursor
    /// position into a newly-allocated `Vec<u8>` and returns it.
    ///
    /// The returned vector is truncated to the actual number of bytes read,
    /// so its length may be smaller than `size` at end-of-file.
    ///
    /// # Errors
    ///
    /// Propagates any I/O error returned by [`Read::read`].
    pub fn read_size(&mut self, size: usize) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0; size];
        let bytes_read = self.file.read(&mut buffer)?;
        buffer.truncate(bytes_read);
        Ok(buffer)
    }

    /// Repositions the file cursor to `offset` bytes from the beginning
    /// of the file and returns the new position.
    ///
    /// # Errors
    ///
    /// Propagates any I/O error returned by [`Seek::seek`].
    pub fn seek_from_start(&mut self, offset: u64) -> io::Result<u64> {
        self.file.seek(SeekFrom::Start(offset))
    }
}

impl Clone for RAW {
    /// Clones the [`RAW`] instance by duplicating the underlying file handle.
    ///
    /// Cloning is cheap (just a file-descriptor duplication) but note that
    /// the new handle has a *separate* seek position.
    ///
    /// # Panics
    ///
    /// Panics if [`File::try_clone`] fails—this usually indicates running
    /// out of file descriptors or OS-level resource limits.
    fn clone(&self) -> Self {
        Self {
            file: self
                .file
                .try_clone()
                .expect("failed to clone RAW file handle"),
        }
    }
}

impl Read for RAW {
    /// Reads data from the underlying file into `buf` and returns the number of bytes read.
    ///
    /// This just forwards to [`File::read`].
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Seek for RAW {
    /// Seeks within the underlying file, delegating to [`File::seek`].
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}
