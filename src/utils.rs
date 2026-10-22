//! Internal binary-reading primitives shared by image formats.
//!
//! These helpers do not interpret format structures or decide whether a short
//! container should be rejected or padded. Callers retain those policies.

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};

#[derive(Debug)]
pub(crate) struct DecodeError {
    offset: usize,
    width: usize,
    len: usize,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}-byte field at offset {} exceeds buffer length {}",
            self.width, self.offset, self.len
        )
    }
}

impl std::error::Error for DecodeError {}

impl From<DecodeError> for String {
    fn from(error: DecodeError) -> Self {
        error.to_string()
    }
}

impl From<DecodeError> for io::Error {
    fn from(error: DecodeError) -> Self {
        Self::new(io::ErrorKind::UnexpectedEof, error)
    }
}

fn field<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], DecodeError> {
    let bytes = offset
        .checked_add(N)
        .and_then(|end| data.get(offset..end))
        .ok_or(DecodeError {
            offset,
            width: N,
            len: data.len(),
        })?;
    let mut value = [0; N];
    value.copy_from_slice(bytes);
    Ok(value)
}

pub(crate) fn le_u16(data: &[u8], offset: usize) -> Result<u16, DecodeError> {
    Ok(u16::from_le_bytes(field(data, offset)?))
}

pub(crate) fn le_u32(data: &[u8], offset: usize) -> Result<u32, DecodeError> {
    Ok(u32::from_le_bytes(field(data, offset)?))
}

pub(crate) fn le_u64(data: &[u8], offset: usize) -> Result<u64, DecodeError> {
    Ok(u64::from_le_bytes(field(data, offset)?))
}

pub(crate) fn le_i64(data: &[u8], offset: usize) -> Result<i64, DecodeError> {
    Ok(i64::from_le_bytes(field(data, offset)?))
}

pub(crate) fn be_u16(data: &[u8], offset: usize) -> Result<u16, DecodeError> {
    Ok(u16::from_be_bytes(field(data, offset)?))
}

pub(crate) fn be_u32(data: &[u8], offset: usize) -> Result<u32, DecodeError> {
    Ok(u32::from_be_bytes(field(data, offset)?))
}

pub(crate) fn be_u64(data: &[u8], offset: usize) -> Result<u64, DecodeError> {
    Ok(u64::from_be_bytes(field(data, offset)?))
}

pub(crate) fn invalid_data(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Seek to `offset` and fill `buf`, failing with `UnexpectedEof` on a short read.
///
/// This advances the underlying cursor. It is not an atomic positional read:
/// duplicated file handles that share a cursor still require synchronization.
pub(crate) fn read_exact_at<R: Read + Seek + ?Sized>(
    reader: &mut R,
    offset: u64,
    buf: &mut [u8],
) -> io::Result<()> {
    reader.seek(SeekFrom::Start(offset))?;
    reader.read_exact(buf)
}

/// Seek and read until EOF or a full buffer, padding any unread tail with zeros.
/// Returns the number of bytes actually read. Other I/O errors are propagated.
/// Like `read_exact_at`, this advances a potentially shared underlying cursor.
pub(crate) fn read_zero_padded_at<R: Read + Seek + ?Sized>(
    reader: &mut R,
    offset: u64,
    buf: &mut [u8],
) -> io::Result<usize> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    buf[filled..].fill(0);
    Ok(filled)
}

/// Add a signed displacement without wrapping or casting the base to `i64`.
/// Bounds relative to a particular image are deliberately checked by callers.
pub(crate) fn checked_offset(base: u64, offset: i64) -> io::Result<u64> {
    base.checked_add_signed(offset).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "seek position is before start or overflows u64",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn decodes_unaligned_fields_in_both_byte_orders() {
        let data = [0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(le_u16(&data, 1).unwrap(), 0x2301);
        assert_eq!(be_u16(&data, 1).unwrap(), 0x0123);
        assert_eq!(le_u32(&data, 1).unwrap(), 0x67452301);
        assert_eq!(be_u32(&data, 1).unwrap(), 0x01234567);
        assert_eq!(le_u64(&data, 1).unwrap(), 0xefcdab8967452301);
        assert_eq!(be_u64(&data, 1).unwrap(), 0x0123456789abcdef);
        assert_eq!(le_i64(&i64::MIN.to_le_bytes(), 0).unwrap(), i64::MIN);
        assert_eq!(le_i64(&(-1i64).to_le_bytes(), 0).unwrap(), -1);
    }

    #[test]
    fn rejects_short_fields_and_overflowing_offsets_without_panicking() {
        fn check<T: fmt::Debug>(decode: fn(&[u8], usize) -> Result<T, DecodeError>, width: usize) {
            for len in 0..width {
                let data = vec![0; len];
                assert!(decode(&data, 0).is_err());
            }
            assert!(decode(&[0; 16], usize::MAX).is_err());
            assert!(decode(&[0; 16], 16).is_err());
            assert!(decode(&[0; 16], 17 - width).is_err());
        }
        check(le_u16, 2);
        check(be_u16, 2);
        check(le_u32, 4);
        check(be_u32, 4);
        check(le_u64, 8);
        check(be_u64, 8);
        check(le_i64, 8);

        let error = le_u64(&[0; 7], 0).unwrap_err();
        let message = error.to_string();
        let io_error: io::Error = error.into();
        assert_eq!(io_error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(io_error.to_string(), message);
        let string_error: String = le_u64(&[0; 7], 0).unwrap_err().into();
        assert_eq!(string_error, message);
    }

    struct ShortReader {
        data: Cursor<Vec<u8>>,
        interrupt_next: bool,
        fail_at: Option<u64>,
        fail_seek: bool,
    }

    impl ShortReader {
        fn new() -> Self {
            Self {
                data: Cursor::new(b"abcdef".to_vec()),
                interrupt_next: true,
                fail_at: None,
                fail_seek: false,
            }
        }
    }

    impl Read for ShortReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if std::mem::take(&mut self.interrupt_next) {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            if self.fail_at.is_some_and(|at| self.data.position() >= at) {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            let len = buf.len().min(2);
            self.data.read(&mut buf[..len])
        }
    }

    impl Seek for ShortReader {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            if self.fail_seek {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            self.data.seek(pos)
        }
    }

    #[test]
    fn exact_reads_retry_interruptions_and_short_reads() {
        let mut reader = ShortReader::new();
        let mut buf = [0; 5];
        read_exact_at(&mut reader, 1, &mut buf).unwrap();
        assert_eq!(&buf, b"bcdef");
        assert_eq!(reader.data.position(), 6);
        assert_eq!(
            read_exact_at(&mut reader, 4, &mut buf).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn padded_reads_report_actual_length_and_only_pad_at_eof() {
        let mut reader = ShortReader::new();
        let mut buf = [0xff; 8];
        assert_eq!(read_zero_padded_at(&mut reader, 1, &mut buf).unwrap(), 5);
        assert_eq!(&buf, b"bcdef\0\0\0");
        assert_eq!(reader.data.position(), 6);
        buf.fill(0xff);
        assert_eq!(read_zero_padded_at(&mut reader, 100, &mut buf).unwrap(), 0);
        assert_eq!(buf, [0; 8]);
        assert_eq!(read_zero_padded_at(&mut reader, 3, &mut []).unwrap(), 0);
        assert_eq!(reader.data.position(), 3);
    }

    #[test]
    fn read_helpers_propagate_seek_and_non_eof_read_errors() {
        for padded in [false, true] {
            let read = |reader: &mut ShortReader, buf: &mut [u8]| {
                if padded {
                    read_zero_padded_at(reader, 0, buf).map(|_| ())
                } else {
                    read_exact_at(reader, 0, buf)
                }
            };
            let mut reader = ShortReader::new();
            reader.fail_seek = true;
            let mut buf = [0xff; 8];
            assert_eq!(
                read(&mut reader, &mut buf).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(buf, [0xff; 8]);

            reader.fail_seek = false;
            reader.fail_at = Some(2);
            assert_eq!(
                read(&mut reader, &mut buf).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(&buf[..2], b"ab");
            assert_eq!(&buf[2..], &[0xff; 6]);
        }
    }

    #[test]
    fn seek_arithmetic_handles_the_full_u64_range() {
        assert_eq!(checked_offset(1 << 63, i64::MIN).unwrap(), 0);
        assert_eq!(checked_offset(u64::MAX, i64::MIN).unwrap(), i64::MAX as u64);
        assert_eq!(checked_offset(i64::MAX as u64, 1).unwrap(), 1 << 63);
        assert_eq!(checked_offset(0, 0).unwrap(), 0);
        for (base, offset) in [(0, -1), (u64::MAX, 1), (0, i64::MIN)] {
            assert_eq!(
                checked_offset(base, offset).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}
