//! Structural input ceilings; these are not exact allocator/RSS accounting.
use std::io::{Read, Seek, SeekFrom};
use std::time::Instant;

use crate::{Error, Result};

pub(crate) const FEED_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const CHECKSUM_BYTES: usize = 1024 * 1024;
pub(crate) const SIGNATURE_BYTES: usize = 64 * 1024;
pub(crate) const ARTIFACT_BYTES: usize = 256 * 1024 * 1024;
pub(crate) const BINARY_BYTES: usize = 256 * 1024 * 1024;
pub(crate) const MARKER_BYTES: usize = 1024 * 1024;

pub(crate) fn append(bytes: &mut Vec<u8>, chunk: &[u8], limit: usize) -> Result<()> {
    let needed = bytes
        .len()
        .checked_add(chunk.len())
        .ok_or_else(|| Error::msg("updater byte count overflow"))?;
    if needed > limit {
        return Err(Error::msg("updater byte limit exceeded"));
    }
    if needed > bytes.capacity() {
        // Bound retained capacity without quadratic copying on tiny chunks.
        let capacity = needed
            .max(bytes.capacity().max(8192).saturating_mul(2))
            .min(limit);
        bytes
            .try_reserve_exact(capacity - bytes.len())
            .map_err(|_| Error::msg("updater buffer allocation refused"))?;
    }
    bytes.extend_from_slice(chunk);
    Ok(())
}

pub(crate) fn read(mut reader: impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        // Read at most one extra byte to distinguish exact fit from overflow,
        // and never retain the overflow byte in the result allocation.
        let window = buffer
            .len()
            .min(limit.saturating_sub(bytes.len()).saturating_add(1));
        let count = reader.read(&mut buffer[..window])?;
        if count == 0 {
            return Ok(bytes);
        }
        append(&mut bytes, &buffer[..count], limit)?;
    }
}

pub(crate) fn file(path: &std::path::Path, limit: usize) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > limit as u64 {
        return Err(Error::msg("updater file byte limit exceeded"));
    }
    // Enforce actual bytes as well: the file may grow after metadata lookup.
    read(file, limit)
}

pub(crate) fn check_deadline(deadline: Instant) -> std::io::Result<()> {
    if Instant::now() >= deadline {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "updater archive deadline exceeded",
        ))
    } else {
        Ok(())
    }
}

pub(crate) struct DeadlineReader<R> {
    pub(crate) inner: R,
    pub(crate) deadline: Instant,
}

impl<R: Read> Read for DeadlineReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        check_deadline(self.deadline)?;
        let count = self.inner.read(bytes)?;
        check_deadline(self.deadline)?;
        Ok(count)
    }
}

impl<R: Seek> Seek for DeadlineReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        check_deadline(self.deadline)?;
        let pos = self.inner.seek(pos)?;
        check_deadline(self.deadline)?;
        Ok(pos)
    }
}

pub(crate) struct ExpandedReader<R> {
    pub(crate) inner: R,
    pub(crate) remaining: usize,
}

impl<R: Read> Read for ExpandedReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let window = bytes.len().min(self.remaining.saturating_add(1));
        let count = self.inner.read(&mut bytes[..window])?;
        if count > self.remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "updater expanded byte limit exceeded",
            ));
        }
        self.remaining -= count;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updater_budget_expired_deadline_prevents_read_and_seek() {
        let mut reader = DeadlineReader {
            inner: std::io::Cursor::new(b"fixture"),
            deadline: Instant::now(),
        };
        assert_eq!(
            reader.read(&mut [0; 1]).unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(
            reader.seek(SeekFrom::End(0)).unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(reader.inner.position(), 0);
    }

    #[test]
    fn updater_budget_reader_exact_fit_actual_overflow_and_file_metadata() {
        assert_eq!(read(&b"four"[..], 4).unwrap(), b"four");
        assert!(read(&b"five!"[..], 4).is_err());
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("staged");
        std::fs::write(&path, b"five!").unwrap();
        assert!(file(&path, 4).is_err());
        let mut bytes = Vec::new();
        assert!(append(&mut bytes, b"five!", 4).is_err());
        assert!(bytes.is_empty());
    }
}
