use std::{fs::File, io::{Read, Seek, SeekFrom, Write}, os::fd::OwnedFd};

use rustix::fs::{Mode, OFlags, fstat, fsync, openat};

use crate::{StateError, error::{errno, io}, fs::verify, model::MAX_LOG_BYTES};

const MARKER: &[u8] = b"\n[dnfast: log truncated at 67108864 bytes]\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogAppend { Written, Truncated }

pub(crate) fn append(directory: &OwnedFd, bytes: &[u8]) -> Result<LogAppend, StateError> {
    let fd = openat(directory, "events.log", OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600)).map_err(errno)?;
    verify(&fd, false, true)?;
    let stat = fstat(&fd).map_err(errno)?;
    let current = u64::try_from(stat.st_size).map_err(|_| StateError::Corrupt("negative log size".into()))?;
    if current > MAX_LOG_BYTES { return Err(StateError::Corrupt("event log exceeds limit".into())); }
    let mut file = File::from(fd);
    if current == MAX_LOG_BYTES {
        let marker_offset = MAX_LOG_BYTES - MARKER.len() as u64;
        file.seek(SeekFrom::Start(marker_offset)).map_err(io)?;
        let mut tail = vec![0; MARKER.len()];
        file.read_exact(&mut tail).map_err(io)?;
        if tail == MARKER { return Ok(LogAppend::Truncated); }
    }
    file.seek(SeekFrom::End(0)).map_err(io)?;
    let remaining = MAX_LOG_BYTES.saturating_sub(current);
    if bytes.len() as u64 <= remaining {
        file.write_all(bytes).map_err(io)?;
        file.sync_all().map_err(io)?;
        fsync(directory).map_err(errno)?;
        return Ok(LogAppend::Written);
    }
    let marker_len = MARKER.len() as u64;
    let payload_end = MAX_LOG_BYTES - marker_len;
    if current > payload_end { file.set_len(payload_end).map_err(io)?; }
    file.seek(SeekFrom::Start(current.min(payload_end))).map_err(io)?;
    let take = usize::try_from(payload_end.saturating_sub(current.min(payload_end))).map_err(|_| StateError::Limit("event log"))?;
    file.write_all(&bytes[..take.min(bytes.len())]).map_err(io)?;
    file.seek(SeekFrom::Start(payload_end)).map_err(io)?;
    file.write_all(MARKER).map_err(io)?;
    file.sync_all().map_err(io)?;
    fsync(directory).map_err(errno)?;
    Ok(LogAppend::Truncated)
}
