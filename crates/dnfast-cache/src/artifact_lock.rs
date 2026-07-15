use std::{fs, os::{fd::{AsFd, AsRawFd, OwnedFd}, unix::ffi::OsStrExt}, path::{Component, Path, PathBuf}, thread, time::{Duration, Instant}};

use rustix::fs::{fcntl_lock, fstat, openat, unlinkat, AtFlags, FlockOperation, Mode, OFlags};

use crate::artifact::ArtifactError;
use sha2::{Digest as _, Sha256};

const LOCK_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) struct ProcessReservation {
    directory: OwnedFd,
    name: String,
    pid: i32,
}

impl ProcessReservation {
    pub(crate) fn acquire(directory: &OwnedFd) -> Result<Self, ArtifactError> {
        scrub_stale_owners(directory)?;
        let pid = rustix::process::getpid().as_raw_pid();
        let start = process_start(pid)?;
        let name = format!(".transaction-owner-{pid}-{start}");
        match openat(directory, name.as_str(), OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::from_raw_mode(0o600)) {
            Ok(_) => Ok(Self { directory: rustix::io::dup(directory).map_err(errno)?, name, pid }),
            Err(rustix::io::Errno::EXIST) => Err(ArtifactError::Busy("artifact transaction already active in this process".into())),
            Err(error) => Err(errno(error)),
        }
    }
}

impl Drop for ProcessReservation {
    fn drop(&mut self) {
        if rustix::process::getpid().as_raw_pid() == self.pid {
            let _ = unlinkat(&self.directory, self.name.as_str(), AtFlags::empty());
        }
    }
}

pub(crate) fn lock_bounded(fd: &OwnedFd) -> Result<(), ArtifactError> {
    let deadline = Instant::now() + LOCK_TIMEOUT;
    loop {
        match fcntl_lock(fd, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(()),
            Err(rustix::io::Errno::WOULDBLOCK) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Err(rustix::io::Errno::WOULDBLOCK) => return Err(ArtifactError::Busy("artifact transaction lock timed out".into())),
            Err(error) => return Err(errno(error)),
        }
    }
}

pub(crate) struct AuthoritySet {
    _held: [dnfast_native_sys::Authority; 2],
}

pub(crate) fn acquire_authorities(root: &Path, directory: &OwnedFd) -> Result<AuthoritySet, ArtifactError> {
    let absolute = normalize_cache_path(root)?;
    let uid = rustix::process::geteuid().as_raw().to_be_bytes();
    let metadata = fstat(directory).map_err(errno)?;
    let path_name = authority_name(b"dnfast-path-authority-v1", &[&uid, absolute.as_os_str().as_bytes()]);
    let identity_name = authority_name(
        b"dnfast-inode-authority-v1",
        &[&uid, &metadata.st_dev.to_be_bytes(), &metadata.st_ino.to_be_bytes()],
    );
    let mut names = [path_name, identity_name];
    names.sort();
    let deadline = Instant::now() + LOCK_TIMEOUT;
    let first = acquire_until(&names[0], deadline)?;
    let second = acquire_until(&names[1], deadline)?;
    Ok(AuthoritySet { _held: [first, second] })
}

fn authority_name(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields { hasher.update(field); }
    format!("dnfast-{}", hex::encode(hasher.finalize()))
}

fn acquire_until(name: &str, deadline: Instant) -> Result<dnfast_native_sys::Authority, ArtifactError> {
    loop {
        match dnfast_native_sys::Authority::acquire(name.as_bytes()) {
            Ok(authority) => return Ok(authority),
            Err(98) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Err(98) => return Err(ArtifactError::Busy("artifact path authority timed out".into())),
            Err(error) => return Err(ArtifactError::Io(format!("artifact path authority error: {error}"))),
        }
    }
}

fn normalize_cache_path(root: &Path) -> Result<PathBuf, ArtifactError> {
    if root.as_os_str().is_empty() {
        return Err(ArtifactError::Policy("empty artifact cache path".into()));
    }
    let absolute = std::path::absolute(root).map_err(io_error)?;
    let mut normalized = PathBuf::from("/");
    for component in absolute.components() {
        match component {
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(ArtifactError::Policy("artifact cache path crosses root".into()));
                }
            }
            Component::Normal(value) => {
                let bytes = value.as_bytes();
                if bytes.contains(&0) || value.to_str().is_none() {
                    return Err(ArtifactError::Policy("artifact cache path is not safe UTF-8".into()));
                }
                normalized.push(value);
            }
            Component::Prefix(_) => return Err(ArtifactError::Policy("unsupported artifact cache path prefix".into())),
        }
    }
    if normalized == Path::new("/") {
        return Err(ArtifactError::Policy("artifact cache root cannot be filesystem root".into()));
    }
    Ok(normalized)
}

pub(crate) fn validate_cache_path(root: &Path) -> Result<(), ArtifactError> {
    normalize_cache_path(root).map(|_| ())
}

fn process_start(pid: i32) -> Result<String, ArtifactError> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).map_err(io_error)?;
    let fields = stat.rsplit_once(')').ok_or_else(|| ArtifactError::Io("invalid process stat".into()))?.1;
    fields.split_whitespace().nth(19).map(str::to_owned).ok_or_else(|| ArtifactError::Io("process start time missing".into()))
}

pub(crate) fn validate_owner_marker(directory: &OwnedFd, name: &std::ffi::OsStr) -> Result<(), ArtifactError> {
    let value = name.to_str().ok_or_else(|| ArtifactError::Io("non-UTF-8 transaction owner marker".into()))?;
    let (pid, start) = parse_owner(value)?;
    validate_marker_file(directory, name)?;
    if process_start(pid).is_ok_and(|actual| actual == start) {
        Ok(())
    } else {
        Err(ArtifactError::Io("inactive transaction owner marker".into()))
    }
}

fn parse_owner(value: &str) -> Result<(i32, &str), ArtifactError> {
    let owner = value.strip_prefix(".transaction-owner-").ok_or_else(|| ArtifactError::Io("unknown transaction control file".into()))?;
    let (pid, start) = owner.split_once('-').ok_or_else(|| ArtifactError::Io("malformed transaction owner marker".into()))?;
    if pid.is_empty() || start.is_empty() || !pid.bytes().all(|byte| byte.is_ascii_digit()) || !start.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ArtifactError::Io("malformed transaction owner marker".into()));
    }
    Ok((pid.parse::<i32>().map_err(|error| ArtifactError::Io(error.to_string()))?, start))
}

fn validate_marker_file(directory: &OwnedFd, name: &std::ffi::OsStr) -> Result<(), ArtifactError> {
    let fd = openat(directory, name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(errno)?;
    let metadata = fstat(fd).map_err(errno)?;
    if metadata.st_mode & 0o170777 != 0o100600 || metadata.st_uid != rustix::process::geteuid().as_raw() || metadata.st_nlink != 1 || metadata.st_size != 0 {
        return Err(ArtifactError::Io("unsafe transaction owner marker".into()));
    }
    Ok(())
}

fn scrub_stale_owners(directory: &OwnedFd) -> Result<(), ArtifactError> {
    let path = format!("/proc/self/fd/{}", directory.as_fd().as_raw_fd());
    for entry in fs::read_dir(path).map_err(io_error)? {
        let name = entry.map_err(io_error)?.file_name();
        let value = name.to_string_lossy();
        let Ok((pid, start)) = parse_owner(&value) else { continue; };
        if validate_marker_file(directory, &name).is_err() { continue; }
        if !process_start(pid).is_ok_and(|value| value == start) {
            unlinkat(directory, name, AtFlags::empty()).map_err(errno)?;
        }
    }
    Ok(())
}

fn io_error(error: std::io::Error) -> ArtifactError { ArtifactError::Io(error.to_string()) }
fn errno(error: rustix::io::Errno) -> ArtifactError { ArtifactError::Io(error.to_string()) }
