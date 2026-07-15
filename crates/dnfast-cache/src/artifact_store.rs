use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Seek, Write},
    os::fd::{AsFd, OwnedFd},
    path::{Path, PathBuf},
};

use rustix::fs::{
    fstat, fstatvfs, fsync, linkat, open, openat, statat, unlinkat, AtFlags, Mode, OFlags,
};
use sha2::{Digest as _, Sha256};

use crate::{
    artifact::{ArtifactError, ArtifactSpec, ArtifactTransport, Capacity, TransactionRequest},
    artifact_lock::{acquire_authorities, lock_bounded, validate_cache_path, validate_owner_marker, AuthoritySet, ProcessReservation},
    fs_safety::create_private_tree,
};

#[derive(Debug)]
pub struct ArtifactCache { root: PathBuf }

#[derive(Debug)]
pub struct CachedArtifact {
    file: fs::File,
}

impl CachedArtifact {
    pub fn file(&self) -> &fs::File { &self.file }

    pub fn from_verified_root_file(file: fs::File, sha256: &str, size: u64) -> Result<Self, ArtifactError> {
        Ok(Self { file: verify_identity(file.into(), sha256, size)? })
    }
}

impl ArtifactCache {
    pub fn new(root: impl Into<PathBuf>) -> Self { Self { root: root.into() } }

    pub fn begin_transaction(
        &self,
        transaction: &TransactionRequest,
    ) -> Result<ArtifactTransaction, ArtifactError> {
        if transaction.identities.is_empty() {
            return Err(ArtifactError::Capacity("transaction has no bound artifacts".into()));
        }
        validate_cache_path(&self.root)?;
        let directory = self.root.join("artifacts/sha256");
        create_private_tree(&self.root, &directory).map_err(cache_error)?;
        let directory_fd = open_directory(&directory)?;
        let process_guard = ProcessReservation::acquire(&directory_fd)?;
        let authority = acquire_authorities(&self.root, &directory_fd)?;
        let pinned = PinnedDirectory::from_fd(&directory, directory_fd)?;
        lock_bounded(&pinned.lock_fd)?;
        pinned.verify_lock_identity()?;
        let missing_bytes = pinned.missing_bytes(&transaction.identities)?;
        let artifact_count = u64::try_from(transaction.identities.len()).map_err(|error| ArtifactError::Capacity(error.to_string()))?;
        TransactionRequest::from_totals(missing_bytes, artifact_count)?
            .validate(pinned.capacity()?)?;
        Ok(ArtifactTransaction {
            directory: pinned,
            remaining: transaction.identities.iter().cloned().collect(),
            _process_guard: process_guard,
            _authority: authority,
        })
    }
}

pub struct ArtifactTransaction {
    directory: PinnedDirectory,
    remaining: BTreeSet<(String, u64)>,
    _process_guard: ProcessReservation,
    _authority: AuthoritySet,
}


impl ArtifactTransaction {
    pub fn fetch(
        &mut self,
        spec: &ArtifactSpec,
        transport: &dyn ArtifactTransport,
    ) -> Result<CachedArtifact, ArtifactError> {
        let identity = (spec.digest.clone(), spec.size);
        if !self.remaining.contains(&identity) {
            return Err(ArtifactError::Capacity("artifact is not pending in this transaction".into()));
        }
        let file = self.directory.fetch(spec, transport)?;
        self.remaining.remove(&identity);
        Ok(CachedArtifact { file })
    }

    pub fn remaining(&self) -> usize { self.remaining.len() }
}

struct PinnedDirectory {
    fd: OwnedFd,
    lock_fd: OwnedFd,
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl PinnedDirectory {
    fn from_fd(path: &Path, fd: OwnedFd) -> Result<Self, ArtifactError> {
        let metadata = fstat(&fd).map_err(errno)?;
        let lock_fd = match openat(&fd, ".transaction-lock", OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::from_raw_mode(0o600)) {
            Ok(created) => created,
            Err(rustix::io::Errno::EXIST) => openat(&fd, ".transaction-lock", OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(errno)?,
            Err(error) => return Err(errno(error)),
        };
        validate_lock(&lock_fd)?;
        Ok(Self { fd, lock_fd, path: path.into(), device: metadata.st_dev, inode: metadata.st_ino })
    }

    fn capacity(&self) -> Result<Capacity, ArtifactError> {
        let filesystem = fstatvfs(&self.fd).map_err(errno)?;
        let available_bytes = filesystem.f_bavail.checked_mul(filesystem.f_frsize).ok_or_else(|| ArtifactError::Capacity("available filesystem bytes overflow".into()))?;
        Ok(Capacity { cached_bytes: self.cached_bytes()?, available_bytes })
    }

    fn verify_lock_identity(&self) -> Result<(), ArtifactError> {
        validate_lock(&self.lock_fd)?;
        let retained = fstat(&self.lock_fd).map_err(errno)?;
        let resolved = statat(&self.fd, ".transaction-lock", AtFlags::SYMLINK_NOFOLLOW).map_err(errno)?;
        validate_lock_metadata(&resolved)?;
        if retained.st_dev != resolved.st_dev || retained.st_ino != resolved.st_ino {
            return Err(ArtifactError::Io("artifact transaction lock changed".into()));
        }
        Ok(())
    }

    fn missing_bytes(&self, identities: &[(String, u64)]) -> Result<u64, ArtifactError> {
        identities.iter().try_fold(0_u64, |total, (digest, size)| {
            match openat(&self.fd, digest.as_str(), OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()) {
                Ok(fd) => { verify_identity(fd, digest, *size)?; Ok(total) }
                Err(rustix::io::Errno::NOENT) => total.checked_add(*size).ok_or_else(|| ArtifactError::Capacity("missing artifact bytes overflow".into())),
                Err(error) => Err(errno(error)),
            }
        })
    }

    fn cached_bytes(&self) -> Result<u64, ArtifactError> {
        fs::read_dir(format!("/proc/self/fd/{}", self.fd.as_fd().as_raw_fd())).map_err(io_error)?.try_fold(0_u64, |total, entry| {
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name();
            if name == ".transaction-lock" { return Ok(total); }
            if name.to_string_lossy().starts_with(".transaction-owner-") {
                validate_owner_marker(&self.fd, &name)?;
                return Ok(total);
            }
            let fd = openat(&self.fd, &name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(errno)?;
            let metadata = fstat(fd).map_err(errno)?;
            total.checked_add(u64::try_from(metadata.st_size).map_err(|error| ArtifactError::Capacity(error.to_string()))?).ok_or_else(|| ArtifactError::Capacity("cached byte count overflow".into()))
        })
    }

    fn fetch(&self, spec: &ArtifactSpec, transport: &dyn ArtifactTransport) -> Result<fs::File, ArtifactError> {
        if let Ok(existing) = self.open_existing(spec) {
            let file = verify_file(existing, spec)?;
            self.verify_path_identity()?;
            return Ok(file);
        }
        let response = transport.open(&spec.url)?;
        if response.status != 200 {
            return Err(ArtifactError::Transport(format!("unexpected HTTP status {}", response.status)));
        }
        self.verify_path_identity()?;
        let temporary = openat(&self.fd, ".", OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC, Mode::from_raw_mode(0o600)).map_err(errno)?;
        let mut file = fs::File::from(temporary);
        stream_verified(response.body, &mut file, spec)?;
        file.sync_all().map_err(io_error)?;
        self.verify_path_identity()?;
        match linkat(&file, "", &self.fd, spec.digest.as_str(), AtFlags::EMPTY_PATH) {
            Ok(()) => {
                if let Err(error) = self.verify_path_identity() {
                    unlinkat(&self.fd, spec.digest.as_str(), AtFlags::empty()).map_err(errno)?;
                    fsync(&self.fd).map_err(errno)?;
                    return Err(error);
                }
                fsync(&self.fd).map_err(errno)?;
                verify_file(self.open_existing(spec)?, spec)
            }
            Err(rustix::io::Errno::EXIST) => {
                let existing = verify_file(self.open_existing(spec)?, spec)?;
                self.verify_path_identity()?;
                Ok(existing)
            }
            Err(error) => Err(errno(error)),
        }
    }

    fn open_existing(&self, spec: &ArtifactSpec) -> Result<OwnedFd, ArtifactError> {
        openat(&self.fd, spec.digest.as_str(), OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(errno)
    }

    fn verify_path_identity(&self) -> Result<(), ArtifactError> {
        let current = open(&self.path, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(errno)?;
        let metadata = fstat(current).map_err(errno)?;
        if metadata.st_dev != self.device || metadata.st_ino != self.inode {
            return Err(ArtifactError::Io("artifact directory changed during transfer".into()));
        }
        Ok(())
    }
}

fn open_directory(path: &Path) -> Result<OwnedFd, ArtifactError> {
    let fd = open(path, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(errno)?;
    let metadata = fstat(&fd).map_err(errno)?;
    if metadata.st_mode & 0o170000 != 0o040000 || metadata.st_mode & 0o022 != 0 || metadata.st_uid != rustix::process::geteuid().as_raw() {
        return Err(ArtifactError::Io("unsafe artifact directory".into()));
    }
    Ok(fd)
}

fn stream_verified(mut input: Box<dyn Read + Send>, output: &mut fs::File, spec: &ArtifactSpec) -> Result<(), ArtifactError> {
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer).map_err(io_error)?;
        if count == 0 { break; }
        total = total.checked_add(u64::try_from(count).map_err(|error| ArtifactError::Integrity(error.to_string()))?).ok_or_else(|| ArtifactError::Integrity("artifact size overflow".into()))?;
        if total > spec.size { return Err(ArtifactError::Integrity("artifact exceeds declared size".into())); }
        output.write_all(&buffer[..count]).map_err(io_error)?;
        hasher.update(&buffer[..count]);
    }
    if total != spec.size { return Err(ArtifactError::Integrity("artifact is truncated".into())); }
    if hex::encode(hasher.finalize()) != spec.digest { return Err(ArtifactError::Integrity("artifact digest mismatch".into())); }
    Ok(())
}

fn verify_file(fd: OwnedFd, spec: &ArtifactSpec) -> Result<fs::File, ArtifactError> {
    verify_identity(fd, &spec.digest, spec.size)
}

fn verify_identity(fd: OwnedFd, digest: &str, size: u64) -> Result<fs::File, ArtifactError> {
    let metadata = fstat(&fd).map_err(errno)?;
    if metadata.st_size < 0 || metadata.st_size as u64 != size || metadata.st_mode & 0o077 != 0 || metadata.st_nlink != 1 || metadata.st_uid != rustix::process::geteuid().as_raw() || metadata.st_mode & 0o170000 != 0o100000 {
        return Err(ArtifactError::Integrity("existing artifact metadata mismatch".into()));
    }
    let mut file = fs::File::from(fd);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(io_error)?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }
    if hex::encode(hasher.finalize()) != digest { return Err(ArtifactError::Integrity("existing artifact digest mismatch".into())); }
    file.rewind().map_err(io_error)?;
    Ok(file)
}

fn validate_lock(fd: &OwnedFd) -> Result<(), ArtifactError> {
    let metadata = fstat(fd).map_err(errno)?;
    validate_lock_metadata(&metadata)
}

fn validate_lock_metadata(metadata: &rustix::fs::Stat) -> Result<(), ArtifactError> {
    if metadata.st_mode & 0o170777 != 0o100600 || metadata.st_uid != rustix::process::geteuid().as_raw() || metadata.st_nlink != 1 || metadata.st_size != 0 {
        return Err(ArtifactError::Io("unsafe artifact transaction lock".into()));
    }
    Ok(())
}

fn io_error(error: std::io::Error) -> ArtifactError { ArtifactError::Io(error.to_string()) }
fn errno(error: rustix::io::Errno) -> ArtifactError { ArtifactError::Io(error.to_string()) }
fn cache_error(error: crate::CacheError) -> ArtifactError { ArtifactError::Io(error.to_string()) }

use std::os::fd::AsRawFd;
