use std::{
    fs::File,
    io::{Read, Seek, Write},
    os::fd::OwnedFd,
    path::{Path, PathBuf},
};

use rustix::fs::{AtFlags, Mode, OFlags, fstat, fsync, linkat, open, openat};
use sha2::{Digest, Sha256};

use crate::{CacheError, fs_safety::create_private_tree, model::io_error};

const CACHE_DIRECTORY: &str = "solv-v1";
const MAX_SOLV_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug)]
pub struct SolvCache {
    root: PathBuf,
}

pub struct CachedSolv {
    file: File,
    sha256: String,
    size: u64,
}

pub struct StagedSolv {
    directory: OwnedFd,
    file: File,
    binding: String,
}

impl SolvCache {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn open(&self, binding: &str) -> Result<Option<CachedSolv>, CacheError> {
        validate_digest(binding, "solv cache binding")?;
        let path = self.root.join(CACHE_DIRECTORY);
        match open_directory_if_present(&path)? {
            Some(directory) => open_cached(&directory, binding),
            None => Ok(None),
        }
    }

    pub fn stage(&self, binding: &str) -> Result<StagedSolv, CacheError> {
        validate_digest(binding, "solv cache binding")?;
        let path = self.root.join(CACHE_DIRECTORY);
        create_private_tree(&self.root, &path)?;
        let directory = open_directory(&path)?;
        let file = File::from(
            openat(
                &directory,
                ".",
                OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(errno)?,
        );
        Ok(StagedSolv {
            directory,
            file,
            binding: binding.into(),
        })
    }
}

impl CachedSolv {
    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub const fn size(&self) -> u64 {
        self.size
    }
}

impl StagedSolv {
    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn commit(mut self) -> Result<CachedSolv, CacheError> {
        self.file.sync_all().map_err(io_error)?;
        let (sha256, size) = verify_stream(&mut self.file, None)?;
        let content_name = format!("{}-{sha256}.solv", self.binding);
        match linkat(
            &self.file,
            "",
            &self.directory,
            content_name.as_str(),
            AtFlags::EMPTY_PATH,
        ) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(errno(error)),
        }
        let existing = open_content(&self.directory, &content_name, &sha256)?;
        if existing.size != size {
            return Err(CacheError::Corrupt(
                "published solv cache size differs".into(),
            ));
        }
        let reference_name = format!("{}.ref", self.binding);
        let mut reference = File::from(
            openat(
                &self.directory,
                ".",
                OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(errno)?,
        );
        reference
            .write_all(format!("{sha256}\n").as_bytes())
            .map_err(io_error)?;
        reference.sync_all().map_err(io_error)?;
        match linkat(
            &reference,
            "",
            &self.directory,
            reference_name.as_str(),
            AtFlags::EMPTY_PATH,
        ) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {
                let bound = read_reference(&self.directory, &reference_name)?;
                if bound != sha256 {
                    return Err(CacheError::Corrupt(
                        "solv cache binding is nondeterministic".into(),
                    ));
                }
            }
            Err(error) => return Err(errno(error)),
        }
        fsync(&self.directory).map_err(errno)?;
        open_cached(&self.directory, &self.binding)?
            .ok_or_else(|| CacheError::Corrupt("committed solv cache disappeared".into()))
    }
}

fn open_directory(path: &Path) -> Result<OwnedFd, CacheError> {
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(errno)?;
    validate_directory(&fd)?;
    Ok(fd)
}

fn open_directory_if_present(path: &Path) -> Result<Option<OwnedFd>, CacheError> {
    let fd = match open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(errno(error)),
    };
    validate_directory(&fd)?;
    Ok(Some(fd))
}

fn validate_directory(fd: &OwnedFd) -> Result<(), CacheError> {
    let metadata = fstat(fd).map_err(errno)?;
    if metadata.st_mode & 0o170000 != 0o040000
        || metadata.st_mode & 0o022 != 0
        || metadata.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(CacheError::Corrupt("unsafe solv cache directory".into()));
    }
    Ok(())
}

fn open_cached(directory: &OwnedFd, binding: &str) -> Result<Option<CachedSolv>, CacheError> {
    let reference_name = format!("{binding}.ref");
    let sha256 = match read_reference_if_present(directory, &reference_name)? {
        Some(value) => value,
        None => return Ok(None),
    };
    let content_name = format!("{binding}-{sha256}.solv");
    Ok(Some(open_content(directory, &content_name, &sha256)?))
}

fn open_content(
    directory: &OwnedFd,
    name: &str,
    expected_sha256: &str,
) -> Result<CachedSolv, CacheError> {
    let fd = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(errno)?;
    validate_regular(&fd)?;
    let before = fstat(&fd).map_err(errno)?;
    let mut file = File::from(fd);
    let (sha256, size) = verify_stream(&mut file, Some(expected_sha256))?;
    let after = fstat(&file).map_err(errno)?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
    {
        return Err(CacheError::Corrupt(
            "solv cache changed while hashing".into(),
        ));
    }
    Ok(CachedSolv { file, sha256, size })
}

fn read_reference(directory: &OwnedFd, name: &str) -> Result<String, CacheError> {
    read_reference_if_present(directory, name)?
        .ok_or_else(|| CacheError::Corrupt("solv cache reference disappeared".into()))
}

fn read_reference_if_present(
    directory: &OwnedFd,
    name: &str,
) -> Result<Option<String>, CacheError> {
    let fd = match openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(errno(error)),
    };
    validate_regular(&fd)?;
    let before = fstat(&fd).map_err(errno)?;
    let mut file = File::from(fd);
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(66)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    let after = fstat(&file).map_err(errno)?;
    if bytes.len() != 65
        || bytes[64] != b'\n'
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
    {
        return Err(CacheError::Corrupt(
            "solv cache reference is invalid".into(),
        ));
    }
    let value = std::str::from_utf8(&bytes[..64])
        .map_err(|_| CacheError::Corrupt("solv cache reference is not UTF-8".into()))?;
    validate_digest(value, "solv cache content")?;
    Ok(Some(value.into()))
}

fn validate_regular(fd: &OwnedFd) -> Result<(), CacheError> {
    let metadata = fstat(fd).map_err(errno)?;
    if metadata.st_mode & 0o170000 != 0o100000
        || metadata.st_mode & 0o022 != 0
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 1
        || metadata.st_size <= 0
        || metadata.st_size as u64 > MAX_SOLV_BYTES
    {
        return Err(CacheError::Corrupt("unsafe solv cache file".into()));
    }
    Ok(())
}

fn verify_stream(
    file: &mut File,
    expected_sha256: Option<&str>,
) -> Result<(String, u64), CacheError> {
    file.rewind().map_err(io_error)?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(io_error)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| CacheError::Corrupt("solv cache size overflow".into()))?;
        if total > MAX_SOLV_BYTES {
            return Err(CacheError::Corrupt("solv cache exceeds limit".into()));
        }
        digest.update(&buffer[..count]);
    }
    if total == 0 {
        return Err(CacheError::Corrupt("solv cache is empty".into()));
    }
    let actual = hex::encode(digest.finalize());
    if expected_sha256.is_some_and(|expected| expected != actual) {
        return Err(CacheError::Corrupt("solv cache digest differs".into()));
    }
    file.rewind().map_err(io_error)?;
    Ok((actual, total))
}

fn validate_digest(value: &str, role: &str) -> Result<(), CacheError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CacheError::Corrupt(format!("invalid {role} digest")));
    }
    Ok(())
}

fn errno(error: rustix::io::Errno) -> CacheError {
    CacheError::Io(std::io::Error::from_raw_os_error(error.raw_os_error()).to_string())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use sha2::{Digest, Sha256};

    use super::SolvCache;

    fn binding() -> String {
        hex::encode(Sha256::digest(b"binding"))
    }

    #[test]
    fn cache_round_trip_revalidates_content_digest() {
        let root = tempfile::tempdir().expect("cache root");
        let cache = SolvCache::new(root.path());
        let staged = cache.stage(&binding()).expect("stage");
        staged.file().write_all(b"solv payload").expect("write");
        let committed = staged.commit().expect("commit");
        assert_eq!(committed.size(), 12);
        assert_eq!(cache.open(&binding()).expect("open").unwrap().size(), 12);
    }

    #[test]
    fn absent_cache_is_a_clean_miss() {
        let root = tempfile::tempdir().expect("cache root");
        assert!(
            SolvCache::new(root.path())
                .open(&binding())
                .expect("cache miss")
                .is_none()
        );
    }

    #[test]
    fn cache_rejects_content_tampering() {
        let root = tempfile::tempdir().expect("cache root");
        let cache = SolvCache::new(root.path());
        let staged = cache.stage(&binding()).expect("stage");
        staged.file().write_all(b"solv payload").expect("write");
        let digest = staged.commit().expect("commit").sha256().to_owned();
        let path = root
            .path()
            .join("solv-v1")
            .join(format!("{}-{digest}.solv", binding()));
        std::fs::write(path, b"evil payload").expect("tamper");
        assert!(cache.open(&binding()).is_err());
    }

    #[test]
    fn concurrent_staging_converges_only_for_identical_content() {
        let root = tempfile::tempdir().expect("cache root");
        let cache = SolvCache::new(root.path());
        let first = cache.stage(&binding()).expect("first stage");
        let second = cache.stage(&binding()).expect("second stage");
        first
            .file()
            .write_all(b"same payload")
            .expect("first write");
        second
            .file()
            .write_all(b"same payload")
            .expect("second write");
        let first = first.commit().expect("first commit");
        let second = second.commit().expect("second commit");
        assert_eq!(first.sha256(), second.sha256());

        let conflicting = cache.stage(&binding()).expect("conflicting stage");
        conflicting
            .file()
            .write_all(b"different payload")
            .expect("conflicting write");
        assert!(conflicting.commit().is_err());
    }
}
