use std::{fs::{self, File}, io::{Read, Write}, os::fd::OwnedFd, path::Path};

use rustix::fs::{fstat, open, openat, Mode, OFlags};

use crate::model::{io_error, sha256, CacheError, FileRecord};

pub(crate) const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_OBJECT_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

pub(crate) struct AnchoredDirectory { fd: OwnedFd }

impl AnchoredDirectory {
    pub(crate) fn open(path: &Path) -> Result<Self, CacheError> {
        let fd = open(path, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(errno)?;
        let metadata = fstat(&fd).map_err(errno)?;
        if metadata.st_uid != rustix::process::geteuid().as_raw() || metadata.st_mode & 0o170000 != 0o040000 || metadata.st_mode & 0o022 != 0 {
            return Err(CacheError::Corrupt("unsafe anchored directory".into()));
        }
        Ok(Self { fd })
    }

    pub(crate) fn read(&self, name: &std::ffi::OsStr, maximum: u64) -> Result<Vec<u8>, CacheError> {
        let fd = openat(&self.fd, name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(errno)?;
        read_owned(fd, maximum)
    }
}

pub(crate) fn create_private_tree(root: &Path, target: &Path) -> Result<(), CacheError> {
    reject_existing_symlink_ancestors(root)?;
    match fs::symlink_metadata(root) {
        Ok(_) => validate_private_directory(root)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_root(root)?;
        }
        Err(error) => return Err(io_error(error)),
    }
    let relative = target.strip_prefix(root).map_err(|_| CacheError::Corrupt("cache path escaped root".into()))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else { return Err(CacheError::Corrupt("unsafe cache path component".into())); };
        current.push(component);
        let created = match fs::create_dir(&current) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(io_error(error)),
        };
        if created { set_private_directory(&current)?; } else { validate_private_directory(&current)?; }
    }
    Ok(())
}

fn create_private_root(root: &Path) -> Result<(), CacheError> {
    let mut missing = Vec::new();
    let mut current = root;
    while fs::symlink_metadata(current).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound) {
        missing.push(current.to_path_buf());
        current = current.parent().ok_or_else(|| CacheError::Corrupt("cache root has no existing ancestor".into()))?;
    }
    for path in missing.into_iter().rev() {
        match fs::create_dir(&path) {
            Ok(()) => set_private_directory(&path)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => validate_private_directory(&path)?,
            Err(error) => return Err(io_error(error)),
        }
    }
    Ok(())
}

fn validate_private_directory(path: &Path) -> Result<(), CacheError> {
    let fd = open(path, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(errno)?;
    let metadata = fstat(fd).map_err(errno)?;
    if metadata.st_mode & 0o170000 != 0o040000 || metadata.st_mode & 0o022 != 0 || metadata.st_uid != rustix::process::geteuid().as_raw() {
        return Err(CacheError::Corrupt(format!(
            "unsafe existing cache directory: {} mode={:o} uid={} links={}",
            path.display(), metadata.st_mode, metadata.st_uid, metadata.st_nlink
        )));
    }
    Ok(())
}

fn set_private_directory(path: &Path) -> Result<(), CacheError> {
    reject_symlink(path, true)?;
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    Ok(())
}

fn reject_existing_symlink_ancestors(path: &Path) -> Result<(), CacheError> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Err(CacheError::Corrupt(format!("symlinked cache ancestor: {}", ancestor.display()))),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
    }
    Ok(())
}

pub(crate) fn reject_symlink(path: &Path, directory: bool) -> Result<(), CacheError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink() || (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
        return Err(CacheError::Corrupt(format!("unsafe cache path: {}", path.display())));
    }
    Ok(())
}

pub(crate) fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), CacheError> {
    let mut file = File::create(path).map_err(io_error)?;
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600)).map_err(io_error)?;
    }
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)
}

pub(crate) fn write_verified(directory: &Path, name: &str, bytes: &[u8]) -> Result<FileRecord, CacheError> {
    write_synced(&directory.join(name), bytes)?;
    Ok(FileRecord { name: name.into(), sha256: sha256(bytes), size: bytes.len() as u64 })
}

pub(crate) fn sync_directory(path: &Path) -> Result<(), CacheError> {
    File::open(path).and_then(|file| file.sync_all()).map_err(io_error)
}

pub(crate) fn read_regular(path: &Path) -> Result<Vec<u8>, CacheError> {
    let parent = path.parent().ok_or_else(|| CacheError::Corrupt("file has no parent".into()))?;
    let name = path.file_name().ok_or_else(|| CacheError::Corrupt("file has no name".into()))?;
    read_anchored(parent, name, MAX_MANIFEST_BYTES)
}

pub(crate) fn read_anchored(directory: &Path, name: &std::ffi::OsStr, maximum: u64) -> Result<Vec<u8>, CacheError> {
    AnchoredDirectory::open(directory)?.read(name, maximum)
}

fn read_owned(fd: OwnedFd, maximum: u64) -> Result<Vec<u8>, CacheError> {
    let before = fstat(&fd).map_err(errno)?;
    if before.st_nlink != 1 || before.st_uid != rustix::process::geteuid().as_raw() || before.st_mode & 0o170000 != 0o100000 || before.st_mode & 0o022 != 0 {
        return Err(CacheError::Corrupt("unsafe cache file ownership, mode, or links".into()));
    }
    let limit = maximum.checked_add(1).ok_or_else(|| CacheError::Corrupt("file size overflow".into()))?;
    let capacity = usize::try_from(before.st_size).map_err(|_| CacheError::Corrupt("file too large for platform".into()))?;
    if before.st_size < 0 || before.st_size as u64 > maximum { return Err(CacheError::Corrupt("cache file exceeds limit".into())); }
    let mut bytes = Vec::with_capacity(capacity);
    File::from(fd).take(limit).read_to_end(&mut bytes).map_err(io_error)?;
    if bytes.len() as u64 > maximum { return Err(CacheError::Corrupt("cache file exceeds limit".into())); }
    Ok(bytes)
}

pub(crate) fn verify_file(directory: &AnchoredDirectory, record: &FileRecord) -> Result<Vec<u8>, CacheError> {
    validate_name(&record.name)?;
    if record.size > MAX_OBJECT_FILE_BYTES { return Err(CacheError::Corrupt("object file exceeds global limit".into())); }
    let bytes = directory.read(std::ffi::OsStr::new(&record.name), record.size)?;
    if bytes.len() as u64 != record.size || sha256(&bytes) != record.sha256 { return Err(CacheError::Corrupt(format!("object verification failed: {}", record.name))); }
    Ok(bytes)
}

pub(crate) fn validate_name(name: &str) -> Result<(), CacheError> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || matches!(name, "." | ".." | "manifest.json") {
        return Err(CacheError::Corrupt("unsafe or reserved manifest path".into()));
    }
    Ok(())
}

fn errno(error: rustix::io::Errno) -> CacheError { CacheError::Io(error.to_string()) }
