use std::{
    fs::File,
    io::Read,
    os::fd::{AsFd, AsRawFd, OwnedFd},
    path::{Component, Path},
};

use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, fchmod, fstat, mkdirat, open, openat2};

use crate::PlanningError;

#[derive(Clone, Copy, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
}

pub(crate) struct TrustedDirectory {
    fd: OwnedFd,
    identity: Identity,
    owner: u32,
}

impl TrustedDirectory {
    pub(crate) fn open(
        path: &Path,
        owner: u32,
        create: bool,
        mode: u32,
    ) -> Result<Self, PlanningError> {
        if !path.is_absolute() {
            return Err(PlanningError::UnsafeRoot(
                "root path is not absolute".into(),
            ));
        }
        let mut current = open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(io)?;
        validate_directory(&current, owner)?;
        for component in path.components().skip(1) {
            let Component::Normal(name) = component else {
                return Err(PlanningError::UnsafeRoot(
                    "root path has an unsafe component".into(),
                ));
            };
            current = open_child(&current, name, owner, create, mode)?;
        }
        Self::from_fd(current, owner)
    }

    pub(crate) fn child(&self, name: &str, create: bool, mode: u32) -> Result<Self, PlanningError> {
        self.recheck()?;
        let child = open_child(
            &self.fd,
            std::ffi::OsStr::new(name),
            self.owner,
            create,
            mode,
        )?;
        self.recheck()?;
        Self::from_fd(child, self.owner)
    }

    pub(crate) fn child_if_present(&self, name: &str) -> Result<Option<Self>, PlanningError> {
        self.recheck()?;
        validate_name(name)?;
        match openat2(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        ) {
            Ok(fd) => Ok(Some(Self::from_fd(fd, self.owner)?)),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(error) => Err(io(error)),
        }
    }

    pub(crate) fn read(&self, name: &str, maximum: usize) -> Result<Vec<u8>, PlanningError> {
        self.recheck()?;
        validate_name(name)?;
        let fd = openat2(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(io)?;
        validate_regular(&fd, self.owner)?;
        let before = identity(&fd)?;
        let mut file = File::from(fd);
        let mut bytes = Vec::new();
        file.by_ref()
            .take(
                u64::try_from(maximum)
                    .map_err(|error| PlanningError::UnsafeSnapshot(error.to_string()))?
                    + 1,
            )
            .read_to_end(&mut bytes)
            .map_err(read)?;
        if bytes.len() > maximum {
            return Err(PlanningError::UnsafeSnapshot(
                "snapshot file exceeds maximum size".into(),
            ));
        }
        if identity(&file.as_fd())? != before {
            return Err(PlanningError::UnsafeSnapshot(
                "snapshot file changed while read".into(),
            ));
        }
        self.recheck()?;
        Ok(bytes)
    }

    pub(crate) fn read_if_present(
        &self,
        name: &str,
        maximum: usize,
    ) -> Result<Option<Vec<u8>>, PlanningError> {
        self.recheck()?;
        validate_name(name)?;
        let fd = match openat2(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(io(error)),
        };
        validate_regular(&fd, self.owner)?;
        let before = identity(&fd)?;
        let mut file = File::from(fd);
        let mut bytes = Vec::new();
        file.by_ref()
            .take(
                u64::try_from(maximum)
                    .map_err(|error| PlanningError::UnsafeSnapshot(error.to_string()))?
                    + 1,
            )
            .read_to_end(&mut bytes)
            .map_err(read)?;
        if bytes.len() > maximum {
            return Err(PlanningError::UnsafeSnapshot(
                "snapshot file exceeds maximum size".into(),
            ));
        }
        if identity(&file.as_fd())? != before {
            return Err(PlanningError::UnsafeSnapshot(
                "snapshot file changed while read".into(),
            ));
        }
        self.recheck()?;
        Ok(Some(bytes))
    }

    pub(crate) fn open_file(&self, name: &str) -> Result<File, PlanningError> {
        self.recheck()?;
        validate_name(name)?;
        let fd = openat2(
            &self.fd,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(io)?;
        validate_regular(&fd, self.owner)?;
        self.recheck()?;
        Ok(File::from(fd))
    }

    pub(crate) fn recheck(&self) -> Result<(), PlanningError> {
        validate_directory(&self.fd, self.owner)?;
        if identity(&self.fd)? != self.identity {
            return Err(PlanningError::UnsafeSnapshot(
                "retained directory identity changed".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn fd(&self) -> &OwnedFd {
        &self.fd
    }

    pub(crate) fn set_mode(&self, mode: u32) -> Result<(), PlanningError> {
        self.recheck()?;
        fchmod(&self.fd, Mode::from_raw_mode(mode)).map_err(io)?;
        self.recheck()
    }

    pub(crate) fn sync(&self) -> Result<(), PlanningError> {
        self.recheck()?;
        File::from(self.fd.as_fd().try_clone_to_owned().map_err(read)?)
            .sync_all()
            .map_err(read)?;
        self.recheck()
    }
}

pub(crate) fn validate_tree(path: &Path, owner: u32) -> Result<(), PlanningError> {
    let directory = TrustedDirectory::open(path, owner, false, 0)?;
    validate_tree_fd(&directory)
}

pub(crate) fn validate_root_executable(path: &Path) -> Result<(), PlanningError> {
    let parent = path
        .parent()
        .ok_or_else(|| PlanningError::UnsafeRoot("executable has no parent directory".into()))?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| PlanningError::UnsafeRoot("executable name is not UTF-8".into()))?;
    let directory = TrustedDirectory::open(parent, 0, false, 0)?;
    validate_name(name)?;
    let fd = openat2(
        directory.fd(),
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io)?;
    let before = identity(&fd)?;
    let stat = fstat(&fd).map_err(io)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != 0
        || stat.st_nlink != 1
        || stat.st_mode & 0o022 != 0
        || stat.st_mode & 0o111 == 0
    {
        return Err(PlanningError::UnsafeRoot(
            "executable ownership, link count, mode, or type".into(),
        ));
    }
    if identity(&fd)? != before {
        return Err(PlanningError::UnsafeRoot(
            "executable changed while validated".into(),
        ));
    }
    directory.recheck()
}

fn validate_tree_fd(directory: &TrustedDirectory) -> Result<(), PlanningError> {
    directory.recheck()?;
    let entries = std::fs::read_dir(format!(
        "/proc/self/fd/{}",
        directory.fd().as_fd().as_raw_fd()
    ))
    .map_err(read)?;
    for entry in entries {
        let entry = entry.map_err(read)?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| PlanningError::UnsafeRoot("non-UTF-8 cache entry".into()))?;
        validate_name(name)?;
        let fd = openat2(
            directory.fd(),
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(io)?;
        let stat = fstat(&fd).map_err(io)?;
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                validate_tree_fd(&TrustedDirectory::from_fd(fd, directory.owner)?)?
            }
            FileType::RegularFile => validate_regular(&fd, directory.owner)?,
            _ => {
                return Err(PlanningError::UnsafeRoot(
                    "cache entry has an unsafe file type".into(),
                ));
            }
        }
    }
    directory.recheck()
}

fn open_child(
    parent: &OwnedFd,
    name: &std::ffi::OsStr,
    owner: u32,
    create: bool,
    mode: u32,
) -> Result<OwnedFd, PlanningError> {
    let name = name
        .to_str()
        .ok_or_else(|| PlanningError::UnsafeRoot("non-UTF-8 root path".into()))?;
    validate_name(name)?;
    let opened = openat2(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    );
    let (fd, created) = match opened {
        Ok(fd) => (fd, false),
        Err(rustix::io::Errno::NOENT) if create => {
            mkdirat(parent, name, Mode::from_raw_mode(mode)).map_err(io)?;
            (
                openat2(
                    parent,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )
                .map_err(io)?,
                true,
            )
        }
        Err(error) => return Err(io(error)),
    };
    validate_directory(&fd, owner)?;
    if created {
        fchmod(&fd, Mode::from_raw_mode(mode)).map_err(io)?;
        validate_directory(&fd, owner)?;
    }
    Ok(fd)
}

impl TrustedDirectory {
    fn from_fd(fd: OwnedFd, owner: u32) -> Result<Self, PlanningError> {
        validate_directory(&fd, owner)?;
        Ok(Self {
            identity: identity(&fd)?,
            fd,
            owner,
        })
    }
}

fn validate_directory(fd: &impl AsFd, owner: u32) -> Result<(), PlanningError> {
    let stat = fstat(fd).map_err(io)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || !owner_valid(stat.st_uid, owner)
        || stat.st_mode & 0o022 != 0
    {
        return Err(PlanningError::UnsafeRoot(
            "directory ownership, mode, or type".into(),
        ));
    }
    Ok(())
}

fn validate_regular(fd: &impl AsFd, owner: u32) -> Result<(), PlanningError> {
    let stat = fstat(fd).map_err(io)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || !owner_valid(stat.st_uid, owner)
        || stat.st_nlink != 1
        || stat.st_mode & 0o022 != 0
    {
        return Err(PlanningError::UnsafeSnapshot(
            "file ownership, link count, mode, or type".into(),
        ));
    }
    Ok(())
}

fn identity(fd: &impl AsFd) -> Result<Identity, PlanningError> {
    let stat = fstat(fd).map_err(io)?;
    Ok(Identity {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

fn validate_name(name: &str) -> Result<(), PlanningError> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\']) {
        return Err(PlanningError::UnsafeSnapshot(
            "unsafe path component".into(),
        ));
    }
    Ok(())
}

fn owner_valid(actual: u32, expected: u32) -> bool {
    actual == expected || (expected != 0 && actual == 0)
}
fn io(error: rustix::io::Errno) -> PlanningError {
    PlanningError::Io(error.to_string())
}
fn read(error: std::io::Error) -> PlanningError {
    PlanningError::Io(error.to_string())
}
