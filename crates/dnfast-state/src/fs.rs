use std::{
    fs::File,
    io::{Read, Write},
    os::fd::OwnedFd,
    path::Path,
};

use rustix::fs::{Mode, OFlags, fchmod, fstat, fsync, mkdirat, open, openat, renameat};

use crate::{FaultPlan, FaultPoint, StateError, error::errno, error::io};

pub(crate) fn open_or_create_root(path: &Path) -> Result<OwnedFd, StateError> {
    let mut names = path.components();
    if !matches!(names.next(), Some(std::path::Component::RootDir)) {
        return Err(StateError::UnsafePath(
            "journal root must be absolute".into(),
        ));
    }
    let components = names
        .map(|component| match component {
            std::path::Component::Normal(name) => Ok(name.to_owned()),
            _ => Err(StateError::UnsafePath(
                "invalid journal root component".into(),
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if components.is_empty() {
        return Err(StateError::UnsafePath(
            "journal root cannot be filesystem root".into(),
        ));
    }
    let mut current = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(errno)?;
    for (index, component) in components.iter().enumerate() {
        if index + 1 == components.len() {
            match mkdirat(&current, component, Mode::from_raw_mode(0o700)) {
                Ok(()) => fsync(&current).map_err(errno)?,
                Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(errno(error)),
            }
        }
        current = openat(
            &current,
            component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(errno)?;
    }
    verify(&current, true, false)?;
    Ok(current)
}

pub(crate) fn create_transaction(
    root: &OwnedFd,
    name: &str,
    faults: &FaultPlan,
) -> Result<OwnedFd, StateError> {
    faults.check(FaultPoint::Create)?;
    mkdirat(root, name, Mode::from_raw_mode(0o700)).map_err(errno)?;
    fsync(root).map_err(errno)?;
    open_transaction(root, name)
}

pub(crate) fn open_transaction(root: &OwnedFd, name: &str) -> Result<OwnedFd, StateError> {
    let fd = openat(
        root,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(errno)?;
    verify(&fd, true, false)?;
    Ok(fd)
}

pub(crate) fn write_record(
    directory: &OwnedFd,
    sequence: u64,
    bytes: &[u8],
    faults: &FaultPlan,
) -> Result<(), StateError> {
    let final_name = format!("{sequence:020}.json");
    if openat(
        directory,
        &final_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .is_ok()
    {
        return Err(StateError::Corrupt("duplicate sequence".into()));
    }
    let temporary = format!(".{sequence:020}.tmp-{}", std::process::id());
    let fd = openat(
        directory,
        &temporary,
        OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(errno)?;
    let mut cleanup = TempCleanup {
        directory,
        name: temporary.clone(),
        armed: true,
    };
    fchmod(&fd, Mode::from_raw_mode(0o600)).map_err(errno)?;
    let mut file = File::from(fd);
    faults.check(FaultPoint::Write)?;
    file.write_all(bytes).map_err(io)?;
    faults.check(FaultPoint::FileSync)?;
    file.sync_all().map_err(io)?;
    faults.check(FaultPoint::Publish)?;
    renameat(directory, &temporary, directory, &final_name).map_err(errno)?;
    fsync(directory).map_err(errno)?;
    cleanup.armed = false;
    faults.check(FaultPoint::DirectorySync)?;
    Ok(())
}

pub(crate) fn read_bounded(
    directory: &OwnedFd,
    name: &str,
    maximum: u64,
) -> Result<Vec<u8>, StateError> {
    let fd = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(errno)?;
    verify(&fd, false, true)?;
    let stat = fstat(&fd).map_err(errno)?;
    if stat.st_size < 0
        || u64::try_from(stat.st_size).map_err(|_| StateError::Limit("record"))? > maximum
    {
        return Err(StateError::Limit("record"));
    }
    let mut bytes = Vec::new();
    File::from(fd)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > maximum {
        return Err(StateError::Limit("record"));
    }
    Ok(bytes)
}

pub(crate) fn verify(fd: &OwnedFd, directory: bool, one_link: bool) -> Result<(), StateError> {
    let stat = fstat(fd).map_err(errno)?;
    let kind = if directory { 0o040000 } else { 0o100000 };
    let expected_mode = if directory { 0o700 } else { 0o600 };
    if stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o170000 != kind
        || stat.st_mode & 0o777 != expected_mode
        || (one_link && stat.st_nlink != 1)
    {
        return Err(StateError::UnsafePath(
            "ownership, mode, type, or link count".into(),
        ));
    }
    Ok(())
}

struct TempCleanup<'a> {
    directory: &'a OwnedFd,
    name: String,
    armed: bool,
}
impl Drop for TempCleanup<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = rustix::fs::unlinkat(self.directory, &self.name, rustix::fs::AtFlags::empty());
        }
    }
}

pub(crate) fn child_names(directory: &OwnedFd) -> Result<Vec<String>, StateError> {
    let mut stream = rustix::fs::Dir::read_from(directory).map_err(errno)?;
    let mut names = Vec::new();
    while let Some(entry) = stream.read() {
        let entry = entry.map_err(errno)?;
        let value = entry
            .file_name()
            .to_str()
            .map_err(|_| StateError::Corrupt("non-UTF8 journal name".into()))?;
        if !matches!(value, "." | "..") {
            names.push(value.into());
        }
    }
    names.sort();
    Ok(names)
}

pub(crate) fn cleanup_private_child(root_path: &Path, child: &str) -> Result<(), StateError> {
    let root = open_existing_root(root_path)?;
    let directory = open_transaction(&root, child)?;
    for name in child_names(&directory)? {
        let fd = openat(
            &directory,
            &name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(errno)?;
        verify(&fd, false, true)?;
        rustix::fs::unlinkat(&directory, &name, rustix::fs::AtFlags::empty()).map_err(errno)?;
    }
    fsync(&directory).map_err(errno)?;
    rustix::fs::unlinkat(&root, child, rustix::fs::AtFlags::REMOVEDIR).map_err(errno)?;
    fsync(&root).map_err(errno)
}

pub(crate) fn remove_failed_transaction(root: &OwnedFd, child: &str) -> Result<(), StateError> {
    let directory = open_transaction(root, child)?;
    for name in child_names(&directory)? {
        rustix::fs::unlinkat(&directory, &name, rustix::fs::AtFlags::empty()).map_err(errno)?;
    }
    fsync(&directory).map_err(errno)?;
    rustix::fs::unlinkat(root, child, rustix::fs::AtFlags::REMOVEDIR).map_err(errno)?;
    fsync(root).map_err(errno)
}

fn open_existing_root(path: &Path) -> Result<OwnedFd, StateError> {
    let mut current = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(errno)?;
    let mut components = path.components();
    if !matches!(components.next(), Some(std::path::Component::RootDir)) {
        return Err(StateError::UnsafePath("root must be absolute".into()));
    }
    for component in components {
        let std::path::Component::Normal(name) = component else {
            return Err(StateError::UnsafePath("invalid root component".into()));
        };
        current = openat(
            &current,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(errno)?;
    }
    verify(&current, true, false)?;
    Ok(current)
}
