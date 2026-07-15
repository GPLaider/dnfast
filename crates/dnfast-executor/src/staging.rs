use std::{
    fs::File,
    io::{Read, Seek, Write},
    os::fd::OwnedFd,
};

use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, ResolveFlags, fstat, fsync, mkdirat, open, openat, openat2,
    unlinkat,
};
use sha2::Digest;

use crate::ExecutorError;

const STAGING_PATH: [&str; 4] = ["var", "lib", "dnfast", "staging"];

pub struct Staging {
    parent: OwnedFd,
    child: String,
    directory: OwnedFd,
    plan: File,
    files: Vec<String>,
}

impl Staging {
    pub fn create(plan: &[u8]) -> Result<Self, ExecutorError> {
        let parent = system_directory(&STAGING_PATH)?;
        let child = transaction_id()?;
        mkdirat(&parent, &child, Mode::from_raw_mode(0o700)).map_err(staging)?;
        let directory = openat2(
            &parent,
            &child,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(staging)?;
        validate_directory(&directory)?;
        let fd = openat(
            &directory,
            "plan.json",
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map_err(staging)?;
        let mut plan_file = File::from(fd);
        plan_file
            .write_all(plan)
            .map_err(|error| ExecutorError::Staging(error.to_string()))?;
        plan_file
            .sync_all()
            .map_err(|error| ExecutorError::Staging(error.to_string()))?;
        fsync(&directory).map_err(staging)?;
        Ok(Self {
            parent,
            child,
            directory,
            plan: plan_file,
            files: Vec::new(),
        })
    }

    pub fn plan(&self) -> &File {
        &self.plan
    }
    pub fn directory(&self) -> &OwnedFd {
        &self.directory
    }
    pub fn id(&self) -> &str {
        &self.child
    }
    pub(crate) fn path(&self, name: &str) -> String {
        format!("/var/lib/dnfast/staging/{}/{}", self.child, name)
    }

    pub fn cleanup(self) -> Result<(), ExecutorError> {
        for file in self
            .files
            .iter()
            .map(String::as_str)
            .chain(std::iter::once("plan.json"))
        {
            unlinkat(&self.directory, file, AtFlags::empty()).map_err(staging)?;
        }
        fsync(&self.directory).map_err(staging)?;
        unlinkat(&self.parent, &self.child, AtFlags::REMOVEDIR).map_err(staging)?;
        fsync(&self.parent).map_err(staging)
    }

    pub(crate) fn copy_file(
        &mut self,
        source: &mut File,
        name: &str,
        digest: &str,
        size: u64,
    ) -> Result<File, ExecutorError> {
        let fd = openat(
            &self.directory,
            name,
            OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map_err(staging)?;
        let mut target = File::from(fd);
        source
            .rewind()
            .map_err(|error| ExecutorError::Staging(error.to_string()))?;
        let mut total = 0_u64;
        let mut hasher = sha2::Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = source
                .read(&mut buffer)
                .map_err(|error| ExecutorError::Staging(error.to_string()))?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(
                    u64::try_from(count)
                        .map_err(|error| ExecutorError::Staging(error.to_string()))?,
                )
                .ok_or_else(|| ExecutorError::Staging("input size overflow".into()))?;
            target
                .write_all(&buffer[..count])
                .map_err(|error| ExecutorError::Staging(error.to_string()))?;
            sha2::Digest::update(&mut hasher, &buffer[..count]);
        }
        if total != size || format!("{:x}", sha2::Digest::finalize(hasher)) != digest {
            return Err(ExecutorError::Staging(
                "input changed during staging".into(),
            ));
        }
        target
            .sync_all()
            .map_err(|error| ExecutorError::Staging(error.to_string()))?;
        fsync(&self.directory).map_err(staging)?;
        target
            .rewind()
            .map_err(|error| ExecutorError::Staging(error.to_string()))?;
        self.files.push(name.into());
        Ok(target)
    }

    pub(crate) fn write_bytes(&mut self, name: &str, bytes: &[u8]) -> Result<File, ExecutorError> {
        let fd = openat(
            &self.directory,
            name,
            OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map_err(staging)?;
        let mut target = File::from(fd);
        target
            .write_all(bytes)
            .map_err(|error| ExecutorError::Staging(error.to_string()))?;
        target
            .sync_all()
            .map_err(|error| ExecutorError::Staging(error.to_string()))?;
        fsync(&self.directory).map_err(staging)?;
        target
            .rewind()
            .map_err(|error| ExecutorError::Staging(error.to_string()))?;
        self.files.push(name.into());
        Ok(target)
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        for file in self
            .files
            .iter()
            .map(String::as_str)
            .chain(std::iter::once("plan.json"))
        {
            let _ = unlinkat(&self.directory, file, AtFlags::empty());
        }
        let _ = fsync(&self.directory);
        let _ = unlinkat(&self.parent, &self.child, AtFlags::REMOVEDIR);
        let _ = fsync(&self.parent);
    }
}

pub(crate) fn system_directory(parts: &[&str]) -> Result<OwnedFd, ExecutorError> {
    let mut current = open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(staging)?;
    for part in parts {
        current = match openat2(
            &current,
            *part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        ) {
            Ok(directory) => directory,
            Err(rustix::io::Errno::NOENT) => {
                match mkdirat(&current, *part, Mode::from_raw_mode(0o700)) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => return Err(staging(error)),
                }
                openat2(
                    &current,
                    *part,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )
                .map_err(staging)?
            }
            Err(error) => return Err(staging(error)),
        };
        validate_directory(&current)?;
    }
    Ok(current)
}

fn validate_directory(fd: &OwnedFd) -> Result<(), ExecutorError> {
    let metadata = fstat(fd).map_err(staging)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != 0
        || metadata.st_mode & 0o022 != 0
    {
        return Err(ExecutorError::Staging("unsafe staging directory".into()));
    }
    Ok(())
}

fn transaction_id() -> Result<String, ExecutorError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| ExecutorError::Staging(error.to_string()))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    ))
}

fn staging(error: rustix::io::Errno) -> ExecutorError {
    ExecutorError::Staging(error.to_string())
}
