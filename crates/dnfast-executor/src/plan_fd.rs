use std::{fs::File, io::Read, os::fd::OwnedFd, path::{Component, Path}};

use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, fstat, open, openat2};

use crate::ExecutorError;

pub const MAX_PLAN_BYTES: u64 = 16 * 1024 * 1024;
pub struct InheritedPlan { bytes: Vec<u8> }

impl InheritedPlan {
    pub fn read() -> Result<Self, ExecutorError> {
        let fd = dnfast_native_sys::take_inherited_plan_fd()
            .map_err(|error| ExecutorError::Read(error.to_string()))?;
        validate_fd(&fd)?;
        let mut file = File::from(fd);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|error| ExecutorError::Read(error.to_string()))?;
        if u64::try_from(bytes.len()).map_err(|error| ExecutorError::Read(error.to_string()))? > MAX_PLAN_BYTES {
            return Err(ExecutorError::PlanTooLarge);
        }
        Ok(Self { bytes })
    }

    pub fn bytes(&self) -> &[u8] { &self.bytes }
}

pub fn validate_plan_path(path: &Path) -> Result<(), ExecutorError> {
    let fd = open_plan(path)?;
    validate_fd(&fd)
}

pub fn open_plan(path: &Path) -> Result<OwnedFd, ExecutorError> {
    if !path.is_absolute() || path.to_str().is_none() { return Err(ExecutorError::PlanPath); }
    let relative = path.strip_prefix("/").map_err(|_| ExecutorError::PlanPath)?;
    if relative.as_os_str().is_empty() || relative.components().any(|part| !matches!(part, Component::Normal(_))) {
        return Err(ExecutorError::UnsafeComponent);
    }
    let root = open("/", OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|error| ExecutorError::Read(error.to_string()))?;
    let fd = openat2(&root, relative, OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(), ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS)
        .map_err(|_| ExecutorError::UnsafePlan)?;
    validate_fd(&fd)?;
    Ok(fd)
}

fn validate_fd(fd: &impl rustix::fd::AsFd) -> Result<(), ExecutorError> {
    let metadata = fstat(fd).map_err(|_| ExecutorError::UnsafePlan)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_nlink != 1 || metadata.st_mode & 0o022 != 0 || metadata.st_size < 0
        || u64::try_from(metadata.st_size).map_err(|_| ExecutorError::UnsafePlan)? > MAX_PLAN_BYTES {
        return Err(ExecutorError::UnsafePlan);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::*;

    #[test]
    fn rejects_non_absolute_and_unsafe_plan_paths() {
        assert!(matches!(validate_plan_path(Path::new("plan.json")), Err(ExecutorError::PlanPath)));
        assert!(matches!(validate_plan_path(Path::new("/tmp/../plan.json")), Err(ExecutorError::UnsafeComponent)));
    }

    #[test]
    fn rejects_group_writable_plan() {
        let directory = tempfile::tempdir().unwrap();
        let plan = directory.path().join("plan.json");
        fs::write(&plan, b"{}").unwrap();
        fs::set_permissions(&plan, fs::Permissions::from_mode(0o620)).unwrap();
        assert!(matches!(validate_plan_path(&plan), Err(ExecutorError::UnsafePlan)));
    }
}
