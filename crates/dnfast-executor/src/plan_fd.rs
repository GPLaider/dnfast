use std::{
    fs::File,
    io::Read,
    os::fd::OwnedFd,
    path::{Component, Path},
};

use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, fstat, open, openat2};

use crate::ExecutorError;

pub const MAX_PLAN_BYTES: u64 = 16 * 1024 * 1024;
pub struct InheritedPlan {
    bytes: Vec<u8>,
}

impl InheritedPlan {
    pub fn read() -> Result<Self, ExecutorError> {
        let fd = dnfast_native_sys::take_inherited_plan_fd()
            .map_err(|error| ExecutorError::Read(error.to_string()))?;
        validate_inherited_fd(&fd)?;
        let bytes = read_plan_bytes(File::from(fd))?;
        Ok(Self { bytes })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub fn validate_plan_path(path: &Path) -> Result<(), ExecutorError> {
    open_path_plan(path).map(drop)
}

pub fn open_plan(path: &Path) -> Result<OwnedFd, ExecutorError> {
    let source = open_path_plan(path)?;
    let bytes = read_plan_bytes(File::from(source))?;
    crate::compact_inputs::sealed_memfd("dnfast-plan", &bytes, MAX_PLAN_BYTES)
}

fn open_path_plan(path: &Path) -> Result<OwnedFd, ExecutorError> {
    if !path.is_absolute() || path.to_str().is_none() {
        return Err(ExecutorError::PlanPath);
    }
    let relative = path
        .strip_prefix("/")
        .map_err(|_| ExecutorError::PlanPath)?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(ExecutorError::UnsafeComponent);
    }
    let root = open(
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| ExecutorError::Read(error.to_string()))?;
    let fd = openat2(
        &root,
        relative,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| ExecutorError::UnsafePlan)?;
    validate_path_fd(&fd)?;
    Ok(fd)
}

fn read_plan_bytes(reader: impl Read) -> Result<Vec<u8>, ExecutorError> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_PLAN_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ExecutorError::Read(error.to_string()))?;
    if bytes.len() as u64 > MAX_PLAN_BYTES {
        return Err(ExecutorError::PlanTooLarge);
    }
    Ok(bytes)
}

fn validate_path_fd(fd: &impl rustix::fd::AsFd) -> Result<(), ExecutorError> {
    let metadata = fstat(fd).map_err(|_| ExecutorError::UnsafePlan)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o022 != 0
        || metadata.st_size < 0
        || u64::try_from(metadata.st_size).map_err(|_| ExecutorError::UnsafePlan)? > MAX_PLAN_BYTES
    {
        return Err(ExecutorError::UnsafePlan);
    }
    Ok(())
}

fn validate_inherited_fd(fd: &impl rustix::fd::AsFd) -> Result<(), ExecutorError> {
    match validate_path_fd(fd).and_then(|_| {
        if fstat(fd).map_err(|_| ExecutorError::UnsafePlan)?.st_uid != 0 {
            return Err(ExecutorError::UnsafePlan);
        }
        Ok(())
    }) {
        Ok(()) => Ok(()),
        Err(_) => crate::compact_inputs::validate_sealed_memfd(fd, MAX_PLAN_BYTES)
            .map_err(|_| ExecutorError::UnsafePlan),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Read, os::unix::fs::PermissionsExt};

    use super::*;

    #[test]
    fn rejects_non_absolute_and_unsafe_plan_paths() {
        assert!(matches!(
            validate_plan_path(Path::new("plan.json")),
            Err(ExecutorError::PlanPath)
        ));
        assert!(matches!(
            validate_plan_path(Path::new("/tmp/../plan.json")),
            Err(ExecutorError::UnsafeComponent)
        ));
    }

    #[test]
    fn rejects_group_writable_plan() {
        let directory = tempfile::tempdir().unwrap();
        let plan = directory.path().join("plan.json");
        fs::write(&plan, b"{}").unwrap();
        fs::set_permissions(&plan, fs::Permissions::from_mode(0o620)).unwrap();
        assert!(matches!(
            validate_plan_path(&plan),
            Err(ExecutorError::UnsafePlan)
        ));
    }

    #[test]
    fn accepts_valid_plan_path() {
        let directory = tempfile::tempdir().unwrap();
        let plan = directory.path().join("plan.json");
        fs::write(&plan, b"canonical-plan").unwrap();
        fs::set_permissions(&plan, fs::Permissions::from_mode(0o600)).unwrap();

        validate_plan_path(&plan).unwrap();
    }

    #[test]
    fn open_plan_returns_sealed_immutable_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let plan = directory.path().join("plan.json");
        fs::write(&plan, b"reviewed-plan").unwrap();
        fs::set_permissions(&plan, fs::Permissions::from_mode(0o600)).unwrap();

        let snapshot = open_plan(&plan).unwrap();
        fs::write(&plan, b"changed-plan!").unwrap();

        crate::compact_inputs::validate_sealed_memfd(&snapshot, MAX_PLAN_BYTES).unwrap();
        validate_inherited_fd(&snapshot).unwrap();
        assert_eq!(
            rustix::io::pwrite(&snapshot, b"x", 0).unwrap_err(),
            rustix::io::Errno::PERM
        );
        let mut observed = Vec::new();
        File::from(snapshot).read_to_end(&mut observed).unwrap();
        assert_eq!(observed, b"reviewed-plan");
    }

    #[test]
    fn accepts_plan_at_exact_size_limit() {
        let directory = tempfile::tempdir().unwrap();
        let plan = directory.path().join("plan.json");
        let file = File::create(&plan).unwrap();
        file.set_len(MAX_PLAN_BYTES).unwrap();
        fs::set_permissions(&plan, fs::Permissions::from_mode(0o600)).unwrap();

        let snapshot = open_plan(&plan).unwrap();
        assert_eq!(fstat(&snapshot).unwrap().st_size as u64, MAX_PLAN_BYTES);
    }

    #[test]
    fn rejects_plan_grown_after_open_past_size_limit() {
        let directory = tempfile::tempdir().unwrap();
        let plan = directory.path().join("plan.json");
        fs::write(&plan, b"small-plan").unwrap();
        fs::set_permissions(&plan, fs::Permissions::from_mode(0o600)).unwrap();
        let source = open_path_plan(&plan).unwrap();

        File::options()
            .write(true)
            .open(&plan)
            .unwrap()
            .set_len(MAX_PLAN_BYTES + 1)
            .unwrap();

        assert!(matches!(
            read_plan_bytes(File::from(source)),
            Err(ExecutorError::PlanTooLarge)
        ));
    }

    #[test]
    fn rejects_non_root_owned_inherited_ordinary_plan() {
        let directory = tempfile::tempdir().unwrap();
        let plan = directory.path().join("plan.json");
        fs::write(&plan, b"canonical-plan").unwrap();
        fs::set_permissions(&plan, fs::Permissions::from_mode(0o600)).unwrap();
        let file = File::open(&plan).unwrap();
        if rustix::process::geteuid().is_root() {
            rustix::fs::fchown(&file, Some(rustix::fs::Uid::from_raw(65_534)), None).unwrap();
        }
        assert_ne!(fstat(&file).unwrap().st_uid, 0);

        assert!(matches!(
            validate_inherited_fd(&file),
            Err(ExecutorError::UnsafePlan)
        ));
    }
}
