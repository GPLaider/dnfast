use std::{fs::File, io::Write, path::{Component, Path}};

use rustix::fs::{Mode, OFlags, ResolveFlags, fsync, open, openat2};

use super::AppFailure;

pub(super) fn write_new_plan(path: &Path, bytes: &[u8]) -> Result<(), AppFailure> {
    validate_new_path(path)?;
    let relative = path.strip_prefix("/").map_err(|_| invalid_path("output path must be absolute"))?;
    let root = open("/", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty()).map_err(errno_failure)?;
    let file = openat2(&root, relative, OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600), ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS).map_err(errno_failure)?;
    let mut file = File::from(file);
    file.write_all(bytes).map_err(std_io_failure)?;
    file.sync_all().map_err(std_io_failure)?;
    fsync(&root).map_err(errno_failure)
}

pub(super) fn validate_new_path(path: &Path) -> Result<(), AppFailure> {
    let raw = path.to_str().ok_or_else(|| invalid_path("output path is not UTF-8"))?;
    if !path.is_absolute() || raw.chars().any(char::is_control) {
        return Err(invalid_path("output path must be absolute UTF-8 without control characters"));
    }
    let relative = path.strip_prefix("/").map_err(|_| invalid_path("output path must be absolute"))?;
    if relative.as_os_str().is_empty() || relative.components().any(|component| !matches!(component, Component::Normal(_))) {
        return Err(invalid_path("output path has an unsafe component"));
    }
    Ok(())
}

fn invalid_path(message: &str) -> AppFailure { AppFailure::with_error_code(2, "invalid_output_path", message) }
fn errno_failure(error: rustix::io::Errno) -> AppFailure { AppFailure::new(1, error.to_string()) }
fn std_io_failure(error: std::io::Error) -> AppFailure { AppFailure::new(1, error.to_string()) }

#[cfg(test)]
mod tests {
    use std::fs;

    use super::write_new_plan;

    #[test]
    fn safe_absolute_plan_output_persists_after_file_and_directory_sync() {
        // Given: a new output below an existing absolute directory.
        let directory = tempfile::tempdir().expect("temporary output directory");
        let path = directory.path().join("proposal.json");
        let bytes = br#"{"schema":"dnfast.solver-plan.v1"}"#;

        // When: the public plan-output boundary writes and synchronizes it.
        let result = write_new_plan(&path, bytes);

        // Then: directory synchronization succeeds and the new file retains its exact bytes.
        assert!(result.is_ok(), "safe output must complete: {result:?}");
        assert_eq!(fs::read(path).expect("persisted public plan output"), bytes);
    }
}
