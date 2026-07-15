use std::{
    fs,
    os::fd::OwnedFd,
    time::{Duration, Instant},
};

use rustix::fs::{FlockOperation, Mode, OFlags, flock, fstat, mkdirat, open, openat};
use sha2::{Digest, Sha256};

use crate::RefreshError;

const LOCK_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) struct RepositoryLock {
    _file: OwnedFd,
}

impl RepositoryLock {
    pub(crate) fn acquire(root: &std::path::Path, repository: &str) -> Result<Self, RefreshError> {
        Self::acquire_with_timeout(root, repository, LOCK_TIMEOUT)
    }

    fn acquire_with_timeout(
        root: &std::path::Path,
        repository: &str,
        timeout: Duration,
    ) -> Result<Self, RefreshError> {
        reject_symlinks(root)?;
        create_private(root).map_err(io_error)?;
        let root_fd = open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(errno)?;
        verify(&root_fd, true)?;
        match mkdirat(&root_fd, "refresh-locks", Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(errno(error)),
        }
        let directory = openat(
            &root_fd,
            "refresh-locks",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(errno)?;
        verify(&directory, true)?;
        let name = format!(
            "{}.lock",
            hex::encode(Sha256::digest(repository.as_bytes()))
        );
        let fd = openat(
            &directory,
            name,
            OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(errno)?;
        verify(&fd, false)?;
        let started = Instant::now();
        loop {
            match flock(&fd, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => {
                    acquisition_hook(repository);
                    let current = open(
                        root,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(errno)?;
                    let anchored = fstat(&root_fd).map_err(errno)?;
                    let visible = fstat(&current).map_err(errno)?;
                    if anchored.st_dev != visible.st_dev || anchored.st_ino != visible.st_ino {
                        return Err(RefreshError::Cache(
                            "cache root changed during lock acquisition".into(),
                        ));
                    }
                    return Ok(Self { _file: fd });
                }
                Err(rustix::io::Errno::WOULDBLOCK) if started.elapsed() < timeout => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(rustix::io::Errno::WOULDBLOCK) => {
                    return Err(RefreshError::Cache(
                        "repository refresh lock timed out".into(),
                    ));
                }
                Err(error) => return Err(errno(error)),
            }
        }
    }
}

fn verify(fd: &OwnedFd, directory: bool) -> Result<(), RefreshError> {
    let metadata = fstat(fd).map_err(errno)?;
    let kind = if directory { 0o040000 } else { 0o100000 };
    if metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode & 0o170000 != kind
        || metadata.st_mode & 0o022 != 0
        || (!directory && metadata.st_nlink != 1)
    {
        return Err(RefreshError::Cache(
            "unsafe repository refresh lock path".into(),
        ));
    }
    Ok(())
}

fn reject_symlinks(path: &std::path::Path) -> Result<(), RefreshError> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(RefreshError::Cache("symlinked cache root ancestor".into()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_private(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(path)
}
#[cfg(not(unix))]
fn create_private(path: &std::path::Path) -> std::io::Result<()> {
    fs::create_dir_all(path)
}
fn io_error(error: std::io::Error) -> RefreshError {
    RefreshError::Cache(error.to_string())
}
fn errno(error: rustix::io::Errno) -> RefreshError {
    RefreshError::Cache(error.to_string())
}

#[cfg(test)]
static ACQUIRE_HOOK: std::sync::Mutex<
    Option<std::sync::Arc<(std::sync::Barrier, std::sync::Barrier)>>,
> = std::sync::Mutex::new(None);

#[cfg(test)]
fn acquisition_hook(repository: &str) {
    if repository != "swap-target" {
        return;
    }
    let hook = ACQUIRE_HOOK.lock().unwrap().clone();
    if let Some(hook) = hook {
        hook.0.wait();
        hook.1.wait();
    }
}

#[cfg(not(test))]
fn acquisition_hook(_repository: &str) {}

#[cfg(all(test, unix))]
mod tests {
    use sha2::Digest;
    use std::os::unix::fs::symlink;

    use super::RepositoryLock;

    #[test]
    fn rejects_symlinked_lock_file_without_changing_target_mode() {
        // Given
        let root = tempfile::tempdir().unwrap();
        let locks = root.path().join("refresh-locks");
        std::fs::create_dir(&locks).unwrap();
        let target = root.path().join("target");
        std::fs::write(&target, b"target").unwrap();
        let name = format!("{}.lock", hex::encode(sha2::Sha256::digest(b"fedora")));
        symlink(&target, locks.join(name)).unwrap();
        let before = std::fs::metadata(&target).unwrap().permissions();

        // When
        let result = RepositoryLock::acquire(root.path(), "fedora");

        // Then
        assert!(result.is_err());
        assert_eq!(std::fs::metadata(target).unwrap().permissions(), before);
    }

    #[test]
    fn rejects_symlinked_lock_directory_without_writing_target() {
        let root = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        symlink(target.path(), root.path().join("refresh-locks")).unwrap();
        let result = RepositoryLock::acquire(root.path(), "fedora");
        assert!(result.is_err());
        assert_eq!(std::fs::read_dir(target.path()).unwrap().count(), 0);
    }

    #[test]
    fn same_repository_serializes_and_drop_releases() {
        let root = tempfile::tempdir().unwrap();
        let first = RepositoryLock::acquire(root.path(), "fedora").unwrap();
        let path = root.path().to_owned();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let second = RepositoryLock::acquire(&path, "fedora").unwrap();
            tx.send(()).unwrap();
            drop(second);
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(50))
                .is_err()
        );
        drop(first);
        rx.recv_timeout(std::time::Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn distinct_repositories_lock_concurrently() {
        let root = tempfile::tempdir().unwrap();
        let first = RepositoryLock::acquire(root.path(), "fedora").unwrap();
        let second = RepositoryLock::acquire(root.path(), "updates").unwrap();
        drop((first, second));
    }

    #[test]
    fn configured_timeout_expires_while_production_remains_thirty_seconds() {
        assert_eq!(super::LOCK_TIMEOUT, std::time::Duration::from_secs(30));
        let root = tempfile::tempdir().unwrap();
        let held = RepositoryLock::acquire(root.path(), "fedora").unwrap();
        let started = std::time::Instant::now();
        let result = RepositoryLock::acquire_with_timeout(
            root.path(),
            "fedora",
            std::time::Duration::from_millis(40),
        );
        let elapsed = started.elapsed();
        assert!(result.is_err());
        assert!(elapsed >= std::time::Duration::from_millis(40));
        assert!(elapsed < std::time::Duration::from_millis(150));
        drop(held);
    }

    #[test]
    fn root_rename_and_symlink_swap_cannot_redirect_held_lock() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("cache");
        let attacker = parent.path().join("attacker");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&attacker).unwrap();
        let lock = RepositoryLock::acquire(&root, "fedora").unwrap();
        let retained = parent.path().join("retained");
        std::fs::rename(&root, &retained).unwrap();
        symlink(&attacker, &root).unwrap();
        drop(lock);
        assert_eq!(std::fs::read_dir(attacker).unwrap().count(), 0);
        assert_eq!(
            std::fs::read_dir(retained.join("refresh-locks"))
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn root_swap_during_acquisition_is_detected() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("cache");
        std::fs::create_dir(&root).unwrap();
        let hook = std::sync::Arc::new((std::sync::Barrier::new(2), std::sync::Barrier::new(2)));
        *super::ACQUIRE_HOOK.lock().unwrap() = Some(hook.clone());
        let acquire_root = root.clone();
        let worker =
            std::thread::spawn(move || RepositoryLock::acquire(&acquire_root, "swap-target"));
        hook.0.wait();
        std::fs::rename(&root, parent.path().join("retained")).unwrap();
        std::fs::create_dir(&root).unwrap();
        hook.1.wait();
        let result = worker.join().unwrap();
        *super::ACQUIRE_HOOK.lock().unwrap() = None;
        assert!(result.is_err());
        assert_eq!(std::fs::read_dir(root).unwrap().count(), 0);
    }

    #[test]
    fn lock_holder_process() {
        let Ok(root) = std::env::var("DNFAST_LOCK_HOLDER_ROOT") else {
            return;
        };
        let lock = RepositoryLock::acquire(std::path::Path::new(&root), "fedora").unwrap();
        std::fs::write(std::path::Path::new(&root).join("ready"), b"ready").unwrap();
        std::thread::sleep(std::time::Duration::from_secs(60));
        drop(lock);
    }

    #[test]
    fn killed_process_releases_repository_lock() {
        let root = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "repo_lock::tests::lock_holder_process"])
            .env("DNFAST_LOCK_HOLDER_ROOT", root.path())
            .spawn()
            .unwrap();
        let ready = root.path().join("ready");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !ready.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(ready.exists());
        child.kill().unwrap();
        child.wait().unwrap();
        let lock = RepositoryLock::acquire_with_timeout(
            root.path(),
            "fedora",
            std::time::Duration::from_secs(1),
        )
        .unwrap();
        drop(lock);
    }
}
