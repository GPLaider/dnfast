use std::{os::fd::OwnedFd, path::PathBuf};

use rustix::{fs::{AtFlags, Mode, OFlags, StatxFlags, fstat, mkdirat, open, openat2, statx, unlinkat}, mount::{MountFlags, MountPropagationFlags, mount_bind, mount_change, mount_remount, unmount}, process::{chdir, chroot, fchdir}, thread::UnshareFlags};

use crate::{ExecutorError, Staging, staging::system_directory};

const ROOT_PATH: [&str; 3] = ["run", "dnfast", "root"];

pub struct MountRoot { parent: OwnedFd, name: String, target: PathBuf, root: OwnedFd, host_root: Option<OwnedFd>, entered_root: bool }

#[derive(Eq, PartialEq)]
struct MountIdentity { mount_id: u64, device_major: u32, device_minor: u32, inode: u64 }

impl MountRoot {
    pub fn create(staging: &Staging) -> Result<Self, ExecutorError> {
        unshare_mount_namespace()?;
        mount_change("/", MountPropagationFlags::PRIVATE | MountPropagationFlags::REC).map_err(mount)?;
        let parent = system_directory(&ROOT_PATH)?;
        mkdirat(&parent, staging.id(), Mode::from_raw_mode(0o700)).map_err(mount)?;
        let target = PathBuf::from("/run/dnfast/root").join(staging.id());
        mount_bind("/", &target).map_err(mount)?;
        mount_remount(&target, MountFlags::BIND | MountFlags::RDONLY, "").map_err(mount)?;
        let root = open_mount_root(&parent, staging.id())?;
        let _ = mount_identity(&root)?;
        Ok(Self { parent, name: staging.id().into(), target, root, host_root: None, entered_root: false })
    }

    pub fn root(&self) -> &PathBuf { &self.target }

    pub fn allow_writes(&mut self) -> Result<(), ExecutorError> {
        self.verify_unchanged()?;
        mount_remount(&self.target, MountFlags::BIND, "").map_err(mount)?;
        self.verify_unchanged()?;
        let host_root = open("/", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty()).map_err(mount)?;
        chroot(&self.target).map_err(mount)?;
        chdir("/").map_err(mount)?;
        self.host_root = Some(host_root);
        self.entered_root = true;
        Ok(())
    }

    pub fn restore_namespace_root(&mut self) -> Result<(), ExecutorError> {
        if !self.entered_root { return Ok(()); }
        let host_root = self.host_root.take().ok_or_else(|| ExecutorError::Mount("missing pre-chroot root fd for post-transaction restore".into()))?;
        fchdir(&host_root).map_err(mount)?;
        chroot(".").map_err(mount)?;
        chdir("/").map_err(mount)?;
        self.entered_root = false;
        Ok(())
    }

    pub fn verify_unchanged(&self) -> Result<(), ExecutorError> {
        let current = if self.entered_root { open("/", OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty()).map_err(mount)? }
            else { open_mount_root(&self.parent, &self.name)? };
        if mount_identity(&current)? == mount_identity(&self.root)? { Ok(()) }
        else { Err(ExecutorError::Mount("root bind mount changed".into())) }
    }

    #[cfg(feature = "test-fixtures")]
    pub fn fixture_replace_bind_mount(&self) -> Result<(), ExecutorError> {
        std::fs::write("/tmp/.dnfast-mount-swap-sentinel", b"fixture").map_err(|error| ExecutorError::Mount(error.to_string()))?;
        unmount(&self.target, rustix::mount::UnmountFlags::DETACH | rustix::mount::UnmountFlags::NOFOLLOW).map_err(mount)?;
        mount_bind("/tmp", &self.target).map_err(mount)
    }

    #[cfg(feature = "test-fixtures")]
    pub fn fixture_replacement_has_sentinel(&self) -> bool { self.target.join(".dnfast-mount-swap-sentinel").is_file() }

    #[cfg(feature = "test-fixtures")]
    pub fn fixture_replace_current_root(&self) -> Result<(), ExecutorError> {
        std::fs::write("/tmp/.dnfast-current-root-sentinel", b"fixture").map_err(|error| ExecutorError::Mount(error.to_string()))?;
        mount_bind("/tmp", "/").map_err(mount)
    }

    #[cfg(feature = "test-fixtures")]
    pub fn fixture_current_root_has_sentinel(&self) -> bool {
        let _ = self;
        std::path::Path::new("/.dnfast-current-root-sentinel").is_file()
    }

    pub fn cleanup(self) -> Result<(), ExecutorError> {
        if self.entered_root { return Ok(()); }
        unmount(&self.target, rustix::mount::UnmountFlags::DETACH | rustix::mount::UnmountFlags::NOFOLLOW).map_err(mount)?;
        unlinkat(&self.parent, &self.name, AtFlags::REMOVEDIR).map_err(mount)
    }
}

impl Drop for MountRoot {
    fn drop(&mut self) {
        if self.entered_root { return; }
        let _ = unmount(&self.target, rustix::mount::UnmountFlags::NOFOLLOW);
        let _ = unlinkat(&self.parent, &self.name, AtFlags::REMOVEDIR);
    }
}

fn unshare_mount_namespace() -> Result<(), ExecutorError> {
    #[allow(deprecated, reason = "NEWNS does not unshare file descriptors")]
    rustix::thread::unshare(UnshareFlags::NEWNS).map_err(mount)
}

fn open_mount_root(parent: &OwnedFd, name: &str) -> Result<OwnedFd, ExecutorError> {
    openat2(parent, name, OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(), rustix::fs::ResolveFlags::BENEATH | rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS).map_err(mount)
}

fn mount_identity(fd: &OwnedFd) -> Result<MountIdentity, ExecutorError> {
    let _ = fstat(fd).map_err(mount)?;
    statx(fd, "", AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW, StatxFlags::MNT_ID)
        .map(|value| MountIdentity { mount_id: value.stx_mnt_id, device_major: value.stx_dev_major,
            device_minor: value.stx_dev_minor, inode: value.stx_ino }).map_err(mount)
}

fn mount(error: rustix::io::Errno) -> ExecutorError { ExecutorError::Mount(error.to_string()) }

#[cfg(all(test, feature = "test-fixtures"))]
mod tests {
    use crate::Staging;

    use super::MountRoot;

    #[test]
    fn recursive_private_bind_replacement_is_rejected() {
        if rustix::process::geteuid().as_raw() != 0 { return; }
        let staging = Staging::create(b"{}") .expect("staging");
        let mut root = MountRoot::create(&staging).expect("private root");
        root.fixture_replace_bind_mount().expect("replace recursive bind root");
        assert!(root.allow_writes().is_err(), "replacement must fail retained mount identity");
        root.cleanup().expect("replacement cleanup");
        staging.cleanup().expect("staging cleanup");
        std::fs::remove_file("/tmp/.dnfast-mount-swap-sentinel").expect("sentinel cleanup");
    }
}
