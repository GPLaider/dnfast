use std::os::fd::OwnedFd;

use rustix::{
    fs::{AtFlags, Mode, OFlags, RenameFlags, ResolveFlags, fsync, openat2, renameat_with, unlinkat},
    io::Errno,
};

use crate::RootInputs;

use super::{InputDraft, errno, inputs, io};
use super::super::{PreparedInputs, PreparationError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Publication { Published, Existing }

impl InputDraft {
    pub(crate) fn publish(mut self, digest: &str, proposal: &dnfast_solver::CanonicalSolverPlan) -> Result<PreparedInputs, PreparationError> {
        match self.publish_generation(digest)? {
            Publication::Published => {
                fsync(&self.parent).map_err(errno)?;
                match RootInputs::open(proposal).map_err(inputs) {
                    Ok(_) => Ok(PreparedInputs { digest: digest.into() }),
                    Err(error) => {
                        remove_generation(&self.parent, digest).map_err(|cleanup| {
                            PreparationError::Publish(format!("published input validation failed: {error}; generation cleanup failed: {cleanup}"))
                        })?;
                        Err(error)
                    }
                }
            }
            Publication::Existing => {
                RootInputs::open(proposal).map_err(inputs)?;
                Ok(PreparedInputs { digest: digest.into() })
            }
        }
    }

    pub(crate) fn publish_generation(&mut self, digest: &str) -> Result<Publication, PreparationError> {
        match renameat_with(&self.parent, &self.name, &self.parent, digest, RenameFlags::NOREPLACE) {
            Ok(()) => {
                self.name.clear();
                Ok(Publication::Published)
            }
            Err(Errno::EXIST) => Ok(Publication::Existing),
            Err(error) => Err(errno(error)),
        }
    }
}

impl Drop for InputDraft {
    fn drop(&mut self) {
        if !self.name.is_empty() {
            let entries = std::fs::read_dir(format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&self.directory)));
            if let Ok(entries) = entries {
                for entry in entries.flatten() {
                    let _ = unlinkat(&self.directory, entry.file_name(), AtFlags::empty());
                }
            }
            let _ = unlinkat(&self.parent, &self.name, AtFlags::REMOVEDIR);
            let _ = fsync(&self.parent);
        }
    }
}

pub(crate) fn remove_generation(parent: &OwnedFd, name: &str) -> Result<(), PreparationError> {
    let directory = openat2(parent, name, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(), ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS).map_err(errno)?;
    let entries = std::fs::read_dir(format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&directory))).map_err(io)?;
    for entry in entries {
        unlinkat(&directory, entry.map_err(io)?.file_name(), AtFlags::empty()).map_err(errno)?;
    }
    unlinkat(parent, name, AtFlags::REMOVEDIR).map_err(errno)?;
    fsync(parent).map_err(errno)
}
