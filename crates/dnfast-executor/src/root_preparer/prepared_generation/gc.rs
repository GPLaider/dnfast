use std::{
    os::fd::{AsRawFd, OwnedFd},
    time::{SystemTime, UNIX_EPOCH},
};

use rustix::{
    fs::{
        AtFlags, FlockOperation, Mode, OFlags, ResolveFlags, flock, fstat, fsync, openat2, unlinkat,
    },
    io::Errno,
};

use super::{PreparationError, errno, io};

pub(super) const STALE_INPUT_GRACE_SECONDS: u64 = 60 * 60;

pub(super) fn garbage_collect(
    parent: &OwnedFd,
    minimum_age_seconds: u64,
) -> Result<usize, PreparationError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| PreparationError::Publish(error.to_string()))?
        .as_secs();
    let entries = std::fs::read_dir(format!("/proc/self/fd/{}", parent.as_raw_fd())).map_err(io)?;
    let mut removed = 0_usize;
    for entry in entries {
        let entry = entry.map_err(io)?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| PreparationError::Publish("input generation name is not UTF-8".into()))?
            .to_owned();
        if !generation_name(&name) {
            return Err(PreparationError::Publish(
                "unexpected entry in private input generation root".into(),
            ));
        }
        let directory = match openat2(
            parent,
            &name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        ) {
            Ok(directory) => directory,
            Err(Errno::NOENT) => continue,
            Err(error) => return Err(errno(error)),
        };
        let stat = fstat(&directory).map_err(errno)?;
        if stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o170000 != 0o040000
            || stat.st_mode & 0o777 != 0o700
        {
            return Err(PreparationError::Publish(
                "unsafe input generation directory".into(),
            ));
        }
        let modified = u64::try_from(stat.st_mtime).unwrap_or_default();
        if now.saturating_sub(modified) < minimum_age_seconds {
            continue;
        }
        match flock(&directory, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(Errno::WOULDBLOCK) => continue,
            Err(error) => return Err(errno(error)),
        }
        remove_locked_generation(parent, &directory, &name)?;
        removed = removed.saturating_add(1);
    }
    Ok(removed)
}

fn remove_locked_generation(
    parent: &OwnedFd,
    directory: &OwnedFd,
    name: &str,
) -> Result<(), PreparationError> {
    let entries =
        std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd())).map_err(io)?;
    for entry in entries {
        let entry = entry.map_err(io)?;
        let file_name = entry.file_name();
        let file = openat2(
            directory,
            &file_name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(errno)?;
        let stat = fstat(&file).map_err(errno)?;
        if stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o170000 != 0o100000
            || stat.st_mode & 0o777 != 0o600
            || stat.st_nlink != 1
        {
            return Err(PreparationError::Publish(
                "unsafe file in input generation".into(),
            ));
        }
        unlinkat(directory, &file_name, AtFlags::empty()).map_err(errno)?;
    }
    fsync(directory).map_err(errno)?;
    match unlinkat(parent, name, AtFlags::REMOVEDIR) {
        Ok(()) => fsync(parent).map_err(errno),
        Err(Errno::NOENT) => Ok(()),
        Err(error) => Err(errno(error)),
    }
}

fn generation_name(name: &str) -> bool {
    let digest = name.strip_prefix(super::PREPARING_PREFIX).unwrap_or(name);
    matches!(digest.len(), 32 | 64)
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && (name.starts_with(super::PREPARING_PREFIX) || name.len() == 64)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};

    use super::{garbage_collect, generation_name};

    #[test]
    fn input_generation_names_are_narrow() {
        assert!(generation_name(&"a".repeat(64)));
        assert!(generation_name(&format!(".prepare-{}", "b".repeat(32))));
        assert!(!generation_name("state.json"));
        assert!(!generation_name(".prepare-../escape"));
        assert!(!generation_name(&"A".repeat(64)));
    }

    #[test]
    fn collection_removes_only_unlocked_private_generations() {
        let fixture = tempfile::tempdir().expect("fixture");
        let stale = fixture.path().join("a".repeat(64));
        let active = fixture.path().join(format!(".prepare-{}", "b".repeat(32)));
        for directory in [&stale, &active] {
            fs::create_dir(directory).expect("generation");
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).expect("mode");
            let input = directory.join("manifest.json");
            fs::write(&input, b"fixture").expect("input");
            fs::set_permissions(input, fs::Permissions::from_mode(0o600)).expect("input mode");
        }
        let parent = open(
            fixture.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("parent");
        let active_lock = open(
            &active,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("active");
        flock(&active_lock, FlockOperation::LockShared).expect("shared lock");

        assert_eq!(garbage_collect(&parent, 0).expect("collection"), 1);
        assert!(!stale.exists());
        assert!(active.exists());
    }
}
