use std::{
    ffi::OsStr,
    io::Read,
    os::{fd::OwnedFd, unix::ffi::OsStrExt},
    path::{Component, Path},
};

use rustix::fs::{AtFlags, FileType, Mode, OFlags, fstat, open, openat, readlinkat, statat};

use crate::MutationError;

pub(crate) fn read_root_file(
    path: &Path,
    limit: u64,
    owner: u32,
) -> Result<Vec<u8>, MutationError> {
    let directory = open_root_regular_file(path, owner)?;
    let mut file = std::fs::File::from(directory);
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| MutationError::new(path, 0, "cannot read trusted file"))?;
    if bytes.len() as u64 > limit {
        return Err(MutationError::new(
            path,
            0,
            "trusted file exceeds size limit",
        ));
    }
    Ok(bytes)
}

pub(crate) fn validate_root_executable(path: &Path, owner: u32) -> Result<(), MutationError> {
    let executable = open_root_regular_file(path, owner)?;
    let stat = fstat(&executable)
        .map_err(|_| MutationError::new(path, 0, "cannot inspect trusted executable"))?;
    if stat.st_mode & 0o111 == 0 {
        return Err(MutationError::new(
            path,
            0,
            "trusted executable is not executable",
        ));
    }
    Ok(())
}

pub(crate) fn read_system_gpg_key(
    path: &Path,
    directory: &Path,
    limit: u64,
    owner: u32,
) -> Result<Vec<u8>, MutationError> {
    let name = system_key_name(path, directory)?;
    let directory_fd = open_root_directory(directory, owner)?;
    let file = open_system_key_member(&directory_fd, name, path, owner)?;
    let mut file = std::fs::File::from(file);
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| MutationError::new(path, 0, "cannot read trusted system key"))?;
    if bytes.len() as u64 > limit {
        return Err(MutationError::new(
            path,
            0,
            "trusted system key exceeds size limit",
        ));
    }
    Ok(bytes)
}

fn open_root_regular_file(path: &Path, owner: u32) -> Result<OwnedFd, MutationError> {
    if !path.is_absolute() {
        return Err(MutationError::new(path, 0, "trusted path is not absolute"));
    }
    let mut directory = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| MutationError::new(path, 0, "cannot anchor root directory"))?;
    let mut components = path.components().peekable();
    if components.next() != Some(Component::RootDir) {
        return Err(MutationError::new(path, 0, "trusted path is not rooted"));
    }
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(MutationError::new(
                path,
                0,
                "trusted path contains invalid component",
            ));
        };
        let final_component = components.peek().is_none();
        let flags = if final_component {
            OFlags::RDONLY | OFlags::NOFOLLOW
        } else {
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW
        };
        let opened = openat(&directory, name, flags, Mode::empty())
            .map_err(|_| MutationError::new(path, 0, "cannot open trusted path component"))?;
        validate(&opened, final_component, path, owner)?;
        directory = opened;
    }
    Ok(directory)
}

fn open_root_directory(path: &Path, owner: u32) -> Result<OwnedFd, MutationError> {
    if !path.is_absolute() {
        return Err(MutationError::new(
            path,
            0,
            "trusted directory is not absolute",
        ));
    }
    let mut directory = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| MutationError::new(path, 0, "cannot anchor root directory"))?;
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(MutationError::new(
            path,
            0,
            "trusted directory is not rooted",
        ));
    }
    for component in components {
        let Component::Normal(name) = component else {
            return Err(MutationError::new(
                path,
                0,
                "trusted directory contains invalid component",
            ));
        };
        let opened = openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| MutationError::new(path, 0, "cannot open trusted directory component"))?;
        validate(&opened, false, path, owner)?;
        directory = opened;
    }
    Ok(directory)
}

fn system_key_name<'a>(path: &'a Path, directory: &Path) -> Result<&'a OsStr, MutationError> {
    if path.parent() != Some(directory) {
        return Err(MutationError::new(
            path,
            0,
            "system gpgkey is outside trusted directory",
        ));
    }
    let name = path
        .file_name()
        .ok_or_else(|| MutationError::new(path, 0, "system gpgkey has no filename"))?;
    if !valid_member_name(name) {
        return Err(MutationError::new(
            path,
            0,
            "system gpgkey has unsafe filename",
        ));
    }
    Ok(name)
}

fn open_system_key_member(
    directory: &OwnedFd,
    initial_name: &OsStr,
    path: &Path,
    owner: u32,
) -> Result<OwnedFd, MutationError> {
    let mut name = initial_name.to_os_string();
    for _ in 0..8 {
        let metadata = statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| MutationError::new(path, 0, "cannot inspect trusted system key"))?;
        match FileType::from_raw_mode(metadata.st_mode) {
            FileType::RegularFile => {
                let file = openat(
                    directory,
                    &name,
                    OFlags::RDONLY | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|_| MutationError::new(path, 0, "cannot open trusted system key"))?;
                validate(&file, true, path, owner)?;
                return Ok(file);
            }
            FileType::Symlink => {
                validate_link_metadata(&metadata, path, owner)?;
                let target = readlinkat(directory, &name, Vec::new()).map_err(|_| {
                    MutationError::new(path, 0, "cannot read trusted system key alias")
                })?;
                let target = OsStr::from_bytes(target.as_bytes());
                if !valid_member_name(target) {
                    return Err(MutationError::new(
                        path,
                        0,
                        "trusted system key alias escapes directory",
                    ));
                }
                name = target.to_os_string();
            }
            _ => {
                return Err(MutationError::new(
                    path,
                    0,
                    "trusted system key has invalid file type",
                ));
            }
        }
    }
    Err(MutationError::new(
        path,
        0,
        "trusted system key alias chain exceeds limit",
    ))
}

fn valid_member_name(value: &OsStr) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty() && !bytes.contains(&b'/') && bytes != b"." && bytes != b".."
}

fn validate_link_metadata(
    stat: &rustix::fs::Stat,
    path: &Path,
    owner: u32,
) -> Result<(), MutationError> {
    if stat.st_uid == owner && stat.st_nlink == 1 {
        Ok(())
    } else {
        Err(MutationError::new(
            path,
            0,
            "untrusted system key alias ownership or mode",
        ))
    }
}

fn validate(fd: &OwnedFd, file: bool, path: &Path, owner: u32) -> Result<(), MutationError> {
    let stat = fstat(fd)
        .map_err(|_| MutationError::new(path, 0, "cannot inspect trusted path component"))?;
    let expected = if file {
        rustix::fs::FileType::RegularFile
    } else {
        rustix::fs::FileType::Directory
    };
    let owner_valid = stat.st_uid == owner || (owner != 0 && stat.st_uid == 0);
    if !owner_valid
        || stat.st_mode & 0o022 != 0
        || (file && stat.st_nlink != 1)
        || rustix::fs::FileType::from_raw_mode(stat.st_mode) != expected
    {
        return Err(MutationError::new(
            path,
            0,
            "untrusted root ownership, mode, or file type",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn directory_swap_to_symlink_cannot_redirect_anchored_walk() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = PathBuf::from(
            std::env::var_os("HOME").expect("HOME must identify the test user's trusted directory"),
        )
        .join(format!("dnfast-anchor-{nonce}"));
        let trusted = root.join("trusted");
        let attacker = root.join("attacker");
        fs::create_dir_all(&trusted).unwrap();
        fs::create_dir(&attacker).unwrap();
        fs::write(trusted.join("value"), b"trusted").unwrap();
        fs::write(attacker.join("value"), b"attacker").unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let owner = fs::metadata(&root).unwrap().uid();
        fs::rename(&trusted, root.join("moved")).unwrap();
        symlink(&attacker, &trusted).unwrap();
        assert!(read_root_file(&trusted.join("value"), 16, owner).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
