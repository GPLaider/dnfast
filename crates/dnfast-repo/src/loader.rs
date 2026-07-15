use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

use crate::{RepoError, Repository, error::parse_error, parse_repository_file};

pub fn load_repository_dirs(directories: &[PathBuf]) -> Result<Vec<Repository>, RepoError> {
    let mut paths = Vec::new();
    for directory in directories {
        if has_symlink_ancestor(directory)? {
            continue;
        }
        let metadata = match std::fs::symlink_metadata(directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => return Err(io_error(directory.clone(), source)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        let entries = match std::fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => return Err(io_error(directory.clone(), source)),
        };
        for entry in entries {
            let entry = entry.map_err(|source| io_error(directory.clone(), source))?;
            let file_type = entry
                .file_type()
                .map_err(|source| io_error(entry.path(), source))?;
            let path = entry.path();
            if file_type.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extension == "repo")
            {
                paths.push(path);
            }
        }
    }
    paths.sort();

    let mut repositories = Vec::new();
    let mut seen = HashMap::<String, PathBuf>::new();
    for path in paths {
        let bytes = read_stable_regular_file(&path)?;
        let input =
            String::from_utf8(bytes).map_err(|_| RepoError::InvalidUtf8 { path: path.clone() })?;
        for repository in parse_repository_file(&path, &input)? {
            if let Some(previous) = seen.insert(repository.id.clone(), path.clone()) {
                return Err(parse_error(
                    &path,
                    1,
                    format!(
                        "duplicate repository id {} (already defined in {})",
                        repository.id,
                        previous.display()
                    ),
                ));
            }
            repositories.push(repository);
        }
    }
    repositories.sort_by(|left, right| {
        left.origin
            .cmp(&right.origin)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(repositories)
}

fn io_error(path: PathBuf, source: io::Error) -> RepoError {
    RepoError::Io { path, source }
}

fn has_symlink_ancestor(path: &Path) -> Result<bool, RepoError> {
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error(ancestor.to_path_buf(), source)),
        }
    }
    Ok(false)
}

fn read_stable_regular_file(path: &Path) -> Result<Vec<u8>, RepoError> {
    let before =
        std::fs::symlink_metadata(path).map_err(|source| io_error(path.to_path_buf(), source))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(parse_error(
            path,
            1,
            "repository path is not a regular file",
        ));
    }
    let mut file = File::open(path).map_err(|source| io_error(path.to_path_buf(), source))?;
    let opened = file
        .metadata()
        .map_err(|source| io_error(path.to_path_buf(), source))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(parse_error(
                path,
                1,
                "repository file changed while opening",
            ));
        }
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| io_error(path.to_path_buf(), source))?;
    Ok(bytes)
}
