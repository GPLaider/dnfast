use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

use dnfast_planning::SYSTEM_CACHE_PATH;
use dnfast_repo::Variables;

use crate::commands::AppFailure;

pub(crate) fn cache_directory(value: Option<PathBuf>) -> Result<PathBuf, AppFailure> {
    if let Some(path) = value {
        return Ok(path);
    }
    let xdg = std::env::var_os("XDG_CACHE_HOME");
    let home = std::env::var_os("HOME");
    default_cache_directory(
        xdg.as_deref(),
        home.as_deref(),
        rustix::process::geteuid().as_raw() == 0,
    )
    .ok_or_else(|| AppFailure::new(1, "cannot determine cache directory; pass --cache-dir"))
}

fn default_cache_directory(
    xdg: Option<&OsStr>,
    home: Option<&OsStr>,
    root: bool,
) -> Option<PathBuf> {
    xdg.map(PathBuf::from)
        .map(|path| path.join("dnfast"))
        .or_else(|| root.then(|| PathBuf::from(SYSTEM_CACHE_PATH)))
        .or_else(|| {
            home.map(PathBuf::from)
                .map(|path| path.join(".cache/dnfast"))
        })
}

pub(crate) fn system_repo_dirs() -> Vec<PathBuf> {
    ["/etc/yum.repos.d", "/etc/dnf/repos.d"]
        .into_iter()
        .map(PathBuf::from)
        .filter(|path| path.is_dir())
        .collect()
}

pub(crate) fn repository_variables(
    releasever: Option<String>,
    basearch: Option<String>,
) -> Result<Variables, AppFailure> {
    let releasever = releasever
        .or_else(|| os_release_value(Path::new("/etc/os-release"), "VERSION_ID"))
        .ok_or_else(|| AppFailure::new(1, "cannot determine releasever; pass --releasever"))?;
    let basearch = basearch.unwrap_or_else(detect_basearch);
    Ok(Variables::from_pairs([
        ("releasever".into(), releasever),
        ("basearch".into(), basearch.clone()),
        ("arch".into(), basearch),
    ]))
}

fn os_release_value(path: &Path, key: &str) -> Option<String> {
    let input = fs::read_to_string(path).ok()?;
    input.lines().find_map(|line| {
        let (candidate, value) = line.split_once('=')?;
        (candidate == key).then(|| value.trim_matches('"').to_owned())
    })
}

fn detect_basearch() -> String {
    fs::read_to_string("/etc/rpm/platform")
        .ok()
        .and_then(|platform| platform.split('-').next().map(str::trim).map(str::to_owned))
        .filter(|architecture| !architecture.is_empty())
        .unwrap_or_else(|| std::env::consts::ARCH.to_owned())
}

pub(crate) fn library_present(file_name: &str) -> bool {
    ["/lib64", "/usr/lib64", "/lib", "/usr/lib"]
        .into_iter()
        .any(|directory| Path::new(directory).join(file_name).exists())
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsStr, path::Path};

    use dnfast_planning::SYSTEM_CACHE_PATH;

    #[test]
    fn root_defaults_to_the_refresh_cache_while_nonroot_retains_a_user_cache() {
        assert_eq!(
            super::default_cache_directory(None, Some(OsStr::new("/root")), true),
            Some(Path::new(SYSTEM_CACHE_PATH).into())
        );
        assert_eq!(
            super::default_cache_directory(None, Some(OsStr::new("/home/alice")), false),
            Some(Path::new("/home/alice/.cache/dnfast").into())
        );
        assert_eq!(
            super::default_cache_directory(
                Some(OsStr::new("/explicit")),
                Some(OsStr::new("/root")),
                true
            ),
            Some(Path::new("/explicit/dnfast").into())
        );
    }
}
