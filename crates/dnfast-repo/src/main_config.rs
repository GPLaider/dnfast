use std::{
    collections::BTreeSet,
    fmt,
    path::{Path, PathBuf},
};

pub const MAX_FILE_BYTES: usize = 1_048_576;
pub const MAX_LINES: usize = 4_096;
pub const MAX_LINE_BYTES: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MainConfig {
    pub reposdir: Vec<PathBuf>,
    pub varsdir: Vec<PathBuf>,
    pub install_weak_deps: bool,
    pub best: bool,
    pub excludepkgs: Vec<String>,
    pub includepkgs: Vec<String>,
    pub protected_packages: Vec<String>,
    pub installonlypkgs: Vec<String>,
    pub installonly_limit: u32,
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            reposdir: vec!["/etc/yum.repos.d".into(), "/etc/dnf/repos.d".into()],
            varsdir: vec!["/etc/dnf/vars".into(), "/etc/yum/vars".into()],
            install_weak_deps: true,
            best: false,
            excludepkgs: Vec::new(),
            includepkgs: Vec::new(),
            protected_packages: words("dnfast dnf dnf5 rpm glibc systemd"),
            installonlypkgs: words(
                "kernel kernel-core kernel-modules kernel-modules-core kernel-modules-extra",
            ),
            installonly_limit: 3,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct MutationError {
    path: PathBuf,
    line: usize,
    message: String,
}

impl MutationError {
    pub(crate) fn new(path: &Path, line: usize, message: impl Into<String>) -> Self {
        Self {
            path: path.to_owned(),
            line,
            message: message.into(),
        }
    }
}

impl fmt::Display for MutationError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "{}:{}: {}",
            self.path.display(),
            self.line,
            self.message
        )
    }
}

impl std::error::Error for MutationError {}

pub fn parse_main_config(path: &Path, input: &str) -> Result<MainConfig, MutationError> {
    check_limits(path, input)?;
    let mut result = MainConfig::default();
    let mut in_main = false;
    let mut seen = BTreeSet::new();
    for (index, raw) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            if line != "[main]" {
                return Err(MutationError::new(
                    path,
                    line_number,
                    "unsupported main configuration section",
                ));
            }
            if in_main {
                return Err(MutationError::new(
                    path,
                    line_number,
                    "duplicate main section",
                ));
            }
            in_main = true;
            continue;
        }
        if !in_main {
            return Err(MutationError::new(
                path,
                line_number,
                "key outside main section",
            ));
        }
        let (key, value) = pair(path, line_number, line)?;
        if !seen.insert(key.to_owned()) && !list_key(key) {
            return Err(MutationError::new(
                path,
                line_number,
                format!("duplicate mutation key: {key}"),
            ));
        }
        apply_main_value(path, line_number, &mut result, key, value)?;
    }
    Ok(result)
}

fn list_key(key: &str) -> bool {
    matches!(
        key,
        "reposdir"
            | "varsdir"
            | "excludepkgs"
            | "includepkgs"
            | "protected_packages"
            | "installonlypkgs"
    )
}

pub(crate) fn apply_main_value(
    path: &Path,
    line: usize,
    result: &mut MainConfig,
    key: &str,
    value: &str,
) -> Result<(), MutationError> {
    match key {
        "reposdir" => reset_or_append(&mut result.reposdir, value, |item| item.into()),
        "varsdir" => reset_or_append(&mut result.varsdir, value, |item| item.into()),
        "install_weak_deps" => result.install_weak_deps = boolean(path, line, value)?,
        "best" => result.best = boolean(path, line, value)?,
        "excludepkgs" => reset_or_append(&mut result.excludepkgs, value, str::to_owned),
        "includepkgs" => reset_or_append(&mut result.includepkgs, value, str::to_owned),
        "protected_packages" => {
            reset_or_append(&mut result.protected_packages, value, str::to_owned)
        }
        "installonlypkgs" => reset_or_append(&mut result.installonlypkgs, value, str::to_owned),
        "installonly_limit" => {
            let parsed = value
                .parse()
                .map_err(|_| MutationError::new(path, line, "invalid installonly_limit"))?;
            if parsed == 1 {
                return Err(MutationError::new(
                    path,
                    line,
                    "installonly_limit must be 0 or at least 2",
                ));
            }
            result.installonly_limit = parsed;
        }
        _ => {
            return Err(MutationError::new(
                path,
                line,
                format!("unsupported mutation key: {key}"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn check_limits(path: &Path, input: &str) -> Result<(), MutationError> {
    if input.len() > MAX_FILE_BYTES {
        return Err(MutationError::new(
            path,
            0,
            "configuration file exceeds 1 MiB",
        ));
    }
    if input.lines().count() > MAX_LINES {
        return Err(MutationError::new(
            path,
            MAX_LINES + 1,
            "configuration file exceeds 4096 lines",
        ));
    }
    if let Some((index, _)) = input
        .lines()
        .enumerate()
        .find(|(_, line)| line.len() > MAX_LINE_BYTES)
    {
        return Err(MutationError::new(
            path,
            index + 1,
            "configuration line exceeds 64 KiB",
        ));
    }
    Ok(())
}

pub(crate) fn pair<'a>(
    path: &Path,
    line: usize,
    input: &'a str,
) -> Result<(&'a str, &'a str), MutationError> {
    let (key, value) = input
        .split_once('=')
        .ok_or_else(|| MutationError::new(path, line, "expected key=value"))?;
    let key = key.trim();
    if key.is_empty()
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return Err(MutationError::new(path, line, "invalid mutation key"));
    }
    if value
        .bytes()
        .any(|byte| byte == 0 || (byte < 32 && byte != b'\t'))
    {
        return Err(MutationError::new(
            path,
            line,
            "invalid control byte in value",
        ));
    }
    Ok((key, value.trim()))
}

pub(crate) fn boolean(path: &Path, line: usize, value: &str) -> Result<bool, MutationError> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(MutationError::new(path, line, "invalid boolean")),
    }
}

pub(crate) fn words(value: &str) -> Vec<String> {
    value.split_whitespace().map(str::to_owned).collect()
}
fn reset_or_append<T>(target: &mut Vec<T>, value: &str, convert: impl Fn(&str) -> T) {
    if value.is_empty() {
        target.clear();
    } else {
        target.extend(value.split_whitespace().map(convert));
    }
}
