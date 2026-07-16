use std::{collections::BTreeSet, path::Path};

use crate::main_config::{
    MainConfig, MutationError, apply_main_value, boolean, check_limits, pair, words,
};
use crate::{Variables, key_bundle_digest, normalize_gpgkey_location};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataExpire {
    AfterSeconds(u64),
    Never,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepoConfig {
    pub id: String,
    pub name: Option<String>,
    pub enabled: bool,
    pub baseurl: Vec<String>,
    pub metalink: Option<String>,
    pub mirrorlist: Option<String>,
    pub priority: u16,
    pub cost: u32,
    pub skip_if_unavailable: bool,
    pub metadata_expire: MetadataExpire,
    pub proxy: Option<String>,
    pub sslverify: bool,
    pub gpgcheck: bool,
    pub pkg_gpgcheck: bool,
    pub repo_gpgcheck: bool,
    pub excludepkgs: Vec<String>,
    pub includepkgs: Vec<String>,
    pub gpgkey: Vec<String>,
    pub allowed_fingerprints: Vec<String>,
    pub key_bundle_digest: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationProfile {
    pub main: MainConfig,
    pub repositories: Vec<RepoConfig>,
    pub variables: Variables,
}

impl RepoConfig {
    fn new(id: &str, main: &MainConfig) -> Self {
        Self {
            id: id.to_owned(),
            name: None,
            enabled: true,
            baseurl: Vec::new(),
            metalink: None,
            mirrorlist: None,
            priority: 99,
            cost: 1000,
            skip_if_unavailable: false,
            metadata_expire: MetadataExpire::AfterSeconds(172_800),
            proxy: None,
            sslverify: true,
            gpgcheck: true,
            pkg_gpgcheck: true,
            repo_gpgcheck: false,
            excludepkgs: main.excludepkgs.clone(),
            includepkgs: main.includepkgs.clone(),
            gpgkey: Vec::new(),
            allowed_fingerprints: Vec::new(),
            key_bundle_digest: None,
        }
    }
}

pub fn parse_repo_profile(
    path: &Path,
    input: &str,
    main: &MainConfig,
) -> Result<MutationProfile, MutationError> {
    check_limits(path, input)?;
    let mut repositories = Vec::new();
    let mut current: Option<RepoConfig> = None;
    let mut seen_ids = BTreeSet::new();
    let mut seen_keys = BTreeSet::new();
    for (index, raw) in input.lines().enumerate() {
        let number = index + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            if !line.ends_with(']') {
                return Err(MutationError::new(
                    path,
                    number,
                    "malformed repository section",
                ));
            }
            if let Some(repo) = current.take() {
                finish(path, number, repo, &mut repositories)?;
            }
            let id = line[1..line.len() - 1].trim();
            if !valid_id(id) {
                return Err(MutationError::new(path, number, "invalid repository id"));
            }
            if !seen_ids.insert(id.to_owned()) {
                return Err(MutationError::new(path, number, "duplicate repository id"));
            }
            if seen_ids.len() > 1024 {
                return Err(MutationError::new(
                    path,
                    number,
                    "repository limit exceeds 1024",
                ));
            }
            seen_keys.clear();
            current = Some(RepoConfig::new(id, main));
            continue;
        }
        let repo = current
            .as_mut()
            .ok_or_else(|| MutationError::new(path, number, "key outside repository section"))?;
        let (key, value) = pair(path, number, line)?;
        if !seen_keys.insert(key.to_owned()) {
            return Err(MutationError::new(
                path,
                number,
                format!("duplicate mutation key: {key}"),
            ));
        }
        assign_repo(path, number, repo, key, value)?;
    }
    if let Some(repo) = current {
        finish(path, input.lines().count(), repo, &mut repositories)?;
    }
    Ok(MutationProfile {
        main: main.clone(),
        repositories,
        variables: Variables::default(),
    })
}

pub(crate) fn expand_variables(
    profile: &mut MutationProfile,
    variables: Variables,
) -> Result<(), MutationError> {
    for repo in &mut profile.repositories {
        repo.name = repo
            .name
            .as_deref()
            .map(|value| variables.expand(value))
            .transpose()
            .map_err(variable_error)?;
        expand_list(&variables, &mut repo.baseurl)?;
        repo.metalink = repo
            .metalink
            .as_deref()
            .map(|value| variables.expand(value))
            .transpose()
            .map_err(variable_error)?;
        repo.mirrorlist = repo
            .mirrorlist
            .as_deref()
            .map(|value| variables.expand(value))
            .transpose()
            .map_err(variable_error)?;
        repo.proxy = repo
            .proxy
            .as_deref()
            .map(|value| variables.expand(value))
            .transpose()
            .map_err(variable_error)?;
        expand_list(&variables, &mut repo.excludepkgs)?;
        expand_list(&variables, &mut repo.includepkgs)?;
        expand_list(&variables, &mut repo.gpgkey)?;
        if repo.enabled {
            normalize_gpgkey_locations(&mut repo.gpgkey)?;
        }
    }
    profile.variables = variables;
    Ok(())
}

fn expand_list(variables: &Variables, values: &mut [String]) -> Result<(), MutationError> {
    for value in values {
        *value = variables.expand(value).map_err(variable_error)?;
    }
    Ok(())
}

fn variable_error(error: crate::RepoError) -> MutationError {
    MutationError::new(Path::new("<variables>"), 0, error.to_string())
}

pub fn parse_before_network<T>(
    path: &Path,
    input: &str,
    main: &MainConfig,
    network: impl FnOnce(&MutationProfile) -> T,
) -> Result<T, MutationError> {
    let profile = parse_repo_profile(path, input, main)?;
    Ok(network(&profile))
}

fn assign_repo(
    path: &Path,
    line: usize,
    repo: &mut RepoConfig,
    key: &str,
    value: &str,
) -> Result<(), MutationError> {
    match key {
        "name" => repo.name = Some(value.to_owned()),
        "type" if rpm_md_repository_type(value) => {}
        "type" => {
            return Err(MutationError::new(
                path,
                line,
                "unsupported repository type",
            ));
        }
        "enabled" => repo.enabled = boolean(path, line, value)?,
        "baseurl" => reset_or_append(&mut repo.baseurl, value),
        "metalink" => repo.metalink = nonempty(value),
        "mirrorlist" => repo.mirrorlist = nonempty(value),
        "priority" => {
            repo.priority = value
                .parse()
                .map_err(|_| MutationError::new(path, line, "invalid priority"))?
        }
        "cost" => {
            repo.cost = value
                .parse()
                .map_err(|_| MutationError::new(path, line, "invalid cost"))?
        }
        "skip_if_unavailable" => repo.skip_if_unavailable = boolean(path, line, value)?,
        "metadata_expire" => repo.metadata_expire = parse_metadata_expire(path, line, value)?,
        "countme" => validate_countme(path, line, value)?,
        "enabled_metadata" => {
            let _ = boolean(path, line, value)?;
        }
        "sslverify" if !boolean(path, line, value)? => return rejected(path, line, key),
        "sslverify" => repo.sslverify = true,
        "gpgcheck" if !boolean(path, line, value)? => return rejected(path, line, key),
        "gpgcheck" => repo.gpgcheck = true,
        "pkg_gpgcheck" if !boolean(path, line, value)? => return rejected(path, line, key),
        "pkg_gpgcheck" => repo.pkg_gpgcheck = true,
        "repo_gpgcheck" => repo.repo_gpgcheck = boolean(path, line, value)?,
        "proxy" if authenticated_proxy(value) => return rejected(path, line, key),
        "proxy" => {
            repo.proxy = match value {
                "" | "_none_" => None,
                _ => Some(value.to_owned()),
            }
        }
        "excludepkgs" => reset_or_append(&mut repo.excludepkgs, value),
        "includepkgs" => reset_or_append(&mut repo.includepkgs, value),
        "gpgkey" => reset_or_append_checked(&mut repo.gpgkey, unique_words(path, line, value)?),
        "dnfast_allowed_fingerprints" => reset_or_append_checked(
            &mut repo.allowed_fingerprints,
            fingerprints(path, line, value)?,
        ),
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

fn rpm_md_repository_type(value: &str) -> bool {
    matches!(value, "rpm" | "rpm-md" | "repomd" | "rpmmd" | "yum" | "YUM")
}

fn validate_countme(path: &Path, line: usize, value: &str) -> Result<(), MutationError> {
    match value {
        "0" | "1" => Ok(()),
        _ => Err(MutationError::new(path, line, "invalid countme")),
    }
}

fn parse_metadata_expire(
    path: &Path,
    line: usize,
    value: &str,
) -> Result<MetadataExpire, MutationError> {
    if matches!(value, "-1" | "never") {
        return Ok(MetadataExpire::Never);
    }
    let value = value.strip_prefix('+').unwrap_or(value);
    let (number, multiplier) = duration_parts(value)
        .ok_or_else(|| MutationError::new(path, line, "invalid metadata_expire"))?;
    if let Some(hexadecimal) = number
        .strip_prefix("0x")
        .or_else(|| number.strip_prefix("0X"))
    {
        let seconds = match hexadecimal_seconds(hexadecimal, multiplier) {
            Ok(seconds) => seconds,
            Err(HexadecimalSecondsError::Invalid) => {
                return Err(MutationError::new(path, line, "invalid metadata_expire"));
            }
            Err(HexadecimalSecondsError::Overflow) => {
                return Err(MutationError::new(
                    path,
                    line,
                    "metadata_expire exceeds u64 seconds",
                ));
            }
        };
        return Ok(MetadataExpire::AfterSeconds(seconds));
    }
    // Intentionally narrower than libdnf's std::stod path: fixed-point decimal only, never exponent syntax.
    let (whole, fraction) = number.split_once('.').map_or((number, ""), |parts| parts);
    if number.matches('.').count() > 1
        || (whole.is_empty() && fraction.is_empty())
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(MutationError::new(path, line, "invalid metadata_expire"));
    }
    let whole_seconds = decimal_seconds(whole, multiplier)
        .ok_or_else(|| MutationError::new(path, line, "metadata_expire exceeds u64 seconds"))?;
    let seconds = whole_seconds
        .checked_add(fractional_seconds(fraction, multiplier))
        .ok_or_else(|| MutationError::new(path, line, "metadata_expire exceeds u64 seconds"))?;
    Ok(MetadataExpire::AfterSeconds(seconds))
}

fn duration_parts(value: &str) -> Option<(&str, u64)> {
    let (number, multiplier) = match value.as_bytes().last().copied() {
        Some(b's' | b'S') => (&value[..value.len() - 1], 1),
        Some(b'm' | b'M') => (&value[..value.len() - 1], 60),
        Some(b'h' | b'H') => (&value[..value.len() - 1], 3_600),
        Some(b'd' | b'D') => (&value[..value.len() - 1], 86_400),
        _ => (value, 1),
    };
    (!number.is_empty()).then_some((number, multiplier))
}

fn decimal_seconds(value: &str, multiplier: u64) -> Option<u64> {
    value
        .bytes()
        .try_fold(0_u64, |total, byte| {
            total.checked_mul(10)?.checked_add(u64::from(byte - b'0'))
        })?
        .checked_mul(multiplier)
}

enum HexadecimalSecondsError {
    Invalid,
    Overflow,
}

fn hexadecimal_seconds(value: &str, multiplier: u64) -> Result<u64, HexadecimalSecondsError> {
    if value.is_empty() {
        return Err(HexadecimalSecondsError::Invalid);
    }
    let seconds = value.bytes().try_fold(0_u64, |total, byte| {
        let digit = hexadecimal_digit(byte).ok_or(HexadecimalSecondsError::Invalid)?;
        total
            .checked_mul(16)
            .and_then(|total| total.checked_add(digit))
            .ok_or(HexadecimalSecondsError::Overflow)
    })?;
    seconds
        .checked_mul(multiplier)
        .ok_or(HexadecimalSecondsError::Overflow)
}

fn hexadecimal_digit(byte: u8) -> Option<u64> {
    match byte {
        b'0'..=b'9' => Some(u64::from(byte - b'0')),
        b'a'..=b'f' => Some(u64::from(byte - b'a') + 10),
        b'A'..=b'F' => Some(u64::from(byte - b'A') + 10),
        _ => None,
    }
}

fn fractional_seconds(value: &str, multiplier: u64) -> u64 {
    value.bytes().rev().fold(0, |carry, byte| {
        (u64::from(byte - b'0') * multiplier + carry) / 10
    })
}

pub fn apply_setopts(
    mut profile: MutationProfile,
    options: &[String],
) -> Result<MutationProfile, MutationError> {
    let cli = Path::new("<command-line>");
    let mut trust_changed = BTreeSet::new();
    for (index, option) in options.iter().enumerate() {
        let (target, value) = pair(cli, index + 1, option)?;
        if let Some(key) = target.strip_prefix("main.") {
            apply_main_value(cli, index + 1, &mut profile.main, key, value)?;
            continue;
        }
        let rest = target
            .strip_prefix("repo.")
            .ok_or_else(|| MutationError::new(cli, index + 1, "malformed setopt target"))?;
        let (id, key) = rest
            .rsplit_once('.')
            .ok_or_else(|| MutationError::new(cli, index + 1, "malformed repo setopt target"))?;
        let repo = profile
            .repositories
            .iter_mut()
            .find(|repo| repo.id == id)
            .ok_or_else(|| {
                MutationError::new(cli, index + 1, "unknown repository setopt target")
            })?;
        if matches!(key, "gpgkey" | "enabled") {
            trust_changed.insert(id.to_owned());
        }
        match key {
            "excludepkgs" => reset_or_append(&mut repo.excludepkgs, value),
            "includepkgs" => reset_or_append(&mut repo.includepkgs, value),
            _ => assign_repo(cli, index + 1, repo, key, value)?,
        }
    }
    for repo in &mut profile.repositories {
        if !trust_changed.contains(&repo.id) {
            continue;
        }
        if repo.enabled {
            normalize_gpgkey_locations(&mut repo.gpgkey)?;
            let paths = repo
                .gpgkey
                .iter()
                .map(std::path::PathBuf::from)
                .collect::<Vec<_>>();
            repo.key_bundle_digest = Some(key_bundle_digest(&repo.id, &paths)?.digest);
        } else {
            repo.key_bundle_digest = None;
        }
    }
    Ok(profile)
}

fn rejected<T>(path: &Path, line: usize, key: &str) -> Result<T, MutationError> {
    Err(MutationError::new(
        path,
        line,
        format!("rejected mutation setting: {key}"),
    ))
}
fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 255
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}
fn reset_or_append(target: &mut Vec<String>, value: &str) {
    if value.is_empty() {
        target.clear();
    } else {
        target.extend(words(value));
    }
}
fn reset_or_append_checked(target: &mut Vec<String>, values: Vec<String>) {
    if values.is_empty() {
        target.clear();
    } else {
        target.extend(values);
    }
}
fn normalize_gpgkey_locations(values: &mut [String]) -> Result<(), MutationError> {
    for value in values {
        *value = normalize_gpgkey_location(value)?
            .into_os_string()
            .into_string()
            .map_err(|_| {
                MutationError::new(Path::new("<gpgkey>"), 0, "gpgkey path is not UTF-8")
            })?;
    }
    Ok(())
}
fn authenticated_proxy(value: &str) -> bool {
    value
        .split_once("://")
        .map_or(value, |(_, authority)| authority)
        .split('/')
        .next()
        .is_some_and(|part| part.contains('@'))
}

fn finish(
    path: &Path,
    line: usize,
    repo: RepoConfig,
    output: &mut Vec<RepoConfig>,
) -> Result<(), MutationError> {
    if repo.enabled
        && repo.baseurl.is_empty()
        && repo.metalink.is_none()
        && repo.mirrorlist.is_none()
    {
        return Err(MutationError::new(
            path,
            line,
            "enabled repository has no source",
        ));
    }
    output.push(repo);
    Ok(())
}

fn unique_words(path: &Path, line: usize, value: &str) -> Result<Vec<String>, MutationError> {
    let values = words(value);
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(MutationError::new(path, line, "duplicate gpgkey path"));
    }
    Ok(values)
}

fn fingerprints(path: &Path, line: usize, value: &str) -> Result<Vec<String>, MutationError> {
    let values = words(value);
    if values
        .iter()
        .any(|item| item.len() != 40 || !item.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(MutationError::new(
            path,
            line,
            "invalid primary certificate fingerprint",
        ));
    }
    Ok(values)
}
