use std::path::Path;

use crate::{RepoError, Repository, error::parse_error};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RefreshPolicy { pub skip_if_unavailable: bool }

pub fn load_refresh_policy(repository: &Repository) -> Result<RefreshPolicy, RepoError> {
    let input = std::fs::read_to_string(&repository.origin)
        .map_err(|error| parse_error(&repository.origin, 0, error.to_string()))?;
    parse(&repository.origin, &input, &repository.id)
}

fn parse(path: &Path, input: &str, id: &str) -> Result<RefreshPolicy, RepoError> {
    let mut selected = false;
    let mut skip = false;
    for (index, raw) in input.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            selected = line[1..line.len() - 1].trim() == id;
            continue;
        }
        if !selected || line.is_empty() || line.starts_with(['#', ';']) { continue; }
        let Some((key, value)) = line.split_once('=') else { continue; };
        match key.trim().to_ascii_lowercase().as_str() {
            "skip_if_unavailable" => skip = boolean(path, index + 1, value.trim())?,
            "sslverify" if !boolean(path, index + 1, value.trim())? => return Err(parse_error(path, index + 1, "sslverify=false is forbidden")),
            "proxy" if !matches!(value.trim(), "" | "_none_") => return Err(parse_error(path, index + 1, "proxy is unsupported for secure refresh")),
            _ => {}
        }
    }
    Ok(RefreshPolicy { skip_if_unavailable: skip })
}

fn boolean(path: &Path, line: usize, value: &str) -> Result<bool, RepoError> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(parse_error(path, line, "invalid refresh policy boolean")),
    }
}
