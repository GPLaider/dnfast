use std::path::Path;

use crate::{RepoError, Repository, error::parse_error};

#[derive(Debug)]
struct RepositoryBuilder {
    repository: Repository,
    section_line: usize,
}

fn finish_repository(
    path: &Path,
    current: Option<RepositoryBuilder>,
    repositories: &mut Vec<Repository>,
) -> Result<(), RepoError> {
    let Some(current) = current else {
        return Ok(());
    };
    if current.repository.enabled && current.repository.selected_source().is_none() {
        return Err(parse_error(
            path,
            current.section_line,
            "enabled repository has no source",
        ));
    }
    if repositories
        .iter()
        .any(|repository| repository.id == current.repository.id)
    {
        return Err(parse_error(
            path,
            current.section_line,
            format!("duplicate repository id: {}", current.repository.id),
        ));
    }
    repositories.push(current.repository);
    Ok(())
}

pub fn parse_repository_file(path: &Path, input: &str) -> Result<Vec<Repository>, RepoError> {
    let mut repositories = Vec::new();
    let mut current: Option<RepositoryBuilder> = None;

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            if !line.ends_with(']') {
                return Err(parse_error(
                    path,
                    line_number,
                    "malformed repository section",
                ));
            }
            let id = line[1..line.len() - 1].trim();
            if id.is_empty() {
                return Err(parse_error(
                    path,
                    line_number,
                    "repository id cannot be empty",
                ));
            }
            finish_repository(path, current.take(), &mut repositories)?;
            current = Some(RepositoryBuilder {
                repository: Repository {
                    id: id.to_owned(),
                    enabled: true,
                    baseurls: Vec::new(),
                    metalink: None,
                    mirrorlist: None,
                    origin: path.to_owned(),
                },
                section_line: line_number,
            });
            continue;
        }

        let Some(current) = current.as_mut() else {
            return Err(parse_error(
                path,
                line_number,
                "key outside repository section",
            ));
        };
        let Some((key, value)) = line.split_once('=') else {
            return Err(parse_error(path, line_number, "expected key=value"));
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match key.as_str() {
            "enabled" => {
                current.repository.enabled = match value.to_ascii_lowercase().as_str() {
                    "1" | "true" | "yes" | "on" => true,
                    "0" | "false" | "no" | "off" => false,
                    _ => {
                        return Err(parse_error(
                            path,
                            line_number,
                            format!("invalid boolean for enabled: {value}"),
                        ));
                    }
                };
            }
            "baseurl" => current
                .repository
                .baseurls
                .extend(value.split_whitespace().map(str::to_owned)),
            "metalink" => {
                current.repository.metalink = (!value.is_empty()).then(|| value.to_owned())
            }
            "mirrorlist" => {
                current.repository.mirrorlist = (!value.is_empty()).then(|| value.to_owned());
            }
            _ => {}
        }
    }
    finish_repository(path, current, &mut repositories)?;
    Ok(repositories)
}
