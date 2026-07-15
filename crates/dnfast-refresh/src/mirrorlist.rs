use crate::{RefreshError, metalink::MAX_METALINK_BYTES, url_policy::validate_https};

pub(crate) const MAX_MIRRORS: usize = 32;

pub(crate) fn parse(input: &[u8]) -> Result<Vec<String>, RefreshError> {
    if input.len() as u64 > MAX_METALINK_BYTES {
        return Err(RefreshError::Policy("mirrorlist exceeds policy limit".into()));
    }
    let text = std::str::from_utf8(input)
        .map_err(|_| RefreshError::Policy("mirrorlist is not UTF-8".into()))?;
    let mut mirrors = Vec::new();
    for line in text.lines() {
        let value = line.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        validate_https(value)?;
        if mirrors.len() == MAX_MIRRORS {
            return Err(RefreshError::Policy("too many mirrorlist entries".into()));
        }
        mirrors.push(value.trim_end_matches('/').to_owned());
    }
    if mirrors.is_empty() {
        return Err(RefreshError::Policy("mirrorlist contains no HTTPS mirrors".into()));
    }
    Ok(mirrors)
}
