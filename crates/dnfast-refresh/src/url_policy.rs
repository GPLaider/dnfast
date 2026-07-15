use crate::RefreshError;

pub(crate) fn validate_https(url: &str) -> Result<(), RefreshError> {
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(RefreshError::Policy(
            "only HTTPS repository sources are allowed".into(),
        ));
    };
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty()
        || authority.contains('@')
        || authority.starts_with('[')
        || url.contains('?')
        || url.contains('#')
        || url.contains('\\')
    {
        return Err(RefreshError::Policy("unsafe HTTPS repository URL".into()));
    }
    Ok(())
}
