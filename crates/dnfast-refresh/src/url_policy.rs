use crate::RefreshError;

pub(crate) fn validate_https(url: &str) -> Result<(), RefreshError> {
    validate(url, false)
}

pub(crate) fn validate_https_endpoint(url: &str) -> Result<(), RefreshError> {
    validate(url, true)
}

fn validate(url: &str, allow_query: bool) -> Result<(), RefreshError> {
    let parsed = url::Url::parse(url)
        .map_err(|_| RefreshError::Policy("only HTTPS repository sources are allowed".into()))?;
    if parsed.scheme() != "https" {
        return Err(RefreshError::Policy(
            "only HTTPS repository sources are allowed".into(),
        ));
    }
    let canonical = parsed.as_str() == url
        || (parsed.path() == "/"
            && parsed.query().is_none()
            && parsed.fragment().is_none()
            && parsed.as_str().strip_suffix('/') == Some(url));
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || (!allow_query && parsed.query().is_some())
        || url.contains('\\')
        || !canonical
    {
        return Err(RefreshError::Policy("unsafe HTTPS repository URL".into()));
    }
    Ok(())
}
