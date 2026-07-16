use std::{io::Read, time::Duration};

use crate::{RefreshError, url_policy::validate_https_endpoint};

pub trait Transport {
    fn get(&self, url: &str, maximum_bytes: u64) -> Result<Vec<u8>, RefreshError>;
}

pub struct HttpTransport {
    agent: ureq::Agent,
}

impl HttpTransport {
    pub fn new() -> Self {
        use ureq::tls::{RootCerts, TlsConfig};

        let agent = ureq::Agent::config_builder()
            .https_only(true)
            .max_redirects(0)
            .max_redirects_will_error(true)
            // Fedora's filelists metadata is often tens of MiB.  A hard 45 second
            // request deadline aborts healthy, continuously-progressing transfers
            // on distant mirrors and makes the mirror fallback download the same
            // objects again.  Keep the short connect/header/body-idle deadlines,
            // but allow a bounded five minutes for a large response to complete.
            .timeout_global(Some(Duration::from_secs(300)))
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_send_request(Some(Duration::from_secs(10)))
            .timeout_send_body(Some(Duration::from_secs(10)))
            // A busy Fedora mirror can take more than ten seconds to begin a
            // large metadata response even though the connection is healthy.
            // Keep connect and body-idle limits short, but do not discard a
            // selected, checksum-bound mirror during normal server queueing.
            .timeout_recv_response(Some(Duration::from_secs(30)))
            .timeout_recv_body(Some(Duration::from_secs(10)))
            .user_agent(concat!("dnfast/", env!("CARGO_PKG_VERSION")))
            .tls_config(
                TlsConfig::builder()
                    .root_certs(RootCerts::PlatformVerifier)
                    .build(),
            )
            .build()
            .new_agent();
        Self { agent }
    }
}

impl Default for HttpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for HttpTransport {
    fn get(&self, url: &str, maximum_bytes: u64) -> Result<Vec<u8>, RefreshError> {
        validate_https_endpoint(url)?;
        let response = self
            .agent
            .get(url)
            .header("Accept-Encoding", "identity")
            .call()
            .map_err(|error| RefreshError::Transport(error.to_string()))?;
        if response.status().is_redirection() {
            return Err(RefreshError::Transport("redirect response rejected".into()));
        }
        if let Some(length) = response.headers().get("content-length") {
            let length = length
                .to_str()
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| RefreshError::Transport("invalid Content-Length".into()))?;
            if length > maximum_bytes {
                return Err(RefreshError::Transport("response exceeds limit".into()));
            }
        }
        let mut bytes = Vec::new();
        response
            .into_body()
            .into_reader()
            .take(
                maximum_bytes
                    .checked_add(1)
                    .ok_or_else(|| RefreshError::Transport("response limit overflow".into()))?,
            )
            .read_to_end(&mut bytes)
            .map_err(|error| RefreshError::Transport(error.to_string()))?;
        if bytes.len() as u64 > maximum_bytes {
            return Err(RefreshError::Transport("response exceeds limit".into()));
        }
        Ok(bytes)
    }
}
