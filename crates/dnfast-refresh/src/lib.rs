#![forbid(unsafe_code)]

use std::{error::Error, fmt};

mod metalink;
mod mirrorlist;
mod openpgp;
mod orchestrator;
mod repo_lock;
mod transport;
mod url_policy;

pub use openpgp::MetadataTrust;
pub use orchestrator::Refresher;
pub use transport::{HttpTransport, Transport};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Source {
    BaseUrl(String),
    Metalink(String),
    Mirrorlist(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefreshOutcome {
    pub digest: String,
    pub packages: usize,
}

#[derive(Debug)]
pub enum RefreshError {
    Policy(String),
    Transport(String),
    Metalink(String),
    Metadata(String),
    Signature(String),
    Cache(String),
}

impl fmt::Display for RefreshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "refresh error: {self:?}")
    }
}

impl Error for RefreshError {}

#[cfg(test)]
mod source_equivalence_tests;
#[cfg(test)]
mod tests;
