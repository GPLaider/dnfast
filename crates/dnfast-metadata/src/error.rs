use std::{error::Error, fmt};

#[derive(Debug, Eq, PartialEq)]
pub enum MetadataError {
    Xml(String),
    MissingPrimary,
    MissingFilelists,
    DuplicateRecord(String),
    InvalidNumber(String),
    UnsafeLocation(String),
    UnsupportedChecksum(String),
    ChecksumMismatch,
    SizeMismatch { expected: u64, actual: u64 },
    UnsupportedCompression(String),
    Io(String),
    LimitExceeded { kind: &'static str, maximum: u64, actual: u64 },
}

impl fmt::Display for MetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "metadata error: {self:?}")
    }
}

impl Error for MetadataError {}
