use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::{DomainError, Sha256Digest};

pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_STRING_BYTES: usize = 1024 * 1024;
pub const MAX_DEPTH: usize = 32;

pub trait CanonicalDocument: Sized {
    fn from_canonical_json(bytes: &[u8]) -> Result<Self, DomainError>;
    fn to_canonical_json(&self) -> Result<Vec<u8>, DomainError>;
    fn canonical_sha256(&self) -> Result<Sha256Digest, DomainError> {
        let digest = Sha256::digest(self.to_canonical_json()?);
        Sha256Digest::parse(format!("{digest:x}"), "canonical_sha256")
    }
}

pub(crate) fn parse<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, DomainError> {
    inspect(bytes)?;
    let value: T =
        serde_json::from_slice(bytes).map_err(|error| DomainError::Json(error.to_string()))?;
    if serialize(&value)? != bytes {
        return Err(DomainError::NonCanonical);
    }
    Ok(value)
}

pub(crate) fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, DomainError> {
    let tree = serde_json::to_value(value).map_err(|error| DomainError::Json(error.to_string()))?;
    serde_json::to_vec(&tree).map_err(|error| DomainError::Json(error.to_string()))
}

fn inspect(bytes: &[u8]) -> Result<(), DomainError> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(DomainError::DocumentTooLarge);
    }
    let mut depth = 0usize;
    let mut string_bytes = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
                string_bytes += 1;
                continue;
            }
            match byte {
                b'\\' => escaped = true,
                b'"' => {
                    in_string = false;
                    string_bytes = 0;
                }
                _ => {
                    string_bytes += 1;
                    if string_bytes > MAX_STRING_BYTES {
                        return Err(DomainError::StringTooLarge);
                    }
                }
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return Err(DomainError::DepthExceeded);
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    Ok(())
}
