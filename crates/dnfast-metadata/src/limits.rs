pub const MAX_FILELISTS_COMPRESSED_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_FILELISTS_OPEN_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_TOTAL_OPEN_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const MAX_FILE_PATHS: u64 = 50_000_000;
pub const MAX_FILES_PER_PACKAGE: usize = 1_000_000;
pub const MAX_XML_TEXT_BYTES: usize = 1024 * 1024;

pub fn checked_total_open(
    sizes: impl IntoIterator<Item = u64>,
) -> Result<u64, crate::MetadataError> {
    let total = sizes.into_iter().try_fold(0_u64, u64::checked_add).ok_or(
        crate::MetadataError::LimitExceeded {
            kind: "total opened metadata",
            maximum: MAX_TOTAL_OPEN_BYTES,
            actual: u64::MAX,
        },
    )?;
    if total > MAX_TOTAL_OPEN_BYTES {
        return Err(crate::MetadataError::LimitExceeded {
            kind: "total opened metadata",
            maximum: MAX_TOTAL_OPEN_BYTES,
            actual: total,
        });
    }
    Ok(total)
}

pub(crate) fn checked_increment(
    current: u64,
    maximum: u64,
    kind: &'static str,
) -> Result<u64, crate::MetadataError> {
    let actual = current
        .checked_add(1)
        .ok_or(crate::MetadataError::LimitExceeded {
            kind,
            maximum,
            actual: u64::MAX,
        })?;
    if actual > maximum {
        return Err(crate::MetadataError::LimitExceeded {
            kind,
            maximum,
            actual,
        });
    }
    Ok(actual)
}
pub(crate) fn checked_limit(
    actual: u64,
    maximum: u64,
    kind: &'static str,
) -> Result<u64, crate::MetadataError> {
    if actual > maximum {
        return Err(crate::MetadataError::LimitExceeded {
            kind,
            maximum,
            actual,
        });
    }
    Ok(actual)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_count_cap_accepts_exact_and_rejects_plus_one() {
        for (maximum, kind) in [
            (2_000_000, "packages"),
            (20_000_000, "relations"),
            (4_096, "relations per package"),
            (50_000_000, "file paths"),
            (1_000_000, "files per package"),
            (1_048_576, "XML text"),
        ] {
            assert_eq!(checked_increment(maximum - 1, maximum, kind), Ok(maximum));
            assert!(checked_increment(maximum, maximum, kind).is_err());
            assert_eq!(checked_limit(maximum, maximum, kind), Ok(maximum));
            assert!(checked_limit(maximum + 1, maximum, kind).is_err());
        }
    }
}
