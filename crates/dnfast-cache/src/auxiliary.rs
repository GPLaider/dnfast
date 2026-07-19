use std::fs;

use dnfast_metadata::AuxiliaryRecord;

use crate::{
    Cache,
    fs_safety::{AnchoredDirectory, create_private_tree, sync_directory, write_synced},
    model::{CacheError, VerifiedBytes, VerifiedSource, io_error, sha256, valid_digest},
};

const PAYLOAD_NAME: &str = "payload";
const MAX_AUXILIARY_BYTES: u64 = 512 * 1024 * 1024;

impl Cache {
    pub fn publish_auxiliary(
        &self,
        record: &AuxiliaryRecord,
        bytes: &[u8],
    ) -> Result<VerifiedBytes, CacheError> {
        validate_record(record)?;
        if bytes.len() as u64 != record.size || sha256(bytes) != record.checksum {
            return Err(CacheError::Corrupt(
                "auxiliary metadata differs from repomd record".into(),
            ));
        }
        let parent = self.root.join("auxiliary/sha256");
        let object = parent.join(&record.checksum);
        create_private_tree(&self.root, &parent)?;
        if !object.exists() {
            let staging = tempfile::Builder::new()
                .prefix(".staging-")
                .tempdir_in(&parent)
                .map_err(io_error)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))
                    .map_err(io_error)?;
            }
            write_synced(&staging.path().join(PAYLOAD_NAME), bytes)?;
            sync_directory(staging.path())?;
            match fs::rename(staging.path(), &object) {
                Ok(()) => {
                    std::mem::forget(staging);
                    sync_directory(&parent)?;
                }
                Err(_) if object.exists() => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        self.open_auxiliary(record)
    }

    pub fn open_auxiliary(&self, record: &AuxiliaryRecord) -> Result<VerifiedBytes, CacheError> {
        validate_record(record)?;
        let object = self.root.join("auxiliary/sha256").join(&record.checksum);
        let anchored = AnchoredDirectory::open(&object).map_err(|error| match error {
            CacheError::Io(_) if !object.exists() => {
                CacheError::MissingSnapshot(record.checksum.clone())
            }
            other => other,
        })?;
        let (bytes, file) =
            anchored.read_retained(std::ffi::OsStr::new(PAYLOAD_NAME), record.size)?;
        if bytes.len() as u64 != record.size || sha256(&bytes) != record.checksum {
            return Err(CacheError::Corrupt(
                "auxiliary metadata object verification failed".into(),
            ));
        }
        Ok(VerifiedBytes {
            sha256: record.checksum.clone(),
            size: record.size,
            bytes,
            source: Some(VerifiedSource::new(file)?),
        })
    }
}

fn validate_record(record: &AuxiliaryRecord) -> Result<(), CacheError> {
    if !valid_digest(&record.checksum) || record.size == 0 || record.size > MAX_AUXILIARY_BYTES {
        return Err(CacheError::Corrupt(
            "invalid auxiliary metadata record".into(),
        ));
    }
    Ok(())
}
