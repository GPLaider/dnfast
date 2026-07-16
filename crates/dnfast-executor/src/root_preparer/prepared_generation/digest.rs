use sha2::{Digest as _, Sha256};

use crate::input_model::{InputArtifact, InputFile, InputRepository};

use super::super::PreparationError;

#[cfg(test)]
pub(crate) fn metadata_digest(
    repositories: &[InputRepository],
) -> Result<String, PreparationError> {
    metadata_digest_version(repositories, false)
}

pub(crate) fn metadata_digest_v4(
    repositories: &[InputRepository],
) -> Result<String, PreparationError> {
    metadata_digest_version(repositories, true)
}

fn metadata_digest_version(
    repositories: &[InputRepository],
    extended: bool,
) -> Result<String, PreparationError> {
    let mut digest = Sha256::new();
    digest.update(if extended {
        b"dnfast-root-metadata-v4".as_slice()
    } else {
        b"dnfast-root-metadata-v3".as_slice()
    });
    for repository in repositories {
        frame(&mut digest, &repository.id, repository.id.as_bytes())?;
        digest.update(repository.priority.to_be_bytes());
        digest.update(repository.cost.to_be_bytes());
        frame(
            &mut digest,
            &repository.generation_sha256,
            repository.generation_sha256.as_bytes(),
        )?;
        frame(
            &mut digest,
            &repository.origin.sha256,
            repository.origin.sha256.as_bytes(),
        )?;
        frame(
            &mut digest,
            &repository.trust.sha256,
            repository.trust.sha256.as_bytes(),
        )?;
        for file in [
            &repository.repomd,
            &repository.primary,
            &repository.filelists,
        ] {
            frame(&mut digest, &file.sha256, file.sha256.as_bytes())?;
            digest.update(file.size.to_be_bytes());
        }
        if extended {
            for (role, file) in [
                ("file-provides", repository.file_provides.as_ref()),
                ("group", repository.group.as_ref()),
                ("modules", repository.modules.as_ref()),
            ] {
                frame(&mut digest, role, role.as_bytes())?;
                if let Some(file) = file {
                    frame(&mut digest, &file.sha256, file.sha256.as_bytes())?;
                    digest.update(file.size.to_be_bytes());
                }
            }
        }
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub(crate) fn trust_digest(repositories: &[InputRepository]) -> Result<String, PreparationError> {
    let mut digest = Sha256::new();
    digest.update(b"dnfast-root-trust-v3");
    for repository in repositories {
        frame(&mut digest, &repository.id, repository.id.as_bytes())?;
        frame(
            &mut digest,
            &repository.trust.sha256,
            repository.trust.sha256.as_bytes(),
        )?;
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub(crate) fn descriptor(name: &str, bytes: &[u8]) -> Result<InputFile, PreparationError> {
    Ok(InputFile {
        name: name.into(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
        size: u64::try_from(bytes.len())
            .map_err(|error| PreparationError::Publish(error.to_string()))?,
    })
}

pub(crate) fn artifact_key(artifact: &InputArtifact) -> (&str, &str, u32, &str, &str, &str) {
    (
        &artifact.repo_id,
        &artifact.name,
        artifact.epoch,
        &artifact.version,
        &artifact.release,
        &artifact.file.sha256,
    )
}

fn frame(digest: &mut Sha256, name: &str, bytes: &[u8]) -> Result<(), PreparationError> {
    digest.update(
        u64::try_from(name.len())
            .map_err(|error| PreparationError::Publish(error.to_string()))?
            .to_be_bytes(),
    );
    digest.update(name.as_bytes());
    digest.update(
        u64::try_from(bytes.len())
            .map_err(|error| PreparationError::Publish(error.to_string()))?
            .to_be_bytes(),
    );
    digest.update(bytes);
    Ok(())
}
