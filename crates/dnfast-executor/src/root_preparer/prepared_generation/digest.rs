use sha2::{Digest as _, Sha256};

use crate::input_model::{InputArtifact, InputFile, InputRepository};

use super::super::PreparationError;

#[cfg(test)]
pub(crate) fn metadata_digest(
    repositories: &[InputRepository],
) -> Result<String, PreparationError> {
    metadata_digest_version(repositories, 3)
}

pub(crate) fn metadata_digest_v5(
    repositories: &[InputRepository],
) -> Result<String, PreparationError> {
    metadata_digest_version(repositories, 5)
}

fn metadata_digest_version(
    repositories: &[InputRepository],
    schema_version: u32,
) -> Result<String, PreparationError> {
    let mut digest = Sha256::new();
    digest.update(match schema_version {
        5 => b"dnfast-root-metadata-v5".as_slice(),
        4 => b"dnfast-root-metadata-v4".as_slice(),
        _ => b"dnfast-root-metadata-v3".as_slice(),
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
        if schema_version >= 4 {
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
        if schema_version >= 5 {
            frame(&mut digest, "updateinfo", b"updateinfo")?;
            if let Some(file) = repository.updateinfo.as_ref() {
                frame(&mut digest, &file.sha256, file.sha256.as_bytes())?;
                digest.update(file.size.to_be_bytes());
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

#[cfg(test)]
mod tests {
    use super::metadata_digest_v5;
    use crate::{
        input_model::{InputFile, InputOrigin, InputRepository, InputRepositoryTrust},
        root_inputs,
    };

    fn file(name: &str, byte: char) -> InputFile {
        InputFile {
            name: name.into(),
            sha256: byte.to_string().repeat(64),
            size: 1,
        }
    }

    #[test]
    fn v5_digest_matches_root_validation_and_binds_updateinfo() {
        let mut repository = InputRepository {
            id: "main".into(),
            priority: 99,
            cost: 1000,
            generation_sha256: "a".repeat(64),
            origin: InputOrigin {
                repomd_url: "https://main.example/repodata/repomd.xml".into(),
                sha256: "b".repeat(64),
            },
            repomd: file("repomd", 'a'),
            primary: file("primary", 'c'),
            filelists: file("filelists", 'd'),
            file_provides: None,
            group: None,
            modules: None,
            updateinfo: Some(file("updateinfo", 'e')),
            trust: InputRepositoryTrust {
                policy: file("trust", 'f'),
                sha256: "f".repeat(64),
                keys: Vec::new(),
            },
        };

        let prepared = metadata_digest_v5(std::slice::from_ref(&repository)).unwrap();
        let validated = root_inputs::metadata_digest(std::slice::from_ref(&repository), 5).unwrap();
        assert_eq!(prepared, validated);

        repository.updateinfo = None;
        let without_updateinfo = metadata_digest_v5(std::slice::from_ref(&repository)).unwrap();
        assert_ne!(prepared, without_updateinfo);
    }
}
