use std::{
    fs::File,
    io::{Read, Seek},
};

use dnfast_core::{Architecture, Evra, SolverPolicy};
use dnfast_metadata::{
    CompletePackage, decode_primary, parse_primary_records, parse_repomd_records,
};
use dnfast_native::{ExpectedPackage, Repository, VerifiedStagedKey};
use dnfast_solver::CandidatePackage;

use crate::{
    ExecutorError, Staging,
    input_model::{InputArtifact, InputFile, InputManifest, InputRepository},
    root_inputs::open_retained,
};

type ParsedCandidates = (Vec<CandidatePackage>, Vec<(String, CompletePackage)>);

pub struct StagedInputs {
    pub policy: SolverPolicy,
    pub repositories: Vec<StagedRepository>,
    pub candidates: Vec<CandidatePackage>,
    pub metadata: Vec<(String, dnfast_metadata::CompletePackage)>,
    pub artifacts: Vec<StagedArtifact>,
}

pub struct StagedRepository {
    pub repository: Repository,
    pub trust: dnfast_core::RepoTrustPolicy,
    pub keys: Vec<VerifiedStagedKey>,
    pub generation_sha256: String,
    pub origin_sha256: String,
    pub trust_sha256: String,
}

pub struct StagedArtifact {
    pub file: File,
    pub expected: ExpectedPackage,
    pub sha256: String,
    pub size: u64,
    pub repo_id: String,
    pub generation_sha256: String,
    pub origin_sha256: String,
    pub trust_sha256: String,
}

pub(crate) fn stage(
    directory: &std::os::fd::OwnedFd,
    manifest: &InputManifest,
    staging: &mut Staging,
) -> Result<StagedInputs, ExecutorError> {
    let policy = parse_policy(directory, &manifest.policy)?;
    let mut repositories = Vec::new();
    let mut candidates = Vec::new();
    let mut metadata = Vec::new();
    for (index, repository) in manifest.repositories.iter().enumerate() {
        let prefix = format!("repo-{index}");
        let mut repomd = copy(
            directory,
            staging,
            &repository.repomd,
            &format!("{prefix}-repomd"),
        )?;
        let mut primary_source = copy(
            directory,
            staging,
            &repository.primary,
            &format!("{prefix}-primary"),
        )?;
        let mut filelists_source = copy(
            directory,
            staging,
            &repository.filelists,
            &format!("{prefix}-filelists"),
        )?;
        let (primary_xml, filelists_xml) =
            materialize_native_metadata(&mut repomd, &mut primary_source, &mut filelists_source)?;
        let mut primary =
            staging.write_bytes(&format!("{prefix}-native-primary.xml"), &primary_xml)?;
        staging.write_bytes(&format!("{prefix}-native-filelists.xml"), &filelists_xml)?;
        let parsed = parse_candidates(repository, &mut repomd, &mut primary, policy.base_arch())?;
        candidates.extend(parsed.0);
        metadata.extend(parsed.1);
        let trust = parse_trust(directory, &repository.trust.policy)?;
        let keys = repository
            .trust
            .keys
            .iter()
            .enumerate()
            .map(|(key_index, key)| {
                let mut file = copy(
                    directory,
                    staging,
                    &key.file,
                    &format!("{prefix}-key-{key_index}"),
                )?;
                let mut certificate = Vec::new();
                file.read_to_end(&mut certificate).map_err(io)?;
                Ok(VerifiedStagedKey {
                    bundle_path: key.bundle_path.clone(),
                    certificate,
                })
            })
            .collect::<Result<Vec<_>, ExecutorError>>()?;
        let native_repository = native_repository(
            repository,
            staging.path(&format!("{prefix}-repomd")),
            staging.path(&format!("{prefix}-native-primary.xml")),
            staging.path(&format!("{prefix}-native-filelists.xml")),
        );
        repositories.push(StagedRepository {
            repository: native_repository,
            trust,
            keys,
            generation_sha256: repository.generation_sha256.clone(),
            origin_sha256: repository.origin.sha256.clone(),
            trust_sha256: repository.trust.sha256.clone(),
        });
    }
    let artifacts = manifest
        .artifacts
        .iter()
        .enumerate()
        .map(|(index, artifact)| stage_artifact(directory, staging, artifact, index, &metadata))
        .collect::<Result<Vec<_>, ExecutorError>>()?;
    Ok(StagedInputs {
        policy,
        repositories,
        candidates,
        metadata,
        artifacts,
    })
}

pub(crate) fn stage_token_bound(
    directory: &std::os::fd::OwnedFd,
    manifest: &InputManifest,
) -> Result<StagedInputs, ExecutorError> {
    let policy = parse_policy(directory, &manifest.policy)?;
    let repositories = manifest
        .repositories
        .iter()
        .map(|repository| {
            let trust = parse_trust(directory, &repository.trust.policy)?;
            let keys = repository
                .trust
                .keys
                .iter()
                .map(|key| {
                    let mut file = open_retained(directory, &key.file)?;
                    let mut certificate = Vec::new();
                    file.read_to_end(&mut certificate).map_err(io)?;
                    Ok(VerifiedStagedKey {
                        bundle_path: key.bundle_path.clone(),
                        certificate,
                    })
                })
                .collect::<Result<Vec<_>, ExecutorError>>()?;
            Ok(StagedRepository {
                repository: Repository {
                    id: repository.id.clone(),
                    repomd_path: String::new(),
                    primary_path: String::new(),
                    filelists_path: String::new(),
                    priority: repository.priority,
                    cost: repository.cost,
                },
                trust,
                keys,
                generation_sha256: repository.generation_sha256.clone(),
                origin_sha256: repository.origin.sha256.clone(),
                trust_sha256: repository.trust.sha256.clone(),
            })
        })
        .collect::<Result<Vec<_>, ExecutorError>>()?;
    let artifacts = manifest
        .artifacts
        .iter()
        .map(|artifact| {
            let file = open_retained(directory, &artifact.file)?;
            Ok(StagedArtifact {
                file,
                expected: ExpectedPackage {
                    name: artifact.name.clone(),
                    epoch: artifact.epoch.into(),
                    version: artifact.version.clone(),
                    release: artifact.release.clone(),
                    arch: artifact.arch.clone(),
                    vendor: artifact.vendor.clone(),
                },
                sha256: artifact.file.sha256.clone(),
                size: artifact.file.size,
                repo_id: artifact.repo_id.clone(),
                generation_sha256: artifact.generation_sha256.clone(),
                origin_sha256: artifact.origin_sha256.clone(),
                trust_sha256: artifact.trust_sha256.clone(),
            })
        })
        .collect::<Result<Vec<_>, ExecutorError>>()?;
    Ok(StagedInputs {
        policy,
        repositories,
        candidates: Vec::new(),
        metadata: Vec::new(),
        artifacts,
    })
}

fn copy(
    directory: &std::os::fd::OwnedFd,
    staging: &mut Staging,
    input: &InputFile,
    name: &str,
) -> Result<File, ExecutorError> {
    let mut source = open_retained(directory, input)?;
    staging.copy_file(&mut source, name, &input.sha256, input.size)
}

fn parse_policy(
    directory: &std::os::fd::OwnedFd,
    input: &InputFile,
) -> Result<SolverPolicy, ExecutorError> {
    let mut file = open_retained(directory, input)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(io)?;
    dnfast_core::CanonicalDocument::from_canonical_json(&bytes)
        .map_err(|error| ExecutorError::Inputs(error.to_string()))
}

fn materialize_native_metadata(
    repomd: &mut File,
    primary: &mut File,
    filelists: &mut File,
) -> Result<(Vec<u8>, Vec<u8>), ExecutorError> {
    let mut repomd_bytes = Vec::new();
    repomd.read_to_end(&mut repomd_bytes).map_err(io)?;
    repomd.rewind().map_err(io)?;
    let records =
        parse_repomd_records(&repomd_bytes).map_err(|error| materialization("repomd", error))?;
    let mut primary_bytes = Vec::new();
    primary.read_to_end(&mut primary_bytes).map_err(io)?;
    primary.rewind().map_err(io)?;
    let primary_xml = decode_primary(&primary_bytes, &records.primary)
        .map_err(|error| materialization("primary", error))?;
    let mut filelists_bytes = Vec::new();
    filelists.read_to_end(&mut filelists_bytes).map_err(io)?;
    filelists.rewind().map_err(io)?;
    let filelists_xml = dnfast_metadata::decode_record(&filelists_bytes, &records.filelists)
        .map_err(|error| materialization("filelists", error))?;
    Ok((primary_xml, filelists_xml))
}

fn native_repository(
    repository: &InputRepository,
    repomd_path: impl Into<String>,
    primary_path: impl Into<String>,
    filelists_path: impl Into<String>,
) -> Repository {
    Repository {
        id: repository.id.clone(),
        repomd_path: repomd_path.into(),
        primary_path: primary_path.into(),
        filelists_path: filelists_path.into(),
        priority: repository.priority,
        cost: repository.cost,
    }
}

fn parse_trust(
    directory: &std::os::fd::OwnedFd,
    input: &InputFile,
) -> Result<dnfast_core::RepoTrustPolicy, ExecutorError> {
    let mut file = open_retained(directory, input)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(io)?;
    dnfast_core::CanonicalDocument::from_canonical_json(&bytes)
        .map_err(|error| ExecutorError::Inputs(error.to_string()))
}

pub(crate) fn parse_candidates(
    repository: &InputRepository,
    repomd: &mut File,
    primary: &mut File,
    base_architecture: Architecture,
) -> Result<ParsedCandidates, ExecutorError> {
    let mut repomd_bytes = Vec::new();
    repomd.read_to_end(&mut repomd_bytes).map_err(io)?;
    let records = parse_repomd_records(&repomd_bytes).map_err(metadata)?;
    let mut primary_bytes = Vec::new();
    primary.read_to_end(&mut primary_bytes).map_err(io)?;
    let decoded = if primary_bytes.starts_with(b"<?xml") || primary_bytes.starts_with(b"<metadata")
    {
        primary_bytes
    } else {
        decode_primary(&primary_bytes, &records.primary).map_err(metadata)?
    };
    let packages = parse_primary_records(decoded.as_slice()).map_err(metadata)?;
    let metadata = packages
        .iter()
        .cloned()
        .map(|item| (repository.id.clone(), item))
        .collect();
    let mut candidates = Vec::new();
    for item in packages {
        let Some(arch) = parse_architecture(&item.arch, base_architecture)? else {
            continue;
        };
        let epoch = item
            .epoch
            .parse()
            .map_err(|_| ExecutorError::Inputs("invalid metadata epoch".into()))?;
        candidates.push(CandidatePackage {
            name: item.name,
            evra: Evra::new(epoch, item.version, item.release, arch),
            vendor: if item.vendor.is_empty() {
                "unknown".into()
            } else {
                item.vendor
            },
            repo_id: repository.id.clone(),
            priority: u32::try_from(repository.priority)
                .map_err(|_| ExecutorError::Inputs("negative repository priority".into()))?,
            cost: u32::try_from(repository.cost)
                .map_err(|_| ExecutorError::Inputs("negative repository cost".into()))?,
            package_size: item.package_size,
            installed_size: item.installed_size,
            checksum_sha256: item.checksum,
            location: item.location,
            excluded: false,
            modular: false,
        });
    }
    Ok((candidates, metadata))
}

fn parse_architecture(
    value: &str,
    base: Architecture,
) -> Result<Option<Architecture>, ExecutorError> {
    match value {
        "aarch64" => Ok(Some(Architecture::Aarch64)),
        "x86_64" => Ok(Some(Architecture::X86_64)),
        "noarch" => Ok(Some(Architecture::Noarch)),
        // Fedora's x86_64 repository intentionally contains i686 multilib
        // packages. The canonical policy has allow_multilib=false, so retain
        // them as signed metadata evidence but exclude them from executable
        // candidate construction exactly as the public planner does.
        "i686" if base == Architecture::X86_64 => Ok(None),
        _ => Err(ExecutorError::Inputs(
            "unsupported metadata architecture".into(),
        )),
    }
}

fn stage_artifact(
    directory: &std::os::fd::OwnedFd,
    staging: &mut Staging,
    artifact: &InputArtifact,
    index: usize,
    metadata: &[(String, dnfast_metadata::CompletePackage)],
) -> Result<StagedArtifact, ExecutorError> {
    validate_artifact_metadata(metadata, artifact)?;
    let file = copy(
        directory,
        staging,
        &artifact.file,
        &format!("artifact-{index}"),
    )?;
    let epoch = artifact.epoch.into();
    Ok(StagedArtifact {
        file,
        expected: ExpectedPackage {
            name: artifact.name.clone(),
            epoch,
            version: artifact.version.clone(),
            release: artifact.release.clone(),
            arch: artifact.arch.clone(),
            vendor: artifact.vendor.clone(),
        },
        sha256: artifact.file.sha256.clone(),
        size: artifact.file.size,
        repo_id: artifact.repo_id.clone(),
        generation_sha256: artifact.generation_sha256.clone(),
        origin_sha256: artifact.origin_sha256.clone(),
        trust_sha256: artifact.trust_sha256.clone(),
    })
}

fn validate_artifact_metadata(
    metadata: &[(String, dnfast_metadata::CompletePackage)],
    artifact: &InputArtifact,
) -> Result<(), ExecutorError> {
    let found = metadata.iter().any(|(repository, item)| {
        repository == &artifact.repo_id
            && item.name == artifact.name
            && item.epoch.parse::<u32>() == Ok(artifact.epoch)
            && item.version == artifact.version
            && item.release == artifact.release
            && item.arch == artifact.arch
            && item.checksum == artifact.file.sha256
            && item.package_size == artifact.file.size
            && metadata_vendor(item) == artifact.vendor
    });
    if found {
        Ok(())
    } else {
        Err(ExecutorError::Inputs(
            "artifact differs from staged rpm-md candidate".into(),
        ))
    }
}

fn metadata_vendor(item: &dnfast_metadata::CompletePackage) -> &str {
    if item.vendor.is_empty() {
        "unknown"
    } else {
        &item.vendor
    }
}

fn io(error: std::io::Error) -> ExecutorError {
    ExecutorError::Inputs(error.to_string())
}
fn metadata(error: dnfast_metadata::MetadataError) -> ExecutorError {
    ExecutorError::Inputs(error.to_string())
}
fn materialization(role: &'static str, error: dnfast_metadata::MetadataError) -> ExecutorError {
    ExecutorError::Inputs(format!("{role} rpm-md materialization failed: {error}"))
}

#[cfg(test)]
mod tests {
    use std::{fs::File, path::PathBuf};

    use super::{
        InputArtifact, InputFile, InputRepository, materialize_native_metadata, native_repository,
        parse_architecture, parse_candidates, validate_artifact_metadata,
    };
    use crate::input_model::{InputOrigin, InputRepositoryTrust};
    use dnfast_core::Architecture;

    fn fixture_repository() -> (InputRepository, PathBuf) {
        let repodata = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/rpm/generated-build10/repos/main/repodata");
        let descriptor = |name: &str| InputFile {
            name: name.into(),
            sha256: "a".repeat(64),
            size: 1,
        };
        (
            InputRepository {
                id: "main".into(),
                priority: 99,
                cost: 1000,
                generation_sha256: "a".repeat(64),
                origin: InputOrigin {
                    repomd_url: "https://mirror.example/fedora/repodata/repomd.xml".into(),
                    sha256: "b".repeat(64),
                },
                repomd: descriptor("repomd"),
                primary: descriptor("primary"),
                filelists: descriptor("filelists"),
                file_provides: None,
                group: None,
                modules: None,
                trust: InputRepositoryTrust {
                    policy: descriptor("trust"),
                    sha256: "c".repeat(64),
                    keys: Vec::new(),
                },
            },
            repodata,
        )
    }

    #[test]
    fn materialized_rpm_md_rewinds_candidate_cursor_and_binds_native_xml_paths() {
        // Given: a verified zstd rpm-md generation and its raw manifest descriptors.
        let (repository, repodata) = fixture_repository();
        let mut repomd = File::open(repodata.join("repomd.xml")).expect("repomd");
        let mut primary = File::open(repodata.join("primary.xml.zst")).expect("primary");
        let mut filelists = File::open(repodata.join("filelists.xml.zst")).expect("filelists");

        // When: staging materializes native XML before parsing the candidate records.
        let (primary_xml, filelists_xml) =
            materialize_native_metadata(&mut repomd, &mut primary, &mut filelists)
                .expect("materialize native XML");
        let parsed = parse_candidates(&repository, &mut repomd, &mut primary, Architecture::X86_64)
            .expect("parse candidate records after materialization");
        let native = native_repository(
            &repository,
            "/staging/repo-0-repomd",
            "/staging/repo-0-native-primary.xml",
            "/staging/repo-0-native-filelists.xml",
        );

        // Then: candidate parsing retains the verified generation and the native ABI receives XML, never raw zstd paths.
        assert!(!parsed.0.is_empty());
        assert!(primary_xml.starts_with(b"<?xml") || primary_xml.starts_with(b"<metadata"));
        assert!(filelists_xml.starts_with(b"<?xml") || filelists_xml.starts_with(b"<filelists"));
        assert_eq!(native.repomd_path, "/staging/repo-0-repomd");
        assert_eq!(native.primary_path, "/staging/repo-0-native-primary.xml");
        assert_eq!(
            native.filelists_path,
            "/staging/repo-0-native-filelists.xml"
        );
    }

    fn complete(vendor: &str) -> dnfast_metadata::CompletePackage {
        dnfast_metadata::CompletePackage {
            name: "dnfast-app".into(),
            arch: "noarch".into(),
            epoch: "0".into(),
            version: "1.0".into(),
            release: "1".into(),
            summary: String::new(),
            checksum: "a".repeat(64),
            location: "dnfast-app.rpm".into(),
            description: String::new(),
            vendor: vendor.into(),
            build_host: String::new(),
            source_rpm: String::new(),
            package_size: 1,
            installed_size: 1,
            archive_size: 1,
            build_time: 0,
            provides: vec![],
            requires: vec![],
            recommends: vec![],
            suggests: vec![],
            supplements: vec![],
            enhances: vec![],
            conflicts: vec![],
            obsoletes: vec![],
            files: vec![],
        }
    }

    #[test]
    fn artifact_with_vendor_different_from_staged_rpm_md_is_rejected() {
        // Given: a staged complete record and an artifact descriptor with another Vendor.
        let metadata = vec![("main".into(), complete("Metadata Vendor"))];
        let artifact = InputArtifact {
            file: InputFile {
                name: "rpm".into(),
                sha256: "a".repeat(64),
                size: 1,
            },
            repo_id: "main".into(),
            generation_sha256: "a".repeat(64),
            origin_sha256: "b".repeat(64),
            trust_sha256: "c".repeat(64),
            name: "dnfast-app".into(),
            epoch: 0,
            version: "1.0".into(),
            release: "1".into(),
            arch: "noarch".into(),
            vendor: "Other Vendor".into(),
        };

        // When: privileged staging binds the artifact to parsed rpm-md.
        let result = validate_artifact_metadata(&metadata, &artifact);

        // Then: an artifact cannot claim a Vendor different from its complete record.
        assert!(result.is_err());
    }

    #[test]
    fn x86_64_metadata_architecture_is_parsed_without_host_fallback() {
        assert_eq!(
            parse_architecture("x86_64", Architecture::X86_64).unwrap(),
            Some(Architecture::X86_64)
        );
        assert_eq!(
            parse_architecture("i686", Architecture::X86_64).unwrap(),
            None
        );
        assert!(parse_architecture("i686", Architecture::Aarch64).is_err());
    }
}
