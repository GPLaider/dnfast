use std::{fs, io::Write};

use dnfast_metadata::{
    CompletePackage, FileListPackage, Package, decode_primary, decode_record,
    parse_filelists_record, parse_primary, parse_primary_records, parse_repomd,
    parse_repomd_records, validate_filelists_generation, validate_filelists_record_identities,
    validate_primary_record,
};
use sha2::Digest;

use crate::{
    Cache,
    fs_safety::{create_private_tree, sync_directory, write_synced, write_verified},
    model::{
        CacheError, CompleteSnapshot, Manifest, RepomdAuthentication, SelectedOrigin, Snapshot,
        SnapshotIntegrity, io_error, metadata_error, sha256,
    },
};

impl Cache {
    /// Reuses an immutable complete generation only when a freshly obtained
    /// repomd document has exactly the current content digest. The raw metadata
    /// objects and search index are rehashed before the pointer authentication
    /// evidence is republished; new or changed repomd always returns `None` and
    /// requires a full download and validation.
    pub fn reuse_current_verified_complete(
        &self,
        repository: &str,
        repomd: &[u8],
        selected_origin: &str,
        repomd_authentication: RepomdAuthentication,
    ) -> Result<Option<Snapshot>, CacheError> {
        repomd_authentication.validate()?;
        SelectedOrigin::parse(selected_origin)
            .map_err(|error| CacheError::Corrupt(error.to_string()))?;
        let pointer = match self.current_pointer(repository) {
            Ok(pointer) => pointer,
            Err(CacheError::MissingSnapshot(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let digest = sha256(repomd);
        if pointer.digest != digest {
            return Ok(None);
        }
        let generation = self.open_verified_complete_generation(&digest)?;
        let (stored_repository, packages) = self.open_search_index(&digest)?;
        if generation.repository() != repository
            || stored_repository != repository
            || generation.repomd().bytes() != repomd
        {
            return Err(CacheError::Corrupt(
                "current complete generation identity mismatch".into(),
            ));
        }
        self.publish_repository_pointer(repository, &digest, &repomd_authentication)?;
        Ok(Some(Snapshot { digest, packages }))
    }

    pub fn publish(
        &self,
        repository: &str,
        repomd: &[u8],
        primary: &[u8],
    ) -> Result<Snapshot, CacheError> {
        let record = parse_repomd(repomd).map_err(metadata_error)?;
        let open = decode_primary(primary, &record).map_err(metadata_error)?;
        let packages = parse_primary(open.as_slice()).map_err(metadata_error)?;
        let snapshot = self.publish_generation(Publication {
            repository,
            repomd,
            primary,
            packages: &packages,
            solver_inputs: None,
            primary_identities: None,
            primary_files: None,
            filelists_bytes: None,
            filelists: None,
            source_origin: None,
            repomd_authentication: &RepomdAuthentication::TransportOnly,
            integrity: SnapshotIntegrity::SearchOnly,
        })?;
        Ok(Snapshot {
            digest: snapshot.digest,
            packages: snapshot.packages,
        })
    }

    pub fn publish_complete(
        &self,
        repository: &str,
        repomd: &[u8],
        primary: &[u8],
        filelists: &[u8],
    ) -> Result<CompleteSnapshot, CacheError> {
        self.publish_complete_with_origin(repository, repomd, primary, filelists, None)
    }

    pub fn publish_complete_with_origin(
        &self,
        repository: &str,
        repomd: &[u8],
        primary: &[u8],
        filelists: &[u8],
        source_origin: Option<&str>,
    ) -> Result<CompleteSnapshot, CacheError> {
        self.publish_complete_with_origin_and_authentication(
            repository,
            repomd,
            primary,
            filelists,
            source_origin,
            RepomdAuthentication::TransportOnly,
        )
    }

    pub fn publish_complete_with_origin_and_authentication(
        &self,
        repository: &str,
        repomd: &[u8],
        primary: &[u8],
        filelists: &[u8],
        source_origin: Option<&str>,
        repomd_authentication: RepomdAuthentication,
    ) -> Result<CompleteSnapshot, CacheError> {
        repomd_authentication.validate()?;
        let source_origin = source_origin
            .map(SelectedOrigin::parse)
            .transpose()
            .map_err(|error| CacheError::Corrupt(error.to_string()))?;
        let records = parse_repomd_records(repomd).map_err(metadata_error)?;
        let primary_open = decode_record(primary, &records.primary).map_err(metadata_error)?;
        let solver_inputs =
            parse_primary_records(primary_open.as_slice()).map_err(metadata_error)?;
        let filelist_inputs =
            parse_filelists_record(filelists, &records.filelists).map_err(metadata_error)?;
        validate_filelists_generation(&solver_inputs, &filelist_inputs).map_err(metadata_error)?;
        let packages = solver_inputs.iter().map(search_package).collect::<Vec<_>>();
        let primary_identities = solver_inputs
            .iter()
            .map(primary_identity)
            .collect::<Vec<_>>();
        let primary_files = primary_file_records(&solver_inputs)?;
        self.publish_generation(Publication {
            repository,
            repomd,
            primary,
            packages: &packages,
            solver_inputs: Some(&solver_inputs),
            primary_identities: Some(&primary_identities),
            primary_files: Some(&primary_files),
            filelists_bytes: Some(filelists),
            filelists: Some(&filelist_inputs),
            integrity: SnapshotIntegrity::CompleteMetadata,
            source_origin: source_origin.as_ref().map(SelectedOrigin::repomd_url),
            repomd_authentication: &repomd_authentication,
        })
    }

    pub fn publish_verified_complete_fast(
        &self,
        repository: &str,
        repomd: &[u8],
        primary: &[u8],
        filelists: &[u8],
        source_origin: Option<&str>,
        repomd_authentication: RepomdAuthentication,
    ) -> Result<Snapshot, CacheError> {
        trace_memory(&format!("cache:{repository}:begin"));
        repomd_authentication.validate()?;
        let source_origin = source_origin
            .map(SelectedOrigin::parse)
            .transpose()
            .map_err(|error| CacheError::Corrupt(error.to_string()))?;
        let records = parse_repomd_records(repomd).map_err(metadata_error)?;
        let validated =
            validate_primary_record(primary, &records.primary).map_err(metadata_error)?;
        trace_memory(&format!("cache:{repository}:primary-validated"));
        validate_filelists_record_identities(filelists, &records.filelists, &validated.identities)
            .map_err(metadata_error)?;
        trace_memory(&format!("cache:{repository}:filelists-validated"));
        let packages = validated.packages;
        let primary_identities = validated.identities;
        let primary_files = validated.primary_files;
        let snapshot = self.publish_generation(Publication {
            repository,
            repomd,
            primary,
            packages: &packages,
            solver_inputs: None,
            primary_identities: Some(&primary_identities),
            primary_files: Some(&primary_files),
            filelists_bytes: Some(filelists),
            filelists: None,
            integrity: SnapshotIntegrity::CompleteMetadata,
            source_origin: source_origin.as_ref().map(SelectedOrigin::repomd_url),
            repomd_authentication: &repomd_authentication,
        })?;
        trace_memory(&format!("cache:{repository}:published"));
        Ok(Snapshot {
            digest: snapshot.digest,
            packages: snapshot.packages,
        })
    }

    fn publish_generation(&self, input: Publication<'_>) -> Result<CompleteSnapshot, CacheError> {
        let digest = sha256(input.repomd);
        let objects = self.root.join("objects/sha256");
        let object = objects.join(&digest);
        create_private_tree(&self.root, &objects)?;
        let published_here = if object.exists() {
            false
        } else {
            self.write_object(&objects, &object, &input)?
        };
        let loaded = if published_here {
            snapshot_from_input(&digest, &input)?
        } else if input.integrity == SnapshotIntegrity::CompleteMetadata
            && input.solver_inputs.is_none()
            && input.filelists.is_none()
        {
            // The fast publisher has already streamed and validated the exact
            // input generation. Reopening an existing object through
            // `open_by_digest` would decompress and retain the complete primary
            // and filelists graphs a second time. Verify the immutable raw
            // generation plus its search index instead, then reuse the already
            // validated in-memory search records.
            let generation = self.open_verified_complete_generation(&digest)?;
            let (stored_repository, stored_packages) = self.open_search_index(&digest)?;
            if generation.repository() != input.repository
                || stored_repository != input.repository
                || stored_packages != input.packages
            {
                return Err(CacheError::Corrupt(
                    "existing object identity or search index mismatch".into(),
                ));
            }
            let mut snapshot = snapshot_from_input(&digest, &input)?;
            // An immutable generation keeps the origin that was authenticated
            // when the object first won publication. The same checksum-bound
            // repomd may be served by another Metalink mirror later; changing
            // the stored origin without creating a new object would make the
            // returned capability disagree with the object on disk.
            snapshot.source_origin = Some(generation.origin().clone());
            snapshot
        } else {
            self.open_by_digest(&digest)?
        };
        if loaded.repository != input.repository || loaded.integrity != input.integrity {
            return Err(CacheError::Corrupt(
                "existing object identity mismatch".into(),
            ));
        }
        self.publish_repository_pointer(input.repository, &digest, input.repomd_authentication)?;
        Ok(loaded)
    }

    fn write_object(
        &self,
        objects: &std::path::Path,
        object: &std::path::Path,
        input: &Publication<'_>,
    ) -> Result<bool, CacheError> {
        let staging = tempfile::Builder::new()
            .prefix(".staging-")
            .tempdir_in(objects)
            .map_err(io_error)?;
        let search_json = json(input.packages)?;
        let repository = write_verified(staging.path(), "repo-id", input.repository.as_bytes())?;
        let mut manifest = Manifest {
            version: 5,
            repomd: write_verified(staging.path(), "repomd.xml", input.repomd)?,
            primary: write_verified(staging.path(), "primary", input.primary)?,
            search_index: write_verified(staging.path(), "packages.json", &search_json)?,
            repository,
            integrity: input.integrity,
            filelists: None,
            filelists_index: None,
            solver_inputs: None,
            primary_identities: None,
            primary_files: None,
            source_origin: None,
        };
        if let Some(bytes) = input.filelists_bytes {
            manifest.filelists = Some(write_verified(staging.path(), "filelists", bytes)?);
        }
        if let Some(identities) = input.primary_identities {
            manifest.primary_identities = Some(write_verified(
                staging.path(),
                "primary-identities.json",
                &json(identities)?,
            )?);
        }
        if let Some(primary_files) = input.primary_files {
            manifest.primary_files = Some(write_verified(
                staging.path(),
                "primary-files.bin",
                &encode_primary_files(primary_files)?,
            )?);
        }
        if let Some(origin) = input.source_origin {
            manifest.source_origin = Some(write_verified(
                staging.path(),
                "source-origin",
                origin.as_bytes(),
            )?);
        }
        write_synced(&staging.path().join("manifest.json"), &json(&manifest)?)?;
        sync_directory(staging.path())?;
        fault(&self.root, ".fail-before-object-rename")?;
        match fs::rename(staging.path(), object) {
            Ok(()) => {
                std::mem::forget(staging);
                sync_directory(objects)?;
                Ok(true)
            }
            Err(_error) if object.exists() => Ok(false),
            Err(error) => Err(io_error(error)),
        }
    }

    fn publish_repository_pointer(
        &self,
        repository: &str,
        digest: &str,
        repomd_authentication: &RepomdAuthentication,
    ) -> Result<(), CacheError> {
        let directory = self.repository_dir(repository);
        create_private_tree(&self.root, &directory)?;
        let id_path = directory.join("repo-id");
        if id_path.exists() {
            let stored = String::from_utf8(crate::fs_safety::read_regular(&id_path)?)
                .map_err(|error| CacheError::Corrupt(error.to_string()))?;
            if stored != repository {
                return Err(CacheError::Corrupt("repository identity mismatch".into()));
            }
        } else {
            write_synced(&id_path, repository.as_bytes())?;
            sync_directory(&directory)?;
        }
        let pointer = crate::model::CurrentPointer {
            version: 1,
            digest: digest.into(),
            repomd_authentication: repomd_authentication.clone(),
        };
        let mut current = tempfile::NamedTempFile::new_in(&directory).map_err(io_error)?;
        current.write_all(&json(&pointer)?).map_err(io_error)?;
        current.as_file().sync_all().map_err(io_error)?;
        fault(&self.root, ".fail-before-current-rename")?;
        current
            .persist(directory.join("current"))
            .map_err(|error| io_error(error.error))?;
        sync_directory(&directory)
    }
}

fn snapshot_from_input(
    digest: &str,
    input: &Publication<'_>,
) -> Result<CompleteSnapshot, CacheError> {
    Ok(CompleteSnapshot {
        digest: digest.into(),
        repository: input.repository.into(),
        integrity: input.integrity,
        packages: input.packages.to_vec(),
        solver_inputs: input.solver_inputs.unwrap_or_default().to_vec(),
        filelists: input.filelists.unwrap_or_default().to_vec(),
        source_origin: input
            .source_origin
            .map(SelectedOrigin::parse)
            .transpose()
            .map_err(|error| CacheError::Corrupt(error.to_string()))?,
    })
}

fn trace_memory(phase: &str) {
    if std::env::var_os("DNFAST_REFRESH_TRACE").is_none() {
        return;
    }
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let fields = status
        .lines()
        .filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
        .collect::<Vec<_>>()
        .join(" ");
    eprintln!("dnfast-refresh-trace phase={phase} {fields}");
}

struct Publication<'a> {
    repository: &'a str,
    repomd: &'a [u8],
    primary: &'a [u8],
    packages: &'a [Package],
    solver_inputs: Option<&'a [CompletePackage]>,
    primary_identities: Option<&'a [dnfast_metadata::PrimaryPackageIdentity]>,
    primary_files: Option<&'a [dnfast_metadata::PrimaryFileRecord]>,
    filelists_bytes: Option<&'a [u8]>,
    filelists: Option<&'a [FileListPackage]>,
    integrity: SnapshotIntegrity,
    source_origin: Option<&'a str>,
    repomd_authentication: &'a RepomdAuthentication,
}

fn search_package(record: &CompletePackage) -> Package {
    Package {
        name: record.name.clone(),
        arch: record.arch.clone(),
        epoch: record.epoch.clone(),
        version: record.version.clone(),
        release: record.release.clone(),
        summary: record.summary.clone(),
    }
}

fn primary_identity(record: &CompletePackage) -> dnfast_metadata::PrimaryPackageIdentity {
    dnfast_metadata::PrimaryPackageIdentity {
        checksum: record.checksum.clone(),
        name: record.name.clone(),
        arch: record.arch.clone(),
        epoch: record.epoch.clone(),
        version: record.version.clone(),
        release: record.release.clone(),
    }
}

fn primary_file_records(
    packages: &[CompletePackage],
) -> Result<Vec<dnfast_metadata::PrimaryFileRecord>, CacheError> {
    let capacity = packages.iter().try_fold(0_usize, |count, package| {
        count
            .checked_add(package.files.len())
            .ok_or_else(|| CacheError::Corrupt("primary file count overflow".into()))
    })?;
    let mut records = Vec::new();
    records
        .try_reserve_exact(capacity)
        .map_err(|error| CacheError::Io(error.to_string()))?;
    for (ordinal, package) in packages.iter().enumerate() {
        let package_ordinal =
            u32::try_from(ordinal).map_err(|error| CacheError::Corrupt(error.to_string()))?;
        records.extend(
            package
                .files
                .iter()
                .map(|path| dnfast_metadata::PrimaryFileRecord {
                    path_sha256: sha2::Sha256::digest(path.as_bytes()).into(),
                    package_ordinal,
                }),
        );
    }
    Ok(records)
}

fn encode_primary_files(
    records: &[dnfast_metadata::PrimaryFileRecord],
) -> Result<Vec<u8>, CacheError> {
    const RECORD_SIZE: usize = 32 + std::mem::size_of::<u32>();
    let mut records = records.to_vec();
    records.sort_unstable_by_key(|record| (record.path_sha256, record.package_ordinal));
    records.dedup();
    let capacity = records
        .len()
        .checked_mul(RECORD_SIZE)
        .ok_or_else(|| CacheError::Corrupt("primary file projection size overflow".into()))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|error| CacheError::Io(error.to_string()))?;
    for record in records {
        bytes.extend_from_slice(&record.path_sha256);
        bytes.extend_from_slice(&record.package_ordinal.to_be_bytes());
    }
    Ok(bytes)
}

fn json<T: serde::Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CacheError> {
    serde_json::to_vec(value).map_err(|error| CacheError::Corrupt(error.to_string()))
}

fn fault(root: &std::path::Path, name: &str) -> Result<(), CacheError> {
    if root.join(name).exists() {
        return Err(CacheError::Io(format!("injected fault: {name}")));
    }
    Ok(())
}
