use std::{collections::BTreeSet, fs, path::PathBuf};

use dnfast_metadata::{parse_repomd, parse_repomd_records, validate_filelists_generation};

use crate::{
    Cache,
    fs_safety::{
        AnchoredDirectory, MAX_MANIFEST_BYTES, read_anchored, read_regular, reject_symlink,
        validate_name, verify_file,
    },
    model::{
        CacheError, CompleteSnapshot, CurrentPointer, Manifest, SelectedOrigin, Snapshot,
        SnapshotIntegrity, VerifiedBytes, VerifiedCompleteGeneration, io_error, metadata_error,
        sha256, valid_digest,
    },
};

type LoadedInputs = (
    Vec<dnfast_metadata::CompletePackage>,
    Vec<dnfast_metadata::FileListPackage>,
    Vec<dnfast_metadata::Package>,
);

impl Cache {
    pub fn open_current_verified_complete_generation(
        &self,
        repository: &str,
    ) -> Result<VerifiedCompleteGeneration, CacheError> {
        let pointer = self.current_pointer(repository)?;
        let mut generation = self.open_verified_complete_generation(&pointer.digest)?;
        if generation.repository() != repository {
            return Err(CacheError::Corrupt("repository identity mismatch".into()));
        }
        generation.repomd_authentication = pointer.repomd_authentication;
        Ok(generation)
    }

    pub fn load(&self, repository: &str) -> Result<Snapshot, CacheError> {
        let digest = self.current_pointer(repository)?.digest;
        let (stored_repository, packages) = self.open_search_index(&digest)?;
        if stored_repository != repository {
            return Err(CacheError::Corrupt("repository identity mismatch".into()));
        }
        Ok(Snapshot { digest, packages })
    }

    pub(crate) fn open_search_index(
        &self,
        digest: &str,
    ) -> Result<(String, Vec<dnfast_metadata::Package>), CacheError> {
        if !valid_digest(digest) {
            return Err(CacheError::Corrupt("invalid object digest".into()));
        }
        let object = self.root.join("objects/sha256").join(digest);
        reject_symlink(&object, true)?;
        let identity = object_identity(&object)?;
        let anchored = AnchoredDirectory::open(&object)?;
        let manifest_bytes =
            anchored.read(std::ffi::OsStr::new("manifest.json"), MAX_MANIFEST_BYTES)?;
        let probe: VersionProbe = serde_json::from_slice(&manifest_bytes)
            .map_err(|error| CacheError::Corrupt(error.to_string()))?;
        match probe.version {
            None | Some(1) => return Err(CacheError::CacheUpgradeRequired),
            Some(2 | 3) => {}
            Some(_) => return Err(CacheError::Corrupt("unsupported manifest version".into())),
        }
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|error| CacheError::Corrupt(error.to_string()))?;
        validate_manifest(&object, &manifest)?;
        if manifest.repomd.sha256 != digest {
            return Err(CacheError::Corrupt("manifest identity mismatch".into()));
        }
        let repomd = verify_file(&anchored, &manifest.repomd)?;
        let primary = verified_bytes(&anchored, &manifest.primary)?;
        let record = parse_repomd(&repomd).map_err(metadata_error)?;
        if record.checksum != primary.sha256() || record.size != primary.size() {
            return Err(CacheError::Corrupt(
                "primary bytes differ from repomd record".into(),
            ));
        }
        let packages = decode_json(&anchored, &manifest.search_index)?;
        let repository = String::from_utf8(verify_file(&anchored, &manifest.repository)?)
            .map_err(|error| CacheError::Corrupt(error.to_string()))?;
        if object_identity(&object)? != identity {
            return Err(CacheError::Corrupt(
                "object directory changed during search-index open".into(),
            ));
        }
        Ok((repository, packages))
    }

    pub fn open_by_digest(&self, digest: &str) -> Result<CompleteSnapshot, CacheError> {
        if !valid_digest(digest) {
            return Err(CacheError::Corrupt("invalid object digest".into()));
        }
        let object = self.root.join("objects/sha256").join(digest);
        reject_symlink(&object, true)?;
        let identity = object_identity(&object)?;
        let anchored = AnchoredDirectory::open(&object)?;
        let manifest_bytes =
            anchored.read(std::ffi::OsStr::new("manifest.json"), MAX_MANIFEST_BYTES)?;
        let probe: VersionProbe = serde_json::from_slice(&manifest_bytes)
            .map_err(|error| CacheError::Corrupt(error.to_string()))?;
        match probe.version {
            None | Some(1) => return Err(CacheError::CacheUpgradeRequired),
            Some(2 | 3) => {}
            Some(_) => return Err(CacheError::Corrupt("unsupported manifest version".into())),
        }
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|error| CacheError::Corrupt(error.to_string()))?;
        validate_manifest(&object, &manifest)?;
        if manifest.repomd.sha256 != digest {
            return Err(CacheError::Corrupt("manifest identity mismatch".into()));
        }
        let repomd = verify_file(&anchored, &manifest.repomd)?;
        if sha256(&repomd) != digest {
            return Err(CacheError::Corrupt("repomd object mismatch".into()));
        }
        let primary = verify_file(&anchored, &manifest.primary)?;
        let packages = decode_json(&anchored, &manifest.search_index)?;
        let repository = String::from_utf8(verify_file(&anchored, &manifest.repository)?)
            .map_err(|error| CacheError::Corrupt(error.to_string()))?;
        let source_origin = manifest
            .source_origin
            .as_ref()
            .map(|record| {
                let value = String::from_utf8(verify_file(&anchored, record)?)
                    .map_err(|error| CacheError::Corrupt(error.to_string()))?;
                SelectedOrigin::parse(&value)
                    .map_err(|error| CacheError::Corrupt(error.to_string()))
            })
            .transpose()?;
        let (solver_inputs, filelists, parsed_packages) =
            self.open_inputs(&anchored, &repomd, &primary, &manifest)?;
        if packages != parsed_packages {
            return Err(CacheError::Corrupt(
                "search index does not match primary".into(),
            ));
        }
        if object_identity(&object)? != identity {
            return Err(CacheError::Corrupt(
                "object directory changed during open".into(),
            ));
        }
        Ok(CompleteSnapshot {
            digest: digest.into(),
            repository,
            integrity: manifest.integrity,
            packages,
            solver_inputs,
            filelists,
            source_origin,
        })
    }

    pub fn open_verified_complete_generation(
        &self,
        digest: &str,
    ) -> Result<VerifiedCompleteGeneration, CacheError> {
        if !valid_digest(digest) {
            return Err(CacheError::Corrupt("invalid object digest".into()));
        }
        let object = self.root.join("objects/sha256").join(digest);
        reject_symlink(&object, true)?;
        let identity = object_identity(&object)?;
        let anchored = AnchoredDirectory::open(&object)?;
        let manifest_bytes =
            anchored.read(std::ffi::OsStr::new("manifest.json"), MAX_MANIFEST_BYTES)?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|error| CacheError::Corrupt(error.to_string()))?;
        validate_manifest(&object, &manifest)?;
        if !matches!(manifest.version, 2 | 3)
            || manifest.repomd.sha256 != digest
            || manifest.integrity != SnapshotIntegrity::CompleteMetadata
        {
            return Err(CacheError::Corrupt(
                "verified generation manifest mismatch".into(),
            ));
        }
        let repomd = verified_bytes(&anchored, &manifest.repomd)?;
        let primary = verified_bytes(&anchored, &manifest.primary)?;
        let filelists = verified_bytes(
            &anchored,
            manifest
                .filelists
                .as_ref()
                .ok_or_else(|| CacheError::Corrupt("missing filelists".into()))?,
        )?;
        let records = parse_repomd_records(repomd.bytes()).map_err(metadata_error)?;
        if records.primary.checksum != primary.sha256()
            || records.primary.size != primary.size()
            || records.filelists.checksum != filelists.sha256()
            || records.filelists.size != filelists.size()
        {
            return Err(CacheError::Corrupt(
                "metadata bytes differ from repomd records".into(),
            ));
        }
        let repository = String::from_utf8(verify_file(&anchored, &manifest.repository)?)
            .map_err(|error| CacheError::Corrupt(error.to_string()))?;
        let origin = manifest
            .source_origin
            .as_ref()
            .ok_or_else(|| CacheError::Corrupt("missing selected origin".into()))?;
        let origin = String::from_utf8(verify_file(&anchored, origin)?)
            .map_err(|error| CacheError::Corrupt(error.to_string()))?;
        let origin = SelectedOrigin::parse(&origin)
            .map_err(|error| CacheError::Corrupt(error.to_string()))?;
        if object_identity(&object)? != identity {
            return Err(CacheError::Corrupt(
                "object directory changed during verified generation open".into(),
            ));
        }
        Ok(VerifiedCompleteGeneration {
            digest: digest.into(),
            repository,
            origin,
            repomd,
            primary,
            filelists,
            repomd_authentication: crate::model::RepomdAuthentication::TransportOnly,
        })
    }

    fn open_inputs(
        &self,
        object: &AnchoredDirectory,
        repomd: &[u8],
        primary: &[u8],
        manifest: &Manifest,
    ) -> Result<LoadedInputs, CacheError> {
        match manifest.integrity {
            SnapshotIntegrity::SearchOnly => {
                if manifest.filelists.is_some()
                    || manifest.filelists_index.is_some()
                    || manifest.solver_inputs.is_some()
                {
                    return Err(CacheError::Corrupt(
                        "search-only manifest has solver inputs".into(),
                    ));
                }
                let record = parse_repomd(repomd).map_err(metadata_error)?;
                let opened =
                    dnfast_metadata::decode_primary(primary, &record).map_err(metadata_error)?;
                let packages =
                    dnfast_metadata::parse_primary(opened.as_slice()).map_err(metadata_error)?;
                Ok((Vec::new(), Vec::new(), packages))
            }
            SnapshotIntegrity::CompleteMetadata => {
                let records = parse_repomd_records(repomd).map_err(metadata_error)?;
                let opened = dnfast_metadata::decode_record(primary, &records.primary)
                    .map_err(metadata_error)?;
                let compressed_files = manifest
                    .filelists
                    .as_ref()
                    .ok_or_else(|| CacheError::Corrupt("missing filelists".into()))?;
                let compressed = verify_file(object, compressed_files)?;
                let parsed = dnfast_metadata::parse_filelists_record(
                    compressed.as_slice(),
                    &records.filelists,
                )
                .map_err(metadata_error)?;
                let parsed_solver = dnfast_metadata::parse_primary_records(opened.as_slice())
                    .map_err(metadata_error)?;
                let (solver_inputs, filelists) = if manifest.version == 2 {
                    let solver = manifest
                        .solver_inputs
                        .as_ref()
                        .ok_or_else(|| CacheError::Corrupt("missing solver inputs".into()))?;
                    let files = manifest
                        .filelists_index
                        .as_ref()
                        .ok_or_else(|| CacheError::Corrupt("missing filelists index".into()))?;
                    let solver_inputs: Vec<dnfast_metadata::CompletePackage> =
                        decode_json(object, solver)?;
                    if parsed_solver != solver_inputs {
                        return Err(CacheError::Corrupt("solver inputs mismatch".into()));
                    }
                    let filelists: Vec<dnfast_metadata::FileListPackage> =
                        decode_json(object, files)?;
                    if parsed != filelists {
                        return Err(CacheError::Corrupt("filelists index mismatch".into()));
                    }
                    (solver_inputs, filelists)
                } else {
                    if manifest.solver_inputs.is_some() || manifest.filelists_index.is_some() {
                        return Err(CacheError::Corrupt(
                            "version three manifest contains derived indexes".into(),
                        ));
                    }
                    (parsed_solver, parsed)
                };
                validate_filelists_generation(&solver_inputs, &filelists)
                    .map_err(metadata_error)?;
                let packages = solver_inputs.iter().map(search_package).collect();
                Ok((solver_inputs, filelists, packages))
            }
        }
    }

    pub(crate) fn current_pointer(&self, repository: &str) -> Result<CurrentPointer, CacheError> {
        let directory = self.repository_dir(repository);
        if fs::symlink_metadata(directory.join("current"))
            .is_ok_and(|metadata| metadata.file_type().is_symlink() || !metadata.is_file())
        {
            return Err(CacheError::Corrupt("current is not a regular file".into()));
        }
        let bytes =
            read_anchored(&directory, std::ffi::OsStr::new("current"), 2048).map_err(|error| {
                match error {
                    CacheError::Io(_) if !directory.join("current").exists() => {
                        CacheError::MissingSnapshot(repository.into())
                    }
                    other => other,
                }
            })?;
        if let Ok(current) = std::str::from_utf8(&bytes) {
            let digest = current.trim();
            if current.lines().count() == 1 && valid_digest(digest) {
                return Ok(CurrentPointer {
                    version: 1,
                    digest: digest.into(),
                    repomd_authentication: crate::model::RepomdAuthentication::TransportOnly,
                });
            }
        }
        let pointer: CurrentPointer = serde_json::from_slice(&bytes)
            .map_err(|_| CacheError::Corrupt("invalid current digest".into()))?;
        if pointer.version != 1
            || !valid_digest(&pointer.digest)
            || serde_json::to_vec(&pointer)
                .map_err(|error| CacheError::Corrupt(error.to_string()))?
                != bytes
        {
            return Err(CacheError::Corrupt("invalid current digest".into()));
        }
        pointer.repomd_authentication.validate()?;
        Ok(pointer)
    }

    pub fn repositories(&self) -> Result<Vec<String>, CacheError> {
        let directory = self.root.join("repos");
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(io_error(error)),
        };
        let mut repositories = Vec::new();
        for entry in entries {
            let entry = entry.map_err(io_error)?;
            let file_type = entry.file_type().map_err(io_error)?;
            if !file_type.is_dir() || file_type.is_symlink() {
                return Err(CacheError::Corrupt("unsafe repository cache entry".into()));
            }
            let key = entry.file_name();
            let key = key
                .to_str()
                .ok_or_else(|| CacheError::Corrupt("non-UTF-8 repository cache key".into()))?;
            if !valid_digest(key) {
                return Err(CacheError::Corrupt("invalid repository cache key".into()));
            }
            let id = String::from_utf8(read_regular(&entry.path().join("repo-id"))?)
                .map_err(|error| CacheError::Corrupt(error.to_string()))?;
            if sha256(id.as_bytes()) != key {
                return Err(CacheError::Corrupt("repository cache key mismatch".into()));
            }
            repositories.push(id);
        }
        repositories.sort();
        repositories.dedup();
        Ok(repositories)
    }

    pub(crate) fn repository_dir(&self, repository: &str) -> PathBuf {
        self.root.join("repos").join(sha256(repository.as_bytes()))
    }
}

fn verified_bytes(
    object: &AnchoredDirectory,
    record: &crate::model::FileRecord,
) -> Result<VerifiedBytes, CacheError> {
    let bytes = verify_file(object, record)?;
    Ok(VerifiedBytes {
        sha256: record.sha256.clone(),
        size: record.size,
        bytes,
    })
}

fn decode_json<T: serde::de::DeserializeOwned>(
    object: &AnchoredDirectory,
    record: &crate::model::FileRecord,
) -> Result<T, CacheError> {
    serde_json::from_slice(&verify_file(object, record)?)
        .map_err(|error| CacheError::Corrupt(error.to_string()))
}

fn search_package(record: &dnfast_metadata::CompletePackage) -> dnfast_metadata::Package {
    dnfast_metadata::Package {
        name: record.name.clone(),
        arch: record.arch.clone(),
        epoch: record.epoch.clone(),
        version: record.version.clone(),
        release: record.release.clone(),
        summary: record.summary.clone(),
    }
}

#[derive(serde::Deserialize)]
struct VersionProbe {
    version: Option<u32>,
}

fn validate_manifest(object: &std::path::Path, manifest: &Manifest) -> Result<(), CacheError> {
    let mut expected = BTreeSet::from(["manifest.json".to_owned()]);
    let required = [
        (&manifest.repomd, "repomd.xml"),
        (&manifest.primary, "primary"),
        (&manifest.search_index, "packages.json"),
        (&manifest.repository, "repo-id"),
    ];
    for (record, exact) in required {
        add_record(&mut expected, record, exact)?;
    }
    if let Some(origin) = &manifest.source_origin {
        add_record(&mut expected, origin, "source-origin")?;
    }
    match manifest.integrity {
        SnapshotIntegrity::SearchOnly => {
            if manifest.filelists.is_some()
                || manifest.filelists_index.is_some()
                || manifest.solver_inputs.is_some()
            {
                return Err(CacheError::Corrupt(
                    "search-only manifest has complete records".into(),
                ));
            }
        }
        SnapshotIntegrity::CompleteMetadata => {
            add_record(
                &mut expected,
                manifest
                    .filelists
                    .as_ref()
                    .ok_or_else(|| CacheError::Corrupt("missing filelists".into()))?,
                "filelists",
            )?;
            if manifest.version == 2 {
                add_record(
                    &mut expected,
                    manifest
                        .filelists_index
                        .as_ref()
                        .ok_or_else(|| CacheError::Corrupt("missing filelists index".into()))?,
                    "filelists-index.json",
                )?;
                add_record(
                    &mut expected,
                    manifest
                        .solver_inputs
                        .as_ref()
                        .ok_or_else(|| CacheError::Corrupt("missing solver inputs".into()))?,
                    "solver-inputs.json",
                )?;
            } else if manifest.filelists_index.is_some() || manifest.solver_inputs.is_some() {
                return Err(CacheError::Corrupt(
                    "version three manifest contains derived indexes".into(),
                ));
            }
        }
    }
    let actual = fs::read_dir(object)
        .map_err(io_error)?
        .map(|entry| {
            let entry = entry.map_err(io_error)?;
            if !entry.file_type().map_err(io_error)?.is_file() {
                return Err(CacheError::Corrupt("non-file object entry".into()));
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| CacheError::Corrupt("non-UTF-8 object entry".into()))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if actual != expected {
        return Err(CacheError::Corrupt(
            "object file set does not match manifest".into(),
        ));
    }
    Ok(())
}

fn add_record(
    expected: &mut BTreeSet<String>,
    record: &crate::model::FileRecord,
    exact: &str,
) -> Result<(), CacheError> {
    validate_name(&record.name)?;
    if record.name != exact || !expected.insert(record.name.clone()) {
        return Err(CacheError::Corrupt(
            "manifest filename mismatch or alias".into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn object_identity(path: &std::path::Path) -> Result<(u64, u64), CacheError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(CacheError::Corrupt("unsafe object directory".into()));
    }
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn object_identity(path: &std::path::Path) -> Result<(u64, u64), CacheError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(CacheError::Corrupt("unsafe object directory".into()));
    }
    Ok((0, 0))
}
