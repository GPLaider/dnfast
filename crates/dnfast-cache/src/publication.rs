use std::{fs, io::Write};

use dnfast_metadata::{
    CompletePackage, FileListPackage, Package, decode_primary, decode_record,
    parse_filelists_record, parse_primary, parse_primary_records, parse_repomd,
    parse_repomd_records, validate_filelists_generation,
};

use crate::{
    Cache,
    fs_safety::{create_private_tree, sync_directory, write_synced, write_verified},
    model::{
        CacheError, CompleteSnapshot, Manifest, RepomdAuthentication, SelectedOrigin, Snapshot,
        SnapshotIntegrity, io_error, metadata_error, sha256,
    },
};

impl Cache {
    pub fn publish(
        &self,
        repository: &str,
        repomd: &[u8],
        primary: &[u8],
    ) -> Result<Snapshot, CacheError> {
        let record = parse_repomd(repomd).map_err(metadata_error)?;
        let open = decode_primary(primary, &record).map_err(metadata_error)?;
        let packages = parse_primary(open.as_slice()).map_err(metadata_error)?;
        let digest = self.publish_generation(Publication {
            repository,
            repomd,
            primary,
            packages: &packages,
            solver_inputs: None,
            filelists_bytes: None,
            filelists: None,
            source_origin: None,
            repomd_authentication: &RepomdAuthentication::TransportOnly,
            integrity: SnapshotIntegrity::SearchOnly,
        })?;
        Ok(Snapshot { digest, packages })
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
        let digest = self.publish_generation(Publication {
            repository,
            repomd,
            primary,
            packages: &packages,
            solver_inputs: Some(&solver_inputs),
            filelists_bytes: Some(filelists),
            filelists: Some(&filelist_inputs),
            integrity: SnapshotIntegrity::CompleteMetadata,
            source_origin: source_origin.as_ref().map(SelectedOrigin::repomd_url),
            repomd_authentication: &repomd_authentication,
        })?;
        self.open_by_digest(&digest)
    }

    fn publish_generation(&self, input: Publication<'_>) -> Result<String, CacheError> {
        let digest = sha256(input.repomd);
        let objects = self.root.join("objects/sha256");
        let object = objects.join(&digest);
        create_private_tree(&self.root, &objects)?;
        if !object.exists() {
            self.write_object(&objects, &object, &input)?;
        }
        let loaded = self.open_by_digest(&digest)?;
        if loaded.repository != input.repository || loaded.integrity != input.integrity {
            return Err(CacheError::Corrupt(
                "existing object identity mismatch".into(),
            ));
        }
        self.publish_repository_pointer(input.repository, &digest, input.repomd_authentication)?;
        Ok(digest)
    }

    fn write_object(
        &self,
        objects: &std::path::Path,
        object: &std::path::Path,
        input: &Publication<'_>,
    ) -> Result<(), CacheError> {
        let staging = tempfile::Builder::new()
            .prefix(".staging-")
            .tempdir_in(objects)
            .map_err(io_error)?;
        let search_json = json(input.packages)?;
        let repository = write_verified(staging.path(), "repo-id", input.repository.as_bytes())?;
        let mut manifest = Manifest {
            version: 2,
            repomd: write_verified(staging.path(), "repomd.xml", input.repomd)?,
            primary: write_verified(staging.path(), "primary", input.primary)?,
            search_index: write_verified(staging.path(), "packages.json", &search_json)?,
            repository,
            integrity: input.integrity,
            filelists: None,
            filelists_index: None,
            solver_inputs: None,
            source_origin: None,
        };
        if let (Some(bytes), Some(solver), Some(files)) =
            (input.filelists_bytes, input.solver_inputs, input.filelists)
        {
            manifest.filelists = Some(write_verified(staging.path(), "filelists", bytes)?);
            manifest.solver_inputs = Some(write_verified(
                staging.path(),
                "solver-inputs.json",
                &json(solver)?,
            )?);
            manifest.filelists_index = Some(write_verified(
                staging.path(),
                "filelists-index.json",
                &json(files)?,
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
                sync_directory(objects)
            }
            Err(_error) if object.exists() => {
                self.open_by_digest(&sha256(input.repomd)).map(|_| ())
            }
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

struct Publication<'a> {
    repository: &'a str,
    repomd: &'a [u8],
    primary: &'a [u8],
    packages: &'a [Package],
    solver_inputs: Option<&'a [CompletePackage]>,
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

fn json<T: serde::Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CacheError> {
    serde_json::to_vec(value).map_err(|error| CacheError::Corrupt(error.to_string()))
}

fn fault(root: &std::path::Path, name: &str) -> Result<(), CacheError> {
    if root.join(name).exists() {
        return Err(CacheError::Io(format!("injected fault: {name}")));
    }
    Ok(())
}
