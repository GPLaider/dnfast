use std::{
    collections::HashMap,
    io::{Read, Seek, Write},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    PlanningBytes, PlanningError, PlanningRepository, PlanningSnapshot, fs::TrustedDirectory,
};

const INDEX_SCHEMA_VERSION: u32 = 3;
const BUCKET_COUNT: usize = 256;
// One independently authenticated blob per leading digest byte keeps an
// absolute-file lookup from rereading unrelated file-provides evidence.
const SHARD_COUNT: usize = 256;
const BUCKETS_PER_SHARD: usize = BUCKET_COUNT / SHARD_COUNT;
const HEADER_SIZE: usize = 24;
const RECORD_SIZE: usize = 36;
const MAGIC: &[u8; 8] = b"DNFASTFP";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    primary_sha256: String,
    filelists_sha256: String,
    package_count: u32,
    record_count: u64,
    shards: Vec<Shard>,
    buckets: Vec<Bucket>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Shard {
    sha256: String,
    size: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bucket {
    shard: u8,
    offset: u64,
    sha256: String,
    size: u64,
}

pub(crate) fn build(
    generation: &dnfast_cache::VerifiedCompleteGeneration,
    blob_store: Option<&TrustedDirectory>,
) -> Result<PlanningBytes, PlanningError> {
    let records =
        dnfast_metadata::parse_repomd_records(generation.repomd().bytes()).map_err(metadata)?;
    let primary =
        dnfast_metadata::validate_primary_record(generation.primary().bytes(), &records.primary)
            .map_err(metadata)?;
    let package_count = u32::try_from(primary.identities.len())
        .map_err(|error| PlanningError::Input(error.to_string()))?;
    let ordinals = primary
        .identities
        .iter()
        .enumerate()
        .map(|(index, package)| {
            u32::try_from(index)
                .map(|index| (package.checksum.as_str(), index))
                .map_err(|error| PlanningError::Input(error.to_string()))
        })
        .collect::<Result<HashMap<_, _>, _>>()?;
    if ordinals.len() != primary.identities.len() {
        return Err(PlanningError::Input(
            "primary package checksums are duplicate".into(),
        ));
    }
    // Fedora filelists contain millions of paths. Holding every 36-byte path
    // digest in 256 Vecs made a first-generation rebuild scale with the whole
    // repository and previously pushed peak RSS above 800 MiB. Anonymous
    // 0600 temporary files retain the exact same deterministic sort/dedup
    // result while bounding resident evidence to one hash bucket at a time.
    let mut buckets = (0..BUCKET_COUNT)
        .map(|_| tempfile::tempfile().map_err(io))
        .collect::<Result<Vec<_>, _>>()?;
    dnfast_metadata::visit_filelists_record_identities(
        generation.filelists().bytes(),
        &records.filelists,
        &primary.identities,
        |package_id, path| {
            let ordinal = ordinals.get(package_id).copied().ok_or_else(|| {
                dnfast_metadata::MetadataError::Xml(
                    "filelists package is absent from primary".into(),
                )
            })?;
            let path_digest = Sha256::digest(path.as_bytes());
            let mut record = [0_u8; RECORD_SIZE];
            record[..32].copy_from_slice(&path_digest);
            record[32..].copy_from_slice(&ordinal.to_be_bytes());
            buckets[usize::from(path_digest[0])]
                .write_all(&record)
                .map_err(|error| dnfast_metadata::MetadataError::Io(error.to_string()))?;
            Ok(())
        },
    )
    .map_err(metadata)?;

    let mut descriptors = Vec::with_capacity(BUCKET_COUNT);
    let mut shards = Vec::with_capacity(SHARD_COUNT);
    let mut record_count = 0_u64;
    for shard_index in 0..SHARD_COUNT {
        let mut shard = Vec::new();
        for (index, spool) in buckets
            .iter_mut()
            .enumerate()
            .skip(shard_index * BUCKETS_PER_SHARD)
            .take(BUCKETS_PER_SHARD)
        {
            spool.rewind().map_err(io)?;
            let length = usize::try_from(spool.metadata().map_err(io)?.len())
                .map_err(|error| PlanningError::Input(error.to_string()))?;
            if length % RECORD_SIZE != 0 {
                return Err(PlanningError::Input(
                    "file-provides spool has a partial record".into(),
                ));
            }
            let mut raw = Vec::new();
            raw.try_reserve_exact(length)
                .map_err(|error| PlanningError::Io(error.to_string()))?;
            spool.read_to_end(&mut raw).map_err(io)?;
            let mut records = raw
                .chunks_exact(RECORD_SIZE)
                .map(|value| {
                    let mut record = [0_u8; RECORD_SIZE];
                    record.copy_from_slice(value);
                    record
                })
                .collect::<Vec<_>>();
            drop(raw);
            records.sort_unstable();
            records.dedup();
            record_count = record_count
                .checked_add(records.len() as u64)
                .ok_or_else(|| {
                    PlanningError::Input("file-provides record count overflow".into())
                })?;
            let bytes = encode_bucket(index, &records)?;
            let offset = shard.len() as u64;
            descriptors.push(Bucket {
                shard: shard_index as u8,
                offset,
                sha256: format!("{:x}", Sha256::digest(&bytes)),
                size: bytes.len() as u64,
            });
            shard.extend_from_slice(&bytes);
        }
        let sha256 = format!("{:x}", Sha256::digest(&shard));
        if let Some(store) = blob_store {
            crate::snapshot_store::publish_blob_deferred(store, &sha256, &shard)?;
        }
        shards.push(Shard {
            sha256,
            size: shard.len() as u64,
        });
    }
    if let Some(store) = blob_store {
        crate::snapshot_store::sync_blobs(store)?;
    }
    let manifest = Manifest {
        schema_version: INDEX_SCHEMA_VERSION,
        primary_sha256: generation.primary().sha256().into(),
        filelists_sha256: generation.filelists().sha256().into(),
        package_count,
        record_count,
        shards,
        buckets: descriptors,
    };
    validate_manifest(
        &manifest,
        generation.primary().sha256(),
        generation.filelists().sha256(),
    )?;
    let bytes = serde_json::to_vec(&manifest).map_err(json)?;
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    if let Some(store) = blob_store {
        crate::snapshot_store::publish_blob(store, &sha256, &bytes)?;
    }
    Ok(PlanningBytes {
        sha256,
        size: bytes.len() as u64,
        base64: String::new(),
    })
}

impl PlanningSnapshot {
    pub fn file_providers(
        &self,
        repository: &PlanningRepository,
        absolute_path: &str,
    ) -> Result<Vec<u32>, PlanningError> {
        if !absolute_path.starts_with('/')
            || absolute_path.contains("//")
            || absolute_path.chars().any(char::is_control)
            || absolute_path
                .split('/')
                .any(|part| part == "." || part == "..")
        {
            return Err(PlanningError::Input(
                "file-provides selector is not a canonical absolute path".into(),
            ));
        }
        let descriptor = repository.file_provides.as_ref().ok_or_else(|| {
            PlanningError::Input("planning repository has no file-provides index".into())
        })?;
        let manifest_bytes = descriptor.decode_verified(self.storage())?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(json)?;
        if serde_json::to_vec(&manifest).map_err(json)? != manifest_bytes {
            return Err(PlanningError::Input(
                "file-provides manifest is not canonical JSON".into(),
            ));
        }
        validate_manifest(
            &manifest,
            &repository.primary.sha256,
            &repository.filelists.sha256,
        )?;
        let digest = Sha256::digest(absolute_path.as_bytes());
        let bucket_index = usize::from(digest[0]);
        let bucket = &manifest.buckets[bucket_index];
        let shard = &manifest.shards[usize::from(bucket.shard)];
        let bytes = read_shard(self, shard)?;
        let bucket_bytes = bucket_slice(&bytes, bucket)?;
        lookup_bucket(bucket_bytes, bucket_index, manifest.package_count, &digest)
    }
}

pub(crate) fn current_descriptor_valid(
    snapshot: &PlanningSnapshot,
    repository: &PlanningRepository,
) -> Result<bool, PlanningError> {
    let descriptor = repository.file_provides.as_ref().ok_or_else(|| {
        PlanningError::Input("planning repository has no file-provides index".into())
    })?;
    let manifest_bytes = descriptor.decode_verified(snapshot.storage())?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(json)?;
    if serde_json::to_vec(&manifest).map_err(json)? != manifest_bytes {
        return Err(PlanningError::Input(
            "file-provides manifest is not canonical JSON".into(),
        ));
    }
    if manifest.schema_version != INDEX_SCHEMA_VERSION {
        return Ok(false);
    }
    validate_manifest(
        &manifest,
        &repository.primary.sha256,
        &repository.filelists.sha256,
    )?;
    Ok(true)
}

pub(crate) fn referenced_shards_for_gc(
    manifest_bytes: &[u8],
    repository: &PlanningRepository,
) -> Result<Vec<String>, PlanningError> {
    let manifest: Manifest = serde_json::from_slice(manifest_bytes).map_err(json)?;
    if serde_json::to_vec(&manifest).map_err(json)? != manifest_bytes {
        return Err(PlanningError::Input(
            "file-provides manifest is not canonical JSON".into(),
        ));
    }
    let shard_count = match manifest.schema_version {
        2 => 16,
        INDEX_SCHEMA_VERSION => SHARD_COUNT,
        _ => {
            return Err(PlanningError::Input(
                "retained file-provides manifest schema is unsupported".into(),
            ));
        }
    };
    validate_manifest_layout(
        &manifest,
        &repository.primary.sha256,
        &repository.filelists.sha256,
        manifest.schema_version,
        shard_count,
    )?;
    Ok(manifest
        .shards
        .into_iter()
        .map(|shard| shard.sha256)
        .collect())
}

fn encode_bucket(index: usize, records: &[[u8; RECORD_SIZE]]) -> Result<Vec<u8>, PlanningError> {
    let body = records
        .len()
        .checked_mul(RECORD_SIZE)
        .and_then(|size| size.checked_add(HEADER_SIZE))
        .ok_or_else(|| PlanningError::Input("file-provides bucket size overflow".into()))?;
    let mut bytes = Vec::with_capacity(body);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&INDEX_SCHEMA_VERSION.to_be_bytes());
    bytes.push(u8::try_from(index).map_err(|error| PlanningError::Input(error.to_string()))?);
    bytes.extend_from_slice(&[0_u8; 3]);
    bytes.extend_from_slice(&(records.len() as u64).to_be_bytes());
    for record in records {
        bytes.extend_from_slice(record);
    }
    Ok(bytes)
}

fn read_shard(snapshot: &PlanningSnapshot, shard: &Shard) -> Result<Vec<u8>, PlanningError> {
    let descriptor = PlanningBytes {
        sha256: shard.sha256.clone(),
        size: shard.size,
        base64: String::new(),
    };
    descriptor.decode_verified(snapshot.storage())
}

fn bucket_slice<'a>(bytes: &'a [u8], bucket: &Bucket) -> Result<&'a [u8], PlanningError> {
    let start =
        usize::try_from(bucket.offset).map_err(|error| PlanningError::Input(error.to_string()))?;
    let size =
        usize::try_from(bucket.size).map_err(|error| PlanningError::Input(error.to_string()))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| PlanningError::Input("file-provides bucket range overflow".into()))?;
    let result = bytes
        .get(start..end)
        .ok_or_else(|| PlanningError::Input("file-provides bucket is outside its shard".into()))?;
    if format!("{:x}", Sha256::digest(result)) != bucket.sha256 {
        return Err(PlanningError::Input(
            "file-provides bucket digest differs".into(),
        ));
    }
    Ok(result)
}

fn lookup_bucket(
    bytes: &[u8],
    bucket_index: usize,
    package_count: u32,
    target: &[u8],
) -> Result<Vec<u32>, PlanningError> {
    let records = validate_bucket(bytes, bucket_index, package_count)?;
    let mut left = 0;
    let mut right = records;
    while left < right {
        let middle = left + (right - left) / 2;
        let offset = HEADER_SIZE + middle * RECORD_SIZE;
        if &bytes[offset..offset + 32] < target {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    let mut providers = Vec::new();
    while left < records {
        let offset = HEADER_SIZE + left * RECORD_SIZE;
        if &bytes[offset..offset + 32] != target {
            break;
        }
        providers.push(u32::from_be_bytes(
            bytes[offset + 32..offset + 36]
                .try_into()
                .expect("fixed record"),
        ));
        left += 1;
    }
    providers.sort_unstable();
    providers.dedup();
    Ok(providers)
}

fn validate_bucket(
    bytes: &[u8],
    bucket_index: usize,
    package_count: u32,
) -> Result<usize, PlanningError> {
    if bytes.len() < HEADER_SIZE
        || &bytes[..8] != MAGIC
        || u32::from_be_bytes(bytes[8..12].try_into().expect("fixed header"))
            != INDEX_SCHEMA_VERSION
        || usize::from(bytes[12]) != bucket_index
        || bytes[13..16] != [0_u8; 3]
    {
        return Err(PlanningError::Input(
            "file-provides bucket header is invalid".into(),
        ));
    }
    let count = usize::try_from(u64::from_be_bytes(
        bytes[16..24].try_into().expect("fixed header"),
    ))
    .map_err(|error| PlanningError::Input(error.to_string()))?;
    let expected = count
        .checked_mul(RECORD_SIZE)
        .and_then(|size| size.checked_add(HEADER_SIZE))
        .ok_or_else(|| PlanningError::Input("file-provides bucket size overflow".into()))?;
    if bytes.len() != expected {
        return Err(PlanningError::Input(
            "file-provides bucket size differs from header".into(),
        ));
    }
    let mut previous = None;
    for record in bytes[HEADER_SIZE..].chunks_exact(RECORD_SIZE) {
        if usize::from(record[0]) != bucket_index
            || u32::from_be_bytes(record[32..36].try_into().expect("fixed record")) >= package_count
            || previous.is_some_and(|value: &[u8]| value >= record)
        {
            return Err(PlanningError::Input(
                "file-provides bucket records are invalid".into(),
            ));
        }
        previous = Some(record);
    }
    Ok(count)
}

fn validate_manifest(
    manifest: &Manifest,
    primary_sha256: &str,
    filelists_sha256: &str,
) -> Result<(), PlanningError> {
    validate_manifest_layout(
        manifest,
        primary_sha256,
        filelists_sha256,
        INDEX_SCHEMA_VERSION,
        SHARD_COUNT,
    )
}

fn validate_manifest_layout(
    manifest: &Manifest,
    primary_sha256: &str,
    filelists_sha256: &str,
    schema_version: u32,
    shard_count: usize,
) -> Result<(), PlanningError> {
    if shard_count == 0 || BUCKET_COUNT % shard_count != 0 {
        return Err(PlanningError::Input(
            "file-provides manifest shard layout is invalid".into(),
        ));
    }
    let buckets_per_shard = BUCKET_COUNT / shard_count;
    if manifest.schema_version != schema_version
        || manifest.primary_sha256 != primary_sha256
        || manifest.filelists_sha256 != filelists_sha256
        || manifest.shards.len() != shard_count
        || manifest.buckets.len() != BUCKET_COUNT
        || manifest.package_count == 0
        || manifest.shards.iter().any(|shard| {
            shard.size < (HEADER_SIZE * buckets_per_shard) as u64 || !valid_sha256(&shard.sha256)
        })
        || manifest.buckets.iter().any(|bucket| {
            usize::from(bucket.shard) >= shard_count
                || bucket.size < HEADER_SIZE as u64
                || (bucket.size - HEADER_SIZE as u64) % RECORD_SIZE as u64 != 0
                || !valid_sha256(&bucket.sha256)
        })
    {
        return Err(PlanningError::Input(
            "file-provides manifest is invalid".into(),
        ));
    }
    let mut counted = 0_u64;
    for shard_index in 0..shard_count {
        let mut offset = 0_u64;
        for bucket_index in shard_index * buckets_per_shard..(shard_index + 1) * buckets_per_shard {
            let bucket = &manifest.buckets[bucket_index];
            if usize::from(bucket.shard) != shard_index || bucket.offset != offset {
                return Err(PlanningError::Input(
                    "file-provides manifest bucket layout is invalid".into(),
                ));
            }
            offset = offset
                .checked_add(bucket.size)
                .ok_or_else(|| PlanningError::Input("file-provides shard size overflow".into()))?;
            counted = counted
                .checked_add((bucket.size - HEADER_SIZE as u64) / RECORD_SIZE as u64)
                .ok_or_else(|| {
                    PlanningError::Input("file-provides record count overflow".into())
                })?;
        }
        if offset != manifest.shards[shard_index].size {
            return Err(PlanningError::Input(
                "file-provides manifest shard size is invalid".into(),
            ));
        }
    }
    if counted != manifest.record_count {
        return Err(PlanningError::Input(
            "file-provides manifest record count is invalid".into(),
        ));
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn metadata(error: dnfast_metadata::MetadataError) -> PlanningError {
    PlanningError::Input(format!(
        "file-provides index source validation failed: {error}"
    ))
}

fn io(error: std::io::Error) -> PlanningError {
    PlanningError::Io(error.to_string())
}

fn json(error: serde_json::Error) -> PlanningError {
    PlanningError::Input(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    use rustix::process::getuid;

    use super::*;

    #[test]
    fn bucket_lookup_preserves_multiple_provider_one_of_set() {
        let digest = Sha256::digest(b"/opt/example");
        let bucket = usize::from(digest[0]);
        let mut records = Vec::new();
        for ordinal in [9_u32, 2_u32] {
            let mut record = [0_u8; RECORD_SIZE];
            record[..32].copy_from_slice(&digest);
            record[32..].copy_from_slice(&ordinal.to_be_bytes());
            records.push(record);
        }
        records.sort_unstable();
        let bytes = encode_bucket(bucket, &records).expect("bucket");
        assert_eq!(
            lookup_bucket(&bytes, bucket, 10, &digest).expect("lookup"),
            [2, 9]
        );
        assert!(validate_bucket(&bytes, (bucket + 1) % 256, 10).is_err());
    }

    #[test]
    fn fixture_index_streams_exact_providers_and_rejects_bucket_tamper() {
        let directory = tempfile::Builder::new()
            .prefix(".file-provides-test-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("temporary root");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("root mode");
        let metadata = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/rpm/generated-build10/repos/main/repodata");
        let cache = dnfast_cache::Cache::new(directory.path().join("cache"));
        cache
            .publish_complete_with_origin(
                "main",
                &fs::read(metadata.join("repomd.xml")).expect("repomd"),
                &fs::read(metadata.join("primary.xml.zst")).expect("primary"),
                &fs::read(metadata.join("filelists.xml.zst")).expect("filelists"),
                Some("https://mirror.example/repo/repodata/repomd.xml"),
            )
            .expect("verified fixture generation");
        let generation = cache
            .open_current_verified_complete_generation("main")
            .expect("generation");
        let planning_root = directory.path().join("planning");
        let owner = getuid().as_raw();
        let planning =
            TrustedDirectory::open(&planning_root, owner, true, 0o700).expect("planning root");
        let descriptor = build(&generation, Some(&planning)).expect("file-provides index");
        let manifest_bytes = descriptor
            .decode_verified(Some((&planning_root, owner)))
            .expect("index manifest");
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes).expect("manifest JSON");
        let target = Sha256::digest(b"/usr/share/dnfast/provided");
        let bucket_index = usize::from(target[0]);
        let bucket = &manifest.buckets[bucket_index];
        let shard = &manifest.shards[usize::from(bucket.shard)];
        let bytes =
            crate::snapshot_store::read_blob(&planning_root, owner, &shard.sha256, shard.size)
                .expect("provider shard");
        assert_eq!(
            lookup_bucket(
                bucket_slice(&bytes, bucket).expect("provider bucket"),
                bucket_index,
                manifest.package_count,
                &target
            )
            .expect("provider lookup"),
            [8, 9]
        );

        let bucket_path = planning_root.join("blobs/sha256").join(&shard.sha256);
        let mut corrupted = bytes;
        corrupted[0] ^= 1;
        fs::write(&bucket_path, corrupted).expect("tamper bucket");
        assert!(read_shard_from_storage(&planning_root, owner, shard).is_err());
    }

    /// Read-only, opt-in Fedora-scale memory gate. It deliberately writes no
    /// cache or planning state; anonymous spools disappear when the process
    /// exits. Run as root with DNFAST_FILE_PROVIDES_BENCH_REPO=fedora.
    #[test]
    #[ignore = "requires an explicitly selected system cache generation"]
    fn system_generation_memory_gate() {
        let repository = std::env::var("DNFAST_FILE_PROVIDES_BENCH_REPO")
            .expect("DNFAST_FILE_PROVIDES_BENCH_REPO must name one repository");
        let cache = dnfast_cache::Cache::new("/var/cache/dnfast");
        let generation = cache
            .open_current_verified_complete_generation(&repository)
            .expect("verified system generation");
        let descriptor = build(&generation, None).expect("bounded file-provides rebuild");
        eprintln!(
            "dnfast-file-provides-gate repository={repository} generation={} manifest={} size={}",
            generation.digest(),
            descriptor.sha256,
            descriptor.size
        );
    }

    fn read_shard_from_storage(
        planning_root: &Path,
        owner: u32,
        shard: &Shard,
    ) -> Result<Vec<u8>, PlanningError> {
        let descriptor = PlanningBytes {
            sha256: shard.sha256.clone(),
            size: shard.size,
            base64: String::new(),
        };
        descriptor.decode_verified(Some((planning_root, owner)))
    }
}
