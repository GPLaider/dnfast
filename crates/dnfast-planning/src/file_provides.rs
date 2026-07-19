use std::{
    collections::HashMap,
    io::{BufWriter, Read, Seek, Write},
    sync::{OnceLock, mpsc},
    time::Instant,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    PlanningBytes, PlanningError, PlanningRepository, PlanningSnapshot, fs::TrustedDirectory,
};

const INDEX_SCHEMA_VERSION: u32 = 4;
const BUCKET_COUNT: usize = 256;
// One independently authenticated blob per leading digest byte keeps an
// absolute-file lookup from rereading unrelated file-provides evidence.
const SHARD_COUNT: usize = 256;
const BUCKETS_PER_SHARD: usize = BUCKET_COUNT / SHARD_COUNT;
const HEADER_SIZE: usize = 24;
const FULL_DIGEST_SIZE: usize = 32;
const INDEX_DIGEST_SIZE: usize = 16;
const SPOOL_RECORD_SIZE: usize = FULL_DIGEST_SIZE + std::mem::size_of::<u32>();
const RECORD_SIZE: usize = INDEX_DIGEST_SIZE + std::mem::size_of::<u32>();
const MAX_SHARD_BYTES: u64 = 64 * 1024 * 1024;
const SPOOL_BUFFER_BYTES: usize = 32 * 1024;
const HASH_WORKERS: usize = 2;
const HASH_BATCH_PATHS: usize = 8192;
const HASH_BATCH_BYTES: usize = 512 * 1024;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uncompressed_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    compression: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bucket {
    shard: u8,
    offset: u64,
    sha256: String,
    size: u64,
}

struct PathBatch {
    bytes: Vec<u8>,
    records: Vec<(u32, u32, u32)>,
}

impl PathBatch {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(HASH_BATCH_BYTES),
            records: Vec::with_capacity(HASH_BATCH_PATHS),
        }
    }

    fn push(&mut self, ordinal: u32, path: &str) -> Result<(), dnfast_metadata::MetadataError> {
        let offset = u32::try_from(self.bytes.len()).map_err(|error| {
            dnfast_metadata::MetadataError::Io(format!("file path batch offset: {error}"))
        })?;
        let length = u32::try_from(path.len()).map_err(|error| {
            dnfast_metadata::MetadataError::Io(format!("file path batch length: {error}"))
        })?;
        self.bytes.extend_from_slice(path.as_bytes());
        self.records.push((ordinal, offset, length));
        Ok(())
    }

    fn is_full(&self) -> bool {
        self.records.len() >= HASH_BATCH_PATHS || self.bytes.len() >= HASH_BATCH_BYTES
    }

    fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

fn spool_buckets() -> Result<Vec<BufWriter<std::fs::File>>, PlanningError> {
    (0..BUCKET_COUNT)
        .map(|_| {
            tempfile::tempfile()
                .map(|file| BufWriter::with_capacity(SPOOL_BUFFER_BYTES, file))
                .map_err(io)
        })
        .collect()
}

fn hash_path_batches(
    receiver: mpsc::Receiver<PathBatch>,
    mut buckets: Vec<BufWriter<std::fs::File>>,
) -> Result<Vec<BufWriter<std::fs::File>>, PlanningError> {
    for batch in receiver {
        for (ordinal, offset, length) in batch.records {
            let start = offset as usize;
            let end = start
                .checked_add(length as usize)
                .ok_or_else(|| PlanningError::Input("file path batch overflow".into()))?;
            let path = batch
                .bytes
                .get(start..end)
                .ok_or_else(|| PlanningError::Input("file path batch range differs".into()))?;
            let path_digest = Sha256::digest(path);
            let mut record = [0_u8; SPOOL_RECORD_SIZE];
            record[..FULL_DIGEST_SIZE].copy_from_slice(&path_digest);
            record[FULL_DIGEST_SIZE..].copy_from_slice(&ordinal.to_be_bytes());
            buckets[usize::from(path_digest[0])]
                .write_all(&record)
                .map_err(io)?;
        }
    }
    for spool in &mut buckets {
        spool.flush().map_err(io)?;
    }
    Ok(buckets)
}

pub(crate) fn build(
    generation: &dnfast_cache::VerifiedCompleteGeneration,
    blob_store: Option<&TrustedDirectory>,
) -> Result<PlanningBytes, PlanningError> {
    trace_build(generation.repository(), "begin");
    let records =
        dnfast_metadata::parse_repomd_records(generation.repomd().bytes()).map_err(metadata)?;
    let primary =
        dnfast_metadata::validate_primary_record(generation.primary().bytes(), &records.primary)
            .map_err(metadata)?;
    let package_count = u32::try_from(primary.identities.len())
        .map_err(|error| PlanningError::Input(error.to_string()))?;
    trace_build(generation.repository(), "primary-validated");
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
    // Fedora filelists contain millions of paths. Two bounded hash workers
    // consume compact path arenas while the XML/checksum reader advances;
    // each owns private anonymous spools, so no locks or per-path syscalls are
    // introduced. The final sort below makes worker scheduling irrelevant to
    // the authenticated output.
    let worker_buckets = (0..HASH_WORKERS)
        .map(|_| spool_buckets())
        .collect::<Result<Vec<_>, _>>()?;
    let buckets_by_worker = std::thread::scope(|scope| {
        let mut senders = Vec::with_capacity(HASH_WORKERS);
        let mut handles = Vec::with_capacity(HASH_WORKERS);
        for buckets in worker_buckets {
            let (sender, receiver) = mpsc::sync_channel(4);
            senders.push(sender);
            handles.push(scope.spawn(move || hash_path_batches(receiver, buckets)));
        }
        let mut batch = PathBatch::new();
        let mut next_worker = 0_usize;
        // RPM filelists groups every path for one package contiguously. Resolve
        // its primary ordinal once at the package boundary rather than once
        // for every path.
        let mut current_package_id = String::new();
        let mut current_ordinal = None;
        let mut parsed = dnfast_metadata::visit_filelists_record_identities(
            generation.filelists().bytes(),
            &records.filelists,
            &primary.identities,
            |package_id, path| {
                if current_package_id != package_id {
                    current_package_id.clear();
                    current_package_id.push_str(package_id);
                    current_ordinal = Some(ordinals.get(package_id).copied().ok_or_else(|| {
                        dnfast_metadata::MetadataError::Xml(
                            "filelists package is absent from primary".into(),
                        )
                    })?);
                }
                batch.push(current_ordinal.expect("package ordinal established"), path)?;
                if batch.is_full() {
                    let ready = std::mem::replace(&mut batch, PathBatch::new());
                    senders[next_worker].send(ready).map_err(|_| {
                        dnfast_metadata::MetadataError::Io("file path hash worker stopped".into())
                    })?;
                    next_worker = (next_worker + 1) % HASH_WORKERS;
                }
                Ok(())
            },
        );
        if parsed.is_ok() && !batch.is_empty() {
            parsed = senders[next_worker].send(batch).map_err(|_| {
                dnfast_metadata::MetadataError::Io("file path hash worker stopped".into())
            });
        }
        drop(senders);
        let mut completed = Vec::with_capacity(HASH_WORKERS);
        let mut worker_error = None;
        for handle in handles {
            match handle.join() {
                Ok(Ok(buckets)) => completed.push(buckets),
                Ok(Err(error)) => {
                    worker_error.get_or_insert(error);
                }
                Err(_) => {
                    worker_error.get_or_insert_with(|| {
                        PlanningError::Io("file path hash worker panicked".into())
                    });
                }
            };
        }
        parsed.map_err(metadata)?;
        if let Some(error) = worker_error {
            return Err(error);
        }
        Ok(completed)
    })?;
    trace_build(generation.repository(), "filelists-spooled");

    let mut descriptors = Vec::with_capacity(BUCKET_COUNT);
    let mut shards = Vec::with_capacity(SHARD_COUNT);
    let mut record_count = 0_u64;
    let mut bucket_iters = buckets_by_worker
        .into_iter()
        .map(Vec::into_iter)
        .collect::<Vec<_>>();
    for shard_index in 0..SHARD_COUNT {
        let mut shard = Vec::new();
        for index in shard_index * BUCKETS_PER_SHARD..(shard_index + 1) * BUCKETS_PER_SHARD {
            let mut raw = Vec::new();
            for buckets in &mut bucket_iters {
                let mut buffered = buckets.next().ok_or_else(|| {
                    PlanningError::Input("file-provides spool count differs".into())
                })?;
                let spool = buffered.get_mut();
                spool.rewind().map_err(io)?;
                let length = usize::try_from(spool.metadata().map_err(io)?.len())
                    .map_err(|error| PlanningError::Input(error.to_string()))?;
                if length % SPOOL_RECORD_SIZE != 0 {
                    return Err(PlanningError::Input(
                        "file-provides spool has a partial record".into(),
                    ));
                }
                raw.try_reserve_exact(length)
                    .map_err(|error| PlanningError::Io(error.to_string()))?;
                spool.read_to_end(&mut raw).map_err(io)?;
            }
            let mut records = raw
                .chunks_exact(SPOOL_RECORD_SIZE)
                .map(|value| {
                    let mut record = [0_u8; SPOOL_RECORD_SIZE];
                    record.copy_from_slice(value);
                    record
                })
                .collect::<Vec<_>>();
            drop(raw);
            records.sort_unstable();
            records.dedup();
            if has_truncated_digest_collision(&records) {
                return Err(PlanningError::Input(
                    "file-provides truncated digest collision".into(),
                ));
            }
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
        let uncompressed_size = shard.len() as u64;
        if uncompressed_size > MAX_SHARD_BYTES {
            return Err(PlanningError::Input(
                "file-provides shard exceeds the decoded size limit".into(),
            ));
        }
        let shard = zstd::stream::encode_all(shard.as_slice(), 1).map_err(io)?;
        let sha256 = format!("{:x}", Sha256::digest(&shard));
        if let Some(store) = blob_store {
            crate::snapshot_store::publish_blob_deferred(store, &sha256, &shard)?;
        }
        shards.push(Shard {
            sha256,
            size: shard.len() as u64,
            uncompressed_size: Some(uncompressed_size),
            compression: Some("zstd".into()),
        });
    }
    trace_build(generation.repository(), "shards-staged");
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
        crate::snapshot_store::publish_blob_deferred(store, &sha256, &bytes)?;
    }
    Ok(PlanningBytes {
        sha256,
        size: bytes.len() as u64,
        base64: String::new(),
    })
}

fn trace_build(repository: &str, phase: &str) {
    if std::env::var_os("DNFAST_REFRESH_TRACE").is_none() {
        return;
    }
    static START: OnceLock<Instant> = OnceLock::new();
    let elapsed = START.get_or_init(Instant::now).elapsed().as_millis();
    eprintln!("dnfast-refresh-trace phase=file-provides:{repository}:{phase} elapsed_ms={elapsed}");
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
        validate_readable_manifest(
            &manifest,
            &repository.primary.sha256,
            &repository.filelists.sha256,
        )?;
        let digest = Sha256::digest(absolute_path.as_bytes());
        let bucket_index = usize::from(digest[0]);
        let bucket = &manifest.buckets[bucket_index];
        let shard = &manifest.shards[usize::from(bucket.shard)];
        let bytes = read_shard(self, &manifest, shard)?;
        let bucket_bytes = bucket_slice(&bytes, bucket)?;
        lookup_bucket(
            bucket_bytes,
            manifest.schema_version,
            bucket_index,
            manifest.package_count,
            &digest,
        )
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
        3 | INDEX_SCHEMA_VERSION => SHARD_COUNT,
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

fn encode_bucket(
    index: usize,
    records: &[[u8; SPOOL_RECORD_SIZE]],
) -> Result<Vec<u8>, PlanningError> {
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
        bytes.extend_from_slice(&record[..INDEX_DIGEST_SIZE]);
        bytes.extend_from_slice(&record[FULL_DIGEST_SIZE..]);
    }
    Ok(bytes)
}

fn read_shard(
    snapshot: &PlanningSnapshot,
    manifest: &Manifest,
    shard: &Shard,
) -> Result<Vec<u8>, PlanningError> {
    let descriptor = PlanningBytes {
        sha256: shard.sha256.clone(),
        size: shard.size,
        base64: String::new(),
    };
    let bytes = descriptor.decode_verified(snapshot.storage())?;
    decode_shard(manifest.schema_version, shard, &bytes)
}

fn decode_shard(
    schema_version: u32,
    shard: &Shard,
    bytes: &[u8],
) -> Result<Vec<u8>, PlanningError> {
    if schema_version < INDEX_SCHEMA_VERSION {
        return Ok(bytes.to_vec());
    }
    let expected = shard.uncompressed_size.ok_or_else(|| {
        PlanningError::Input("file-provides compressed shard size is absent".into())
    })?;
    if shard.compression.as_deref() != Some("zstd") || expected > MAX_SHARD_BYTES {
        return Err(PlanningError::Input(
            "file-provides compressed shard descriptor is invalid".into(),
        ));
    }
    let capacity =
        usize::try_from(expected).map_err(|error| PlanningError::Input(error.to_string()))?;
    let limit = expected
        .checked_add(1)
        .ok_or_else(|| PlanningError::Input("file-provides shard size overflow".into()))?;
    let decoder = zstd::stream::read::Decoder::new(bytes).map_err(io)?;
    let mut decoded = Vec::with_capacity(capacity);
    decoder.take(limit).read_to_end(&mut decoded).map_err(io)?;
    if decoded.len() as u64 != expected {
        return Err(PlanningError::Input(
            "file-provides decoded shard size differs".into(),
        ));
    }
    Ok(decoded)
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
    schema_version: u32,
    bucket_index: usize,
    package_count: u32,
    target: &[u8],
) -> Result<Vec<u32>, PlanningError> {
    let digest_size = digest_size_for_schema(schema_version)?;
    let record_size = digest_size + std::mem::size_of::<u32>();
    let records = validate_bucket(bytes, schema_version, bucket_index, package_count)?;
    let mut left = 0;
    let mut right = records;
    while left < right {
        let middle = left + (right - left) / 2;
        let offset = HEADER_SIZE + middle * record_size;
        if bytes[offset..offset + digest_size] < target[..digest_size] {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    let mut providers = Vec::new();
    while left < records {
        let offset = HEADER_SIZE + left * record_size;
        if bytes[offset..offset + digest_size] != target[..digest_size] {
            break;
        }
        providers.push(u32::from_be_bytes(
            bytes[offset + digest_size..offset + record_size]
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
    schema_version: u32,
    bucket_index: usize,
    package_count: u32,
) -> Result<usize, PlanningError> {
    let digest_size = digest_size_for_schema(schema_version)?;
    let record_size = digest_size + std::mem::size_of::<u32>();
    if bytes.len() < HEADER_SIZE
        || &bytes[..8] != MAGIC
        || u32::from_be_bytes(bytes[8..12].try_into().expect("fixed header")) != schema_version
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
        .checked_mul(record_size)
        .and_then(|size| size.checked_add(HEADER_SIZE))
        .ok_or_else(|| PlanningError::Input("file-provides bucket size overflow".into()))?;
    if bytes.len() != expected {
        return Err(PlanningError::Input(
            "file-provides bucket size differs from header".into(),
        ));
    }
    let mut previous = None;
    for record in bytes[HEADER_SIZE..].chunks_exact(record_size) {
        if usize::from(record[0]) != bucket_index
            || u32::from_be_bytes(
                record[digest_size..record_size]
                    .try_into()
                    .expect("fixed record"),
            ) >= package_count
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

fn validate_readable_manifest(
    manifest: &Manifest,
    primary_sha256: &str,
    filelists_sha256: &str,
) -> Result<(), PlanningError> {
    let shard_count = match manifest.schema_version {
        2 => 16,
        3 | INDEX_SCHEMA_VERSION => SHARD_COUNT,
        _ => {
            return Err(PlanningError::Input(
                "file-provides manifest schema is unsupported".into(),
            ));
        }
    };
    validate_manifest_layout(
        manifest,
        primary_sha256,
        filelists_sha256,
        manifest.schema_version,
        shard_count,
    )
}

fn digest_size_for_schema(schema_version: u32) -> Result<usize, PlanningError> {
    match schema_version {
        2 | 3 => Ok(FULL_DIGEST_SIZE),
        INDEX_SCHEMA_VERSION => Ok(INDEX_DIGEST_SIZE),
        _ => Err(PlanningError::Input(
            "file-provides bucket schema is unsupported".into(),
        )),
    }
}

fn has_truncated_digest_collision(records: &[[u8; SPOOL_RECORD_SIZE]]) -> bool {
    records.windows(2).any(|pair| {
        pair[0][..INDEX_DIGEST_SIZE] == pair[1][..INDEX_DIGEST_SIZE]
            && pair[0][..FULL_DIGEST_SIZE] != pair[1][..FULL_DIGEST_SIZE]
    })
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
    let record_size = if schema_version < INDEX_SCHEMA_VERSION {
        SPOOL_RECORD_SIZE
    } else {
        RECORD_SIZE
    };
    if manifest.schema_version != schema_version
        || manifest.primary_sha256 != primary_sha256
        || manifest.filelists_sha256 != filelists_sha256
        || manifest.shards.len() != shard_count
        || manifest.buckets.len() != BUCKET_COUNT
        || manifest.package_count == 0
        || manifest.shards.iter().any(|shard| {
            let layout_size = if schema_version < INDEX_SCHEMA_VERSION {
                shard.size
            } else {
                shard.uncompressed_size.unwrap_or(0)
            };
            layout_size < (HEADER_SIZE * buckets_per_shard) as u64
                || layout_size > MAX_SHARD_BYTES
                || !valid_sha256(&shard.sha256)
                || (schema_version < INDEX_SCHEMA_VERSION
                    && (shard.uncompressed_size.is_some() || shard.compression.is_some()))
                || (schema_version == INDEX_SCHEMA_VERSION
                    && (shard.size == 0 || shard.compression.as_deref() != Some("zstd")))
        })
        || manifest.buckets.iter().any(|bucket| {
            usize::from(bucket.shard) >= shard_count
                || bucket.size < HEADER_SIZE as u64
                || (bucket.size - HEADER_SIZE as u64) % record_size as u64 != 0
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
                .checked_add((bucket.size - HEADER_SIZE as u64) / record_size as u64)
                .ok_or_else(|| {
                    PlanningError::Input("file-provides record count overflow".into())
                })?;
        }
        let shard_layout_size = if schema_version < INDEX_SCHEMA_VERSION {
            manifest.shards[shard_index].size
        } else {
            manifest.shards[shard_index].uncompressed_size.unwrap_or(0)
        };
        if offset != shard_layout_size {
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
            let mut record = [0_u8; SPOOL_RECORD_SIZE];
            record[..FULL_DIGEST_SIZE].copy_from_slice(&digest);
            record[FULL_DIGEST_SIZE..].copy_from_slice(&ordinal.to_be_bytes());
            records.push(record);
        }
        records.sort_unstable();
        let bytes = encode_bucket(bucket, &records).expect("bucket");
        assert_eq!(
            lookup_bucket(&bytes, INDEX_SCHEMA_VERSION, bucket, 10, &digest).expect("lookup"),
            [2, 9]
        );
        assert!(validate_bucket(&bytes, INDEX_SCHEMA_VERSION, (bucket + 1) % 256, 10).is_err());
    }

    #[test]
    fn truncated_digest_collision_is_fail_closed() {
        let mut left = [0_u8; SPOOL_RECORD_SIZE];
        let mut right = [0_u8; SPOOL_RECORD_SIZE];
        left[..FULL_DIGEST_SIZE].fill(7);
        right[..INDEX_DIGEST_SIZE].fill(7);
        right[INDEX_DIGEST_SIZE..FULL_DIGEST_SIZE].fill(8);
        left[FULL_DIGEST_SIZE..].copy_from_slice(&1_u32.to_be_bytes());
        right[FULL_DIGEST_SIZE..].copy_from_slice(&2_u32.to_be_bytes());
        assert!(has_truncated_digest_collision(&[left, right]));

        right[..FULL_DIGEST_SIZE].copy_from_slice(&left[..FULL_DIGEST_SIZE]);
        assert!(!has_truncated_digest_collision(&[left, right]));
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
        let compressed =
            crate::snapshot_store::read_blob(&planning_root, owner, &shard.sha256, shard.size)
                .expect("provider shard");
        let bytes = decode_shard(manifest.schema_version, shard, &compressed)
            .expect("decode provider shard");
        assert_eq!(
            lookup_bucket(
                bucket_slice(&bytes, bucket).expect("provider bucket"),
                manifest.schema_version,
                bucket_index,
                manifest.package_count,
                &target
            )
            .expect("provider lookup"),
            [8, 9]
        );

        let bucket_path = planning_root.join("blobs/sha256").join(&shard.sha256);
        let mut corrupted = compressed;
        corrupted[0] ^= 1;
        fs::write(&bucket_path, corrupted).expect("tamper bucket");
        assert!(read_shard_from_storage(&planning_root, owner, &manifest, shard).is_err());
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
        manifest: &Manifest,
        shard: &Shard,
    ) -> Result<Vec<u8>, PlanningError> {
        let descriptor = PlanningBytes {
            sha256: shard.sha256.clone(),
            size: shard.size,
            base64: String::new(),
        };
        let bytes = descriptor.decode_verified(Some((planning_root, owner)))?;
        decode_shard(manifest.schema_version, shard, &bytes)
    }
}
