use crate::{
    RefreshError, RefreshOutcome, Source, Transport,
    metalink::{MAX_METALINK_BYTES, MAX_REPOMD_BYTES, parse_metalink},
    mirrorlist,
    openpgp::{MetadataTrust, verify_repomd},
    repo_lock::RepositoryLock,
    url_policy::{validate_https, validate_https_endpoint},
};
use dnfast_cache::{Cache, RepomdAuthentication, SelectedOrigin};
use dnfast_metadata::{AuxiliaryRecord, parse_repomd_records};
use std::sync::Mutex;

// Downloads from independent repositories can overlap, but validating several
// Fedora-scale primary/filelists streams at once multiplies their peak working
// sets and can push a small host into swap. Serializing only the CPU/memory-heavy
// verification/publication phase preserves network concurrency and fail-closed
// publication while bounding memory independently of the enabled repo count.
static METADATA_PUBLICATION_PERMIT: Mutex<()> = Mutex::new(());

pub struct Refresher<'a, T> {
    transport: T,
    cache: &'a Cache,
}

impl<'a, T: Transport + Sync> Refresher<'a, T> {
    pub fn new(transport: T, cache: &'a Cache) -> Self {
        Self { transport, cache }
    }

    pub fn refresh(
        &self,
        repository: &str,
        source: Source,
    ) -> Result<RefreshOutcome, RefreshError> {
        self.refresh_with_metadata_trust(repository, source, None)
    }

    pub fn refresh_with_metadata_trust(
        &self,
        repository: &str,
        source: Source,
        metadata_trust: Option<&MetadataTrust>,
    ) -> Result<RefreshOutcome, RefreshError> {
        let _lock = RepositoryLock::acquire(self.cache.root(), repository)?;
        match source {
            Source::BaseUrl(base) => {
                validate_https(&base)?;
                let base = base.trim_end_matches('/');
                let url = format!("{base}/repodata/repomd.xml");
                let bytes = self.transport.get(&url, MAX_REPOMD_BYTES)?;
                self.finish_generation(repository, &url, true, bytes, metadata_trust)
            }
            Source::Metalink(url) => {
                validate_https_endpoint(&url)?;
                let metalink = self.transport.get(&url, MAX_METALINK_BYTES)?;
                let metalink = parse_metalink(&metalink)?;
                let mut last_error = None;
                let mut last_verification_error = None;
                for resource in &metalink.resources {
                    let bytes = match self.transport.get(&resource.url, MAX_REPOMD_BYTES) {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            last_error = Some(error);
                            continue;
                        }
                    };
                    if metalink.accepts(&bytes) {
                        match self.finish_generation(
                            repository,
                            &resource.url,
                            metalink.max_connections != Some(1),
                            bytes,
                            metadata_trust,
                        ) {
                            Ok(outcome) => return Ok(outcome),
                            Err(error) => {
                                if !matches!(error, RefreshError::Transport(_)) {
                                    last_verification_error = Some(error);
                                } else {
                                    last_error = Some(error);
                                }
                            }
                        }
                    }
                }
                Err(last_verification_error.or(last_error).unwrap_or_else(|| {
                    RefreshError::Metalink("all mirrors failed verification".into())
                }))
            }
            Source::Mirrorlist(url) => {
                validate_https_endpoint(&url)?;
                let list = self.transport.get(&url, MAX_METALINK_BYTES)?;
                let mut last_error = None;
                for base in mirrorlist::parse(&list)? {
                    let repomd_url = format!("{base}/repodata/repomd.xml");
                    match self
                        .transport
                        .get(&repomd_url, MAX_REPOMD_BYTES)
                        .and_then(|bytes| {
                            self.finish_generation(
                                repository,
                                &repomd_url,
                                true,
                                bytes,
                                metadata_trust,
                            )
                        }) {
                        Ok(outcome) => return Ok(outcome),
                        Err(error) => last_error = Some(error),
                    }
                }
                Err(last_error
                    .unwrap_or_else(|| RefreshError::Transport("all mirrors failed".into())))
            }
        }
    }

    fn finish_generation(
        &self,
        repository: &str,
        repomd_url: &str,
        parallel_artifacts: bool,
        repomd: Vec<u8>,
        metadata_trust: Option<&MetadataTrust>,
    ) -> Result<RefreshOutcome, RefreshError> {
        trace_memory(&format!("refresh:{repository}:repomd-received"));
        let authentication = match metadata_trust {
            Some(trust) => {
                let signature_url = format!("{repomd_url}.asc");
                let signature = self.transport.get(&signature_url, 1024 * 1024)?;
                verify_repomd(trust, &signature, &repomd)?
            }
            None => RepomdAuthentication::TransportOnly,
        };
        let records = parse_repomd_records(&repomd)
            .map_err(|error| RefreshError::Metadata(error.to_string()))?;
        let origin = SelectedOrigin::parse(repomd_url)
            .map_err(|error| RefreshError::Policy(error.to_string()))?;
        if let Some(snapshot) = self
            .cache
            .reuse_current_verified_complete(
                repository,
                &repomd,
                origin.repomd_url(),
                authentication.clone(),
            )
            .map_err(|error| RefreshError::Cache(error.to_string()))?
        {
            self.ensure_auxiliary(&origin, records.group.as_ref())?;
            self.ensure_auxiliary(&origin, records.modules.as_ref())?;
            self.ensure_auxiliary(&origin, records.updateinfo.as_ref())?;
            trace_memory(&format!("refresh:{repository}:generation-reused"));
            return Ok(RefreshOutcome {
                digest: snapshot.digest,
                packages: snapshot.packages.len(),
            });
        }
        let primary_url = origin
            .artifact_url(&records.primary.href)
            .map_err(|error| RefreshError::Policy(error.to_string()))?;
        let filelists_url = origin
            .artifact_url(&records.filelists.href)
            .map_err(|error| RefreshError::Policy(error.to_string()))?;
        let (primary, filelists) = if parallel_artifacts {
            std::thread::scope(|scope| {
                let primary =
                    scope.spawn(|| self.transport.get(&primary_url, records.primary.size));
                let filelists = self.transport.get(&filelists_url, records.filelists.size);
                let primary = primary
                    .join()
                    .map_err(|_| RefreshError::Transport("metadata worker panicked".into()))?;
                Ok::<_, RefreshError>((primary?, filelists?))
            })?
        } else {
            // Respect repository service policy.  In particular Fedora metalinks
            // advertise maxconnections=1 and some mirrors reject the second
            // simultaneous request rather than queueing it.
            (
                self.transport.get(&primary_url, records.primary.size)?,
                self.transport.get(&filelists_url, records.filelists.size)?,
            )
        };
        self.ensure_auxiliary(&origin, records.group.as_ref())?;
        self.ensure_auxiliary(&origin, records.modules.as_ref())?;
        self.ensure_auxiliary(&origin, records.updateinfo.as_ref())?;
        trace_memory(&format!("refresh:{repository}:artifacts-received"));
        let _publication_permit = METADATA_PUBLICATION_PERMIT
            .lock()
            .map_err(|_| RefreshError::Cache("metadata publication lock poisoned".into()))?;
        let snapshot = self
            .cache
            .publish_verified_complete_fast(
                repository,
                &repomd,
                &primary,
                &filelists,
                Some(origin.repomd_url()),
                authentication,
            )
            .map_err(|error| RefreshError::Cache(error.to_string()))?;
        Ok(RefreshOutcome {
            digest: snapshot.digest,
            packages: snapshot.packages.len(),
        })
    }

    fn ensure_auxiliary(
        &self,
        origin: &SelectedOrigin,
        record: Option<&AuxiliaryRecord>,
    ) -> Result<(), RefreshError> {
        let Some(record) = record else { return Ok(()) };
        match self.cache.open_auxiliary(record) {
            Ok(_) => return Ok(()),
            Err(dnfast_cache::CacheError::MissingSnapshot(_)) => {}
            Err(error) => return Err(RefreshError::Cache(error.to_string())),
        }
        let url = origin
            .artifact_url(&record.href)
            .map_err(|error| RefreshError::Policy(error.to_string()))?;
        let bytes = self.transport.get(&url, record.size)?;
        self.cache
            .publish_auxiliary(record, &bytes)
            .map_err(|error| RefreshError::Cache(error.to_string()))?;
        Ok(())
    }
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
