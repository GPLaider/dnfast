use dnfast_cache::{Cache, RepomdAuthentication, SelectedOrigin};
use dnfast_metadata::parse_repomd_records;
use sha2::{Digest, Sha256};

use crate::{
    RefreshError, RefreshOutcome, Source, Transport,
    metalink::{MAX_METALINK_BYTES, MAX_REPOMD_BYTES, parse_metalink},
    mirrorlist,
    openpgp::{MetadataTrust, verify_repomd},
    repo_lock::RepositoryLock,
    url_policy::validate_https,
};

pub struct Refresher<'a, T> {
    transport: T,
    cache: &'a Cache,
}

impl<'a, T: Transport> Refresher<'a, T> {
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
                self.finish_generation(repository, &url, bytes, metadata_trust)
            }
            Source::Metalink(url) => {
                validate_https(&url)?;
                let metalink = self.transport.get(&url, MAX_METALINK_BYTES)?;
                let metalink = parse_metalink(&metalink)?;
                let mut last_error = None;
                for resource in metalink.resources {
                    let bytes = match self.transport.get(&resource.url, MAX_REPOMD_BYTES) {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            last_error = Some(error);
                            continue;
                        }
                    };
                    if bytes.len() as u64 == metalink.size
                        && hex::encode(Sha256::digest(&bytes)) == metalink.sha256
                    {
                        match self.finish_generation(
                            repository,
                            &resource.url,
                            bytes,
                            metadata_trust,
                        ) {
                            Ok(outcome) => return Ok(outcome),
                            Err(error) => last_error = Some(error),
                        }
                    }
                }
                Err(last_error.unwrap_or_else(|| {
                    RefreshError::Metalink("all mirrors failed verification".into())
                }))
            }
            Source::Mirrorlist(url) => {
                validate_https(&url)?;
                let list = self.transport.get(&url, MAX_METALINK_BYTES)?;
                let mut last_error = None;
                for base in mirrorlist::parse(&list)? {
                    let repomd_url = format!("{base}/repodata/repomd.xml");
                    match self
                        .transport
                        .get(&repomd_url, MAX_REPOMD_BYTES)
                        .and_then(|bytes| {
                            self.finish_generation(repository, &repomd_url, bytes, metadata_trust)
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
        repomd: Vec<u8>,
        metadata_trust: Option<&MetadataTrust>,
    ) -> Result<RefreshOutcome, RefreshError> {
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
        let primary_url = origin
            .artifact_url(&records.primary.href)
            .map_err(|error| RefreshError::Policy(error.to_string()))?;
        let primary = self.transport.get(&primary_url, records.primary.size)?;
        let filelists_url = origin
            .artifact_url(&records.filelists.href)
            .map_err(|error| RefreshError::Policy(error.to_string()))?;
        let filelists = self.transport.get(&filelists_url, records.filelists.size)?;
        let snapshot = self
            .cache
            .publish_complete_with_origin_and_authentication(
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
}
