use std::{os::{fd::AsRawFd, unix::fs::FileExt}, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

use dnfast_cache::CachedArtifact;
use dnfast_core::{RepoTrustPolicy, SigningSubkeyRule};
use thiserror::Error;
use sha2::{Digest, Sha256};

use crate::{KeyringInstalled, NativeError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedPackage {
    pub name: String,
    pub epoch: u64,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub vendor: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedArtifact {
    pub package: ExpectedPackage,
    pub primary_fingerprint: String,
    pub signing_fingerprint: String,
    pub artifact_sha256: String,
    pub artifact_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedStagedKey {
    pub bundle_path: String,
    pub certificate: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum TrustError {
    #[error("repository key bundle is untrusted: {0}")]
    Bundle(String),
    #[error("repository key bundle digest changed")]
    BundleDigestMismatch,
    #[error("trust policy verification time differs from the current verification window")]
    VerificationTimeMismatch,
    #[error("RPM signer is not authorized by repository policy")]
    UnauthorizedSigner,
    #[error("RPM header NEVRA differs from metadata and plan")]
    NevraMismatch,
    #[error("RPM header Vendor differs from rpm-md and plan")]
    VendorMismatch,
    #[error("primary-only policy rejected a signing subkey")]
    SigningSubkeyRejected,
    #[error(transparent)]
    Native(#[from] NativeError),
}

impl KeyringInstalled {
    pub fn from_verified_staged_bundle(
        policy: &RepoTrustPolicy,
        repository: &str,
        keys: &[VerifiedStagedKey],
    ) -> Result<Self, TrustError> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|error| TrustError::Bundle(error.to_string()))?.as_secs();
        validate_staged_bundle(policy, repository, keys, now)?;
        let certificates = keys.iter().map(|key| key.certificate.as_slice()).collect::<Vec<_>>();
        let native = dnfast_native_sys::Keyring::open(&certificates).map_err(NativeError::from)?;
        Ok(Self { native, allowed_primary_fingerprints: policy.allowed_primary_fingerprints().to_vec() })
    }

    pub fn from_verified_staged_bundles(
        bundles: &[(&RepoTrustPolicy, &str, &[VerifiedStagedKey])],
    ) -> Result<Self, TrustError> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|error| TrustError::Bundle(error.to_string()))?.as_secs();
        let mut certificates = Vec::new();
        let mut allowed_primary_fingerprints = Vec::new();
        for (policy, repository, keys) in bundles {
            validate_staged_bundle(policy, repository, keys, now)?;
            certificates.extend(keys.iter().map(|key| key.certificate.as_slice()));
            allowed_primary_fingerprints.extend_from_slice(policy.allowed_primary_fingerprints());
        }
        if certificates.is_empty() { return Err(TrustError::Bundle("no staged repository keys".into())); }
        let native = dnfast_native_sys::Keyring::open(&certificates).map_err(NativeError::from)?;
        Ok(Self { native, allowed_primary_fingerprints })
    }

    pub fn from_repository(
        policy: &RepoTrustPolicy,
        repository: &str,
        key_paths: &[PathBuf],
    ) -> Result<Self, TrustError> {
        if repository != policy.repo_id() {
            return Err(TrustError::Bundle("repository id differs from trust policy".into()));
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|error| TrustError::Bundle(error.to_string()))?.as_secs();
        if now.abs_diff(policy.valid_at_unix()) > 300 {
            return Err(TrustError::VerificationTimeMismatch);
        }
        let bundle = dnfast_repo::key_bundle_digest(repository, key_paths)
            .map_err(|error| TrustError::Bundle(error.to_string()))?;
        let digest = hex::encode(bundle.digest);
        if digest != policy.key_bundle_sha256().as_str() {
            return Err(TrustError::BundleDigestMismatch);
        }
        let certificates = bundle.certificates.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let native = dnfast_native_sys::Keyring::open(&certificates)
            .map_err(NativeError::from)?;
        Ok(Self {
            native,
            allowed_primary_fingerprints: policy.allowed_primary_fingerprints().to_vec(),
        })
    }

    pub fn verify_artifact(
        &self,
        artifact: &CachedArtifact,
        expected: &ExpectedPackage,
        subkey_rule: SigningSubkeyRule,
    ) -> Result<VerifiedArtifact, TrustError> {
        let verified = self.native.verify_fd(artifact.file().as_raw_fd())
            .map_err(NativeError::from)?;
        let actual = ExpectedPackage {
            name: verified.name,
            epoch: verified.epoch.parse().map_err(|_| TrustError::NevraMismatch)?,
            version: verified.version,
            release: verified.release,
            arch: verified.arch,
            vendor: verified.vendor,
        };
        authorize(
            &self.allowed_primary_fingerprints,
            &verified.primary_fingerprint,
            &verified.signing_fingerprint,
            subkey_rule,
            &actual,
            expected,
        )?;
        let file = artifact.file();
        let artifact_size = file.metadata().map_err(|error| TrustError::Bundle(error.to_string()))?.len();
        let mut digest = Sha256::new();
        let mut offset = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        while offset < artifact_size {
            let count = file.read_at(&mut buffer, offset).map_err(|error| TrustError::Bundle(error.to_string()))?;
            if count == 0 { return Err(TrustError::Bundle("retained artifact truncated".into())); }
            digest.update(&buffer[..count]);
            offset = offset.checked_add(u64::try_from(count).map_err(|error| TrustError::Bundle(error.to_string()))?)
                .ok_or_else(|| TrustError::Bundle("retained artifact size overflow".into()))?;
        }
        Ok(VerifiedArtifact { package: actual, primary_fingerprint: verified.primary_fingerprint,
            signing_fingerprint: verified.signing_fingerprint, artifact_sha256: hex::encode(digest.finalize()), artifact_size })
    }
}

fn validate_staged_bundle(policy: &RepoTrustPolicy, repository: &str, keys: &[VerifiedStagedKey], now: u64) -> Result<(), TrustError> {
    if repository != policy.repo_id() { return Err(TrustError::Bundle("repository id differs from trust policy".into())); }
    if now.abs_diff(policy.valid_at_unix()) > 300 { return Err(TrustError::VerificationTimeMismatch); }
    let mut digest = Sha256::new();
    digest.update(b"dnfast-key-bundle-v1");
    let mut paths = std::collections::BTreeSet::new();
    for key in keys {
        if !paths.insert(&key.bundle_path) { return Err(TrustError::Bundle("duplicate staged key path".into())); }
        digest.update(u64::try_from(key.bundle_path.len()).map_err(|error| TrustError::Bundle(error.to_string()))?.to_be_bytes());
        digest.update(key.bundle_path.as_bytes());
        digest.update(u64::try_from(key.certificate.len()).map_err(|error| TrustError::Bundle(error.to_string()))?.to_be_bytes());
        digest.update(&key.certificate);
    }
    if hex::encode(digest.finalize()) == policy.key_bundle_sha256().as_str() { Ok(()) }
    else { Err(TrustError::BundleDigestMismatch) }
}

fn authorize(
    allowed: &[String],
    primary: &str,
    signing: &str,
    rule: SigningSubkeyRule,
    actual: &ExpectedPackage,
    expected: &ExpectedPackage,
) -> Result<(), TrustError> {
    if !allowed.iter().any(|item| item == primary) {
        return Err(TrustError::UnauthorizedSigner);
    }
    if rule == SigningSubkeyRule::PrimaryOnly && signing != primary {
        return Err(TrustError::SigningSubkeyRejected);
    }
    if actual.name != expected.name || actual.epoch != expected.epoch || actual.version != expected.version
        || actual.release != expected.release || actual.arch != expected.arch { return Err(TrustError::NevraMismatch); }
    if actual.vendor != expected.vendor && !(expected.vendor == "unknown" && actual.vendor.is_empty()) {
        return Err(TrustError::VendorMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package() -> ExpectedPackage {
        ExpectedPackage { name: "dnfast-app".into(), epoch: 0, version: "1.0".into(), release: "1".into(), arch: "noarch".into(), vendor: "Vendor".into() }
    }

    #[test]
    fn unrelated_cryptographically_valid_signer_is_rejected() {
        let actual = package();
        let result = authorize(&["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()], "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", SigningSubkeyRule::AuthorizedSubkeys, &actual, &actual);
        assert!(matches!(result, Err(TrustError::UnauthorizedSigner)));
    }

    #[test]
    fn exact_nevra_and_authorized_subkey_are_required() {
        let expected = package();
        assert!(authorize(&["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", SigningSubkeyRule::AuthorizedSubkeys, &expected, &expected).is_ok());
        let mut mismatch = package();
        mismatch.release = "2".into();
        assert!(matches!(authorize(&["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", SigningSubkeyRule::AuthorizedSubkeys, &mismatch, &expected), Err(TrustError::NevraMismatch)));
        assert!(matches!(authorize(&["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", SigningSubkeyRule::PrimaryOnly, &expected, &expected), Err(TrustError::SigningSubkeyRejected)));
    }

    #[test]
    fn signed_package_with_vendor_different_from_metadata_is_rejected() {
        // Given: a signature from an authorized repository key and identical NEVRA.
        let expected = ExpectedPackage { vendor: "Metadata Vendor".into(), ..package() };
        let actual = ExpectedPackage { vendor: "RPM Header Vendor".into(), ..package() };

        // When: the native verifier compares the signed RPM header with rpm-md.
        let result = authorize(&["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", SigningSubkeyRule::AuthorizedSubkeys, &actual, &expected);

        // Then: a valid signature cannot substitute its Vendor provenance.
        assert!(matches!(result, Err(TrustError::VendorMismatch)));
    }

    #[test]
    fn unknown_metadata_vendor_permits_only_an_absent_rpm_header_vendor() {
        // Given: rpm-md's canonical `unknown` marker for an absent Vendor header.
        let expected = ExpectedPackage { vendor: "unknown".into(), ..package() };
        let actual = ExpectedPackage { vendor: String::new(), ..package() };

        // When: the trusted RPM header is compared with that canonical marker.
        let result = authorize(&["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", SigningSubkeyRule::AuthorizedSubkeys, &actual, &expected);

        // Then: the only permitted unknown case is an actually absent header field.
        assert!(result.is_ok());
    }
}
