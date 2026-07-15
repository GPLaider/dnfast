use std::{
    collections::BTreeSet,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use dnfast_cache::RepomdAuthentication;
use openpgp::{
    Cert, KeyHandle,
    cert::CertParser,
    parse::{
        Parse,
        stream::{DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper},
    },
    policy::StandardPolicy,
};
use sequoia_openpgp as openpgp;
use sha2::{Digest, Sha256};

use crate::RefreshError;

const MAX_CERTIFICATES: usize = 256;
const MAX_CERTIFICATE_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct MetadataTrust {
    certificates: Vec<Cert>,
    allowed_primary_fingerprints: BTreeSet<String>,
    key_bundle_sha256: String,
    valid_at: SystemTime,
}

impl MetadataTrust {
    pub fn new(
        certificate_files: impl IntoIterator<Item = Vec<u8>>,
        allowed_primary_fingerprints: impl IntoIterator<Item = String>,
        key_bundle_sha256: impl Into<String>,
        valid_at_unix: u64,
    ) -> Result<Self, RefreshError> {
        let mut certificates = Vec::new();
        for bytes in certificate_files {
            if bytes.is_empty() || bytes.len() > MAX_CERTIFICATE_BYTES {
                return Err(signature_error(
                    "OpenPGP certificate file is empty or oversized",
                ));
            }
            let parser = CertParser::from_bytes(&bytes)
                .map_err(|error| signature_error(error.to_string()))?;
            for certificate in parser {
                certificates.push(certificate.map_err(|error| signature_error(error.to_string()))?);
                if certificates.len() > MAX_CERTIFICATES {
                    return Err(signature_error("OpenPGP certificate limit exceeds 256"));
                }
            }
        }
        if certificates.is_empty() {
            return Err(signature_error("OpenPGP certificate bundle is empty"));
        }
        let allowed_primary_fingerprints = allowed_primary_fingerprints
            .into_iter()
            .map(|value| value.to_ascii_uppercase())
            .collect::<BTreeSet<_>>();
        if allowed_primary_fingerprints.is_empty()
            || allowed_primary_fingerprints
                .iter()
                .any(|value| !valid_fingerprint(value))
            || !allowed_primary_fingerprints.iter().all(|allowed| {
                certificates
                    .iter()
                    .any(|certificate| certificate.fingerprint().to_hex() == *allowed)
            })
        {
            return Err(signature_error(
                "allowed primary fingerprint is absent or invalid",
            ));
        }
        let key_bundle_sha256 = key_bundle_sha256.into().to_ascii_lowercase();
        if !valid_digest(&key_bundle_sha256) {
            return Err(signature_error("key bundle digest is invalid"));
        }
        let valid_at = UNIX_EPOCH
            .checked_add(Duration::from_secs(valid_at_unix))
            .ok_or_else(|| signature_error("metadata verification time is invalid"))?;
        Ok(Self {
            certificates,
            allowed_primary_fingerprints,
            key_bundle_sha256,
            valid_at,
        })
    }
}

struct Helper {
    certificates: Vec<Cert>,
    allowed_primary_fingerprints: BTreeSet<String>,
    verified: Option<(String, String)>,
}

impl VerificationHelper for Helper {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(self.certificates.clone())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure {
            let MessageLayer::SignatureGroup { results } = layer else {
                continue;
            };
            for result in results {
                let Ok(good) = result else {
                    continue;
                };
                let primary = good.ka.cert().fingerprint().to_hex();
                if self.allowed_primary_fingerprints.contains(&primary) {
                    let signing = good.ka.key().fingerprint().to_hex();
                    self.verified = Some((primary, signing));
                    return Ok(());
                }
            }
        }
        Err(openpgp::Error::InvalidOperation(
            "repomd has no valid signature from an allowed primary certificate".into(),
        )
        .into())
    }
}

pub(crate) fn verify_repomd(
    trust: &MetadataTrust,
    signature: &[u8],
    repomd: &[u8],
) -> Result<RepomdAuthentication, RefreshError> {
    if signature.is_empty() {
        return Err(signature_error("repomd detached signature is empty"));
    }
    let helper = Helper {
        certificates: trust.certificates.clone(),
        allowed_primary_fingerprints: trust.allowed_primary_fingerprints.clone(),
        verified: None,
    };
    let policy = StandardPolicy::new();
    let mut verifier = DetachedVerifierBuilder::from_bytes(signature)
        .map_err(|error| signature_error(error.to_string()))?
        .with_policy(&policy, trust.valid_at, helper)
        .map_err(|error| signature_error(error.to_string()))?;
    verifier
        .verify_bytes(repomd)
        .map_err(|error| signature_error(error.to_string()))?;
    let helper = verifier.into_helper();
    let (primary, signing) = helper.verified.ok_or_else(|| {
        signature_error("repomd signature verification produced no authorized signer")
    })?;
    RepomdAuthentication::openpgp(
        primary,
        signing,
        &trust.key_bundle_sha256,
        hex::encode(Sha256::digest(signature)),
    )
    .map_err(|error| signature_error(error.to_string()))
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn signature_error(message: impl Into<String>) -> RefreshError {
    RefreshError::Signature(message.into())
}

#[cfg(test)]
pub(crate) fn signed_fixture(data: &[u8]) -> (Vec<u8>, String, Vec<u8>, u64) {
    use openpgp::{
        cert::prelude::CertBuilder,
        serialize::{
            Marshal,
            stream::{Message, Signer},
        },
    };
    use std::io::Write;

    let policy = StandardPolicy::new();
    let (certificate, _) = CertBuilder::new()
        .add_userid("dnfast-test@example.invalid")
        .add_signing_subkey()
        .generate()
        .expect("test certificate");
    let keypair = certificate
        .keys()
        .unencrypted_secret()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .next()
        .expect("test signing key")
        .key()
        .clone()
        .into_keypair()
        .expect("test keypair");
    let mut signature = Vec::new();
    let message = Message::new(&mut signature);
    let mut signer = Signer::new(message, keypair)
        .expect("test signer")
        .detached()
        .build()
        .expect("detached signer");
    signer.write_all(data).expect("signed test data");
    signer.finalize().expect("finalized test signature");
    let mut certificate_bytes = Vec::new();
    certificate
        .serialize(&mut certificate_bytes)
        .expect("serialized test certificate");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock")
        .as_secs();
    (
        certificate_bytes,
        certificate.fingerprint().to_hex(),
        signature,
        now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorized_detached_signature_verifies_and_repomd_mutation_fails() {
        let repomd = b"<repomd/>";
        let (certificate, fingerprint, signature, now) = signed_fixture(repomd);
        let trust = MetadataTrust::new([certificate], [fingerprint.clone()], "a".repeat(64), now)
            .expect("metadata trust");

        let authentication = verify_repomd(&trust, &signature, repomd).expect("valid signature");

        assert!(matches!(authentication, RepomdAuthentication::OpenPgp {
            primary_fingerprint, ..
        } if primary_fingerprint == fingerprint));
        assert!(verify_repomd(&trust, &signature, b"<repomd changed='true'/>").is_err());
    }

    #[test]
    fn metadata_trust_rejects_unlisted_or_malformed_primary_fingerprint() {
        let repomd = b"<repomd/>";
        let (certificate, _, _, now) = signed_fixture(repomd);
        assert!(
            MetadataTrust::new([certificate.clone()], ["B".repeat(40)], "a".repeat(64), now,)
                .is_err()
        );
        assert!(MetadataTrust::new([certificate], ["short".into()], "a".repeat(64), now,).is_err());
    }
}
