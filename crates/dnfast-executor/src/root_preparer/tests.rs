mod published;

use std::{
    fs::{self, File},
    io::Read,
};

use base64::Engine as _;
use dnfast_core::{RepoTrustPolicy, SigningSubkeyRule};
use dnfast_planning::{PlanningBytes, PlanningKey, PlanningOrigin, PlanningRepository};
use rustix::fs::{Mode, OFlags, ResolveFlags, open, openat, openat2};
use sha2::{Digest, Sha256};

use super::prepared_generation::{
    InputDraft, PREPARING_PREFIX, Publication, metadata_digest, payload_bytes, trust_digest,
};
use super::{PreparationError, require_root_uid};
use crate::input_model::InputManifest;

pub(super) fn draft(root: &std::path::Path) -> InputDraft {
    let parent = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .expect("open test root");
    InputDraft::create_under(parent, root.to_str().expect("UTF-8 test root"))
        .expect("create test draft")
}

#[test]
fn preparation_requires_root_before_any_system_source_is_opened() {
    // Given: a non-root effective UID.
    let uid = 1000;

    // When: the preparation authority gate is evaluated.
    let result = require_root_uid(uid);

    // Then: the caller cannot reach snapshot, cache, or RPMDB loading.
    assert!(matches!(result, Err(PreparationError::NotRoot)));
}

#[test]
fn payload_digest_tamper_fails_before_a_generation_is_publishable() {
    // Given: a temporary root-owned system-like input parent and a tampered snapshot payload descriptor.
    let root = tempfile::tempdir().expect("temporary root");
    let mut draft = draft(root.path());
    let payload = PlanningBytes {
        sha256: "a".repeat(64),
        size: 4,
        base64: "Z29vZA==".into(),
    };

    // When: the root preparer materializes that raw planning payload.
    let result = draft.write_payload("repomd", &payload);

    // Then: no generation is publishable and Drop removes the private draft.
    assert!(matches!(result, Err(PreparationError::Snapshot(_))));
    drop(draft);
    let names = fs::read_dir(root.path())
        .expect("root listing")
        .map(|entry| entry.expect("entry").file_name())
        .collect::<Vec<_>>();
    assert!(
        names
            .iter()
            .all(|name| !name.to_string_lossy().starts_with(PREPARING_PREFIX))
    );
}

#[test]
fn zstd_snapshot_metadata_materializes_xml_for_the_native_solver_boundary() {
    // Given: a fully verified planning repository whose rpm-md primary and filelists records are zstd-compressed.
    let root = tempfile::tempdir().expect("temporary root");
    let mut draft = draft(root.path());
    let repository = zstd_repository();

    // When: the root planner writes its native-solver metadata inputs.
    let materialized = draft
        .write_legacy_repository(&repository, 0)
        .expect("materialized repository");
    let mut primary_source = draft
        .open(&materialized.input.primary)
        .expect("source primary");
    let mut filelists_source = draft
        .open(&materialized.input.filelists)
        .expect("source filelists");
    let mut primary = draft
        .open(&materialized.native_primary)
        .expect("native primary");
    let mut filelists = draft
        .open(&materialized.native_filelists)
        .expect("native filelists");
    let mut primary_zstd = Vec::new();
    let mut filelists_zstd = Vec::new();
    let mut primary_xml = Vec::new();
    let mut filelists_xml = Vec::new();
    primary_source
        .read_to_end(&mut primary_zstd)
        .expect("read source primary");
    filelists_source
        .read_to_end(&mut filelists_zstd)
        .expect("read source filelists");
    primary
        .read_to_end(&mut primary_xml)
        .expect("read native primary");
    filelists
        .read_to_end(&mut filelists_xml)
        .expect("read native filelists");

    // Then: the local inputs are XML that the same rpm-md parsers used to bind the solver can consume.
    assert_eq!(
        primary_zstd,
        payload_bytes("primary", &repository.primary).expect("trusted primary")
    );
    assert_eq!(
        filelists_zstd,
        payload_bytes("filelists", &repository.filelists).expect("trusted filelists")
    );
    assert!(primary_zstd.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]));
    assert!(filelists_zstd.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]));
    assert!(primary_xml.starts_with(b"<?xml") || primary_xml.starts_with(b"<metadata"));
    assert!(filelists_xml.starts_with(b"<?xml") || filelists_xml.starts_with(b"<filelists"));
    assert!(
        !dnfast_metadata::parse_primary_records(primary_xml.as_slice())
            .expect("native primary XML")
            .is_empty()
    );
    assert!(
        !dnfast_metadata::parse_filelists(filelists_xml.as_slice())
            .expect("native filelists XML")
            .is_empty()
    );
}

#[test]
fn durable_generation_omits_native_xml_and_redecodes_raw_compressed_metadata() {
    // Given: verified compressed rpm-md records materialized for a temporary native solve.
    let root = tempfile::tempdir().expect("temporary root");
    let mut draft = draft(root.path());
    let repository = zstd_repository();
    let materialized = draft
        .write_legacy_repository(&repository, 0)
        .expect("materialized repository");
    let repomd_name = materialized.input.repomd.name.clone();
    let primary_name = materialized.input.primary.name.clone();
    let filelists_name = materialized.input.filelists.name.clone();
    let policy = draft.write_bytes("policy.json", b"{}").expect("policy");
    let metadata_sha256 =
        metadata_digest(std::slice::from_ref(&materialized.input)).expect("metadata digest");
    let trust_sha256 =
        trust_digest(std::slice::from_ref(&materialized.input)).expect("trust digest");

    // When: preparation discards its temporary native XML before publication.
    draft
        .discard_native_metadata(std::slice::from_ref(&materialized))
        .expect("discard native metadata");
    draft
        .write_manifest(&InputManifest {
            schema_version: 3,
            policy,
            metadata_sha256,
            trust_sha256,
            repositories: vec![materialized.input],
            artifacts: Vec::new(),
        })
        .expect("manifest");
    let digest = "d".repeat(64);
    assert_eq!(
        draft.publish_generation(&digest).expect("publish"),
        Publication::Published
    );
    let published = openat2(
        &draft.parent,
        &digest,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .expect("published generation");

    // Then: only raw compressed records are durable, and staging's decode boundary can recover XML.
    assert_eq!(
        openat(
            &published,
            "repo-0-native-primary.xml",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty()
        )
        .expect_err("native primary absent"),
        rustix::io::Errno::NOENT
    );
    assert_eq!(
        openat(
            &published,
            "repo-0-native-filelists.xml",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty()
        )
        .expect_err("native filelists absent"),
        rustix::io::Errno::NOENT
    );
    let mut repomd = Vec::new();
    let mut primary = Vec::new();
    let mut filelists = Vec::new();
    File::from(
        openat(
            &published,
            &repomd_name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("repomd"),
    )
    .read_to_end(&mut repomd)
    .expect("read repomd");
    File::from(
        openat(
            &published,
            &primary_name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("primary"),
    )
    .read_to_end(&mut primary)
    .expect("read primary");
    File::from(
        openat(
            &published,
            &filelists_name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("filelists"),
    )
    .read_to_end(&mut filelists)
    .expect("read filelists");
    let records = dnfast_metadata::parse_repomd_records(&repomd).expect("repomd records");
    assert!(primary.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]));
    assert!(filelists.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]));
    assert!(
        !dnfast_metadata::decode_primary(&primary, &records.primary)
            .expect("staged primary XML")
            .is_empty()
    );
    assert!(
        !dnfast_metadata::decode_record(&filelists, &records.filelists)
            .expect("staged filelists XML")
            .is_empty()
    );
}

#[test]
fn primary_materialization_failure_identifies_the_metadata_role() {
    // Given: a trusted snapshot-shaped repository with a primary payload that cannot satisfy its bound record.
    let root = tempfile::tempdir().expect("temporary root");
    let mut draft = draft(root.path());
    let mut repository = zstd_repository();
    repository.primary = planning_bytes(b"not-zstd");

    // When: root materializes local metadata for the native solver.
    let result = draft.write_legacy_repository(&repository, 0);

    // Then: the actionable failure names the role without exposing payload contents.
    assert!(
        matches!(result, Err(PreparationError::Snapshot(message)) if message.contains("primary rpm-md materialization failed:"))
    );
}

pub(super) fn zstd_repository() -> PlanningRepository {
    let metadata = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/rpm/generated-build10/repos/main/repodata");
    let repomd = fs::read(metadata.join("repomd.xml")).expect("repomd");
    let primary = fs::read(metadata.join("primary.xml.zst")).expect("primary");
    let filelists = fs::read(metadata.join("filelists.xml.zst")).expect("filelists");
    let certificate = b"planning-key";
    let bundle_path = "/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-aarch64";
    let mut bundle = Sha256::new();
    bundle.update(b"dnfast-key-bundle-v1");
    frame_digest(&mut bundle, bundle_path, certificate);
    let trust = RepoTrustPolicy::new(
        "main",
        format!("{:x}", bundle.finalize()),
        ["A".repeat(40)],
        SigningSubkeyRule::AuthorizedSubkeys,
        7,
    )
    .expect("trust");
    PlanningRepository {
        id: "main".into(),
        priority: 99,
        cost: 1000,
        generation_sha256: format!("{:x}", Sha256::digest(&repomd)),
        origin: PlanningOrigin {
            repomd_url: "https://mirror.example/fedora/repodata/repomd.xml".into(),
            sha256: format!(
                "{:x}",
                Sha256::digest(b"https://mirror.example/fedora/repodata/repomd.xml")
            ),
        },
        repomd: planning_bytes(&repomd),
        primary: planning_bytes(&primary),
        filelists: planning_bytes(&filelists),
        file_provides: None,
        group: None,
        modules: None,
        trust,
        keys: vec![PlanningKey {
            bundle_path: bundle_path.into(),
            certificate_base64: base64::engine::general_purpose::STANDARD.encode(certificate),
        }],
        repomd_authentication: dnfast_cache::RepomdAuthentication::TransportOnly,
    }
}

pub(super) fn planning_bytes(bytes: &[u8]) -> PlanningBytes {
    PlanningBytes {
        sha256: format!("{:x}", Sha256::digest(bytes)),
        size: u64::try_from(bytes.len()).expect("fixture length"),
        base64: base64::engine::general_purpose::STANDARD.encode(bytes),
    }
}

pub(super) fn frame_digest(digest: &mut Sha256, name: &str, bytes: &[u8]) {
    digest.update(
        u64::try_from(name.len())
            .expect("name length")
            .to_be_bytes(),
    );
    digest.update(name.as_bytes());
    digest.update(
        u64::try_from(bytes.len())
            .expect("byte length")
            .to_be_bytes(),
    );
    digest.update(bytes);
}
