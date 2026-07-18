use std::{
    sync::{Arc, Barrier},
    thread,
};

use dnfast_core::{
    Action, Architecture, CanonicalDocument, InstalledInventory, RepoPreference, RepoTrustPolicy,
    RepositoryBinding, Sha256Digest, SigningSubkeyRule, SolverPolicy, TransactionIntent,
};
use dnfast_solver::{
    CandidatePackage, IntegritySnapshots, PlanBuilder, ResolvedAction, ResolvedOperation,
};
use rustix::fs::{Mode, OFlags, ResolveFlags, fstat, openat, openat2};
use sha2::{Digest, Sha256};

use super::super::PreparedInputs;
use super::super::prepared_generation::{
    Publication, metadata_digest, remove_generation, trust_digest,
};
use super::{draft, frame_digest};
use crate::input_model::{
    InputArtifact, InputKey, InputManifest, InputOrigin, InputRepository, InputRepositoryTrust,
};

#[test]
fn published_generation_cleanup_reports_a_missing_generation() {
    // Given: a root-owned inputs parent without the generation that must be removed.
    let root = tempfile::tempdir().expect("temporary root");
    let parent = rustix::fs::open(
        root.path(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .expect("open test root");

    // When: the publication rollback tries to remove the missing generation.
    let result = remove_generation(&parent, &"a".repeat(64));

    // Then: cleanup cannot be silently treated as successful.
    assert!(result.is_err());
}

#[test]
fn retained_fd3_handoff_opens_the_root_published_generation() {
    // Given: a complete root-owned v3 input generation and its exact canonical proposal.
    let root = tempfile::tempdir().expect("temporary root");
    let mut draft = draft(root.path());
    let policy = SolverPolicy::fedora44_aarch64(Vec::new(), Vec::new()).with_repositories(vec![
        RepoPreference::new("main", 99, 1000).expect("preference"),
    ]);
    let policy_file = draft
        .write_bytes(
            "policy.json",
            &policy.to_canonical_json().expect("canonical policy"),
        )
        .expect("policy file");
    let repomd = draft.write_bytes("main-repomd", b"repomd").expect("repomd");
    let primary = draft
        .write_bytes("main-primary", b"primary")
        .expect("primary");
    let filelists = draft
        .write_bytes("main-filelists", b"filelists")
        .expect("filelists");
    let key_bytes = b"key";
    let bundle_path = "/etc/dnfast/keys/main/allowed.asc";
    let mut bundle = Sha256::new();
    bundle.update(b"dnfast-key-bundle-v1");
    frame_digest(&mut bundle, bundle_path, key_bytes);
    let trust = RepoTrustPolicy::new(
        "main",
        format!("{:x}", bundle.finalize()),
        ["A".repeat(40)],
        SigningSubkeyRule::AuthorizedSubkeys,
        1,
    )
    .expect("trust");
    let trust_file = draft
        .write_bytes(
            "main-trust.json",
            &trust.to_canonical_json().expect("canonical trust"),
        )
        .expect("trust file");
    let trust_sha256 = trust
        .canonical_sha256()
        .expect("trust digest")
        .as_str()
        .to_owned();
    assert_eq!(trust_file.sha256, trust_sha256);
    let key_file = draft.write_bytes("main-key", key_bytes).expect("key file");
    let repository = InputRepository {
        id: "main".into(),
        priority: 99,
        cost: 1000,
        generation_sha256: repomd.sha256.clone(),
        origin: InputOrigin {
            repomd_url: "https://main.example/repo/repodata/repomd.xml".into(),
            sha256: format!(
                "{:x}",
                Sha256::digest(b"https://main.example/repo/repodata/repomd.xml")
            ),
        },
        repomd,
        primary,
        filelists,
        file_provides: None,
        group: None,
        modules: None,
        updateinfo: None,
        trust: InputRepositoryTrust {
            policy: trust_file,
            sha256: trust_sha256.clone(),
            keys: vec![InputKey {
                file: key_file,
                bundle_path: bundle_path.into(),
            }],
        },
    };
    let artifact_file = draft.write_bytes("artifact-0", b"rpm").expect("artifact");
    let metadata_sha256 =
        metadata_digest(std::slice::from_ref(&repository)).expect("metadata digest");
    let all_trust_sha256 = trust_digest(std::slice::from_ref(&repository)).expect("trust digest");
    let inventory = InstalledInventory::new("sqlite", "1", Vec::new()).expect("inventory");
    let binding = RepositoryBinding::new(
        "main",
        Sha256Digest::parse(repository.generation_sha256.clone(), "generation")
            .expect("generation"),
        Sha256Digest::parse(repository.origin.sha256.clone(), "origin").expect("origin"),
        Sha256Digest::parse(trust_sha256.clone(), "trust").expect("trust"),
    )
    .expect("binding");
    let snapshots = IntegritySnapshots::new(
        [
            policy.canonical_sha256().expect("policy digest").as_str(),
            all_trust_sha256.as_str(),
            inventory
                .canonical_sha256()
                .expect("inventory digest")
                .as_str(),
            metadata_sha256.as_str(),
            &"f".repeat(64),
        ],
        vec![binding],
    )
    .expect("integrity");
    let candidate = CandidatePackage {
        name: "app".into(),
        evra: dnfast_core::Evra::new(0, "1", "1", Architecture::Noarch),
        vendor: "Dnfast".into(),
        repo_id: "main".into(),
        priority: 99,
        cost: 1000,
        package_size: artifact_file.size,
        installed_size: artifact_file.size,
        checksum_sha256: artifact_file.sha256.clone(),
        location: "packages/app.rpm".into(),
        excluded: false,
        modular: false,
    };
    let intent = TransactionIntent::from_package_names(Action::Install, &["app"]).expect("intent");
    let resolved = ResolvedAction {
        operation: ResolvedOperation::Install,
        name: "app".into(),
        requested: true,
        requested_spec: Some(dnfast_core::PackageSpec::parse("app").expect("requested spec")),
        requested_relation: false,
        candidate: Some(candidate.clone()),
        installed_instance: None,
        installed_header_sha256: None,
        installed_vendor: None,
        dependency_edges: Vec::new(),
        provenance: None,
        required_by_remaining: Vec::new(),
        unresolved_dependencies: Vec::new(),
        introduced_by_requested: false,
        solver_rule: "requested package".into(),
    };
    let plan = PlanBuilder {
        intent: &intent,
        snapshots: &snapshots,
        inventory: &inventory,
        policy: &policy,
        candidates: std::slice::from_ref(&candidate),
        expires_at_unix: 100,
    }
    .build(&[resolved])
    .expect("canonical plan");
    let manifest = InputManifest {
        schema_version: 3,
        policy: policy_file,
        metadata_sha256,
        trust_sha256: all_trust_sha256,
        repositories: vec![repository.clone()],
        artifacts: vec![InputArtifact {
            file: artifact_file,
            repo_id: "main".into(),
            generation_sha256: repository.generation_sha256.clone(),
            origin_sha256: repository.origin.sha256.clone(),
            trust_sha256,
            name: "app".into(),
            epoch: 0,
            version: "1".into(),
            release: "1".into(),
            arch: "noarch".into(),
            vendor: "Dnfast".into(),
        }],
    };
    draft.write_manifest(&manifest).expect("manifest");
    let digest = plan.digest().expect("plan digest").as_str().to_owned();
    assert_eq!(
        draft.publish_generation(&digest).expect("publish"),
        Publication::Published
    );
    let prepared = PreparedInputs { digest };

    // When: the root handoff boundary re-opens the exact retained generation.
    let result = prepared.revalidate_before_fd3_under(&plan, &draft.parent);

    // Then: the immutable generation is accepted at the FD3-adjacent boundary.
    result.expect("FD3 handoff validation");
}

#[test]
fn same_plan_race_publishes_once_and_preserves_the_first_generation_for_twenty_runs() {
    // Given: twenty independent pairs racing to publish one immutable proposal digest.
    for run in 0..20 {
        let root = tempfile::tempdir().expect("temporary root");
        let path = Arc::new(root.path().to_path_buf());
        let gate = Arc::new(Barrier::new(2));
        let handles = (0..2)
            .map(|worker| {
                let path = Arc::clone(&path);
                let gate = Arc::clone(&gate);
                thread::spawn(move || {
                    let mut draft = draft(&path);
                    draft
                        .write_bytes("winner", format!("run-{run}-worker-{worker}").as_bytes())
                        .expect("draft write");
                    gate.wait();
                    draft
                        .publish_generation("a".repeat(64).as_str())
                        .expect("publish")
                })
            })
            .collect::<Vec<_>>();

        // When: both root-owned drafts hit renameat2(NOREPLACE) together.
        let outcomes = handles
            .into_iter()
            .map(|handle| handle.join().expect("publisher thread"))
            .collect::<Vec<_>>();

        // Then: exactly one generation becomes visible; the loser cannot replace it.
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == Publication::Published)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == Publication::Existing)
                .count(),
            1
        );
        assert!(root.path().join("a".repeat(64)).join("winner").is_file());
    }
}

#[test]
fn different_plans_publish_without_cross_plan_replacement() {
    // Given: two draft inputs for distinct canonical proposal digests.
    let root = tempfile::tempdir().expect("temporary root");
    let mut first = draft(root.path());
    let mut second = draft(root.path());
    first.write_bytes("first", b"first").expect("first write");
    second
        .write_bytes("second", b"second")
        .expect("second write");

    // When: both generations are atomically published.
    let first_result = first
        .publish_generation("a".repeat(64).as_str())
        .expect("first publish");
    let second_result = second
        .publish_generation("b".repeat(64).as_str())
        .expect("second publish");

    // Then: each proposal retains only its own immutable input generation.
    assert_eq!(first_result, Publication::Published);
    assert_eq!(second_result, Publication::Published);
    assert!(root.path().join("a".repeat(64)).join("first").is_file());
    assert!(root.path().join("b".repeat(64)).join("second").is_file());
}

#[test]
fn manual_root_owned_generation_smoke_opens_an_input_fd_only_after_atomic_publish() {
    // Given: a root-owned system-like parent and a complete private draft generation.
    let root = tempfile::tempdir().expect("temporary root");
    let mut generation = draft(root.path());
    generation
        .write_bytes("input", b"verified")
        .expect("input write");
    let digest = "c".repeat(64);

    // When: the generation crosses the no-replace atomic publication boundary.
    assert!(!root.path().join(&digest).exists());
    assert_eq!(
        generation.publish_generation(&digest).expect("publish"),
        Publication::Published
    );

    // Then: the published input has a retained regular-file descriptor and was absent before publication.
    let directory = openat2(
        &generation.parent,
        &digest,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .expect("published directory FD");
    let file = openat(
        &directory,
        "input",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .expect("published input FD");
    assert_eq!(fstat(&file).expect("input stat").st_size, 8);
}
