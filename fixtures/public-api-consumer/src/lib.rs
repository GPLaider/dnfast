#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use dnfast_cache::{Cache, CacheError, Snapshot};
use dnfast_core::{
    canonical_actions, Action, Architecture, CandidateAction, CanonicalDocument, CanonicalPlan,
    DomainError, Evra, HistoryRecord, InstalledInventory, InstalledPackage, IntentError,
    JournalRecord, JournalState, PackageAction, PackageOperation, PackageReason, PackageSpec,
    PlanEnvelope, PlanIntegrity, ReasonRecord, RepoPreference, RepoTrustPolicy, RepositoryBinding,
    Sha256Digest, SigningSubkeyRule, SolverPolicy, TransactionIntent,
};
use dnfast_metadata::{
    decode_primary, parse_primary, parse_repomd, search, verify_compressed, MetadataError, Package,
    PrimaryRecord, MAX_PACKAGES, MAX_PRIMARY_COMPRESSED_BYTES, MAX_PRIMARY_OPEN_BYTES,
};
use dnfast_refresh::{
    HttpTransport, RefreshError, RefreshOutcome, Refresher, Source, Transport,
};
use dnfast_repo::{
    load_repository_dirs, parse_repository_file, RepoError, Repository, SourceKind, Variables,
};

struct OfflineTransport;

impl Transport for OfflineTransport {
    fn get(&self, _url: &str, _maximum_bytes: u64) -> Result<Vec<u8>, RefreshError> {
        Err(RefreshError::Transport("offline fixture".into()))
    }
}

pub fn compile_m1_contract(cache_root: &Path) {
    let package_spec = PackageSpec::parse("dnfast").expect("fixture package is valid");
    let intent = TransactionIntent::new(Action::Install, vec![package_spec.clone()])
        .expect("fixture intent is valid");
    let _core_contract: (&str, Action, &[PackageSpec], IntentError) = (
        package_spec.as_str(),
        intent.action(),
        intent.packages(),
        IntentError::EmptyPackage,
    );
    let digest = "a".repeat(64);
    let evra = Evra::new(0, "1", "1", Architecture::Aarch64);
    let installed = InstalledPackage::new("dnfast", evra.clone(), "Fedora", 1, 1, digest.clone())
        .expect("fixture inventory package is valid");
    let inventory = InstalledInventory::new("rpm.sqlite", "6.0.1", vec![installed])
        .expect("fixture inventory is valid");
    let trust = RepoTrustPolicy::new(
        "fedora", digest.clone(), vec!["A".repeat(40)],
        SigningSubkeyRule::AuthorizedSubkeys, 1,
    ).expect("fixture trust policy is valid");
    let solver = SolverPolicy::fedora44_aarch64(vec!["dnfast".into()], vec!["kernel".into()])
        .with_repositories(vec![RepoPreference::new("fedora", 99, 1000).expect("fixture repo is valid")]);
    let candidate = CandidateAction::upgrade(evra.clone(), Evra::new(0, "2", "1", Architecture::Aarch64), "fedora", "fedora");
    let action = PackageAction::install("dnfast", evra, "fedora", PackageReason::User);
    let binding = RepositoryBinding::new("fedora", Sha256Digest::parse(digest.clone(), "generation").expect("fixture generation is valid"),
        Sha256Digest::parse(digest.clone(), "origin").expect("fixture origin is valid"), Sha256Digest::parse(digest.clone(), "trust").expect("fixture trust is valid"))
        .expect("fixture repository binding is valid");
    let integrity = PlanIntegrity::new([&digest, &digest, &digest, &digest, &digest], vec![binding])
        .expect("fixture plan integrity is valid");
    let plan = CanonicalPlan::new(intent.clone(), integrity, 2, vec![action])
        .expect("fixture plan is valid");
    let journal = JournalRecord::new(digest, 1, JournalState::Prepared).expect("fixture journal is valid");
    let history = HistoryRecord::new("dnfast", PackageReason::User, JournalState::Reconciled)
        .expect("fixture history is valid");
    let _todo7_contract = (
        inventory.to_canonical_json(), trust.canonical_sha256(), solver.validate_upgrade(&candidate),
        plan.to_canonical_json(), journal.to_canonical_json(), history.to_canonical_json(),
    );
    let _all_todo7_exports: (
        PlanEnvelope, PackageOperation, ReasonRecord, Result<Vec<PackageAction>, DomainError>,
        Sha256Digest,
    ) = (
        plan, PackageOperation::Install, history,
        canonical_actions(Vec::new()), Sha256Digest::parse("b".repeat(64), "fixture").expect("fixture digest is valid"),
    );

    let package = Package {
        name: "dnfast".into(),
        arch: "aarch64".into(),
        epoch: "0".into(),
        version: "1".into(),
        release: "1".into(),
        summary: "fixture".into(),
    };
    let packages = vec![package];
    let _metadata_contract = (
        parse_repomd(b"<invalid/>"),
        parse_primary(b"<invalid/>".as_slice()),
        search(&packages, "dnfast"),
        MetadataError::MissingPrimary,
        MAX_PACKAGES,
        MAX_PRIMARY_COMPRESSED_BYTES,
        MAX_PRIMARY_OPEN_BYTES,
    );
    let record = PrimaryRecord {
        href: "repodata/primary.xml".into(),
        checksum: String::new(),
        size: 0,
        open_checksum: String::new(),
        open_size: 0,
    };
    let _compression_contract = (
        verify_compressed(&[], &record),
        decode_primary(&[], &record),
        packages[0].nevra(),
    );

    let cache = Cache::new(cache_root);
    let _cache_contract: (
        &Path,
        Result<Snapshot, CacheError>,
        Result<Vec<String>, CacheError>,
        Result<Snapshot, CacheError>,
    ) = (
        cache.root(),
        cache.load("missing"),
        cache.repositories(),
        cache.publish("fixture", b"invalid", b"invalid"),
    );

    let variables = Variables::from_pairs([("releasever".into(), "44".into())]);
    let repository = Repository {
        id: "fixture".into(),
        enabled: true,
        baseurls: vec!["https://example.invalid/44".into()],
        metalink: None,
        mirrorlist: None,
        origin: PathBuf::from("fixture.repo"),
    };
    let _repo_contract = (
        variables.expand("$releasever"),
        repository.sources().next(),
        repository.selected_source(),
        SourceKind::BaseUrl.as_str(),
        parse_repository_file(Path::new("fixture.repo"), "[fixture]\nbaseurl=https://example.invalid\n"),
        load_repository_dirs(&[]),
        RepoError::MalformedVariable("fixture".into()),
    );

    let refresher = Refresher::new(OfflineTransport, &cache);
    let _refresh_contract = (
        refresher.refresh("fixture", Source::BaseUrl("https://example.invalid".into())),
        Source::Metalink("https://example.invalid/metalink".into()),
        RefreshOutcome { digest: String::new(), packages: 0 },
        RefreshError::Policy("fixture".into()),
        HttpTransport::new(),
        HttpTransport::default(),
    );
}

#[cfg(test)]
mod tests {
    use super::compile_m1_contract;
    use dnfast_state::{JournalStore, RecoveryAction, TransactionId, recover};

    #[test]
    fn downstream_consumer_compiles_every_m1_public_api() {
        let root = std::env::temp_dir().join(format!(
            "dnfast-public-api-consumer-{}",
            std::process::id()
        ));
        compile_m1_contract(&root);
    }

    #[test]
    fn downstream_consumer_compiles_state_store_public_api() {
        let root = std::env::temp_dir().join(format!("dnfast-state-consumer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = JournalStore::open(&root).unwrap();
        let id = TransactionId::parse("01890f6e-7b2c-7cc0-98c4-dc0c0c07398f").unwrap();
        let journal = store.create(&id, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert_eq!(recover(&journal).unwrap(), RecoveryAction::CleanupRevalidateAndReapprove);
        drop(journal);
        std::fs::remove_dir_all(root).unwrap();
    }
}
