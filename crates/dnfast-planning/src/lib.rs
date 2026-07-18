#![forbid(unsafe_code)]
#![deny(warnings)]

mod auxiliary;
mod error;
mod file_provides;
mod fs;
mod model;
mod modulemd;
mod native_xml;
mod publisher;
mod snapshot_store;

pub use error::PlanningError;
pub use model::{
    PlanningBytes, PlanningConfiguration, PlanningKey, PlanningOrigin, PlanningPayload,
    PlanningPolicy, PlanningRepository, PlanningSnapshot,
};
pub use modulemd::{
    Module, ModuleCatalog, ModuleMutation, ModuleProfile, ModuleState, ModuleStateEntry,
    ModuleStream,
};
pub use native_xml::{NativeRepositoryPrimary, NativeRepositoryXml};
pub use publisher::{
    PlanningRoots, RootPlanningPublisher, SYSTEM_CACHE_PATH, SYSTEM_PLANNING_PATH,
    host_rpm_architecture, installed_solv_cache_binding, repository_solv_cache_binding,
};

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    use base64::Engine;
    use dnfast_core::{
        Architecture, Evra, InstalledInventory, InstalledPackage, RepoPreference, RepoTrustPolicy,
        SigningSubkeyRule, SolverPolicy,
    };
    use rustix::process::getuid;
    use sha2::{Digest, Sha256};

    use super::{
        PlanningBytes, PlanningConfiguration, PlanningKey, PlanningOrigin, PlanningPayload,
        PlanningPolicy, PlanningRepository, PlanningRoots, PlanningSnapshot, RootPlanningPublisher,
        fs::TrustedDirectory,
        host_rpm_architecture,
        snapshot_store::{garbage_collect, publish_snapshot, valid_digest},
    };

    #[test]
    fn planning_digests_require_canonical_lowercase_hex() {
        assert!(valid_digest(&"ab".repeat(32)));
        assert!(!valid_digest(&"AB".repeat(32)));
        assert!(!valid_digest(&"g0".repeat(32)));
        assert!(!valid_digest(&"a".repeat(63)));
    }

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join(format!(".planning-test-{}-{nonce}", std::process::id()));
            fs::create_dir(&path).expect("fixture directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("fixture mode");
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("fixture cleanup");
        }
    }

    #[test]
    fn snapshot_reader_rejects_a_user_owned_pointer_before_payload_is_opened() {
        // Given: a planning root with an attacker-owned current pointer.
        let directory = tempfile::tempdir().expect("temporary planning root");
        let roots = PlanningRoots::for_test(directory.path());
        std::fs::create_dir_all(roots.planning_root()).expect("planning root");
        std::fs::write(roots.planning_root().join("current"), b"0".repeat(64)).expect("pointer");

        // When: an unprivileged reader opens the public snapshot boundary.
        let opened = RootPlanningPublisher::open_snapshot_for_test(&roots);

        // Then: ownership is checked before any snapshot payload is deserialized.
        assert!(opened.is_err());
    }

    #[test]
    fn test_publisher_rejects_a_noncanonical_pointer_without_deserializing_payload() {
        let directory = tempfile::tempdir().expect("temporary planning root");
        let roots = PlanningRoots::for_test(directory.path());
        std::fs::create_dir_all(roots.planning_root()).expect("planning root");
        std::fs::write(roots.planning_root().join("current"), b"not-a-digest\n").expect("pointer");
        let publisher = RootPlanningPublisher::for_test(roots);
        assert!(publisher.open_test_snapshot().is_err());
    }

    #[test]
    fn public_reader_returns_the_same_full_payload_twice_and_rejects_mutation() {
        let fixture = Fixture::new();
        let metadata = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/rpm/generated-build10/repos/main/repodata");
        let repomd = fs::read(metadata.join("repomd.xml")).expect("repomd");
        let primary = fs::read(metadata.join("primary.xml.zst")).expect("primary");
        let filelists = fs::read(metadata.join("filelists.xml.zst")).expect("filelists");
        let certificate = b"planning-key";
        let bundle_path = "/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44-x86_64";
        let mut bundle = Sha256::new();
        bundle.update(b"dnfast-key-bundle-v1");
        for value in [bundle_path.as_bytes(), certificate.as_slice()] {
            bundle.update(u64::try_from(value.len()).expect("length").to_be_bytes());
            bundle.update(value);
        }
        let trust = RepoTrustPolicy::new(
            "main",
            format!("{:x}", bundle.finalize()),
            ["A".repeat(40)],
            SigningSubkeyRule::AuthorizedSubkeys,
            7,
        )
        .expect("trust");
        let payload = PlanningPayload {
            policy: PlanningPolicy {
                solver: SolverPolicy::fedora44_x86_64(vec!["dnfast".into()], vec!["kernel".into()])
                    .with_repositories(vec![
                        RepoPreference::new("main", 99, 1000).expect("preference"),
                    ]),
                included_packages: Vec::new(),
                installonly_limit: 3,
            },
            inventory: InstalledInventory::new("sqlite", "4.20", Vec::new()).expect("inventory"),
            allowed_repositories: vec![PlanningRepository {
                id: "main".into(),
                priority: 99,
                cost: 1000,
                generation_sha256: format!("{:x}", Sha256::digest(&repomd)),
                origin: PlanningOrigin {
                    repomd_url: "https://mirror.example/fedora/repodata/repomd.xml".into(),
                    sha256: format!(
                        "{:x}",
                        Sha256::digest("https://mirror.example/fedora/repodata/repomd.xml")
                    ),
                },
                repomd: bytes(&repomd),
                primary: bytes(&primary),
                filelists: bytes(&filelists),
                file_provides: None,
                group: None,
                modules: None,
                trust,
                keys: vec![PlanningKey {
                    bundle_path: bundle_path.into(),
                    certificate_base64: base64::engine::general_purpose::STANDARD
                        .encode(certificate),
                }],
                repomd_authentication: dnfast_cache::RepomdAuthentication::TransportOnly,
            }],
            configuration: vec![PlanningConfiguration {
                id: "main".into(),
                enabled: true,
                baseurl: vec!["https://mirror.example/fedora".into()],
                metalink: None,
                mirrorlist: None,
                priority: 99,
                cost: 1000,
                excludes: Vec::new(),
                includes: Vec::new(),
                gpgkey: vec![bundle_path.into()],
                allowed_fingerprints: vec!["A".repeat(40)],
                repo_gpgcheck: false,
            }],
            module_state: Default::default(),
        };
        let snapshot = PlanningSnapshot::new(7, payload).expect("snapshot");
        let mut schema4_value: serde_json::Value =
            serde_json::from_slice(&snapshot.canonical_bytes().expect("schema 5 bytes"))
                .expect("snapshot JSON");
        schema4_value["schema_version"] = 4.into();
        let schema4 = PlanningSnapshot::from_canonical_bytes(
            &serde_json::to_vec(&schema4_value).expect("schema 4 bytes"),
        )
        .expect("schema 4 compatibility");
        schema4_value["schema_version"] = 3.into();
        let schema3 = PlanningSnapshot::from_canonical_bytes(
            &serde_json::to_vec(&schema4_value).expect("schema 3 bytes"),
        )
        .expect("schema 3 compatibility");
        assert_eq!(
            schema3
                .integrity_for_repositories(&[])
                .expect("schema 3 integrity")
                .metadata_sha256(),
            schema4
                .integrity_for_repositories(&[])
                .expect("schema 4 integrity")
                .metadata_sha256()
        );
        schema4_value["schema_version"] = 4.into();
        schema4_value["payload"]["allowed_repositories"][0]["group"] =
            serde_json::to_value(bytes(b"unbound legacy group")).expect("group descriptor");
        assert!(
            PlanningSnapshot::from_canonical_bytes(
                &serde_json::to_vec(&schema4_value).expect("extended schema 4 bytes")
            )
            .is_err()
        );

        let mut group_payload = snapshot.payload().clone();
        group_payload.allowed_repositories[0].group = Some(bytes(b"group payload"));
        let group_snapshot = PlanningSnapshot::new(7, group_payload).expect("group snapshot");
        assert_ne!(
            snapshot
                .integrity_for_repositories(&[])
                .expect("without group")
                .metadata_sha256(),
            group_snapshot
                .integrity_for_repositories(&[])
                .expect("with group")
                .metadata_sha256()
        );
        let mut tampered_group_payload = group_snapshot.payload().clone();
        tampered_group_payload.allowed_repositories[0]
            .group
            .as_mut()
            .expect("group descriptor")
            .sha256 = "f".repeat(64);
        let tampered_group =
            PlanningSnapshot::new(7, tampered_group_payload).expect("bound tamper descriptor");
        assert!(
            tampered_group
                .materialize_payload(
                    tampered_group.payload().allowed_repositories[0]
                        .group
                        .as_ref()
                        .expect("tampered group")
                )
                .is_err()
        );
        let mut unsigned_required_payload = snapshot.payload().clone();
        unsigned_required_payload.configuration[0].repo_gpgcheck = true;
        assert!(PlanningSnapshot::new(7, unsigned_required_payload.clone()).is_err());
        unsigned_required_payload.allowed_repositories[0].repomd_authentication =
            dnfast_cache::RepomdAuthentication::openpgp(
                "A".repeat(40),
                "A".repeat(40),
                unsigned_required_payload.allowed_repositories[0]
                    .trust
                    .key_bundle_sha256()
                    .as_str(),
                "f".repeat(64),
            )
            .expect("OpenPGP evidence");
        assert!(PlanningSnapshot::new(7, unsigned_required_payload).is_ok());
        let default_selection = snapshot
            .integrity_for_repositories(&[])
            .expect("default selected integrity");
        let explicit_selection = snapshot
            .integrity_for_repositories(&["main".into()])
            .expect("explicit selected integrity");
        assert_eq!(default_selection, explicit_selection);
        let mut trust_mutated_payload = snapshot.payload().clone();
        trust_mutated_payload.allowed_repositories[0].trust = RepoTrustPolicy::new(
            "main",
            trust_mutated_payload.allowed_repositories[0]
                .trust
                .key_bundle_sha256()
                .as_str(),
            ["B".repeat(40)],
            SigningSubkeyRule::AuthorizedSubkeys,
            7,
        )
        .expect("mutated trust");
        trust_mutated_payload.configuration[0].allowed_fingerprints = vec!["B".repeat(40)];
        let trust_mutated =
            PlanningSnapshot::new(7, trust_mutated_payload).expect("trust-mutated snapshot");
        let mutated_integrity = trust_mutated
            .integrity_for_repositories(&["main".into()])
            .expect("trust-mutated integrity");
        assert_ne!(
            default_selection.metadata_sha256(),
            mutated_integrity.metadata_sha256()
        );
        assert!(super::publisher::require_same_source_payload(&snapshot, &trust_mutated).is_err());
        let mut configuration_mutated_payload = snapshot.payload().clone();
        configuration_mutated_payload.configuration[0]
            .includes
            .push("changed".into());
        let configuration_mutated = PlanningSnapshot::new(7, configuration_mutated_payload)
            .expect("configuration-mutated snapshot");
        assert!(
            super::publisher::require_same_source_payload(&snapshot, &configuration_mutated)
                .is_err()
        );
        let mut origin_mutated_payload = snapshot.payload().clone();
        origin_mutated_payload.allowed_repositories[0]
            .origin
            .repomd_url = "https://other.example/repo/repodata/repomd.xml".into();
        origin_mutated_payload.allowed_repositories[0].origin.sha256 = format!(
            "{:x}",
            Sha256::digest("https://other.example/repo/repodata/repomd.xml")
        );
        let origin_mutated =
            PlanningSnapshot::new(7, origin_mutated_payload).expect("origin-mutated snapshot");
        assert!(super::publisher::require_same_source_payload(&snapshot, &origin_mutated).is_err());
        let pointer_mutated =
            PlanningSnapshot::new(8, snapshot.payload().clone()).expect("pointer-mutated snapshot");
        assert!(super::publisher::require_current_snapshot(&snapshot, &pointer_mutated).is_err());
        assert!(
            snapshot
                .integrity_for_repositories(&["disabled".into()])
                .is_err()
        );
        assert!(
            snapshot
                .integrity_for_repositories(&["main".into(), "main".into()])
                .is_err()
        );
        let roots = PlanningRoots::for_test(&fixture.0);
        let owner = getuid().as_raw();
        let planning = TrustedDirectory::open(roots.planning_root(), owner, true, 0o755)
            .expect("planning root");
        let snapshots = planning
            .child("snapshots", true, 0o755)
            .expect("snapshot directory");
        let bytes = snapshot.canonical_bytes().expect("canonical snapshot");
        let digest = snapshot.digest().expect("snapshot digest");
        publish_snapshot(&planning, &snapshots, &digest, &bytes).expect("atomic publication");
        let reader = RootPlanningPublisher::for_test(roots.clone());
        let first = reader.open_test_snapshot().expect("first public read");
        let second = reader.open_test_snapshot().expect("second public read");
        assert_eq!(first, second);

        // Given: a root-published snapshot and a new RPMDB inventory.
        let replacement = replacement_inventory();
        let original_payload = first.payload().clone();

        // When: a successful transaction republished only its inventory.
        reader
            .publish_inventory_onto_current(replacement.clone())
            .expect("inventory-only republish");
        let republished = reader.open_test_snapshot().expect("republished snapshot");

        // Then: the plan gate is fresh while publication time and source bindings stay fixed.
        assert_eq!(republished.payload().inventory, replacement);
        assert_eq!(republished.published_at_unix(), first.published_at_unix());
        assert_eq!(republished.payload().policy, original_payload.policy);
        assert_eq!(
            republished.payload().allowed_repositories,
            original_payload.allowed_repositories
        );
        assert_eq!(
            republished.payload().allowed_repositories[0].trust,
            original_payload.allowed_repositories[0].trust
        );
        assert_eq!(
            republished.payload().configuration,
            original_payload.configuration
        );

        let mut current = digest;
        for published_at in 8..18 {
            let retained = PlanningSnapshot::new(published_at, snapshot.payload().clone())
                .expect("retained snapshot");
            let retained_bytes = retained.canonical_bytes().expect("retained bytes");
            current = retained.digest().expect("retained digest");
            publish_snapshot(&planning, &snapshots, &current, &retained_bytes)
                .expect("retained publication");
        }
        garbage_collect(&snapshots, &current).expect("bounded collection");
        let retained = fs::read_dir(roots.planning_root().join("snapshots"))
            .expect("snapshot listing")
            .count();
        assert_eq!(retained, 8);
        let snapshot_file = roots
            .planning_root()
            .join("snapshots")
            .join(current)
            .join("snapshot.json");
        let linked = fixture.0.join("linked-snapshot");
        fs::hard_link(&snapshot_file, &linked).expect("hardlink fixture");
        assert!(reader.open_test_snapshot().is_err());
        fs::remove_file(&linked).expect("hardlink cleanup");
        fs::write(snapshot_file, b"{}").expect("mutation fixture");
        assert!(reader.open_test_snapshot().is_err());
    }

    #[test]
    fn reader_rejects_a_symlinked_planning_ancestor_and_user_owned_cache_root() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let roots = PlanningRoots::for_test(&fixture.0);
        fs::create_dir_all(roots.planning_root()).expect("planning root");
        let moved = fixture.0.join("moved-planning");
        fs::rename(roots.planning_root(), &moved).expect("move planning root");
        symlink(&moved, roots.planning_root()).expect("symlinked planning root");
        let reader = RootPlanningPublisher::for_test(roots.clone());
        assert!(reader.open_test_snapshot().is_err());
        let cache = fixture.0.join("user-cache");
        fs::create_dir(&cache).expect("cache root");
        assert!(TrustedDirectory::open(&cache, 0, false, 0o700).is_err());
    }

    #[test]
    fn publisher_prepares_and_revalidates_the_trusted_refresh_cache() {
        let fixture = Fixture::new();
        let roots = PlanningRoots::for_test(&fixture.0);
        let publisher = RootPlanningPublisher::for_test(roots.clone());

        publisher
            .prepare_system_cache_for_verified_refresh()
            .expect("trusted cache root must be created");
        fs::set_permissions(roots.cache_root(), fs::Permissions::from_mode(0o777))
            .expect("unsafe cache mode");

        assert!(
            publisher
                .prepare_system_cache_for_verified_refresh()
                .is_err()
        );
    }

    #[test]
    fn inventory_only_republish_fails_without_current_snapshot_or_partial_publication() {
        // Given: a planning root with no published current snapshot.
        let fixture = Fixture::new();
        let roots = PlanningRoots::for_test(&fixture.0);
        let publisher = RootPlanningPublisher::for_test(roots.clone());

        // When: post-transaction inventory publication is attempted.
        let result = publisher.publish_inventory_onto_current(replacement_inventory());

        // Then: it fails closed without creating a partial current pointer.
        assert!(result.is_err());
        assert!(!roots.planning_root().join("current").exists());
        assert!(!roots.planning_root().exists());
    }

    #[test]
    fn host_rpm_architecture_ignores_untrusted_process_environment() {
        const CHILD_MARKER: &str = "DNFAST_PLANNING_PATH_SHADOW_MARKER";
        if let Ok(marker) = std::env::var(CHILD_MARKER) {
            let expected = rpm_architecture(Path::new("/usr/bin/rpm"));
            assert_eq!(
                host_rpm_architecture().expect("host architecture"),
                expected
            );
            assert!(!Path::new(&marker).exists());
            return;
        }
        let fixture = Fixture::new();
        let fake = fixture.0.join("rpm");
        let marker = fixture.0.join("shadowed-rpm-ran");
        let malicious_configdir = fixture.0.join("malicious-rpm-configdir");
        fs::write(
            &fake,
            format!(
                "#!/bin/sh\nprintf shadowed > {}\nprintf 'aarch64\\n'\n",
                marker.display()
            ),
        )
        .expect("fake rpm");
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).expect("fake rpm mode");
        let status = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "tests::host_rpm_architecture_ignores_untrusted_process_environment",
                "--nocapture",
            ])
            .env("PATH", &fixture.0)
            .env("RPM_CONFIGDIR", malicious_configdir)
            .env(CHILD_MARKER, &marker)
            .status()
            .expect("shadow child");
        assert!(status.success());
        assert!(!marker.exists());
    }

    #[test]
    fn installed_solv_binding_hashes_cookie_inventory_and_architecture() {
        let first = dnfast_native::InventorySnapshot {
            inventory: InstalledInventory::new("sqlite", "4.20", Vec::new()).unwrap(),
            rpmdb_cookie: "cookie-a\nwith-delimiter".into(),
        };
        let second = dnfast_native::InventorySnapshot {
            inventory: first.inventory.clone(),
            rpmdb_cookie: "cookie-b".into(),
        };
        let (first_bytes, first_digest) =
            super::installed_solv_cache_binding(&first, Architecture::X86_64).unwrap();
        assert!(
            !String::from_utf8(first_bytes.clone())
                .unwrap()
                .contains(&first.rpmdb_cookie)
        );
        assert_eq!(first_digest, format!("{:x}", Sha256::digest(first_bytes)));
        assert_ne!(
            first_digest,
            super::installed_solv_cache_binding(&second, Architecture::X86_64)
                .unwrap()
                .1
        );
        assert_ne!(
            first_digest,
            super::installed_solv_cache_binding(&first, Architecture::Aarch64)
                .unwrap()
                .1
        );
    }

    fn bytes(input: &[u8]) -> PlanningBytes {
        PlanningBytes {
            sha256: format!("{:x}", Sha256::digest(input)),
            size: u64::try_from(input.len()).expect("length"),
            base64: base64::engine::general_purpose::STANDARD.encode(input),
        }
    }

    fn replacement_inventory() -> InstalledInventory {
        let package = InstalledPackage::new(
            "dnfast-noarch",
            Evra::new(0, "1.0", "1", Architecture::Noarch),
            "unknown",
            1,
            1,
            format!("{:x}", Sha256::digest(b"republished-header")),
        )
        .expect("installed package");
        InstalledInventory::new("sqlite", "4.20", vec![package]).expect("replacement inventory")
    }

    fn rpm_architecture(executable: &Path) -> dnfast_core::Architecture {
        match String::from_utf8(
            Command::new(executable)
                .env_clear()
                .args(["--eval", "%{_arch}"])
                .output()
                .expect("rpm output")
                .stdout,
        )
        .expect("rpm UTF-8")
        .trim()
        {
            "aarch64" => dnfast_core::Architecture::Aarch64,
            "x86_64" => dnfast_core::Architecture::X86_64,
            value => panic!("unsupported RPM architecture in test: {value}"),
        }
    }
}
