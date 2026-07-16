use std::path::{Path, PathBuf};

use dnfast_core::Architecture;
use dnfast_native::{FileProvider, MappedSelector, NativeContext, Repository};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/rpm/generated-build10/repos/main/repodata")
        .join(name)
}

fn primary_only_repository(directory: &tempfile::TempDir) -> Repository {
    let primary = std::process::Command::new("/usr/bin/zstd")
        .args(["-qdc", &fixture("primary.xml.zst").display().to_string()])
        .output()
        .expect("run zstd");
    assert!(primary.status.success(), "decode fixture primary");
    let primary_path = directory.path().join("primary.xml");
    std::fs::write(&primary_path, primary.stdout).expect("materialized primary");
    Repository {
        id: "main".into(),
        repomd_path: fixture("repomd.xml").display().to_string(),
        primary_path: primary_path.display().to_string(),
        filelists_path: directory
            .path()
            .join("filelists-must-not-be-opened.xml")
            .display()
            .to_string(),
        priority: 99,
        cost: 1000,
    }
}

#[test]
fn mapped_absolute_selector_uses_one_of_primary_ordinals_and_binds_identity() {
    let directory = tempfile::tempdir().expect("temporary metadata");
    let mut context = NativeContext::open(Architecture::Aarch64, || false).expect("context");
    context
        .add_repository_primary(primary_only_repository(&directory))
        .expect("primary-only repository");
    context.prepare_solver().expect("prepared solver");

    let selector = "/usr/share/dnfast/provided";
    let mapping = MappedSelector {
        selector_index: 0,
        providers: vec![
            FileProvider {
                repository_id: "main".into(),
                package_ordinal: 8,
                expected_identity: "dnfast-file-collision-0:1.0-1.noarch".into(),
            },
            FileProvider {
                repository_id: "main".into(),
                package_ordinal: 9,
                expected_identity: "dnfast-file-provider-0:1.0-1.noarch".into(),
            },
        ],
    };
    let solved = context
        .solve_install_many_mapped(&[selector], false, true, std::slice::from_ref(&mapping))
        .expect("mapped ONE_OF solve");
    assert_eq!(solved.actions.len(), 1);
    assert!(matches!(
        solved.actions[0].as_str(),
        "dnfast-file-collision-0:1.0-1.noarch" | "dnfast-file-provider-0:1.0-1.noarch"
    ));
    assert_eq!(solved.requested_specs, [Some(selector.into())]);
    assert_eq!(solved.repositories, ["main"]);

    let mut wrong = mapping;
    wrong.providers[0].expected_identity = "wrong-0:1-1.noarch".into();
    assert!(
        context
            .solve_install_many_mapped(&[selector], false, true, &[wrong])
            .is_err()
    );
}
