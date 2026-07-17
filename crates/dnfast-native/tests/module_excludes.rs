use std::path::{Path, PathBuf};

use dnfast_core::Architecture;
use dnfast_native::{NativeContext, Repository};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/rpm/generated-build11/repos/main/repodata")
        .join(name)
}

fn repository(directory: &tempfile::TempDir) -> Repository {
    let decode = |name: &str| {
        let output = std::process::Command::new("/usr/bin/zstd")
            .args(["-qdc", &fixture(name).display().to_string()])
            .output()
            .expect("run zstd");
        assert!(output.status.success(), "decode {name}");
        let path = directory.path().join(name.trim_end_matches(".zst"));
        std::fs::write(&path, output.stdout).expect("materialize metadata");
        path
    };
    Repository {
        id: "main".into(),
        repomd_path: fixture("repomd.xml").display().to_string(),
        primary_path: decode("primary.xml.zst").display().to_string(),
        filelists_path: decode("filelists.xml.zst").display().to_string(),
        priority: 99,
        cost: 1000,
    }
}

#[test]
fn module_blacklist_jobs_preserve_selector_provenance_and_choose_active_stream() {
    let directory = tempfile::tempdir().expect("temporary metadata");
    let mut context = NativeContext::open(Architecture::X86_64, || false).expect("context");
    context
        .add_repository(repository(&directory))
        .expect("repository");
    context
        .set_module_excludes(&["dnfast-upgrade-0:2.0-1.noarch".into()])
        .expect("stable stream filter");
    context.prepare_solver().expect("prepared solver");

    let stable = context
        .solve_install("dnfast-upgrade", false, true)
        .expect("solve with module filter");
    assert_eq!(stable.actions, ["dnfast-upgrade-0:1.0-1.noarch"]);
    assert_eq!(stable.requested_specs, [Some("dnfast-upgrade".into())]);

    context
        .set_module_excludes(&["dnfast-upgrade-0:1.0-1.noarch".into()])
        .expect("next stream filter");
    let next = context
        .solve_install("dnfast-upgrade", false, true)
        .expect("solve after module stream switch");
    assert_eq!(next.actions, ["dnfast-upgrade-0:2.0-1.noarch"]);
    assert_eq!(next.requested_specs, [Some("dnfast-upgrade".into())]);
}
