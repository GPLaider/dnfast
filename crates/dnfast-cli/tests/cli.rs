use std::{
    path::PathBuf,
    process::{Command, Output},
};

use dnfast_cache::Cache;
use dnfast_metadata::Package;
use sha2::{Digest, Sha256};

fn dnfast(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dnfast"))
        .args(arguments)
        .output()
        .expect("dnfast binary must run")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(path)
}

fn generation(package: &Package) -> (Vec<u8>, Vec<u8>) {
    let primary = format!(
        r#"<metadata xmlns="http://linux.duke.edu/metadata/common" packages="1"><package type="rpm"><name>{}</name><arch>{}</arch><version epoch="{}" ver="{}" rel="{}"/><summary>{}</summary></package></metadata>"#,
        package.name, package.arch, package.epoch, package.version, package.release, package.summary
    )
    .into_bytes();
    let checksum = hex::encode(Sha256::digest(&primary));
    let repomd = format!(
        r#"<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><checksum type="sha256">{checksum}</checksum><open-checksum type="sha256">{checksum}</open-checksum><location href="repodata/primary.xml"/><size>{}</size><open-size>{}</open-size></data></repomd>"#,
        primary.len(), primary.len()
    )
    .into_bytes();
    (repomd, primary)
}

#[test]
fn plan_never_claims_resolution_when_the_root_published_snapshot_is_absent() {
    if dnfast_planning::PlanningSnapshot::open_system().is_ok() {
        eprintln!("skipped: the host has a root-published planning snapshot");
        return;
    }
    let output = dnfast(&[
        "plan",
        "install",
        "bash",
        "--output",
        "/tmp/dnfast-missing-snapshot-plan.json",
    ]);
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(output.stderr.is_empty());
    assert_eq!(response["schema"], "dnfast.cli.v1");
    assert_eq!(response["status"], "failed");
    assert_eq!(response["plan_digest"], serde_json::Value::Null);
    assert!(!std::path::Path::new("/tmp/dnfast-missing-snapshot-plan.json").exists());
}

#[test]
fn invalid_and_unsupported_commands_exit_two() {
    for arguments in [
        &["plan", "install", "--bad"][..],
        &["plan", "repo", "list"][..],
        &["apply"][..],
    ] {
        let output = dnfast(arguments);
        assert_eq!(
            output.status.code(),
            Some(2),
            "args={arguments:?}, stderr={}",
            stderr(&output)
        );
    }
}

#[test]
fn repo_list_is_expanded_and_deterministic() {
    let directory = fixture("repos");
    let output = Command::new(env!("CARGO_BIN_EXE_dnfast"))
        .args(["repo", "list", "--repo-dir"])
        .arg(&directory)
        .args(["--releasever", "44", "--basearch", "aarch64"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(output.stderr.is_empty());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["schema"], "dnfast.cli.v1");
    assert_eq!(response["command"], "repo");
    assert_eq!(response["status"], "planned");
    assert!(
        response["message"]
            .as_str()
            .unwrap()
            .contains("fedora=enabled")
    );
    assert!(
        response["message"]
            .as_str()
            .unwrap()
            .contains("disabled=disabled")
    );
    assert!(!response["message"].as_str().unwrap().contains("https://"));
}

#[test]
fn malformed_repo_exits_one_with_provenance() {
    let directory = fixture("malformed");
    let output = Command::new(env!("CARGO_BIN_EXE_dnfast"))
        .args(["repo", "list", "--repo-dir"])
        .arg(&directory)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["status"], "failed");
    assert!(
        response["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("broken.repo:3: invalid boolean for enabled: perhaps")
    );
}

#[test]
fn unresolved_variable_in_secondary_baseurl_fails_closed() {
    let directory = fixture("hidden-variable");
    let output = Command::new(env!("CARGO_BIN_EXE_dnfast"))
        .args(["repo", "list", "--repo-dir"])
        .arg(&directory)
        .args(["--releasever", "44", "--basearch", "aarch64"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        response["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("unresolved repository variable: unknown")
    );
}

#[test]
fn doctor_reports_runtime_without_execution_claim() {
    let output = dnfast(&["doctor"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(output.stderr.is_empty());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["schema"], "dnfast.cli.v1");
    assert_eq!(response["command"], "doctor");
    assert_eq!(response["status"], "planned");
    let text = response["message"].as_str().unwrap();
    for expected in [
        "fedora_config",
        "metadata_refresh",
        "libsolv",
        "librpm",
        "fixed_executor",
        "root_apply",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in {text:?}");
    }
}

#[test]
fn help_lists_root_only_refresh_and_offline_search() {
    let help = dnfast(&["--help"]);
    assert!(help.status.success());
    let help_response: serde_json::Value = serde_json::from_slice(&help.stdout).unwrap();
    assert!(
        help_response["message"]
            .as_str()
            .unwrap()
            .contains("search")
    );
    let refresh = dnfast(&["repo", "refresh", "--help"]);
    assert!(refresh.status.success(), "{}", stderr(&refresh));
    let refresh_response: serde_json::Value = serde_json::from_slice(&refresh.stdout).unwrap();
    assert_eq!(refresh_response["schema"], "dnfast.cli.v1");
    assert_eq!(refresh_response["command"], "repo");
    let refresh_help = refresh_response["message"].as_str().unwrap();
    assert!(refresh_help.contains("--repo"));
    assert!(!refresh_help.contains("--cache-dir"));
    assert!(!refresh_help.contains("--repo-dir"));
}

#[test]
fn search_reads_published_cache_offline() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::new(directory.path());
    let package = Package {
        name: "ripgrep".into(),
        arch: "aarch64".into(),
        epoch: "0".into(),
        version: "14.1.1".into(),
        release: "1.fc44".into(),
        summary: "Fast search tool".into(),
    };
    let (repomd, primary) = generation(&package);
    cache.publish("fedora", &repomd, &primary).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_dnfast"))
        .args(["search", "--repo", "fedora", "--cache-dir"])
        .arg(directory.path())
        .arg("ripgrep")
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(output.stderr.is_empty());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["schema"], "dnfast.cli.v1");
    assert_eq!(response["command"], "search");
    assert_eq!(response["status"], "planned");
    assert!(
        response["message"]
            .as_str()
            .unwrap()
            .contains("fedora ripgrep-0:14.1.1-1.fc44.aarch64 Fast search")
    );

    let all_repositories = Command::new(env!("CARGO_BIN_EXE_dnfast"))
        .args(["search", "--cache-dir"])
        .arg(directory.path())
        .arg("ripgrep")
        .output()
        .unwrap();
    assert!(
        all_repositories.status.success(),
        "{}",
        stderr(&all_repositories)
    );
    let all_response: serde_json::Value = serde_json::from_slice(&all_repositories.stdout).unwrap();
    assert!(
        all_response["message"]
            .as_str()
            .unwrap()
            .contains("fedora ripgrep-0:14.1.1-1.fc44.aarch64")
    );
}

#[test]
fn search_missing_cache_and_deprecated_refresh_paths_fail_closed() {
    let cache = tempfile::tempdir().unwrap();
    let missing = Command::new(env!("CARGO_BIN_EXE_dnfast"))
        .args(["search", "--repo", "fedora", "--cache-dir"])
        .arg(cache.path())
        .arg("bash")
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(1));
    assert!(missing.stderr.is_empty());
    let missing_response: serde_json::Value = serde_json::from_slice(&missing.stdout).unwrap();
    assert_eq!(missing_response["status"], "failed");
    assert!(
        missing_response["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("MissingSnapshot")
    );

    for arguments in [
        &["repo", "refresh", "--repo-dir", "/tmp/untrusted"][..],
        &["repo", "refresh", "--cache-dir", "/tmp/untrusted"][..],
        &["repo", "refresh", "--releasever", "44"][..],
        &["repo", "refresh", "--basearch", "x86_64"][..],
    ] {
        let output = dnfast(arguments);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stderr.is_empty());
        let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(response["schema"], "dnfast.cli.v1");
        assert_eq!(response["command"], "repo");
        assert_eq!(response["status"], "failed");
        assert_eq!(response["exit_code"], 2);
    }
}
