use std::{
    ffi::OsString,
    os::unix::{ffi::OsStringExt, process::CommandExt},
    process::{Command, Output},
};

const UNSUPPORTED: &[&str] = &["plugin", "copr", "system-upgrade", "offline"];

#[test]
fn history_as_a_non_root_user_fails_before_journal_access() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dnfast"));
    command.args(["history", "list"]);
    if rustix::process::geteuid().as_raw() == 0 {
        command.uid(65_534).gid(65_534);
    }
    let output = command.output().expect("dnfast binary must run");
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(body["command"], "history");
    assert_eq!(body["errors"][0]["message"], "history requires root");
}

fn dnfast(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dnfast"))
        .args(arguments)
        .output()
        .expect("dnfast binary must run")
}

#[test]
fn every_deferred_top_level_command_exits_two_with_one_v1_json_object() {
    for command in UNSUPPORTED {
        // Given one documented deferred command and no repository/configuration input.
        let output = dnfast(&[command, "mutation"]);
        // When the actual process starts.
        let stdout = String::from_utf8(output.stdout).unwrap();
        // Then it cannot reach configuration, networking, or solving and has one response.
        assert_eq!(
            output.status.code(),
            Some(2),
            "command={command}, stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "command={command}");
        assert_eq!(
            stdout.lines().count(),
            1,
            "command={command}, stdout={stdout:?}"
        );
        let response: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(response["schema"], "dnfast.cli.v1");
        assert_eq!(response["command"], *command);
        assert_eq!(response["status"], "unsupported");
        assert_eq!(response["exit_code"], 2);
        assert_eq!(response["actions"], serde_json::json!([]));
    }
}

fn assert_json_flag_preserves_v1_response(arguments: &[&str]) {
    let unflagged = dnfast(arguments);
    let mut flagged_arguments = vec!["--json"];
    flagged_arguments.extend(arguments);
    let flagged = dnfast(&flagged_arguments);
    assert_eq!(flagged.status.code(), unflagged.status.code());
    assert_eq!(flagged.stdout, unflagged.stdout);
    assert_eq!(flagged.stderr, unflagged.stderr);
}

#[test]
fn json_global_flag_preserves_doctor_v1_response() {
    assert_json_flag_preserves_v1_response(&["doctor"]);
}

#[test]
fn json_global_flag_is_accepted_after_a_supported_command() {
    let unflagged = dnfast(&["doctor"]);
    let flagged = dnfast(&["doctor", "--json"]);
    assert_eq!(flagged.status.code(), unflagged.status.code());
    assert_eq!(flagged.stdout, unflagged.stdout);
    assert_eq!(flagged.stderr, unflagged.stderr);
}

#[test]
fn json_global_flag_preserves_plan_v1_syntax_failure() {
    assert_json_flag_preserves_v1_response(&["plan", "install", "bash"]);
}

#[test]
fn json_global_flag_preserves_unsupported_command_response() {
    assert_json_flag_preserves_v1_response(&["plugin", "mutation"]);
}

#[test]
fn non_utf8_argument_is_a_v1_syntax_failure_without_stderr() {
    let output = Command::new(env!("CARGO_BIN_EXE_dnfast"))
        .arg(OsString::from_vec(b"bad\xff".to_vec()))
        .output()
        .expect("dnfast binary must run");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let body: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    assert_eq!(stdout.lines().count(), 1);
    assert_eq!(body["schema"], "dnfast.cli.v1");
    assert_eq!(body["command"], "cli");
    assert_eq!(body["status"], "failed");
    assert_eq!(body["exit_code"], 2);
    assert_eq!(body["errors"][0]["code"], "syntax_error");
}

#[test]
fn plan_with_a_relative_output_path_is_a_v1_syntax_failure_before_snapshot_access() {
    // Given: an output plan path which cannot be safely anchored at the filesystem root.
    let output = dnfast(&["plan", "install", "bash", "--output", "proposal.json"]);

    // When: the real public CLI parses the request.
    let body: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("syntax failures must still have one JSON response");

    // Then: it rejects before the root-published snapshot, network, or native solver is touched.
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    assert_eq!(body["schema"], "dnfast.cli.v1");
    assert_eq!(body["command"], "plan");
    assert_eq!(body["status"], "failed");
    assert_eq!(body["exit_code"], 2);
    assert_eq!(body["actions"], serde_json::json!([]));
    assert_eq!(body["errors"][0]["code"], "invalid_output_path");
}

#[test]
fn apply_as_a_non_root_user_is_a_v1_failure_before_plan_open_or_helper_spawn() {
    // Given: a caller without root authority and a path that does not exist.
    let mut command = Command::new(env!("CARGO_BIN_EXE_dnfast"));
    command.args(["apply", "/tmp/dnfast-plan-must-not-open.json"]);
    if rustix::process::geteuid().as_raw() == 0 {
        command.uid(65_534).gid(65_534);
    }

    // When: the public mutation boundary starts.
    let output = command.output().expect("dnfast binary must run");
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    // Then: it fails before the untrusted plan path can be opened or any helper is launched.
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    assert_eq!(body["command"], "apply");
    assert_eq!(body["status"], "failed");
    assert_eq!(body["exit_code"], 1);
    assert_eq!(body["errors"][0]["code"], "runtime_failure");
    assert_eq!(body["errors"][0]["message"], "apply requires root");
}

#[test]
fn refresh_as_a_non_root_user_is_a_v1_failure_before_system_config_or_cache_access() {
    // Given: a caller without root authority and a repository selection that would otherwise
    // require reading root configuration.
    let mut command = Command::new(env!("CARGO_BIN_EXE_dnfast"));
    command.args(["repo", "refresh", "--repo", "must-not-be-read"]);
    if rustix::process::geteuid().as_raw() == 0 {
        command.uid(65_534).gid(65_534);
    }

    // When: the public refresh boundary starts.
    let output = command.output().expect("dnfast binary must run");
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    // Then: authority is rejected before configuration, cache, network, or publisher work.
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    assert_eq!(body["command"], "repo");
    assert_eq!(body["status"], "failed");
    assert_eq!(body["exit_code"], 1);
    assert_eq!(body["errors"][0]["code"], "runtime_failure");
    assert_eq!(body["errors"][0]["message"], "repo refresh requires root");
}

#[test]
fn refresh_rejects_deprecated_caller_controlled_path_flags_before_system_access() {
    // Given: a legacy refresh command that tries to redirect root refresh to a caller path.
    let output = dnfast(&[
        "repo",
        "refresh",
        "--repo-dir",
        "/tmp/dnfast-untrusted-repositories",
    ]);
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    // When/Then: clap rejects the removed boundary before command dispatch or any side effect.
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    assert_eq!(body["command"], "repo");
    assert_eq!(body["status"], "failed");
    assert_eq!(body["exit_code"], 2);
    assert_eq!(body["errors"][0]["code"], "syntax_error");
}

#[test]
fn duplicate_repository_selection_is_a_v1_syntax_failure_before_snapshot_access() {
    let output = dnfast(&[
        "plan",
        "install",
        "bash",
        "--output",
        "/tmp/dnfast-duplicate-repository-plan.json",
        "--repo",
        "main",
        "--repo",
        "main",
    ]);
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    assert_eq!(body["errors"][0]["code"], "invalid_repository_selection");
    assert!(!std::path::Path::new("/tmp/dnfast-duplicate-repository-plan.json").exists());
}

#[test]
fn enable_repo_is_the_same_canonical_selection_alias_as_repo() {
    let output = dnfast(&[
        "plan",
        "install",
        "bash",
        "--output",
        "/tmp/dnfast-enable-repository-plan.json",
        "--enable-repo",
        "main",
        "--repo",
        "main",
    ]);
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(body["errors"][0]["code"], "invalid_repository_selection");
}
