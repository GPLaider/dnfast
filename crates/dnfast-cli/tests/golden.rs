use std::process::{Command, Output};

fn dnfast(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dnfast"))
        .args(arguments)
        .output()
        .expect("dnfast binary must run")
}

#[test]
fn help_and_empty_invocation_are_one_v1_json_object() {
    for arguments in [&["--help"][..], &[][..]] {
        // Given a parser-supported informational invocation.
        let output = dnfast(arguments);
        // When the real public binary handles it.
        let response: serde_json::Value = serde_json::from_slice(&output.stdout)
            .expect("informational output must be one v1 JSON object");
        // Then text help never leaks to stdout outside the frozen response envelope.
        assert!(output.status.success(), "args={arguments:?}");
        assert!(output.stderr.is_empty(), "args={arguments:?}");
        assert_eq!(response["schema"], "dnfast.cli.v1");
        assert_eq!(response["command"], "cli");
        assert_eq!(response["status"], "planned");
        assert_eq!(response["exit_code"], 0);
        assert!(response["message"].as_str().unwrap().contains("dnfast"));
    }
}

#[test]
fn plan_syntax_failures_are_one_v1_json_object() {
    // Given a plan request which omitted the mandatory output boundary.
    // When the real public binary parses it.
    let output = dnfast(&["plan", "install", "bash"]);
    // Then syntax failure remains structured and does not print a partial plan.
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["schema"], "dnfast.cli.v1");
    assert_eq!(response["command"], "plan");
    assert_eq!(response["status"], "failed");
    assert_eq!(response["exit_code"], 2);
}

#[test]
fn apply_syntax_errors_are_v1_json_not_clap_text() {
    // Given an unsupported top-level intent.
    // When clap rejects it at the process boundary.
    let output = dnfast(&["apply"]);
    // Then public stdout remains the strict machine response.
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["command"], "apply");
    assert_eq!(response["status"], "failed");
    assert_eq!(response["exit_code"], 2);
}
