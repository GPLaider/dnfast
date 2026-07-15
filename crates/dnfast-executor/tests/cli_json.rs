use std::{
    ffi::OsString,
    os::unix::ffi::OsStringExt,
    process::Command,
};

#[test]
fn executor_argument_failure_is_one_v1_json_object() {
    let output = Command::new(env!("CARGO_BIN_EXE_dnfast-executor"))
        .output()
        .expect("executor binary must run");
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    assert_eq!(response["schema"], "dnfast.cli.v1");
    assert_eq!(response["command"], "apply");
    assert_eq!(response["status"], "failed");
    assert_eq!(response["exit_code"], 1);
    assert_eq!(response["actions"], serde_json::json!([]));
}

#[test]
fn executor_non_utf8_argument_is_one_v1_json_failure_without_stderr() {
    let output = Command::new(env!("CARGO_BIN_EXE_dnfast-executor"))
        .arg(OsString::from_vec(b"bad\xff".to_vec()))
        .output()
        .expect("executor binary must run");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let response: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    assert_eq!(stdout.lines().count(), 1);
    assert_eq!(response["schema"], "dnfast.cli.v1");
    assert_eq!(response["command"], "apply");
    assert_eq!(response["status"], "failed");
    assert_eq!(response["exit_code"], 1);
    assert_eq!(response["errors"][0]["code"], "runtime_failure");
}
