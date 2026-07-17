const VALID: &[u8] = br#"---
document: modulemd
version: 2
data:
  name: demo
  stream: stable
  version: 1
  context: c0
  arch: x86_64
  summary: Demo stable
  description: Demo stable stream
  license:
    module:
      - MIT
  profiles:
    default:
      description: Default profile
      rpms:
        - demo
  artifacts:
    rpms:
      - demo-0:1-1.x86_64
---
document: modulemd-defaults
version: 1
data:
  module: demo
  stream: stable
  profiles:
    stable:
      - default
"#;

#[test]
fn strict_libmodulemd_catalog_exposes_stream_policy() {
    let json = dnfast_native::parse_modulemd_json(VALID).expect("valid modulemd");
    assert!(json.contains("\"name\":\"demo\""));
    assert!(json.contains("\"default_stream\":\"stable\""));
    assert!(json.contains("\"artifacts\":[\"demo-0:1-1.x86_64\"]"));
    assert!(json.contains("\"profiles\":[{\"name\":\"default\""));
}

#[test]
fn strict_libmodulemd_rejects_unknown_keys() {
    let invalid = String::from_utf8(VALID.to_vec()).unwrap().replace(
        "  summary: Demo stable",
        "  surprise: rejected\n  summary: Demo stable",
    );
    dnfast_native::parse_modulemd_json(invalid.as_bytes())
        .expect_err("strict parsing must reject unknown keys");
}
