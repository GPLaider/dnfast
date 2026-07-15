use std::{fs, path::Path, process::Command};

use sha2::{Digest, Sha256};
use tempfile::tempdir;

const X86_POOL_PROBE: &str = "target/debug/examples/x86_pool_probe fixtures/rpm/generated-build10/repos/main/repodata/repomd.xml /tmp/dnfast-x86-pool-probe-primary.xml /tmp/dnfast-x86-pool-probe-filelists.xml";

fn receipt_without_guest_transcript() -> String {
    let hash = "a".repeat(64);
    format!(
        concat!(
            "x86_pool_probe_receipt_format=1\n",
            "x86_pool_probe_native_tests=passed\n",
            "native_pool_arch=x86_64 noarch_solve=passed\n",
            "x86_pool_probe_runtime_cleanup=completed status=0\n",
            "x86_pool_probe_host_harness_sha256={0}\n",
            "x86_pool_probe_source_harness_sha256={0}\n",
            "x86_pool_probe_source_rpm_c_sha256={0}\n",
            "x86_pool_probe_source_native_rs_sha256={0}\n",
            "x86_pool_probe_binary_sha256={0}\n",
            "x86_pool_probe_result_sha256={0}\n",
        ),
        hash,
    )
}

fn validate_receipt(receipt: &Path) -> std::process::Output {
    Command::new("bash")
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("tools/fedora44-native-build.sh"),
        )
        .arg("--validate-x86-pool-probe-receipt")
        .arg(receipt)
        .output()
        .unwrap()
}

#[test]
fn x86_pool_probe_when_using_rpm_md_fixture_passes_uncompressed_metadata_to_native_loader() {
    // Given: the x86 QEMU probe uses the generated rpm-md fixture.
    let script = include_str!("../../../tools/fedora44-native-build.sh");

    // When: the probe materializes its metadata paths.
    let primary = "zstd -qdf fixtures/rpm/generated-build10/repos/main/repodata/primary.xml.zst -o /tmp/dnfast-x86-pool-probe-primary.xml";
    let filelists = "zstd -qdf fixtures/rpm/generated-build10/repos/main/repodata/filelists.xml.zst -o /tmp/dnfast-x86-pool-probe-filelists.xml";

    // Then: libsolv's rpm-md reader receives XML rather than compressed bytes.
    assert!(
        script.contains(primary),
        "x86 probe must decompress primary metadata"
    );
    assert!(
        script.contains(filelists),
        "x86 probe must decompress filelists metadata"
    );
    assert!(
        script.contains(X86_POOL_PROBE),
        "x86 probe must pass decompressed metadata paths"
    );
}

#[test]
fn x86_pool_probe_when_complete_emits_a_verifiable_host_receipt() {
    // Given: the focused QEMU probe must survive deletion of its ephemeral runtime directory.
    let script = include_str!("../../../tools/fedora44-native-build.sh");

    // When: the guest command finishes successfully.
    // Then: its output is copied to stdout and the host receipt has stable verification markers.
    for marker in [
        "x86-pool-probe-guest.log",
        "x86_pool_probe_native_tests=passed",
        "x86_pool_probe_binary_sha256=",
        "x86_pool_probe_source_harness_sha256=",
        "x86_pool_probe_host_harness_sha256=",
        "x86_pool_probe_runtime_cleanup=completed",
        "--validate-x86-pool-probe-receipt",
    ] {
        assert!(
            script.contains(marker),
            "x86 probe receipt must include {marker}"
        );
    }
}

#[test]
fn x86_pool_probe_receipt_rejects_a_missing_persistent_guest_transcript() {
    // Given: all legacy markers are present, but the guest transcript did not survive runtime cleanup.
    let temporary = tempdir().unwrap();
    let receipt = temporary.path().join("task-1-x86-pool-probe-qemu.log");
    fs::write(&receipt, receipt_without_guest_transcript()).unwrap();

    // When: the public receipt validator is invoked without booting QEMU.
    let output = validate_receipt(&receipt);

    // Then: it must not accept a receipt that cannot expose the guest-side proof.
    assert!(
        !output.status.success(),
        "receipt without persistent guest transcript must be rejected; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn x86_pool_probe_receipt_accepts_a_hash_bound_persistent_guest_transcript() {
    // Given: the persistent transcript and its receipt binding survive independently of QEMU runtime state.
    let temporary = tempdir().unwrap();
    let transcript = temporary.path().join("x86-pool-probe-guest.log");
    let transcript_bytes = b"native_pool_arch=x86_64 noarch_solve=passed\n";
    fs::write(&transcript, transcript_bytes).unwrap();
    let transcript_hash = hex::encode(Sha256::digest(transcript_bytes));
    let receipt = temporary.path().join("task-1-x86-pool-probe-qemu.log");
    fs::write(
        &receipt,
        format!(
            "{}x86_pool_probe_guest_log={}\nx86_pool_probe_guest_log_sha256={transcript_hash}\n",
            receipt_without_guest_transcript(),
            transcript.display(),
        ),
    )
    .unwrap();

    // When: the public receipt validator runs without QEMU.
    let output = validate_receipt(&receipt);

    // Then: it accepts the content-addressed transcript binding.
    assert!(
        output.status.success(),
        "receipt with hash-bound persistent guest transcript must validate; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
