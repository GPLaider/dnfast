use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

use dnfast_state::{
    CallbackSummary, JournalStore, LogAppend, ReconcileResult, RecoveryAction, StateError,
    TransactionId, TransactionState, recover, recover_with_staging,
};

const ID: &str = "01890f6e-7b2c-7cc0-98c4-dc0c0c07398f";
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn setup() -> (tempfile::TempDir, JournalStore, TransactionId) {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("transactions");
    let store = JournalStore::open(&root).unwrap();
    (temporary, store, TransactionId::parse(ID).unwrap())
}

#[test]
fn completes_immutable_sequence_when_transaction_succeeds() {
    let (temporary, store, id) = setup();
    let journal = store.create(&id, DIGEST).unwrap();
    journal.mark_started().unwrap();
    journal.record_rpm_result(0, summary()).unwrap();
    journal.reconcile(result(true)).unwrap();
    let entries = journal.entries().unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3]
    );
    assert_eq!(entries.last().unwrap().state, TransactionState::Reconciled);
    let directory = temporary.path().join("transactions").join(ID);
    assert_eq!(
        fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!((0..4).all(|sequence| {
        fs::metadata(directory.join(format!("{sequence:020}.json")))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
            == 0o600
    }));
}

#[test]
fn recovery_never_accepts_run_callback_after_started() {
    let (_temporary, store, id) = setup();
    let journal = store.create(&id, DIGEST).unwrap();
    journal.mark_started().unwrap();
    assert_eq!(recover(&journal).unwrap(), RecoveryAction::ReconcileOnly);
    assert_eq!(
        journal.entries().unwrap().last().unwrap().state,
        TransactionState::RpmResult
    );
    journal.reconcile(result(false)).unwrap();
    assert_eq!(
        recover(&journal).unwrap(),
        RecoveryAction::Terminal(result(false))
    );
}

#[test]
fn every_potentially_stateful_native_failure_recovers_without_second_run() {
    let summaries = [
        CallbackSummary {
            pretrans: 1,
            pre: 0,
            post: 0,
            triggers: 0,
            payload: 0,
            database: 0,
            script_log_truncated: false,
        },
        CallbackSummary {
            pretrans: 1,
            pre: 1,
            post: 0,
            triggers: 0,
            payload: 0,
            database: 0,
            script_log_truncated: false,
        },
        CallbackSummary {
            pretrans: 1,
            pre: 1,
            post: 1,
            triggers: 0,
            payload: 0,
            database: 0,
            script_log_truncated: false,
        },
        CallbackSummary {
            pretrans: 1,
            pre: 1,
            post: 1,
            triggers: 1,
            payload: 0,
            database: 0,
            script_log_truncated: false,
        },
        CallbackSummary {
            pretrans: 1,
            pre: 1,
            post: 1,
            triggers: 1,
            payload: 1,
            database: 0,
            script_log_truncated: false,
        },
        CallbackSummary {
            pretrans: 1,
            pre: 1,
            post: 1,
            triggers: 1,
            payload: 1,
            database: 1,
            script_log_truncated: false,
        },
    ];
    for (index, callbacks) in summaries.into_iter().enumerate() {
        let temporary = tempfile::tempdir().unwrap();
        let store = JournalStore::open(&temporary.path().join(format!("tx-{index}"))).unwrap();
        let id = TransactionId::parse(ID).unwrap();
        let journal = store.create(&id, DIGEST).unwrap();
        let run_calls = std::sync::atomic::AtomicUsize::new(0);
        journal.mark_started().unwrap();
        run_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        journal.record_rpm_result(-1, callbacks).unwrap();
        assert_eq!(recover(&journal).unwrap(), RecoveryAction::ReconcileOnly);
        assert_eq!(run_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        journal.reconcile(result(false)).unwrap();
        assert_eq!(journal.entries().unwrap().len(), 4);
    }
}

#[test]
fn prepared_requires_fresh_revalidation_and_reapproval() {
    let (temporary, store, id) = setup();
    let journal = store.create(&id, DIGEST).unwrap();
    let staging = temporary.path().join("staging");
    fs::create_dir(&staging).unwrap();
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(staging.join(ID)).unwrap();
    fs::set_permissions(staging.join(ID), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(staging.join(ID).join("artifact.rpm"), b"staged").unwrap();
    fs::set_permissions(
        staging.join(ID).join("artifact.rpm"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert_eq!(
        recover_with_staging(&journal, &staging, &id).unwrap(),
        RecoveryAction::CleanupRevalidateAndReapprove
    );
    assert!(!staging.join(ID).exists());
    assert_eq!(
        recover_with_staging(&journal, &staging, &id).unwrap(),
        RecoveryAction::CleanupRevalidateAndReapprove
    );
}

#[test]
fn staging_ancestor_replacement_cannot_redirect_prepared_cleanup() {
    let (temporary, store, id) = setup();
    let journal = store.create(&id, DIGEST).unwrap();
    let parent = temporary.path().join("parent");
    let staging = parent.join("staging");
    fs::create_dir(&parent).unwrap();
    fs::create_dir(&staging).unwrap();
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(staging.join(ID)).unwrap();
    fs::set_permissions(staging.join(ID), fs::Permissions::from_mode(0o700)).unwrap();
    let attacker = temporary.path().join("attacker");
    fs::create_dir(&attacker).unwrap();
    fs::set_permissions(&attacker, fs::Permissions::from_mode(0o700)).unwrap();
    fs::rename(&parent, temporary.path().join("retained-parent")).unwrap();
    std::os::unix::fs::symlink(&attacker, &parent).unwrap();
    assert!(recover_with_staging(&journal, &staging, &id).is_err());
    assert_eq!(fs::read_dir(attacker).unwrap().count(), 0);
}

#[test]
fn malformed_torn_and_duplicate_sequences_hard_fail() {
    let (temporary, store, id) = setup();
    drop(store.create(&id, DIGEST).unwrap());
    let directory = temporary.path().join("transactions").join(ID);
    fs::write(directory.join("00000000000000000002.json"), b"{}").unwrap();
    fs::set_permissions(
        directory.join("00000000000000000002.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let journal = store.open_transaction(&id).unwrap();
    assert!(matches!(journal.entries(), Err(StateError::Corrupt(_))));
}

#[test]
fn noncanonical_reordered_duplicate_and_unknown_state_records_fail() {
    for (suffix, mutation) in [
        (
            "space",
            " {\"native_result\":null,\"plan_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"reconciliation\":null,\"schema_version\":1,\"sequence\":0,\"state\":\"prepared\",\"transaction_id\":\"01890f6e-7b2c-7cc0-98c4-dc0c0c07398f\"}",
        ),
        (
            "duplicate",
            "{\"native_result\":null,\"plan_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"reconciliation\":null,\"schema_version\":1,\"schema_version\":1,\"sequence\":0,\"state\":\"prepared\",\"transaction_id\":\"01890f6e-7b2c-7cc0-98c4-dc0c0c07398f\"}",
        ),
        (
            "unknown",
            "{\"native_result\":null,\"plan_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"reconciliation\":null,\"schema_version\":1,\"sequence\":0,\"state\":\"unknown\",\"transaction_id\":\"01890f6e-7b2c-7cc0-98c4-dc0c0c07398f\"}",
        ),
    ] {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(format!("transactions-{suffix}"));
        let store = JournalStore::open(&root).unwrap();
        let id = TransactionId::parse(ID).unwrap();
        drop(store.create(&id, DIGEST).unwrap());
        let path = root.join(ID).join("00000000000000000000.json");
        fs::write(&path, mutation).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(store.open_transaction(&id).unwrap().entries().is_err());
    }
}

#[test]
fn canonical_forged_started_to_reconciled_transition_fails() {
    let (temporary, store, id) = setup();
    let journal = store.create(&id, DIGEST).unwrap();
    journal.mark_started().unwrap();
    drop(journal);
    let forged = format!(
        "{{\"native_result\":null,\"plan_sha256\":\"{DIGEST}\",\"reconciliation\":{{\"changed_packages\":0,\"inventory_sha256\":\"{DIGEST}\",\"success\":false}},\"schema_version\":1,\"sequence\":2,\"state\":\"reconciled\",\"transaction_id\":\"{ID}\"}}"
    );
    let path = temporary
        .path()
        .join("transactions")
        .join(ID)
        .join("00000000000000000002.json");
    fs::write(&path, forged).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(store.open_transaction(&id).unwrap().entries().is_err());
}

#[test]
fn symlinked_root_and_hardlinked_record_are_rejected() {
    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&target, temporary.path().join("transactions")).unwrap();
    assert!(JournalStore::open(&temporary.path().join("transactions")).is_err());
    let root = temporary.path().join("safe");
    let store = JournalStore::open(&root).unwrap();
    let id = TransactionId::parse(ID).unwrap();
    drop(store.create(&id, DIGEST).unwrap());
    fs::hard_link(
        root.join(ID).join("00000000000000000000.json"),
        temporary.path().join("copy"),
    )
    .unwrap();
    assert!(store.open_transaction(&id).unwrap().entries().is_err());
}

#[test]
fn retained_directory_is_not_redirected_by_path_swap() {
    let (temporary, store, id) = setup();
    let journal = store.create(&id, DIGEST).unwrap();
    let visible = temporary.path().join("transactions").join(ID);
    let retained = temporary.path().join("retained");
    fs::rename(&visible, &retained).unwrap();
    fs::create_dir(&visible).unwrap();
    fs::set_permissions(&visible, fs::Permissions::from_mode(0o700)).unwrap();
    journal.mark_started().unwrap();
    assert!(retained.join("00000000000000000001.json").exists());
    assert_eq!(fs::read_dir(visible).unwrap().count(), 0);
}

#[test]
fn event_log_marks_truncation_and_never_exceeds_limit() {
    let (temporary, store, id) = setup();
    let journal = store.create(&id, DIGEST).unwrap();
    let path = temporary
        .path()
        .join("transactions")
        .join(ID)
        .join("events.log");
    fs::write(&path, vec![b'x'; 64 * 1024 * 1024 - 8]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        journal.append_event(b"0123456789abcdef").unwrap(),
        LogAppend::Truncated
    );
    let bytes = fs::read(path).unwrap();
    let marker = b"[dnfast: log truncated at 67108864 bytes]";
    assert_eq!(bytes.len(), 64 * 1024 * 1024);
    assert_eq!(
        bytes
            .windows(marker.len())
            .filter(|window| *window == marker)
            .count(),
        1
    );
    assert_eq!(
        journal.append_event(b"ignored").unwrap(),
        LogAppend::Truncated
    );
}

#[test]
fn record_limit_plus_one_fails_before_json_parsing() {
    let (temporary, store, id) = setup();
    drop(store.create(&id, DIGEST).unwrap());
    let path = temporary
        .path()
        .join("transactions")
        .join(ID)
        .join("00000000000000000000.json");
    fs::write(&path, vec![b' '; 8 * 1024 * 1024 + 1]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let journal = store.open_transaction(&id).unwrap();
    assert!(matches!(
        journal.entries(),
        Err(StateError::Limit("record"))
    ));
}

#[test]
fn rpm_result_record_accepts_exact_eight_mib_and_rejects_plus_one() {
    let (temporary, store, id) = setup();
    let journal = store.create(&id, DIGEST).unwrap();
    journal.mark_started().unwrap();
    let empty = vec![String::new(); 9];
    let base = journal
        .rpm_result_encoded_len(-1, summary(), empty)
        .unwrap();
    let payload = bounded_chunks(8 * 1024 * 1024 - base);
    assert_eq!(
        journal
            .rpm_result_encoded_len(-1, summary(), payload.clone())
            .unwrap(),
        8 * 1024 * 1024
    );
    journal
        .record_rpm_result_with_problems(-1, summary(), payload)
        .unwrap();
    assert_eq!(
        fs::metadata(
            temporary
                .path()
                .join("transactions")
                .join(ID)
                .join("00000000000000000002.json")
        )
        .unwrap()
        .len(),
        8 * 1024 * 1024
    );

    let other_root = temporary.path().join("other");
    let other_store = JournalStore::open(&other_root).unwrap();
    let other_id = TransactionId::parse("01890f6e-7b2c-7cc0-98c4-dc0c0c073990").unwrap();
    let other = other_store.create(&other_id, DIGEST).unwrap();
    other.mark_started().unwrap();
    let too_large = bounded_chunks(8 * 1024 * 1024 - base + 1);
    assert!(matches!(
        other.record_rpm_result_with_problems(-1, summary(), too_large),
        Err(StateError::Limit("record"))
    ));
    assert_eq!(other.entries().unwrap().len(), 2);
}

#[test]
fn concurrent_creator_and_writer_fail_closed() {
    let (_temporary, store, id) = setup();
    let journal = store.create(&id, DIGEST).unwrap();
    assert!(store.create(&id, DIGEST).is_err());
    assert!(matches!(store.open_transaction(&id), Err(StateError::Busy)));
    journal.mark_started().unwrap();
}

#[test]
fn uuidv7_parser_rejects_wrong_version_case_and_shape() {
    assert!(TransactionId::parse("01890f6e-7b2c-6cc0-98c4-dc0c0c07398f").is_err());
    assert!(TransactionId::parse("01890F6E-7B2C-7CC0-98C4-DC0C0C07398F").is_err());
    assert!(TransactionId::parse("../escape").is_err());
}

#[test]
fn sigkill_after_started_recovers_without_run_surface() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("transactions");
    let ready = temporary.path().join("ready");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("sigkill_child")
        .arg("--nocapture")
        .env("DNFAST_STATE_CHILD_ROOT", &root)
        .env("DNFAST_STATE_CHILD_READY", &ready)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !ready.exists() && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(ready.exists());
    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::KILL).unwrap();
    assert!(!child.wait().unwrap().success());
    let store = JournalStore::open(&root).unwrap();
    let journal = store
        .open_transaction(&TransactionId::parse(ID).unwrap())
        .unwrap();
    assert_eq!(recover(&journal).unwrap(), RecoveryAction::ReconcileOnly);
    assert_eq!(journal.entries().unwrap().len(), 3);
}

#[test]
fn sigkill_child() {
    let Ok(root) = std::env::var("DNFAST_STATE_CHILD_ROOT") else {
        return;
    };
    let ready = std::env::var("DNFAST_STATE_CHILD_READY").unwrap();
    let store = JournalStore::open(std::path::Path::new(&root)).unwrap();
    let journal = store
        .create(&TransactionId::parse(ID).unwrap(), DIGEST)
        .unwrap();
    journal.mark_started().unwrap();
    fs::write(ready, b"ready").unwrap();
    std::thread::sleep(std::time::Duration::from_secs(60));
}

fn summary() -> CallbackSummary {
    CallbackSummary {
        pretrans: 1,
        pre: 1,
        post: 1,
        triggers: 1,
        payload: 1,
        database: 1,
        script_log_truncated: false,
    }
}
fn result(success: bool) -> ReconcileResult {
    ReconcileResult {
        inventory_sha256: DIGEST.into(),
        success,
        changed_packages: u64::from(success),
    }
}
fn bounded_chunks(mut bytes: usize) -> Vec<String> {
    (0..9)
        .map(|_| {
            let size = bytes.min(1024 * 1024);
            bytes -= size;
            "x".repeat(size)
        })
        .collect()
}
