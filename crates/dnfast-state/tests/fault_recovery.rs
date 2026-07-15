use std::{io::Write, sync::Arc};
use dnfast_state::{FaultPlan, FaultPoint, JournalStore, RecoveryAction, TransactionId, recover};

const ID: &str = "01890f6e-7b2c-7cc0-98c4-dc0c0c07398f";
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn every_durable_publish_boundary_failure_has_conservative_authority() {
    for point in [FaultPoint::Write, FaultPoint::FileSync, FaultPoint::Publish, FaultPoint::DirectorySync] {
        let temporary = tempfile::tempdir().unwrap();
        let faults = Arc::new(FaultPlan::none());
        let store = JournalStore::with_faults(&temporary.path().join("transactions"), faults.clone()).unwrap();
        let id = TransactionId::parse(ID).unwrap();
        let journal = store.create(&id, DIGEST).unwrap(); faults.arm(point);
        assert!(journal.mark_started().is_err());
        if point == FaultPoint::DirectorySync {
            assert_eq!(journal.entries().unwrap().len(), 2);
            assert_eq!(recover(&journal).unwrap(), RecoveryAction::ReconcileOnly);
        } else {
            assert_eq!(journal.entries().unwrap().len(), 1);
            assert_eq!(recover(&journal).unwrap(), RecoveryAction::CleanupRevalidateAndReapprove);
        }
    }
}

#[test]
fn failed_sequence_zero_publication_cleans_uuid_and_retry_succeeds() {
    for point in [FaultPoint::Write, FaultPoint::FileSync, FaultPoint::Publish, FaultPoint::DirectorySync] {
        let temporary = tempfile::tempdir().unwrap();
        let faults = Arc::new(FaultPlan::none());
        let store = JournalStore::with_faults(&temporary.path().join("transactions"), faults.clone()).unwrap();
        let id = TransactionId::parse(ID).unwrap(); faults.arm(point);
        assert!(store.create(&id, DIGEST).is_err());
        assert!(!temporary.path().join("transactions").join(ID).exists());
        assert_eq!(store.create(&id, DIGEST).unwrap().entries().unwrap().len(), 1);
    }
    let temporary = tempfile::tempdir().unwrap();
    let faults = Arc::new(FaultPlan::once(FaultPoint::Create));
    let store = JournalStore::with_faults(&temporary.path().join("transactions"), faults).unwrap();
    assert!(store.create(&TransactionId::parse(ID).unwrap(), DIGEST).is_err());
}

#[test]
fn actual_os_enospc_source_preserves_prior_sequence_on_write_abort() {
    let error = std::fs::OpenOptions::new().write(true).open("/dev/full").unwrap().write_all(b"probe").unwrap_err();
    assert_eq!(error.raw_os_error(), Some(28));
    let temporary = tempfile::tempdir().unwrap();
    let faults = Arc::new(FaultPlan::none());
    let store = JournalStore::with_faults(&temporary.path().join("transactions"), faults.clone()).unwrap();
    let id = TransactionId::parse(ID).unwrap(); let journal = store.create(&id, DIGEST).unwrap();
    faults.arm(FaultPoint::Write); assert!(journal.mark_started().is_err());
    assert_eq!(journal.entries().unwrap().len(), 1);
    assert_eq!(recover(&journal).unwrap(), RecoveryAction::CleanupRevalidateAndReapprove);
}

#[test]
fn bounded_journal_filesystem_enospc_keeps_prepared_authoritative() {
    let temporary = tempfile::tempdir().unwrap();
    let status = std::process::Command::new("unshare").args(["-Ur", "-m"])
        .arg(std::env::current_exe().unwrap()).arg("--exact").arg("journal_enospc_child").arg("--nocapture")
        .env("DNFAST_ENOSPC_MOUNT", temporary.path()).status().unwrap();
    assert!(status.success());
}

#[test]
fn journal_enospc_child() {
    let Ok(path) = std::env::var("DNFAST_ENOSPC_MOUNT") else { return; };
    let mounted = std::process::Command::new("mount").args(["-t", "tmpfs", "-o", "size=1m", "tmpfs", &path]).status().unwrap();
    assert!(mounted.success());
    let root = std::path::Path::new(&path).join("transactions");
    let store = JournalStore::open(&root).unwrap(); let id = TransactionId::parse(ID).unwrap();
    let journal = store.create(&id, DIGEST).unwrap();
    let mut filler = std::fs::File::create(std::path::Path::new(&path).join("filler")).unwrap();
    let block = [0u8; 4096]; while filler.write_all(&block).is_ok() {}
    assert!(journal.mark_started().is_err());
    assert_eq!(journal.entries().unwrap().len(), 1);
    assert_eq!(recover(&journal).unwrap(), RecoveryAction::CleanupRevalidateAndReapprove);
}
