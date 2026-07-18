use dnfast_state::{
    CallbackSummary, GroupRecord, GroupStateStore, JournalStore, ReconcileResult, TransactionId,
};

const PLAN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn pending_group_state_requires_a_new_successful_terminal_journal() {
    let fixture = tempfile::tempdir().expect("fixture");
    let groups = fixture.path().join("groups");
    let transactions = fixture.path().join("transactions");
    let journal = JournalStore::open(&transactions).expect("journal");
    finish(&journal, "018f22a0-0000-7000-8000-000000000001", true);
    let store = GroupStateStore::open_with_journal(&groups, &transactions).expect("group store");
    let records = [GroupRecord {
        id: "editors".into(),
        owned_packages: vec!["vim-enhanced".into()],
    }];

    store
        .record_pending_install(PLAN, &records, &["vim-enhanced".into()])
        .expect("pending install");
    assert!(store.installed_group_ids().expect("ids").is_empty());

    finish(&journal, "018f22a0-0000-7000-8000-000000000002", false);
    assert!(store.installed_group_ids().expect("failed ids").is_empty());

    store
        .record_pending_install(PLAN, &records, &["vim-enhanced".into()])
        .expect("second pending install");
    finish(&journal, "018f22a0-0000-7000-8000-000000000003", true);
    assert_eq!(
        store.installed_group_ids().expect("successful ids"),
        vec!["editors"]
    );
}

#[test]
fn overlapping_group_ownership_removes_only_the_last_owner() {
    let fixture = tempfile::tempdir().expect("fixture");
    let store = GroupStateStore::open_with_journal(
        &fixture.path().join("groups"),
        &fixture.path().join("transactions"),
    )
    .expect("group store");
    store
        .apply_install_now(
            &[
                GroupRecord {
                    id: "first".into(),
                    owned_packages: vec!["common".into(), "first-only".into()],
                },
                GroupRecord {
                    id: "second".into(),
                    owned_packages: vec!["common".into(), "second-only".into()],
                },
            ],
            &["common".into(), "first-only".into(), "second-only".into()],
        )
        .expect("install records");

    assert_eq!(
        store
            .packages_to_remove(&["first".into()])
            .expect("first removal"),
        vec!["first-only"]
    );
    store
        .apply_remove_now(&["first".into()])
        .expect("remove first");
    assert_eq!(
        store
            .packages_to_remove(&["second".into()])
            .expect("second removal"),
        vec!["common", "second-only"]
    );
}

#[test]
fn sequential_group_install_retains_a_shared_package_and_never_adopts_a_direct_one() {
    let fixture = tempfile::tempdir().expect("fixture");
    let store = GroupStateStore::open_with_journal(
        &fixture.path().join("groups"),
        &fixture.path().join("transactions"),
    )
    .expect("group store");
    store
        .apply_install_now(
            &[GroupRecord {
                id: "first".into(),
                owned_packages: vec!["common".into(), "first-only".into()],
            }],
            &["common".into(), "first-only".into()],
        )
        .expect("first install");
    store
        .apply_install_now(
            &[GroupRecord {
                id: "second".into(),
                owned_packages: vec!["common".into(), "direct".into()],
            }],
            &[],
        )
        .expect("second install");

    assert_eq!(
        store
            .packages_to_remove(&["first".into()])
            .expect("first removal"),
        vec!["first-only"]
    );
    store
        .apply_remove_now(&["first".into()])
        .expect("remove first");
    assert_eq!(
        store
            .packages_to_remove(&["second".into()])
            .expect("second removal"),
        vec!["common"]
    );
}

fn finish(store: &JournalStore, id: &str, success: bool) {
    let id = TransactionId::parse(id).expect("transaction id");
    let journal = store.create(&id, PLAN).expect("create transaction");
    journal.mark_started().expect("started");
    journal
        .record_rpm_result(
            if success { 0 } else { 1 },
            CallbackSummary {
                pretrans: 0,
                pre: 0,
                post: 0,
                triggers: 0,
                payload: 0,
                database: 0,
                script_log_truncated: false,
            },
        )
        .expect("rpm result");
    journal
        .reconcile(ReconcileResult {
            inventory_sha256: "b".repeat(64),
            success,
            changed_packages: u64::from(success),
        })
        .expect("reconciled");
}
