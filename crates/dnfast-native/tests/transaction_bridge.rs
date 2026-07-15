use dnfast_native::{TransactionFailureClass, TransactionProblem};

#[test]
fn failure_class_never_claims_zero_write_after_real_run_starts() {
    assert_eq!(
        TransactionFailureClass::from_real_result(-1),
        TransactionFailureClass::PotentiallyStateful,
    );
}

#[test]
fn transaction_problems_preserve_native_text() {
    let problem = TransactionProblem::new("file /usr/bin/tool conflicts")
        .expect("valid native problem");
    assert_eq!(problem.as_str(), "file /usr/bin/tool conflicts");
    assert!(TransactionProblem::new("").is_err());
}
