use dnfast_native::{ExecutionState, ExecutorInventory, InventoryError, InventoryReader, KeyringInstalled};

fn main() {
    let mut reader = InventoryReader::open(dnfast_core::Architecture::Aarch64).expect("inventory reader");
    let expected = reader.read().expect("initial inventory");
    let mut run_count = 0usize;
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    dnfast_native::fixture_reset_inventory_counts();
    if arguments.first().map(String::as_str) == Some("--test-fail") {
        let mut execution = ExecutorInventory::begin(dnfast_core::Architecture::Aarch64, KeyringInstalled::fixture().expect("fixture keyring"), &expected).expect("prepared context");
        execution.fixture_fail_next_test();
        assert!(matches!(execution.test_transaction(), Err(InventoryError::TestFailed(-99))));
        assert_eq!(execution.state(), ExecutionState::TestFailed(-99));
        assert!(matches!(execution.run_transaction(), Err(InventoryError::InvalidState)));
        assert_eq!(dnfast_native::fixture_inventory_counts(), (1, 0));
        println!("test_failed=-99 test_calls=1 real_calls=0");
    } else if arguments.first().map(String::as_str) == Some("--interrupt-contention") {
        let mut holder = std::process::Command::new(&arguments[1]).arg(&arguments[2]).spawn().expect("lock holder");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !std::path::Path::new(&arguments[2]).exists() && std::time::Instant::now() < deadline { std::thread::sleep(std::time::Duration::from_millis(10)); }
        let interrupted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let signal = interrupted.clone();
        let trigger = std::thread::spawn(move || { std::thread::sleep(std::time::Duration::from_millis(200)); signal.store(true, std::sync::atomic::Ordering::Release); });
        let started = std::time::Instant::now();
        assert!(matches!(ExecutorInventory::begin_interruptible(dnfast_core::Architecture::Aarch64, KeyringInstalled::fixture().expect("fixture keyring"), &expected, interrupted), Err(InventoryError::Interrupted)));
        trigger.join().expect("interrupt trigger");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert_eq!(dnfast_native::fixture_inventory_counts(), (0, 0));
        holder.kill().expect("kill holder");
        holder.wait().expect("wait holder");
        let mut replacement = ExecutorInventory::begin(dnfast_core::Architecture::Aarch64, KeyringInstalled::fixture().expect("replacement keyring"), &expected).expect("released authority and context");
        replacement.request_cancel().expect("replacement cancel");
        println!("interrupted_promptly=true test_calls=0 real_calls=0");
    } else if arguments.first().map(String::as_str) == Some("--cancel-before") {
        let mut execution = ExecutorInventory::begin(dnfast_core::Architecture::Aarch64, KeyringInstalled::fixture().expect("fixture keyring"), &expected).expect("prepared context");
        execution.request_cancel().expect("pre-start cancel");
        let mut replacement = ExecutorInventory::begin(dnfast_core::Architecture::Aarch64, KeyringInstalled::fixture().expect("replacement keyring"), &expected).expect("released authority");
        replacement.request_cancel().expect("replacement cancel");
        println!("pre_start_cancel_released=true");
    } else if arguments.first().map(String::as_str) == Some("--contention") {
        let mut holder = std::process::Command::new(&arguments[1]).arg(&arguments[2]).spawn().expect("lock holder");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !std::path::Path::new(&arguments[2]).exists() && std::time::Instant::now() < deadline { std::thread::sleep(std::time::Duration::from_millis(10)); }
        let started = std::time::Instant::now();
        assert!(ExecutorInventory::begin(dnfast_core::Architecture::Aarch64, KeyringInstalled::fixture().expect("fixture keyring"), &expected).is_err());
        println!("contention_elapsed={}", started.elapsed().as_secs());
        holder.kill().expect("kill holder");
        holder.wait().expect("wait holder");
    } else if let Some(rpm) = arguments.first() {
        let status = std::process::Command::new("sudo").args(["rpm", "--nodeps", "--nosignature", "-i", &rpm]).status().expect("rpm mutation");
        assert!(status.success());
        match ExecutorInventory::begin(dnfast_core::Architecture::Aarch64, KeyringInstalled::fixture().expect("fixture keyring"), &expected) {
            Err(InventoryError::StaleInventory) => println!("stale_inventory=true"),
            _ => panic!("external mutation was not rejected"),
        }
    } else {
        let mut execution = ExecutorInventory::begin(dnfast_core::Architecture::Aarch64, KeyringInstalled::fixture().expect("fixture keyring"), &expected).expect("same inventory");
        let order = execution.native_call_order();
        assert_eq!(order, (1, 2));
        let test_result = execution.test_transaction().expect("actual RPM TEST");
        assert_eq!(test_result, 0);
        let test_count = execution.rpm_run_count();
        assert_eq!(test_count, 1);
        let run_result = execution.run_transaction().expect("actual RPM run");
        assert_eq!(run_result, 0);
        assert!(matches!(execution.request_cancel(), Err(InventoryError::TooLate)));
        assert!(execution.fixture_authority_is_held());
        execution.reconcile().expect("post-start reconcile");
        run_count = execution.rpm_run_count() as usize;
        println!("keyring_sequence={} rpmdb_sequence={} test_result={test_result} test_count={test_count} run_result={run_result} too_late_held=true", order.0, order.1);
    }
    println!("real_run_count={run_count}");
}
