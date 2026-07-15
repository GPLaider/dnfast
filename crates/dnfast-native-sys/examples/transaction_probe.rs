use std::{env, fs, os::fd::AsRawFd, time::Duration};

use dnfast_native_sys::{Context, Keyring, PoolArchitecture};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let key_path = arguments.next().ok_or("missing key path")?;
    let rpm_path = arguments.next().ok_or("missing RPM path")?;
    let mode = arguments.next().unwrap_or_else(|| "happy".into());
    let key = fs::read(key_path)?;
    let keyring = Keyring::open(&[&key])?;
    let rpm = fs::File::open(&rpm_path)?;
    let verified = keyring.verify_fd(rpm.as_raw_fd())?;
    let bytes = fs::read(&rpm_path)?;
    use sha2::{Digest as _, Sha256};
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let mut context = Context::open(PoolArchitecture::Aarch64, || false)?;
    context.begin_inventory_write(&keyring, "/", Duration::from_secs(30))?;
    context.transaction_add_install(
        &keyring,
        rpm.as_raw_fd(),
        &verified,
        &digest,
        u64::try_from(bytes.len())?,
        mode == "upgrade",
    )?;
    if mode == "mutation" {
        use std::io::{Seek, SeekFrom, Write};
        let mut writer = fs::OpenOptions::new().write(true).open(&rpm_path)?;
        writer.seek(SeekFrom::Start(128))?;
        writer.write_all(&[bytes[128] ^ 1])?;
        writer.sync_all()?;
        if context.transaction_prepare().is_ok() {
            return Err("in-place mutation passed".into());
        }
        let counts = context.transaction_counts();
        println!("mutation_rejected=true real_runs={}", counts.real_run);
        if counts.real_run != 0 {
            return Err("mutation reached real run".into());
        }
        return Ok(());
    }
    if let Some(point) = mode.strip_prefix("callback-") {
        context.transaction_prepare()?;
        let point = match point {
            "open" => 1,
            "rewind" => 2,
            "close" => 3,
            _ => return Err("unknown callback fault".into()),
        };
        context.fixture_fail_transaction_callback(point);
        if context.transaction_test().is_ok() {
            return Err("callback fault passed".into());
        }
        let counts = context.transaction_counts();
        println!(
            "callback_fault={point} opens={}/{} open_failed={} rewinds={}/{} rewind_failed={} closes={}/{} close_failed={} real_runs={}",
            counts.fd_open,
            counts.open_attempted,
            counts.open_failed,
            counts.rewind_succeeded,
            counts.rewind_attempted,
            counts.rewind_failed,
            counts.fd_close,
            counts.close_attempted,
            counts.close_failed,
            counts.real_run
        );
        if counts.real_run != 0
            || (point == 3
                && (counts.fd_open != 2
                    || counts.fd_close != 0
                    || counts.close_attempted != 2
                    || counts.close_failed != 2))
            || (point != 3 && (counts.fd_open != 0 || counts.fd_close != 0))
        {
            return Err("callback fault counts differ".into());
        }
        return Ok(());
    }
    if mode == "check-failure" || mode == "order-failure" {
        context.fixture_fail_transaction_callback(if mode == "check-failure" { 4 } else { 5 });
        if context.transaction_prepare().is_ok() {
            return Err("preflight fault passed".into());
        }
        let counts = context.transaction_counts();
        println!("preflight_fault={mode} real_runs={}", counts.real_run);
        if counts.real_run != 0 {
            return Err("preflight fault reached real run".into());
        }
        return Ok(());
    }
    if mode == "preflight-failure" {
        let stage = if context.transaction_prepare().is_err() {
            "check"
        } else {
            if context.transaction_test().is_ok() {
                return Err("TEST unexpectedly passed".into());
            }
            "test"
        };
        let counts = context.transaction_counts();
        let problems = context.transaction_problems()?;
        println!(
            "preflight_failed=true stage={stage} test_runs={} real_runs={} problems={}",
            counts.test_run,
            counts.real_run,
            problems.join(" | ")
        );
        if counts.real_run != 0 || problems.is_empty() {
            return Err("preflight failure contract differs".into());
        }
        return Ok(());
    }
    context.transaction_prepare()?;
    let test = context.transaction_test()?;
    let after_test = context.transaction_counts();
    if mode == "start-panic" {
        context.set_transaction_start_callback(|| panic!("transaction_start fixture panic"));
        if context.transaction_run().is_ok() {
            return Err("start panic passed".into());
        }
        let counts = context.transaction_counts();
        println!(
            "transaction_start_panic=contained real_runs={} phase={:?}",
            counts.real_run,
            context.transaction_phase()?
        );
        if counts.real_run != 0
            || context.transaction_phase()? != dnfast_native_sys::TransactionPhase::Preflight
        {
            return Err("start panic crossed real boundary".into());
        }
        return Ok(());
    }
    if mode == "payload-failure" {
        context.fixture_fail_transaction_callback(7);
    }
    let real = match context.transaction_run() {
        Ok(result) => result,
        Err(error) if mode == "real-failure" || mode == "payload-failure" => {
            let counts = context.transaction_counts();
            let problems = context.transaction_problems()?;
            println!(
                "potentially_stateful=true real_runs={} problems={} error={error}",
                counts.real_run,
                problems.join(" | ")
            );
            if counts.real_run != 1 {
                return Err("real failure call count differs".into());
            }
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    if mode == "real-failure" || mode == "payload-failure" {
        return Err("real transaction unexpectedly passed".into());
    }
    if mode == "db-failure" {
        context.fixture_fail_transaction_callback(6);
        if context.transaction_verify_db().is_ok() {
            return Err("DB fault passed".into());
        }
        println!(
            "db_failure=true potentially_stateful=true real_runs={}",
            context.transaction_counts().real_run
        );
        return Ok(());
    }
    context.transaction_verify_db()?;
    let final_counts = context.transaction_counts();
    println!(
        "test={test} real={real} opens={} closes={} test_runs={} real_runs={} scripts={}/{} packages={}",
        final_counts.fd_open,
        final_counts.fd_close,
        final_counts.test_run,
        final_counts.real_run,
        final_counts.script_start,
        final_counts.script_stop,
        final_counts.package_stop
    );
    if after_test.test_run != 1
        || after_test.real_run != 0
        || final_counts.test_run != 1
        || final_counts.real_run != 1
        || final_counts.fd_open != final_counts.fd_close
    {
        return Err("transaction lifecycle counts differ".into());
    }
    Ok(())
}
