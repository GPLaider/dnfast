use std::{fs, os::fd::AsRawFd, process::ExitCode};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let key_path = match args.next() {
        Some(value) => value,
        None => return ExitCode::from(2),
    };
    let rpm_path = match args.next() {
        Some(value) => value,
        None => return ExitCode::from(2),
    };
    let key = match fs::read(key_path) {
        Ok(value) => value,
        Err(_) => return ExitCode::from(2),
    };
    let rpm = match fs::File::open(rpm_path) {
        Ok(value) => value,
        Err(_) => return ExitCode::from(2),
    };
    let keyring = match dnfast_native_sys::Keyring::open(&[&key]) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("keyring:{}:{}", error.status, error.message);
            return ExitCode::FAILURE;
        }
    };
    match keyring.verify_fd(rpm.as_raw_fd()) {
        Ok(package) => {
            println!(
                "{}-{}:{}-{}.{} primary={} signing={}",
                package.name,
                package.epoch,
                package.version,
                package.release,
                package.arch,
                package.primary_fingerprint,
                package.signing_fingerprint
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("verify:{}:{}", error.status, error.message);
            ExitCode::FAILURE
        }
    }
}
