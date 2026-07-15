use std::time::Instant;

use dnfast_core::CanonicalDocument;

fn main() {
    let mut context = dnfast_native::NativeContext::open(
        dnfast_core::Architecture::X86_64,
        || false,
    ).expect("native context");
    let started = Instant::now();
    let first = context.read_installed_inventory().expect("first inventory");
    let first_elapsed = started.elapsed();
    let started = Instant::now();
    let second = context.read_installed_inventory().expect("cached inventory");
    let second_elapsed = started.elapsed();
    assert_eq!(
        first.canonical_sha256().expect("first digest"),
        second.canonical_sha256().expect("second digest"),
    );
    println!(
        "packages={} first_ns={} unchanged_ns={}",
        first.packages().len(),
        first_elapsed.as_nanos(),
        second_elapsed.as_nanos(),
    );
}
