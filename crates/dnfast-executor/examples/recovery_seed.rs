use std::{io::Write, time::Duration};

const ID: &str = "018f1234-5678-7abc-8def-0123456789ab";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if rustix::process::geteuid().as_raw() != 0 { return Err("recovery seed requires root".into()); }
    let store = dnfast_state::JournalStore::open_system()?;
    let id = dnfast_state::TransactionId::parse(ID)?;
    let journal = store.create(&id, &"0".repeat(64))?;
    journal.mark_started()?;
    println!("recovery_seed_started={ID}");
    println!("recovery_seed_pid={}", std::process::id());
    std::io::stdout().flush()?;
    loop { std::thread::sleep(Duration::from_secs(60)); }
}
