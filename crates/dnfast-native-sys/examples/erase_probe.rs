use std::{env, fs, time::Duration};

use dnfast_native_sys::{Context, Keyring, PoolArchitecture};

fn decode(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if value.len() != 64 { return Err("invalid digest length".into()); }
    let mut output = [0_u8; 32];
    for (index, target) in output.iter_mut().enumerate() {
        *target = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(output)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let key = fs::read(arguments.next().ok_or("missing key")?)?;
    let package_name = arguments.next().ok_or("missing package")?;
    let keyring = Keyring::open(&[&key])?;
    let mut context = Context::open(PoolArchitecture::Aarch64, || false)?;
    context.begin_inventory_write(&keyring, "/", Duration::from_secs(30))?;
    let inventory = context.read_locked_inventory()?;
    let package = inventory.packages.iter().find(|item| item.name == package_name)
        .ok_or("installed package missing")?;
    let digest = decode(&package.immutable_header_sha256)?;
    context.transaction_add_erase(package.db_instance, &digest)?;
    context.transaction_prepare()?;
    context.transaction_test()?;
    context.transaction_run()?;
    context.transaction_verify_db()?;
    let counts = context.transaction_counts();
    println!("erase=true test_runs={} real_runs={}", counts.test_run, counts.real_run);
    Ok(())
}
