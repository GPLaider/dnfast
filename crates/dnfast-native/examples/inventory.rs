use dnfast_core::{CanonicalDocument, InstalledInventory};

fn main() {
    let mut context = dnfast_native::NativeContext::open(dnfast_core::Architecture::Aarch64, || false).expect("native context");
    let inventory = context.read_installed_inventory().expect("installed inventory");
    emit(&inventory);
}

fn emit(inventory: &InstalledInventory) {
    println!("backend={}", inventory.rpmdb_backend());
    println!("rpm_version={}", inventory.rpm_version());
    println!("packages={}", inventory.packages().len());
    println!("digest={}", inventory.canonical_sha256().expect("inventory digest").as_str());
    for package in inventory.packages() {
        println!("package={} epoch={} version={} release={} arch={:?} vendor={} instance={} installtime={} header={}",
            package.name(), package.evra().epoch(), package.evra().version(), package.evra().release(),
            package.evra().arch(), package.vendor(), package.db_instance(), package.install_time(),
            package.immutable_header_sha256().as_str());
    }
}
