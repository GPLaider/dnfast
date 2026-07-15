fn main() {
    let mut context =
        dnfast_native::NativeContext::open(dnfast_core::Architecture::Aarch64, || false)
            .expect("native context");
    context.add_installed_rpmdb("/").expect("installed rpmdb");
}
