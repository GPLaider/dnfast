use dnfast_core::Architecture;
use dnfast_native::{NativeContext, Repository};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let repository = Repository {
        id: "main".into(),
        repomd_path: arguments.next().ok_or("missing repomd path")?,
        primary_path: arguments.next().ok_or("missing primary path")?,
        filelists_path: arguments.next().ok_or("missing filelists path")?,
        priority: 10,
        cost: 10,
    };
    if arguments.next().is_some() { return Err("unexpected argument".into()); }
    let mut context = NativeContext::open(Architecture::X86_64, || false)?;
    assert_eq!(context.pool_architecture()?, Architecture::X86_64);
    context.add_repository(repository)?;
    let result = context.solve_install("dnfast-noarch", false, false)?;
    if !result.actions.iter().any(|action| action == "dnfast-noarch-0:1.0-1.noarch") {
        return Err("x86_64 pool did not solve the noarch fixture".into());
    }
    println!("native_pool_arch=x86_64 noarch_solve=passed");
    Ok(())
}
