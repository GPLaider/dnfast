use dnfast_executor::{MountRoot, Staging};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err("mount swap probe requires root".into());
    }
    verify_pre_approval_swap()?;
    verify_post_approval_swap()?;
    println!("mount_swap_rejected=true");
    println!("post_approval_mount_swap_rejected=true");
    Ok(())
}

fn verify_pre_approval_swap() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("mount_probe=pre:create:before");
    let staging = Staging::create(b"{}")?;
    eprintln!("mount_probe=pre:create:after");
    let mut root = MountRoot::create(&staging)?;
    eprintln!("mount_probe=pre:swap:before");
    root.fixture_replace_bind_mount()
        .map_err(|error| format!("pre_swap: {error}"))?;
    eprintln!("mount_probe=pre:swap:after");
    eprintln!("mount_probe=pre:verify:before");
    if !root.fixture_replacement_has_sentinel() {
        return Err("mount swap did not replace root".into());
    }
    eprintln!("mount_probe=pre:verify:after");
    eprintln!("mount_probe=pre:allow_writes:before");
    let rejected = match root.allow_writes() {
        Ok(()) => false,
        Err(error) => {
            eprintln!("mount_probe=pre:allow_writes:error:{error}");
            true
        }
    };
    eprintln!("mount_probe=pre:allow_writes:after");
    eprintln!("mount_probe=pre:cleanup:before");
    if let Err(error) = root.cleanup() {
        return Err(format!("pre_cleanup: {error}").into());
    }
    eprintln!("mount_probe=pre:cleanup:after");
    staging.cleanup()?;
    std::fs::remove_file("/tmp/.dnfast-mount-swap-sentinel")?;
    if !rejected {
        return Err("mount swap was accepted".into());
    }
    Ok(())
}

fn verify_post_approval_swap() -> Result<(), Box<dyn std::error::Error>> {
    let staging = Staging::create(b"{}")?;
    eprintln!("mount_probe=post:first_instruction");
    eprintln!("mount_probe=post:create:before");
    let mut root = MountRoot::create(&staging)?;
    eprintln!("mount_probe=post:create:after");
    eprintln!("mount_probe=post:allow_writes:before");
    root.allow_writes()?;
    eprintln!("mount_probe=post:allow_writes:after");
    println!(
        "post_approval_mountinfo={}",
        std::fs::read_to_string("/proc/self/mountinfo")?
            .lines()
            .find(|line| line.split_whitespace().nth(4) == Some("/"))
            .ok_or("root mountinfo absent")?
    );
    eprintln!("mount_probe=post:replace:before");
    root.fixture_replace_current_root()?;
    if !root.fixture_current_root_has_sentinel() {
        return Err("post-approval mount swap did not replace root".into());
    }
    let rejected = root.verify_unchanged().is_err();
    root.cleanup()?;
    staging.cleanup()?;
    std::fs::remove_file("/.dnfast-current-root-sentinel")?;
    if !rejected {
        return Err("post-approval mount swap was accepted".into());
    }
    Ok(())
}
