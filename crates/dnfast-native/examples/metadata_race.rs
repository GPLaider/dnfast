use dnfast_core::Architecture;
use dnfast_native::{NativeContext, NativeLimits, Repository};
use std::cell::Cell;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::rc::Rc;

fn repo(specification: &str) -> Repository {
    let fields: Vec<_> = specification.split(',').collect();
    Repository { id: fields[0].into(), repomd_path: fields[1].into(), primary_path: fields[2].into(), filelists_path: fields[3].into(), priority: fields[4].parse().unwrap(), cost: fields[5].parse().unwrap() }
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    let mode = arguments.next().unwrap();
    let failing = repo(&arguments.next().unwrap());
    let valid = repo(&arguments.next().unwrap());
    let primary = failing.primary_path.clone();
    let callback_mode = mode.clone();
    let calls = Rc::new(Cell::new(0_u8));
    let callback_calls = Rc::clone(&calls);
    let mut context = NativeContext::open_with_limits(Architecture::Aarch64, move || {
        let call = callback_calls.get() + 1;
        callback_calls.set(call);
        let barrier = if callback_mode == "grow-final" { 3 } else { 2 };
        if call == barrier {
            if callback_mode.starts_with("grow") {
                OpenOptions::new().append(true).open(&primary).unwrap().write_all(b"\n").unwrap();
            } else {
                fs::rename(format!("{primary}.replacement"), &primary).unwrap();
            }
        }
        false
    }, NativeLimits { max_packages: 25, max_relations_per_package: 5, max_metadata_bytes: u64::MAX }).unwrap();
    assert!(context.add_repository(failing).is_err());
    context.add_repository(valid).unwrap();
    let result = context.solve_install("dnfast-app", false, false).unwrap();
    assert_eq!(result.actions.last().unwrap(), "dnfast-app-0:1.0-1.noarch");
    println!("assert metadata-{mode}-rollback=true");
}
