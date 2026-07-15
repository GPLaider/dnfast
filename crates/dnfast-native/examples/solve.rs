use dnfast_core::Architecture;
use dnfast_native::{NativeContext, NativeLimits, Repository};

fn repository(specification: &str) -> Repository {
    let fields: Vec<_> = specification.split(',').collect();
    assert_eq!(fields.len(), 6, "repo specification");
    Repository {
        id: fields[0].into(),
        repomd_path: fields[1].into(),
        primary_path: fields[2].into(),
        filelists_path: fields[3].into(),
        priority: fields[4].parse().expect("priority"),
        cost: fields[5].parse().expect("cost"),
    }
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    let names = arguments.next().expect("package names");
    let weak = arguments.next().as_deref() != Some("no-weak");
    let u32_value = |name: &str, fallback| {
        std::env::var(name)
            .ok()
            .and_then(|item| item.parse::<u32>().ok())
            .unwrap_or(fallback)
    };
    let u64_value = |name: &str, fallback| {
        std::env::var(name)
            .ok()
            .and_then(|item| item.parse::<u64>().ok())
            .unwrap_or(fallback)
    };
    let limits = NativeLimits {
        max_packages: u32_value("DNFAST_MAX_PACKAGES", 2_000_000),
        max_relations_per_package: u32_value("DNFAST_MAX_RELATIONS", 4_096),
        max_metadata_bytes: u64_value("DNFAST_MAX_METADATA_BYTES", 17_179_869_184),
    };
    let mut context = NativeContext::open_with_limits(Architecture::Aarch64, || false, limits)
        .expect("native context");
    if let Ok(root) = std::env::var("DNFAST_RPMDB_ROOT") {
        context.add_installed_rpmdb(&root).expect("installed rpmdb");
    }
    if let Ok(failing) = std::env::var("DNFAST_FAIL_REPO") {
        for _ in 0..3 {
            assert!(context.add_repository(repository(&failing)).is_err());
        }
    }
    for specification in arguments {
        let repository = repository(&specification);
        if repository.id == "@System" {
            context.add_installed_repository(repository)
        } else {
            context.add_repository(repository)
        }
        .expect("add repository");
    }
    if let Ok(residual) = std::env::var("DNFAST_RESIDUAL_NAME") {
        assert!(context.solve_install(&residual, false, false).is_err());
    }
    let names: Vec<_> = if names == "@all" {
        Vec::new()
    } else {
        names.split('+').collect()
    };
    let best = std::env::var("DNFAST_BEST").as_deref() == Ok("1");
    let result = match std::env::var("DNFAST_OPERATION").as_deref() {
        Ok("upgrade") => context.solve_upgrade_many(&names, best),
        Ok("erase") => context.solve_erase_many(&names),
        Ok(_) => panic!("unsupported DNFAST_OPERATION"),
        Err(_) => context.solve_install_many(&names, weak, best),
    }
    .expect("solve");
    for (((((action, repository), kind), counterpart), requested_spec), requested_relation_kind) in
        result
            .actions
            .into_iter()
            .zip(result.repositories)
            .zip(result.kinds)
            .zip(result.obsoletes)
            .zip(result.requested_specs)
            .zip(result.requested_relation_kinds)
    {
        println!("action\t{kind}\t{repository}\t{action}");
        if let Some(counterpart) = counterpart {
            println!("pair\t{action}\t{counterpart}");
        }
        if let Some(requested_spec) = requested_spec {
            println!("selector\t{requested_spec}\t{action}");
            println!(
                "selector-kind\t{}\t{action}",
                if requested_relation_kind {
                    "relation"
                } else {
                    "bare"
                }
            );
        }
    }
    for problem in result.problems {
        println!("problem\t{problem}");
    }
    for decision in result.decisions {
        println!(
            "decision\t{}\t{}\t{}\t{}\t{}",
            if decision.weak { "weak" } else { "strong" },
            if decision.provider_installed {
                "installed"
            } else {
                "action"
            },
            decision.requiring,
            decision.provider,
            decision.relation
        );
    }
}
