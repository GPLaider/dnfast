fn main() {
    println!("cargo:rerun-if-env-changed=DNFAST_NATIVE_REAL");
    println!("cargo:rerun-if-changed=../../native/include/dnfast_native.h");
    for file in ["common.c", "solver.c", "solver_state.c", "decisions.c", "actions.c", "installed.c", "inventory.c", "inventory_write.c", "transaction.c", "transaction_run.c", "transaction_result.c", "transaction_payload_fault.c", "keyring.c", "keyring_identity.c", "rpm_signature.c", "rpm_payload.c", "limits.c", "metadata_io.c", "rpm.c", "callbacks.c", "authority.c", "executor_fd.c"] {
        println!("cargo:rerun-if-changed=../../native/src/{file}");
    }
    let mut build = cc::Build::new();
    let mut real_link_libraries = Vec::new();
    build
        .include("../../native/include")
        .include("../../native/src");
    if std::env::var("DNFAST_NATIVE_REAL").as_deref() == Ok("1") {
        let solv = pkg_config::Config::new()
            .cargo_metadata(false)
            .exactly_version("0.7.39")
            .probe("libsolv")
            .unwrap_or_else(|error| panic!("libsolv 0.7.39 build contract failed: {error}"));
        let rpm = pkg_config::Config::new()
            .cargo_metadata(false)
            .exactly_version("6.0.1")
            .probe("rpm")
            .unwrap_or_else(|error| panic!("RPM 6.0.1 build contract failed: {error}"));
        for include in solv.include_paths.iter().chain(rpm.include_paths.iter()) {
            build.include(include);
        }
        build.define("DNFAST_NATIVE_REAL", None);
        append_unique(&mut real_link_libraries, solv.libs);
        append_unique(&mut real_link_libraries, ["solvext".into(), "rpm".into(), "rpmio".into()]);
        append_unique(&mut real_link_libraries, rpm.libs);
    }
    build
        .files([
            "../../native/src/common.c",
            "../../native/src/solver.c",
            "../../native/src/solver_state.c",
            "../../native/src/decisions.c",
            "../../native/src/actions.c",
            "../../native/src/installed.c",
            "../../native/src/inventory.c",
            "../../native/src/inventory_write.c",
            "../../native/src/transaction.c",
            "../../native/src/transaction_run.c",
            "../../native/src/transaction_result.c",
            "../../native/src/transaction_payload_fault.c",
            "../../native/src/keyring.c",
            "../../native/src/keyring_identity.c",
            "../../native/src/rpm_signature.c",
            "../../native/src/rpm_payload.c",
            "../../native/src/limits.c",
            "../../native/src/metadata_io.c",
            "../../native/src/rpm.c",
            "../../native/src/callbacks.c",
            "../../native/src/authority.c",
            "../../native/src/executor_fd.c",
        ])
        .flag("-std=c17")
        .flag("-Wno-unused-parameter")
        .warnings_into_errors(true)
        .compile("dnfast_native");
    for library in real_link_libraries {
        println!("cargo:rustc-link-lib={library}");
    }
    println!("cargo:rustc-link-lib=dl");
    println!("cargo:rustc-link-lib=pthread");
}

fn append_unique(target: &mut Vec<String>, libraries: impl IntoIterator<Item = String>) {
    for library in libraries {
        if !target.contains(&library) { target.push(library); }
    }
}
