#![forbid(unsafe_code)]
#![deny(warnings)]

fn main() -> std::process::ExitCode {
    match dnfast_executor::serve_system() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dnfastd: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
