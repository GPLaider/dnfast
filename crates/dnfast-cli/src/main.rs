#![forbid(unsafe_code)]

mod args;
mod commands;
mod environment;
mod rendering;
mod response;

use std::{ffi::OsString, process::ExitCode};

use args::Cli;
use clap::error::ErrorKind;
use clap::{CommandFactory, Parser};
use response::{JsonOutput, Response, emit};

const UNSUPPORTED_COMMANDS: &[&str] = &[
    "group",
    "environment",
    "module",
    "plugin",
    "copr",
    "system-upgrade",
    "offline",
    "autoremove",
    "downgrade",
    "reinstall",
    "distro-sync",
    "advisory",
    "history",
];

fn main() -> ExitCode {
    let arguments = match arguments() {
        Ok(arguments) => arguments,
        Err(()) => {
            return emit_failure(
                "cli",
                2,
                "syntax_error",
                "arguments must be valid UTF-8".into(),
                JsonOutput::NativeV1,
            );
        }
    };
    if let Some(command) = unsupported_top_level_command(arguments.iter().cloned()) {
        return match emit(&Response::unsupported(command), JsonOutput::NativeV1) {
            Ok(()) => ExitCode::from(2),
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::from(1)
            }
        };
    }
    let cli = match Cli::try_parse_from(
        std::iter::once("dnfast").chain(arguments.iter().map(String::as_str)),
    ) {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(error.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                let command = command_from_arguments(arguments.iter().cloned()).unwrap_or("cli");
                return emit_completed(command, error.to_string(), JsonOutput::NativeV1);
            }
            let command = command_from_arguments(arguments.iter().cloned()).unwrap_or("cli");
            return emit_failure(command, 2, "syntax_error", error.to_string(), JsonOutput::NativeV1);
        }
    };
    let output = cli.json_output();
    let Some(command) = cli.command else {
        return emit_completed("cli", Cli::command().render_long_help().to_string(), output);
    };
    let command_name = commands::name(&command);
    match commands::run(command) {
        Ok(response) => match emit(&response, output) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::from(1)
            }
        },
        Err(error) => emit_failure(command_name, error.code, error.error_code, error.message, output),
    }
}

fn arguments() -> Result<Vec<String>, ()> {
    std::env::args_os()
        .skip(1)
        .map(OsString::into_string)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ())
}

fn emit_completed(command: &str, message: String, output: JsonOutput) -> ExitCode {
    match emit(&Response::completed(command, message), output) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn emit_failure(command: &str, exit_code: u8, code: &str, message: String, output: JsonOutput) -> ExitCode {
    match emit(&Response::failed(command, exit_code, code, message), output) {
        Ok(()) => ExitCode::from(exit_code),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn command_from_arguments(arguments: impl IntoIterator<Item = String>) -> Option<&'static str> {
    match first_command_argument(arguments)?.as_str() {
        "plan" => Some("plan"),
        "apply" => Some("apply"),
        "install" => Some("install"),
        "remove" => Some("remove"),
        "upgrade" => Some("upgrade"),
        "repo" => Some("repo"),
        "search" => Some("search"),
        "doctor" => Some("doctor"),
        _ => Some("cli"),
    }
}

fn unsupported_top_level_command(arguments: impl IntoIterator<Item = String>) -> Option<&'static str> {
    let first = first_command_argument(arguments)?;
    UNSUPPORTED_COMMANDS
        .iter()
        .copied()
        .find(|candidate| *candidate == first)
}

fn first_command_argument(arguments: impl IntoIterator<Item = String>) -> Option<String> {
    arguments.into_iter().find(|argument| argument != "--json")
}

#[cfg(test)]
mod tests {
    use super::unsupported_top_level_command;

    #[test]
    fn unsupported_command_is_detected_before_clap() {
        // Given an unsupported mutation command.
        let arguments = ["history".to_owned(), "undo".to_owned()];
        // When the pre-dispatch boundary examines the command.
        let detected = unsupported_top_level_command(arguments);
        // Then it is classified before any configuration or solver is reachable.
        assert_eq!(detected, Some("history"));
    }
}
