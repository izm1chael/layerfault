#![forbid(unsafe_code)]

mod cli;

use std::process::ExitCode;

/// `--json` is a per-subcommand clap flag (not global), so there is no single
/// typed field to check once a command has already failed to build its own
/// result. Scanning the raw args is what every caller who bothered to pass
/// `--json` in the first place is checking for, and is enough to decide
/// whether a hard failure should be reported as JSON instead of prose.
fn wants_json_output() -> bool {
    std::env::args().any(|arg| arg == "--json")
}

fn main() -> ExitCode {
    match cli::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            cli::render_failure(&error, wants_json_output());
            ExitCode::FAILURE
        }
    }
}
