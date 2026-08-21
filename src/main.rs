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
            if wants_json_output() {
                let payload = serde_json::json!({
                    "error": {
                        "message": error.to_string(),
                        "causes": error.chain().skip(1).map(ToString::to_string).collect::<Vec<_>>(),
                    }
                });
                let _ = layerfault::json_stream::write_stdout_json(&payload, true);
            } else {
                eprintln!("Error: {error:?}");
            }
            ExitCode::FAILURE
        }
    }
}
