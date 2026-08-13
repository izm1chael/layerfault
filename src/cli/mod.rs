mod args;
mod commands;
mod dispatch;
mod output;
mod scan_setup;
mod validation;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use layerfault::admission::{self, ArtifactAdmission};
use layerfault::app::{self};
use layerfault::baseline::Baseline;
use layerfault::formats::artifact::{self, ArtifactScanMode};
use layerfault::policy::{PolicyDocument, PolicyProfile};
use layerfault::sources::SourceKind;
use layerfault::trust::TrustStore;
use layerfault::{
    advisory, audit, baseline, binding, certify, content_cache, doctor, evidence, explain, gc,
    inventory, json_stream, manifest, modeldiff, package, policy, provenance, quarantine, report,
    sigstore, sources,
};
use std::fs;
use std::path::{Path, PathBuf};

use args::*;
use output::*;
use scan_setup::*;
use validation::sigstore_request;

pub(crate) fn run() -> Result<()> {
    let cli = Cli::parse();
    if cli.no_cache {
        std::env::set_var("LAYERFAULT_HASH_CACHE", "off");
        std::env::set_var("LAYERFAULT_CONTENT_CACHE", "off");
    }
    if let Some(cache_dir) = cli.cache_dir.as_ref() {
        std::env::set_var("LAYERFAULT_CACHE_DIR", cache_dir.as_os_str());
    }
    dispatch::dispatch(cli)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behaviour_cli_enforces_mutation_cap_end_to_end() {
        fn parsed_mutation_count(requested: &str) -> usize {
            let cli = Cli::try_parse_from([
                "layerfault",
                "behaviour",
                "fixture.gguf",
                "--profile",
                "standard",
                "--max-mutations",
                requested,
            ])
            .expect("parse behaviour command");
            let Some(Command::Behaviour(args)) = cli.command else {
                panic!("expected behaviour command");
            };
            let limits = commands::behaviour::resolve_behaviour_limits(&args)
                .expect("resolve behaviour limits");
            let original =
                layerfault::behaviour::probes::load_suite(None).expect("load bundled probe suite");
            let original_count = original.probes.len();
            let expanded =
                layerfault::behaviour::probes::expand_mutations(original, limits.max_mutations);
            expanded.probes.len() - original_count
        }

        assert_eq!(parsed_mutation_count("7"), 7);
        assert_eq!(parsed_mutation_count("10000"), 32);
    }

    #[test]
    fn guarded_workflow_accepts_explicit_runtime_path() {
        let cli = Cli::try_parse_from([
            "layerfault",
            "run",
            "fixture.gguf",
            "--source",
            "llama-cpp",
            "--runtime-path",
            "/opt/llama/llama-cli",
        ])
        .expect("parse guarded run");
        let Some(Command::Run(args)) = cli.command else {
            panic!("expected run command");
        };
        assert_eq!(
            args.runtime_security.runtime_path.as_deref(),
            Some(Path::new("/opt/llama/llama-cli"))
        );
    }
}
