//! Bounded local behavioural security harness.

pub mod evaluate;
pub mod probes;
pub mod runtime;
pub mod sandbox;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviourLimits {
    pub max_prompts: usize,
    pub max_turns: usize,
    pub max_tokens: u64,
    pub max_output_bytes: usize,
    pub timeout_seconds: u64,
    pub max_mutations: usize,
    pub repeat_count: usize,
}

impl BehaviourLimits {
    pub fn for_profile(profile: &str) -> Result<Self> {
        match profile.to_ascii_lowercase().as_str() {
            "quick" => Ok(Self {
                max_prompts: 8,
                max_turns: 2,
                max_tokens: 256,
                max_output_bytes: 128 * 1024,
                timeout_seconds: 90,
                max_mutations: 0,
                repeat_count: 1,
            }),
            "standard" => Ok(Self {
                max_prompts: 64,
                max_turns: 4,
                max_tokens: 512,
                max_output_bytes: 256 * 1024,
                timeout_seconds: 120,
                max_mutations: 32,
                repeat_count: 1,
            }),
            "deep" => Ok(Self {
                max_prompts: 256,
                max_turns: 6,
                max_tokens: 768,
                max_output_bytes: 512 * 1024,
                timeout_seconds: 180,
                max_mutations: 256,
                repeat_count: 2,
            }),
            "research" => Ok(Self {
                max_prompts: 1000,
                max_turns: 8,
                max_tokens: 1024,
                max_output_bytes: 1024 * 1024,
                timeout_seconds: 300,
                max_mutations: 4096,
                repeat_count: 3,
            }),
            other => bail!("unsupported review/behaviour profile '{other}'"),
        }
    }

    pub fn clamp(
        mut self,
        prompts: usize,
        turns: usize,
        tokens: u64,
        timeout: u64,
        mutations: usize,
        repeats: usize,
    ) -> Self {
        if prompts > 0 {
            self.max_prompts = self.max_prompts.min(prompts);
        }
        if turns > 0 {
            self.max_turns = self.max_turns.min(turns);
        }
        if tokens > 0 {
            self.max_tokens = self.max_tokens.min(tokens);
        }
        if timeout > 0 {
            self.timeout_seconds = self.timeout_seconds.min(timeout);
        }
        if mutations > 0 {
            self.max_mutations = self.max_mutations.min(mutations);
        }
        if repeats > 0 {
            self.repeat_count = self.repeat_count.min(repeats);
        }
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeIdentity {
    pub backend: String,
    pub executable: String,
    pub executable_sha256: String,
    pub version: Option<String>,
    pub sandbox: sandbox::SandboxCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeExecution {
    pub probe_id: String,
    pub category: String,
    pub prompt_sha256: String,
    pub response_sha256: String,
    pub response_excerpt: String,
    pub duration_ms: u64,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub evaluation: evaluate::Evaluation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviourReport {
    pub schema_version: String,
    pub model_identity: String,
    pub model_path: String,
    pub runtime: RuntimeIdentity,
    pub probe_suite_id: String,
    pub probe_suite_version: u32,
    pub seed: u64,
    pub limits: BehaviourLimits,
    pub executions: Vec<ProbeExecution>,
    pub state: crate::transformation::BehaviourState,
    pub findings: Vec<String>,
    pub boundary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialRow {
    pub probe_id: String,
    pub category: String,
    pub base_risk: String,
    pub derived_risk: String,
    pub classification: crate::transformation::DifferentialBehaviourState,
    pub rule_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialReport {
    pub schema_version: String,
    pub base: BehaviourReport,
    pub derived: BehaviourReport,
    pub rows: Vec<DifferentialRow>,
    pub state: crate::transformation::DifferentialBehaviourState,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviourReplayManifest {
    pub version: u32,
    pub model_path: String,
    pub model_identity: String,
    pub runtime_path: String,
    pub runtime_sha256: String,
    pub probe_suite_path: Option<String>,
    pub probe_suite_id: String,
    pub probe_suite_version: u32,
    pub seed: u64,
    pub limits: BehaviourLimits,
}

pub fn replay_manifest(
    report: &BehaviourReport,
    probe_suite_path: Option<&Path>,
) -> BehaviourReplayManifest {
    BehaviourReplayManifest {
        version: 1,
        model_path: report.model_path.clone(),
        model_identity: report.model_identity.clone(),
        runtime_path: report.runtime.executable.clone(),
        runtime_sha256: report.runtime.executable_sha256.clone(),
        probe_suite_path: probe_suite_path.map(|p| p.display().to_string()),
        probe_suite_id: report.probe_suite_id.clone(),
        probe_suite_version: report.probe_suite_version,
        seed: report.seed,
        limits: report.limits.clone(),
    }
}

pub fn load_replay(path: &Path) -> Result<BehaviourReplayManifest> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let bytes = crate::safeio::read_all_from_file(&file, 4 * 1024 * 1024)?;
    let manifest: BehaviourReplayManifest = serde_json::from_slice(&bytes)?;
    if manifest.version != 1 {
        bail!(
            "unsupported behaviour replay manifest version {}",
            manifest.version
        );
    }
    Ok(manifest)
}

pub fn run_external_llama(
    model: &Path,
    runtime_path: Option<&Path>,
    suite_path: Option<&Path>,
    seed: u64,
    limits: BehaviourLimits,
) -> Result<BehaviourReport> {
    static_admit(model)?;
    let model = resolve_gguf(model)?;
    let model_identity = crate::modelmeta::build_snapshot(&model)?.identity.canonical;
    let suite = probes::expand_mutations(probes::load_suite(suite_path)?, limits.max_mutations);
    let executable = match runtime_path {
        Some(path) => path.to_path_buf(),
        None => crate::sources::find_executable("llama-cli")
            .or_else(|| crate::sources::find_executable("main"))
            .ok_or_else(|| anyhow::anyhow!("llama.cpp CLI was not found on PATH"))?,
    };
    let runtime = runtime::RuntimeAdapter::new(executable, &limits)?;
    let identity = runtime.identity()?;
    let canary_a = synthetic_canary(&model_identity, seed, "A");
    let canary_b = synthetic_canary(&model_identity, seed, "B");
    let mut executions = Vec::new();
    for probe in suite.probes.iter().take(limits.max_prompts) {
        let repeat = probe.repeat.max(1).min(limits.repeat_count.max(1));
        for repeat_index in 0..repeat {
            let system = probes::render(&probe.system, &canary_a, &canary_b);
            let prompt = probes::render(&probe.prompt, &canary_a, &canary_b);
            let combined = format!("<system>\n{system}\n</system>\n<user>\n{prompt}\n</user>");
            let result = runtime.run(
                &model,
                &combined,
                seed.saturating_add(repeat_index as u64),
                limits.max_tokens,
            )?;
            let evaluation =
                evaluate::evaluate(&probe.category, &result.stdout, &[&canary_a, &canary_b]);
            executions.push(ProbeExecution {
                probe_id: probe.id.clone(),
                category: probe.category.clone(),
                prompt_sha256: sha256(combined.as_bytes()),
                response_sha256: sha256(result.stdout.as_bytes()),
                response_excerpt: bounded_excerpt(&result.stdout, 4096),
                duration_ms: result.duration_ms,
                exit_code: result.exit_code,
                timed_out: result.timed_out,
                evaluation,
            });
        }
    }
    let mut findings: Vec<String> = executions
        .iter()
        .flat_map(|v| v.evaluation.rule_ids.clone())
        .collect();
    findings.sort();
    findings.dedup();
    let high = executions
        .iter()
        .any(|v| v.evaluation.risk == evaluate::Risk::High);
    let suspicious = executions.iter().any(|v| {
        matches!(
            v.evaluation.risk,
            evaluate::Risk::Medium | evaluate::Risk::High
        )
    });
    Ok(BehaviourReport {
        schema_version: "1.0".to_owned(), model_identity, model_path: model.display().to_string(), runtime: identity,
        probe_suite_id: suite.id, probe_suite_version: suite.version, seed, limits,
        executions,
        state: if high { crate::transformation::BehaviourState::HighRisk } else if suspicious { crate::transformation::BehaviourState::Suspicious } else { crate::transformation::BehaviourState::NoSuspiciousObserved },
        findings,
        boundary: "No suspicious behaviour observed means only that no suspicious behaviour was observed under the executed probe suite; it does not prove absence of hidden triggers or backdoors.".to_owned(),
    })
}

pub fn compare_external_llama(
    base: &Path,
    derived: &Path,
    runtime_path: Option<&Path>,
    suite_path: Option<&Path>,
    seed: u64,
    limits: BehaviourLimits,
) -> Result<DifferentialReport> {
    let base_report = run_external_llama(base, runtime_path, suite_path, seed, limits.clone())?;
    let derived_report = run_external_llama(derived, runtime_path, suite_path, seed, limits)?;
    let mut rows = Vec::new();
    let mut findings = Vec::new();
    let base_map: std::collections::BTreeMap<_, _> = base_report
        .executions
        .iter()
        .map(|v| ((v.probe_id.as_str(), v.category.as_str()), v))
        .collect();
    let mut overall = crate::transformation::DifferentialBehaviourState::Expected;
    for d in &derived_report.executions {
        let Some(b) = base_map.get(&(d.probe_id.as_str(), d.category.as_str())) else {
            continue;
        };
        let class = evaluate::classify_difference(&b.evaluation, &d.evaluation);
        overall = evaluate::stronger_difference(overall, class);
        let mut rules = Vec::new();
        if matches!(
            class,
            crate::transformation::DifferentialBehaviourState::SecurityRegression
                | crate::transformation::DifferentialBehaviourState::SuspiciousTrigger
                | crate::transformation::DifferentialBehaviourState::HighRiskBehaviour
        ) {
            rules.push("LF-DIFF-SECURITY-REGRESSION".to_owned());
            findings.push("LF-DIFF-SECURITY-REGRESSION".to_owned());
        }
        rows.push(DifferentialRow {
            probe_id: d.probe_id.clone(),
            category: d.category.clone(),
            base_risk: b.evaluation.risk.as_str().to_owned(),
            derived_risk: d.evaluation.risk.as_str().to_owned(),
            classification: class,
            rule_ids: rules,
        });
    }
    findings.sort();
    findings.dedup();
    Ok(DifferentialReport {
        schema_version: "1.0".to_owned(),
        base: base_report,
        derived: derived_report,
        rows,
        state: overall,
        findings,
    })
}

fn static_admit(path: &Path) -> Result<()> {
    if path.is_dir() {
        let report = crate::package::inspect(path)?;
        if report.blocking() {
            bail!(
                "static admission blocked package '{}'; behaviour was not run",
                path.display()
            );
        }
    } else {
        let report = crate::formats::artifact::inspect(
            path,
            crate::formats::artifact::ArtifactScanMode::Full,
        )?;
        if report.blocking() {
            bail!(
                "static admission blocked artifact '{}'; behaviour was not run",
                path.display()
            );
        }
    }
    Ok(())
}

fn resolve_gguf(path: &Path) -> Result<PathBuf> {
    if path.is_file() {
        let snap = crate::modelmeta::build_snapshot(path)?;
        if snap.format != "gguf" {
            bail!(
                "llama.cpp behavioural backend requires a GGUF artifact, got {}",
                snap.format
            );
        }
        return Ok(path.to_path_buf());
    }
    let report = crate::package::inspect(path)?;
    let ggufs: Vec<_> = report
        .files
        .iter()
        .filter(|v| v.relative_path.to_ascii_lowercase().ends_with(".gguf"))
        .collect();
    if ggufs.len() != 1 {
        bail!(
            "llama.cpp behavioural package must contain exactly one GGUF artifact; found {}",
            ggufs.len()
        );
    }
    Ok(PathBuf::from(report.root).join(&ggufs[0].relative_path))
}

fn synthetic_canary(identity: &str, seed: u64, label: &str) -> String {
    let digest =
        Sha256::digest(format!("layerfault-canary\0{identity}\0{seed}\0{label}").as_bytes());
    format!("LF_CANARY_{label}_{}", &hex::encode(digest)[..24])
}
fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn bounded_excerpt(value: &str, cap: usize) -> String {
    if value.len() <= cap {
        return value.to_owned();
    }
    let mut end = cap;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

/// Run the same bounded probe framework using Layerfault's embedded Rust/Candle
/// backend. The operator must supply a local tokenizer.json; this function does
/// not download it.
pub fn run_embedded(
    model: &Path,
    tokenizer: &Path,
    suite_path: Option<&Path>,
    seed: u64,
    limits: BehaviourLimits,
) -> Result<BehaviourReport> {
    static_admit(model)?;
    let model = resolve_gguf(model)?;
    let model_identity = crate::modelmeta::build_snapshot(&model)?.identity.canonical;
    let suite = probes::expand_mutations(probes::load_suite(suite_path)?, limits.max_mutations);
    let canary_a = synthetic_canary(&model_identity, seed, "A");
    let canary_b = synthetic_canary(&model_identity, seed, "B");
    let mut executions = Vec::new();
    let mut embedded_identity: Option<crate::embedded::EmbeddedIdentity> = None;

    for probe in suite.probes.iter().take(limits.max_prompts) {
        let repeat = probe.repeat.max(1).min(limits.repeat_count.max(1));
        for _repeat_index in 0..repeat {
            let system = probes::render(&probe.system, &canary_a, &canary_b);
            let prompt = probes::render(&probe.prompt, &canary_a, &canary_b);
            let combined = format!("<system>\n{system}\n</system>\n<user>\n{prompt}\n</user>");
            let result = crate::embedded::run(
                &model,
                tokenizer,
                &combined,
                usize::try_from(limits.max_tokens).unwrap_or(4096),
                limits.timeout_seconds,
            )?;
            if result.output.len() > limits.max_output_bytes {
                bail!("embedded response exceeded the selected behaviour output cap");
            }
            embedded_identity.get_or_insert_with(|| result.identity.clone());
            let evaluation =
                evaluate::evaluate(&probe.category, &result.output, &[&canary_a, &canary_b]);
            executions.push(ProbeExecution {
                probe_id: probe.id.clone(),
                category: probe.category.clone(),
                prompt_sha256: sha256(combined.as_bytes()),
                response_sha256: result.output_sha256.clone(),
                response_excerpt: bounded_excerpt(&result.output, 4096),
                duration_ms: result.duration_ms,
                exit_code: Some(0),
                timed_out: false,
                evaluation,
            });
        }
    }
    let embedded_identity =
        embedded_identity.ok_or_else(|| anyhow::anyhow!("no embedded probes executed"))?;
    let runtime = RuntimeIdentity {
        backend: embedded_identity.backend,
        executable: "embedded".to_owned(),
        executable_sha256: format!("crate:candelabra:{}", embedded_identity.version),
        version: Some(embedded_identity.version),
        sandbox: sandbox::SandboxCapabilities {
            workspace_isolated: true,
            home_isolated: true,
            environment_scrubbed: true,
            network_isolation: true,
            network_mechanism: Some("in-process-no-network-api".to_owned()),
            host_files_hidden: false,
            real_tools_disabled: true,
        },
    };
    finalize_report(
        model_identity,
        model.display().to_string(),
        runtime,
        suite,
        seed,
        limits,
        executions,
    )
}

pub fn compare_embedded(
    base: &Path,
    derived: &Path,
    tokenizer: &Path,
    suite_path: Option<&Path>,
    seed: u64,
    limits: BehaviourLimits,
) -> Result<DifferentialReport> {
    let base_report = run_embedded(base, tokenizer, suite_path, seed, limits.clone())?;
    let derived_report = run_embedded(derived, tokenizer, suite_path, seed, limits)?;
    differential_from_reports(base_report, derived_report)
}

fn finalize_report(
    model_identity: String,
    model_path: String,
    runtime: RuntimeIdentity,
    suite: probes::ProbeSuite,
    seed: u64,
    limits: BehaviourLimits,
    executions: Vec<ProbeExecution>,
) -> Result<BehaviourReport> {
    let mut findings: Vec<String> = executions
        .iter()
        .flat_map(|value| value.evaluation.rule_ids.clone())
        .collect();
    findings.sort();
    findings.dedup();
    let high = executions
        .iter()
        .any(|value| value.evaluation.risk == evaluate::Risk::High);
    let suspicious = executions.iter().any(|value| {
        matches!(
            value.evaluation.risk,
            evaluate::Risk::Medium | evaluate::Risk::High
        )
    });
    Ok(BehaviourReport {
        schema_version: "1.0".to_owned(),
        model_identity,
        model_path,
        runtime,
        probe_suite_id: suite.id,
        probe_suite_version: suite.version,
        seed,
        limits,
        executions,
        state: if high {
            crate::transformation::BehaviourState::HighRisk
        } else if suspicious {
            crate::transformation::BehaviourState::Suspicious
        } else {
            crate::transformation::BehaviourState::NoSuspiciousObserved
        },
        findings,
        boundary: "No suspicious behaviour observed means only that no suspicious behaviour was observed under the executed probe suite; it does not prove absence of hidden triggers or backdoors.".to_owned(),
    })
}

fn differential_from_reports(
    base_report: BehaviourReport,
    derived_report: BehaviourReport,
) -> Result<DifferentialReport> {
    let mut rows = Vec::new();
    let mut findings = Vec::new();
    let base_map: std::collections::BTreeMap<_, _> = base_report
        .executions
        .iter()
        .map(|value| ((value.probe_id.as_str(), value.category.as_str()), value))
        .collect();
    let mut overall = crate::transformation::DifferentialBehaviourState::Expected;
    for derived in &derived_report.executions {
        let Some(base) = base_map.get(&(derived.probe_id.as_str(), derived.category.as_str()))
        else {
            continue;
        };
        let class = evaluate::classify_difference(&base.evaluation, &derived.evaluation);
        overall = evaluate::stronger_difference(overall, class);
        let mut rules = Vec::new();
        if matches!(
            class,
            crate::transformation::DifferentialBehaviourState::SecurityRegression
                | crate::transformation::DifferentialBehaviourState::SuspiciousTrigger
                | crate::transformation::DifferentialBehaviourState::HighRiskBehaviour
        ) {
            rules.push("LF-DIFF-SECURITY-REGRESSION".to_owned());
            findings.push("LF-DIFF-SECURITY-REGRESSION".to_owned());
        }
        rows.push(DifferentialRow {
            probe_id: derived.probe_id.clone(),
            category: derived.category.clone(),
            base_risk: base.evaluation.risk.as_str().to_owned(),
            derived_risk: derived.evaluation.risk.as_str().to_owned(),
            classification: class,
            rule_ids: rules,
        });
    }
    findings.sort();
    findings.dedup();
    Ok(DifferentialReport {
        schema_version: "1.0".to_owned(),
        base: base_report,
        derived: derived_report,
        rows,
        state: overall,
        findings,
    })
}
