#![forbid(unsafe_code)]

mod commands;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::VerifyingKey;
use layerfault::admission::{self, ArtifactAdmission, SigstoreRequest};
use layerfault::app::{self, ScanOptions};
use layerfault::baseline::Baseline;
use layerfault::formats::artifact::{self, ArtifactScanMode};
use layerfault::policy::{PolicyDocument, PolicyProfile};
use layerfault::sources::SourceKind;
use layerfault::trust::TrustStore;
use layerfault::{
    advisory, audit, baseline, binding, certify, doctor, evidence, explain, gc, inventory,
    manifest, modeldiff, package, policy, provenance, quarantine, report, safeio, sigstore,
    sources, ThresholdConfig,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

#[derive(Parser, Debug)]
#[command(
    name = "layerfault",
    version,
    about = "Offline-first admission, provenance and supply-chain security for local AI model artifacts and runtimes"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Backward-compatible Ollama scan flags. Prefer `layerfault scan ...` for new automation.
    #[command(flatten)]
    legacy_scan: ScanArgs,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan one model or the complete local Ollama model store.
    Scan(ScanArgs),
    /// Inspect a standalone GGUF/Safetensors artifact before importing or loading it.
    Inspect(InspectArgs),
    /// Evaluate a standalone artifact against Layerfault policy.
    VerifyFile(VerifyFileArgs),
    /// Scan model artifacts in a directory.
    ScanDir(ScanDirArgs),
    /// Compute a runtime-independent canonical fingerprint for a complete local model package.
    Fingerprint(FingerprintArgs),
    /// Scan a complete local model package and evaluate it against policy.
    VerifyPackage(VerifyPackageArgs),
    /// Run a complete pre-execution admission check for an artifact or package.
    Pipeline(PipelineArgs),
    /// Scan and evaluate an Ollama model as an explicit security/policy gate.
    Verify(VerifyArgs),
    /// Verify a model/artifact and invoke the selected runtime only when policy allows it.
    Run(RunArgs),
    /// Verify a local artifact and import it into a supported runtime.
    Import(ImportArgs),
    /// Verify a GGUF artifact and start llama-server only when policy allows it.
    Serve(ServeArgs),
    /// Manage trusted Ed25519 publisher/operator keys.
    Trust(TrustArgs),
    /// Create or verify provenance attestations.
    Attest(AttestArgs),
    /// Audit model stores, local runtime inventories and Hugging Face caches.
    Audit(AuditArgs),
    /// Capture, diff, sign, update or verify known-good model-store baselines.
    Baseline(BaselineArgs),
    /// Non-destructively isolate, inspect, export, purge or restore local models.
    Quarantine(QuarantineArgs),
    /// Create, lint, inspect, diff or test Layerfault policies.
    Policy(PolicyArgs),
    /// Conservatively plan or remove demonstrably orphaned Ollama blobs.
    Gc(GcArgs),
    /// Report installed runtime integrations and local model-store health.
    Doctor(OutputArgs),
    /// List available local model sources/runtimes.
    Sources(OutputArgs),
    /// Explain a stable Layerfault detector/rule identifier.
    Explain(ExplainArgs),
    /// Compare two local artifacts or two Ollama model identities.
    Diff(DiffArgs),
    /// Compare two local model artifacts for vNext lineage and derivation evidence.
    Compare(CompareArgs),
    /// Run bounded local behavioral probes against a model.
    Behaviour(BehaviourArgs),
    /// Compare bounded behavioral probe outcomes for a base and derived model.
    CompareBehaviour(CompareBehaviourArgs),
    /// Produce a versioned multi-domain model security review.
    Review(ReviewArgs),
    /// Run lightweight built-in parser/policy self-tests.
    Selftest(OutputArgs),
    /// Run the built-in adversarial certification suite.
    Certify(CertifyArgs),
    /// Inspect or verify the offline runtime vulnerability advisory catalog.
    Advisories(AdvisoryArgs),
    /// Verify signed Layerfault scan/admission evidence.
    Evidence(EvidenceArgs),
    /// Print build/runtime contract information.
    Version(VersionArgs),
}

#[derive(clap::Args, Debug, Clone)]
struct ScanCommon {
    /// Override the Ollama models directory. OLLAMA_MODELS and platform defaults are used otherwise.
    #[arg(long, value_name = "PATH")]
    ollama_dir: Option<PathBuf>,

    /// Operator policy maximum for temperature.
    #[arg(long, default_value_t = 2.0, value_parser = parse_nonnegative_finite_f64)]
    max_temperature: f64,

    /// Operator policy maximum for context size.
    #[arg(long, default_value_t = 1_048_576, value_parser = parse_positive_u64)]
    max_ctx: u64,

    /// Operator policy maximum for positive prediction-token limits.
    #[arg(long, default_value_t = 32_768, value_parser = parse_nonnegative_i64)]
    max_predict: i64,

    /// Legacy PEM Ed25519 public key for raw .sig verification.
    #[arg(long)]
    public_key: Option<PathBuf>,

    /// Trust-store JSON path. Defaults to the Layerfault config directory.
    #[arg(long)]
    trust_store: Option<PathBuf>,

    /// Built-in policy profile: permissive, workstation, ci, strict.
    #[arg(long, default_value = "workstation")]
    policy: String,

    /// JSON policy document. When supplied it takes precedence over --policy.
    #[arg(long)]
    policy_file: Option<PathBuf>,

    /// Maximum number of models scanned concurrently.
    #[arg(long, value_parser = parse_jobs)]
    jobs: Option<usize>,
}

impl Default for ScanCommon {
    fn default() -> Self {
        Self {
            ollama_dir: None,
            max_temperature: 2.0,
            max_ctx: 1_048_576,
            max_predict: 32_768,
            public_key: None,
            trust_store: None,
            policy: "workstation".to_owned(),
            policy_file: None,
            jobs: None,
        }
    }
}

#[derive(clap::Args, Debug, Clone, Default)]
struct ScanArgs {
    /// Target one Ollama model. Canonical registry/namespace/model:tag names are supported.
    #[arg(short, long)]
    model: Option<String>,
    #[command(flatten)]
    common: ScanCommon,
    /// Emit versioned JSON to stdout.
    #[arg(long, default_value_t = false, conflicts_with = "sarif")]
    json: bool,
    /// Emit SARIF 2.1.0 to stdout.
    #[arg(long, default_value_t = false, conflicts_with = "json")]
    sarif: bool,
}

#[derive(clap::Args, Debug)]
struct InspectArgs {
    path: PathBuf,
    #[arg(long, default_value_t = false)]
    structure_only: bool,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct VerifyFileArgs {
    path: PathBuf,
    #[command(flatten)]
    common: ScanCommon,
    #[arg(long, default_value = "file")]
    source: String,
    #[arg(long)]
    identity: Option<String>,
    #[arg(long)]
    architecture: Option<String>,
    #[arg(long)]
    quantization: Option<String>,
    #[arg(long)]
    sigstore_bundle: Option<PathBuf>,
    #[arg(long, requires = "sigstore_bundle")]
    certificate_identity: Option<String>,
    #[arg(long, requires = "sigstore_bundle")]
    certificate_issuer: Option<String>,
    #[command(flatten)]
    evidence: EvidenceWriteArgs,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct ScanDirArgs {
    path: PathBuf,
    #[arg(long, default_value_t = true)]
    recursive: bool,
    #[arg(long, default_value_t = false)]
    structure_only: bool,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct FingerprintArgs {
    path: PathBuf,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct VerifyPackageArgs {
    path: PathBuf,
    #[command(flatten)]
    common: ScanCommon,
    #[command(flatten)]
    evidence: EvidenceWriteArgs,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct PipelineArgs {
    path: PathBuf,
    #[command(flatten)]
    common: ScanCommon,
    #[command(flatten)]
    evidence: EvidenceWriteArgs,
    #[arg(long, default_value_t = false, conflicts_with_all = ["sarif", "summary"])]
    json: bool,
    #[arg(long, default_value_t = false, conflicts_with_all = ["json", "summary"])]
    sarif: bool,
    #[arg(long, default_value_t = false, conflicts_with_all = ["json", "sarif"])]
    summary: bool,
}

#[derive(clap::Args, Debug, Clone, Default)]
struct EvidenceWriteArgs {
    #[arg(long, requires = "evidence_key")]
    evidence_out: Option<PathBuf>,
    #[arg(long, requires = "evidence_out")]
    evidence_key: Option<PathBuf>,
}

#[derive(clap::Args, Debug, Clone, Default)]
struct RuntimeSecurityArgs {
    /// Optional signed external advisory database. Built-in advisories are compiled into Layerfault.
    #[arg(long, requires_all = ["advisory_signature", "advisory_public_key"])]
    advisory_db: Option<PathBuf>,
    #[arg(long, requires = "advisory_db")]
    advisory_signature: Option<PathBuf>,
    #[arg(long, requires = "advisory_db")]
    advisory_public_key: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct VerifyArgs {
    model: String,
    #[command(flatten)]
    common: ScanCommon,
    #[command(flatten)]
    evidence: EvidenceWriteArgs,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct RunArgs {
    model: String,
    #[command(flatten)]
    common: ScanCommon,
    #[command(flatten)]
    runtime_security: RuntimeSecurityArgs,
    #[command(flatten)]
    evidence: EvidenceWriteArgs,
    /// Runtime/source: ollama, lmstudio, llama-cpp.
    #[arg(long, default_value = "ollama")]
    source: String,
    /// Override a policy-only block with a mandatory audited reason. Scanner/provenance failures cannot be overridden.
    #[arg(long, value_name = "REASON")]
    override_reason: Option<String>,
    #[arg(long)]
    override_log: Option<PathBuf>,
    /// Arguments passed to the selected runtime after the model/path.
    #[arg(last = true, allow_hyphen_values = true)]
    runtime_args: Vec<String>,
}

#[derive(clap::Args, Debug)]
struct ImportArgs {
    path: PathBuf,
    #[command(flatten)]
    common: ScanCommon,
    #[command(flatten)]
    runtime_security: RuntimeSecurityArgs,
    #[command(flatten)]
    evidence: EvidenceWriteArgs,
    /// Currently supported: lmstudio.
    #[arg(long, default_value = "lmstudio")]
    source: String,
    /// Actually perform the import. Without this flag LM Studio is called with --dry-run.
    #[arg(long, default_value_t = false)]
    execute: bool,
    #[arg(last = true, allow_hyphen_values = true)]
    runtime_args: Vec<String>,
}

#[derive(clap::Args, Debug)]
struct ServeArgs {
    path: PathBuf,
    #[command(flatten)]
    common: ScanCommon,
    #[command(flatten)]
    runtime_security: RuntimeSecurityArgs,
    #[command(flatten)]
    evidence: EvidenceWriteArgs,
    #[arg(last = true, allow_hyphen_values = true)]
    runtime_args: Vec<String>,
}

#[derive(clap::Args, Debug)]
struct TrustArgs {
    #[command(subcommand)]
    command: TrustCommand,
    #[arg(long)]
    store: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum TrustCommand {
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long = "namespace")]
        namespaces: Vec<String>,
    },
    List {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Remove {
        selector: String,
    },
    Revoke {
        selector: String,
    },
    Unrevoke {
        selector: String,
    },
    Configure {
        selector: String,
        #[arg(long)]
        active_from_unix: Option<u64>,
        #[arg(long)]
        expires_unix: Option<u64>,
        #[arg(long)]
        rotation_group: Option<String>,
    },
    Export {
        #[arg(long)]
        output: PathBuf,
    },
    Import {
        #[arg(long)]
        input: PathBuf,
    },
}

#[derive(clap::Args, Debug)]
struct AttestArgs {
    #[command(subcommand)]
    command: AttestCommand,
}

#[derive(Subcommand, Debug)]
enum AttestCommand {
    Sign {
        model: String,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        ollama_dir: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Verify a Sigstore bundle for a standalone artifact using an installed cosign binary.
    SigstoreVerify {
        path: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        certificate_identity: String,
        #[arg(long)]
        certificate_issuer: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(clap::Args, Debug)]
struct AuditArgs {
    #[command(flatten)]
    common: ScanCommon,
    /// Source: ollama, lmstudio, hf-cache, all.
    #[arg(long, default_value = "ollama")]
    source: String,
    /// Additional standalone model directories included by --source all.
    #[arg(long = "directory")]
    directories: Vec<PathBuf>,
    #[arg(long)]
    hf_cache: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    deep: bool,
    #[arg(long)]
    mlbom: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct BaselineArgs {
    #[command(subcommand)]
    command: BaselineCommand,
}

#[derive(Subcommand, Debug)]
enum BaselineCommand {
    Create {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        ollama_dir: Option<PathBuf>,
    },
    Verify {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long)]
        ollama_dir: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        require_signature: bool,
        #[arg(long)]
        trust_store: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Diff {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long)]
        ollama_dir: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Update {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long)]
        ollama_dir: Option<PathBuf>,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        sign_with: Option<PathBuf>,
    },
    Sign {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long)]
        private_key: PathBuf,
    },
    VerifySignature {
        #[arg(long, default_value = "default")]
        name: String,
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long)]
        trust_store: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(clap::Args, Debug)]
struct QuarantineArgs {
    #[command(subcommand)]
    command: QuarantineCommand,
}

#[derive(Subcommand, Debug)]
enum QuarantineCommand {
    Put {
        model: String,
        #[arg(long)]
        ollama_dir: Option<PathBuf>,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, default_value_t = false)]
        no_scan: bool,
    },
    List {
        #[arg(long)]
        ollama_dir: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Inspect {
        id: String,
        #[arg(long)]
        ollama_dir: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Export {
        id: String,
        #[arg(long)]
        ollama_dir: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = false)]
        include_blobs: bool,
        #[arg(long)]
        sign_with: Option<PathBuf>,
    },
    Purge {
        id: String,
        #[arg(long)]
        ollama_dir: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
    Restore {
        id: String,
        #[arg(long)]
        ollama_dir: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

#[derive(clap::Args, Debug)]
struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Subcommand, Debug)]
enum PolicyCommand {
    Init {
        #[arg(long, default_value = "workstation")]
        profile: String,
        #[arg(long)]
        output: PathBuf,
    },
    Show {
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long, default_value = "workstation")]
        profile: String,
    },
    Lint {
        file: PathBuf,
    },
    Explain {
        file: PathBuf,
    },
    Test {
        file: PathBuf,
        artifact: PathBuf,
        #[arg(long, default_value = "file")]
        source: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Diff {
        left: PathBuf,
        right: PathBuf,
    },
}

#[derive(clap::Args, Debug)]
struct GcArgs {
    #[arg(long)]
    ollama_dir: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    execute: bool,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct OutputArgs {
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct ExplainArgs {
    rule_id: String,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct DiffArgs {
    left: String,
    right: String,
    #[arg(long)]
    ollama_dir: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct CompareArgs {
    base: PathBuf,
    derived: PathBuf,
    #[arg(long)]
    claim: Option<String>,
    #[arg(long)]
    transformation_manifest: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct BehaviourArgs {
    model: PathBuf,
    #[arg(long, default_value = "llama-cpp")]
    runtime: String,
    #[arg(long, default_value = "standard")]
    profile: String,
    #[arg(long)]
    probe_suite: Option<PathBuf>,
    #[arg(long, default_value_t = 0)]
    seed: u64,
    #[arg(long)]
    max_prompts: Option<usize>,
    #[arg(long)]
    max_turns: Option<usize>,
    #[arg(long)]
    max_tokens: Option<usize>,
    #[arg(long)]
    timeout_seconds: Option<u64>,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct CompareBehaviourArgs {
    base: PathBuf,
    derived: PathBuf,
    #[arg(long, default_value = "llama-cpp")]
    runtime: String,
    #[arg(long, default_value = "standard")]
    profile: String,
    #[arg(long)]
    probe_suite: Option<PathBuf>,
    #[arg(long, default_value_t = 0)]
    seed: u64,
    #[arg(long)]
    max_prompts: Option<usize>,
    #[arg(long)]
    max_turns: Option<usize>,
    #[arg(long)]
    max_tokens: Option<usize>,
    #[arg(long)]
    timeout_seconds: Option<u64>,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct ReviewArgs {
    model: PathBuf,
    #[arg(long)]
    base: Option<PathBuf>,
    #[arg(long)]
    claim: Option<String>,
    #[arg(long)]
    transformation_manifest: Option<PathBuf>,
    #[arg(long, default_value = "standard")]
    profile: String,
    #[arg(long, default_value = "llama-cpp")]
    runtime: String,
    #[arg(long)]
    probe_suite: Option<PathBuf>,
    #[arg(long)]
    evidence_out: Option<PathBuf>,
    #[arg(long)]
    evidence_key: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct CertifyArgs {
    #[arg(long, default_value_t = false)]
    sparse: bool,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct AdvisoryArgs {
    #[command(subcommand)]
    command: AdvisoryCommand,
}

#[derive(Subcommand, Debug)]
enum AdvisoryCommand {
    List {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Check {
        runtime: String,
        #[command(flatten)]
        security: RuntimeSecurityArgs,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Verify {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        signature: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
}

#[derive(clap::Args, Debug)]
struct EvidenceArgs {
    #[command(subcommand)]
    command: EvidenceCommand,
}

#[derive(Subcommand, Debug)]
enum EvidenceCommand {
    Verify {
        path: PathBuf,
        #[arg(long)]
        trust_store: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(clap::Args, Debug)]
struct VersionArgs {
    #[arg(long, default_value_t = false)]
    json: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Scan(args)) => commands::ollama::run_scan(args),
        Some(Command::Inspect(args)) => commands::artifacts::run_inspect(args),
        Some(Command::VerifyFile(args)) => commands::artifacts::run_verify_file(args),
        Some(Command::ScanDir(args)) => commands::artifacts::run_scan_dir(args),
        Some(Command::Fingerprint(args)) => commands::artifacts::run_fingerprint(args),
        Some(Command::VerifyPackage(args)) => commands::artifacts::run_verify_package(args),
        Some(Command::Pipeline(args)) => commands::artifacts::run_pipeline(args),
        Some(Command::Verify(args)) => commands::ollama::run_verify(args),
        Some(Command::Run(args)) => commands::runtimes::run_guarded(args),
        Some(Command::Import(args)) => commands::runtimes::run_import(args),
        Some(Command::Serve(args)) => commands::runtimes::run_serve(args),
        Some(Command::Trust(args)) => commands::trust::run_trust(args),
        Some(Command::Attest(args)) => commands::trust::run_attest(args),
        Some(Command::Audit(args)) => commands::stores::run_audit(args),
        Some(Command::Baseline(args)) => commands::stores::run_baseline(args),
        Some(Command::Quarantine(args)) => commands::stores::run_quarantine(args),
        Some(Command::Policy(args)) => commands::operator::run_policy(args),
        Some(Command::Gc(args)) => commands::stores::run_gc(args),
        Some(Command::Doctor(args)) => commands::operator::run_doctor(args),
        Some(Command::Sources(args)) => commands::operator::run_sources(args),
        Some(Command::Explain(args)) => commands::operator::run_explain(args),
        Some(Command::Diff(args)) => commands::operator::run_diff(args),
        Some(Command::Compare(args)) => commands::vnext::run_compare(args),
        Some(Command::Behaviour(args)) => commands::vnext::run_behaviour(args),
        Some(Command::CompareBehaviour(args)) => commands::vnext::run_compare_behaviour(args),
        Some(Command::Review(args)) => commands::vnext::run_review(args),
        Some(Command::Selftest(args)) => commands::operator::run_selftest(args),
        Some(Command::Certify(args)) => commands::operator::run_certify(args),
        Some(Command::Advisories(args)) => commands::security::run_advisories(args),
        Some(Command::Evidence(args)) => commands::security::run_evidence(args),
        Some(Command::Version(args)) => commands::operator::run_version(args),
        None => commands::ollama::run_scan(cli.legacy_scan),
    }
}

struct Prepared {
    thresholds: ThresholdConfig,
    verifying_key: Option<VerifyingKey>,
    trust_store: TrustStore,
    policy: policy::EffectivePolicy,
}

fn prepare(common: &ScanCommon) -> Result<Prepared> {
    let thresholds = ThresholdConfig {
        max_temperature: common.max_temperature,
        max_ctx: common.max_ctx,
        max_predict: common.max_predict,
    };
    let verifying_key = match common.public_key.as_deref() {
        Some(path) => Some(load_verifying_key(path)?),
        None => None,
    };
    let trust_store = TrustStore::load(common.trust_store.as_deref())?;
    let policy_doc = match common.policy_file.as_deref() {
        Some(path) => PolicyDocument::load(path)?,
        None => PolicyDocument::builtin(PolicyProfile::parse(&common.policy)?),
    };
    policy_doc.validate()?;
    Ok(Prepared {
        thresholds,
        verifying_key,
        trust_store,
        policy: policy_doc.effective(),
    })
}

fn scan_options<'a>(common: &ScanCommon, prepared: &'a Prepared, quiet: bool) -> ScanOptions<'a> {
    ScanOptions {
        thresholds: &prepared.thresholds,
        verifying_key: prepared.verifying_key.as_ref(),
        trust_store: &prepared.trust_store,
        policy: &prepared.policy,
        jobs: common.jobs.unwrap_or_else(app::default_jobs),
        quiet,
    }
}

fn record_override(
    model: &str,
    reason: &str,
    profile: PolicyProfile,
    trust_state: provenance::TrustState,
    scanner_exit_code: i32,
    path: Option<&Path>,
) -> Result<()> {
    let record = policy::OverrideRecord {
        version: 1,
        created_unix: layerfault::paths::now_unix(),
        model: model.to_owned(),
        reason: reason.to_owned(),
        profile,
        trust_state,
        scanner_exit_code,
    };
    let path = policy::record_policy_override(&record, path)?;
    eprintln!("AUDITED POLICY OVERRIDE: {}", path.display());
    Ok(())
}

fn sigstore_request<'a>(
    bundle: Option<&'a Path>,
    identity: Option<&'a str>,
    issuer: Option<&'a str>,
) -> Result<Option<SigstoreRequest<'a>>> {
    match (bundle, identity, issuer) {
        (None, None, None) => Ok(None),
        (Some(bundle), Some(identity), Some(issuer)) => Ok(Some(SigstoreRequest { bundle, identity, issuer })),
        _ => Err(anyhow!("Sigstore verification requires --sigstore-bundle, --certificate-identity and --certificate-issuer together")),
    }
}

fn emit_admission(result: &ArtifactAdmission, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&admission_json(result))?);
    } else {
        print_artifact_report(&result.report);
        println!(
            "Trust: {:?} ({} trusted signature(s))",
            result.trust_state, result.trusted_signatures
        );
        println!("Policy: {:?}", result.policy.action);
        for reason in &result.policy.reasons {
            println!("  {reason}");
        }
    }
    Ok(())
}

fn print_artifact_report(result: &artifact::ArtifactReport) {
    println!(
        "{}  format={}  bytes={}  sha256={}",
        result.path,
        result.format.as_str(),
        result.size,
        result.sha256.as_deref().unwrap_or("not-computed")
    );
    print_actionable_findings(&result.results);
}

fn artifact_json_report(result: &artifact::ArtifactReport) -> serde_json::Value {
    let mut output = serde_json::to_value(result).expect("artifact report is serializable");
    if let Some(object) = output.as_object_mut() {
        object.insert(
            "results".to_owned(),
            serde_json::Value::Array(report::enriched_findings(&result.results)),
        );
    }
    output
}

fn package_json_report(result: &package::PackageReport) -> serde_json::Value {
    let mut output = serde_json::to_value(result).expect("package report is serializable");
    if let Some(object) = output.as_object_mut() {
        object.insert(
            "findings".to_owned(),
            serde_json::Value::Array(report::enriched_findings(&result.findings)),
        );
    }
    output
}

fn admission_json(result: &ArtifactAdmission) -> serde_json::Value {
    let mut output = serde_json::to_value(result).expect("admission report is serializable");
    if let Some(report) = output.get_mut("report") {
        *report = artifact_json_report(&result.report);
    }
    output
}

fn print_actionable_findings(findings: &[layerfault::scanner::LayerScanResult]) {
    let mut grouped = BTreeMap::<
        String,
        (
            layerfault::scanner::ScanStatus,
            usize,
            String,
            String,
            Vec<String>,
        ),
    >::new();
    for finding in findings {
        if finding.status == layerfault::scanner::ScanStatus::Pass {
            continue;
        }
        let rule = policy::rule_id(finding);
        let risk = explain::risk_lookup(&rule);
        let entry = grouped.entry(rule).or_insert_with(|| {
            (
                finding.status,
                0,
                risk.title.clone(),
                risk.risk.clone(),
                Vec::new(),
            )
        });
        entry.1 += 1;
        if let Some(detail) = &finding.detail {
            if entry.4.len() < 4 && !entry.4.iter().any(|value| value == detail) {
                entry.4.push(detail.clone());
            }
        }
        if finding.status == layerfault::scanner::ScanStatus::Fail {
            entry.0 = finding.status;
        }
    }
    for (rule, (status, count, title, risk, details)) in grouped {
        println!(
            "  {} {}{}",
            match status {
                layerfault::scanner::ScanStatus::Fail => "BLOCK",
                layerfault::scanner::ScanStatus::Warn => "WARN",
                layerfault::scanner::ScanStatus::Pass => "PASS",
            },
            title,
            if count > 1 {
                format!(" ({} findings)", count)
            } else {
                String::new()
            }
        );
        println!("    Finding: {rule}");
        for detail in details {
            println!("    - {detail}");
        }
        println!("    Risk: {risk}");
        let explanation = explain::risk_lookup(&rule);
        println!("    Action: {}", explanation.recommended_actions.join(" "));
    }
}

fn artifact_report_exit(result: &artifact::ArtifactReport) -> i32 {
    let mut warning = false;
    for finding in &result.results {
        match finding.status {
            layerfault::scanner::ScanStatus::Fail
                if finding.finding_class == layerfault::scanner::FindingClass::Integrity =>
            {
                return 2
            }
            layerfault::scanner::ScanStatus::Fail => return 3,
            layerfault::scanner::ScanStatus::Warn => warning = true,
            layerfault::scanner::ScanStatus::Pass => {}
        }
    }
    if warning {
        1
    } else {
        0
    }
}

fn print_store_audit(store: &audit::StoreAudit) {
    println!("Models: {}", store.model_count);
    println!("Invalid models: {}", store.invalid_model_count);
    println!("Blob files: {}", store.blob_file_count);
    println!("Referenced blobs: {}", store.referenced_blob_count);
    println!("Orphaned blobs: {}", store.orphaned_blobs.len());
    println!("Missing blobs: {}", store.missing_blobs.len());
    println!("Shared blobs: {}", store.shared_blobs.len());
    println!(
        "Partial/temp files: {}",
        store.partial_or_temporary_files.len()
    );
    println!(
        "Invalid manifest paths: {}",
        store.invalid_manifest_paths.len()
    );
}

fn exit_for_store_audit(store: &audit::StoreAudit, reports: Option<&[app::EvaluatedReport]>) -> ! {
    if store.invalid_model_count > 0
        || !store.missing_blobs.is_empty()
        || !store.invalid_manifest_paths.is_empty()
    {
        std::process::exit(3);
    }
    let deep_code = reports.map(app::policy_exit_code).unwrap_or(0);
    if matches!(deep_code, 2..=4) {
        std::process::exit(deep_code);
    }
    if deep_code == 1
        || !store.orphaned_blobs.is_empty()
        || !store.partial_or_temporary_files.is_empty()
    {
        std::process::exit(1);
    }
    std::process::exit(0);
}

fn print_inventory_entries(entries: &[inventory::InventoryEntry]) {
    println!("SOURCE      FORMAT              BLOCK  BYTES        IDENTITY");
    for entry in entries {
        println!(
            "{:<11} {:<19} {:<6} {:<12} {}",
            entry.source.as_str(),
            entry.format.as_str(),
            entry.blocking,
            entry.size,
            entry.identity
        );
    }
}

fn write_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    layerfault::paths::write_private(path, &serde_json::to_vec_pretty(value)?)
}

fn top_level_json_diff(left: &serde_json::Value, right: &serde_json::Value) -> serde_json::Value {
    let mut changed = serde_json::Map::new();
    let left_obj = left.as_object();
    let right_obj = right.as_object();
    let mut keys = std::collections::BTreeSet::new();
    if let Some(object) = left_obj {
        keys.extend(object.keys().cloned());
    }
    if let Some(object) = right_obj {
        keys.extend(object.keys().cloned());
    }
    for key in keys {
        let a = left_obj.and_then(|object| object.get(&key));
        let b = right_obj.and_then(|object| object.get(&key));
        if a != b {
            changed.insert(key, serde_json::json!({"left":a,"right":b}));
        }
    }
    serde_json::Value::Object(changed)
}

fn load_verifying_key(path: &Path) -> Result<VerifyingKey> {
    use ed25519_dalek::pkcs8::DecodePublicKey;
    let file = safeio::open_readonly_nofollow(path)?;
    let bytes = safeio::read_all_from_file(&file, 64 * 1024)?;
    let pem =
        std::str::from_utf8(&bytes).map_err(|_| anyhow!("Public key PEM must be valid UTF-8"))?;
    Ok(VerifyingKey::from_public_key_pem(pem)?)
}

fn parse_nonnegative_finite_f64(value: &str) -> std::result::Result<f64, String> {
    let parsed: f64 = value
        .parse()
        .map_err(|_| format!("'{value}' is not a number"))?;
    if !parsed.is_finite() || parsed < 0.0 {
        return Err("value must be finite and >= 0".to_owned());
    }
    Ok(parsed)
}
fn parse_positive_u64(value: &str) -> std::result::Result<u64, String> {
    let parsed: u64 = value
        .parse()
        .map_err(|_| format!("'{value}' is not a positive integer"))?;
    if parsed == 0 {
        return Err("value must be > 0".to_owned());
    }
    Ok(parsed)
}
fn parse_jobs(value: &str) -> std::result::Result<usize, String> {
    let parsed: usize = value
        .parse()
        .map_err(|_| format!("'{value}' is not a positive integer"))?;
    if !(1..=64).contains(&parsed) {
        return Err("jobs must be between 1 and 64".to_owned());
    }
    Ok(parsed)
}
fn parse_nonnegative_i64(value: &str) -> std::result::Result<i64, String> {
    let parsed: i64 = value
        .parse()
        .map_err(|_| format!("'{value}' is not an integer"))?;
    if parsed < 0 {
        return Err("value must be >= 0".to_owned());
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_non_finite_cli_thresholds() {
        assert!(parse_nonnegative_finite_f64("NaN").is_err());
        assert!(parse_nonnegative_finite_f64("inf").is_err());
        assert!(parse_nonnegative_finite_f64("-1").is_err());
    }
    #[test]
    fn jobs_are_bounded() {
        assert!(parse_jobs("1").is_ok());
        assert!(parse_jobs("64").is_ok());
        assert!(parse_jobs("0").is_err());
        assert!(parse_jobs("65").is_err());
    }
}
