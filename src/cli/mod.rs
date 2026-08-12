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
    advisory, audit, baseline, binding, certify, content_cache, doctor, evidence, explain, gc,
    inventory, json_stream, manifest, modeldiff, package, policy, provenance, quarantine, report,
    safeio, sigstore, sources, ThresholdConfig,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "layerfault",
    version,
    about = "Offline-first admission, provenance and supply-chain security for local AI model artifacts and runtimes"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Disable persistent local hash/scan-evidence reuse and force fresh file reads.
    #[arg(long, global = true, default_value_t = false)]
    no_cache: bool,

    /// Override the persistent Layerfault cache directory.
    #[arg(long, global = true, value_name = "PATH")]
    cache_dir: Option<PathBuf>,

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
    /// Report host capabilities for static and active analysis.
    Capabilities(OutputArgs),
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
    /// Manage local model observations and history.
    Models(ModelsArgs),
    /// Compare a model against a stored local observation.
    Drift(DriftArgs),
    /// Verify a signed local transformation chain.
    Lineage(LineageArgs),
    /// Inspect, fingerprint, compare and review local training datasets.
    Dataset(DatasetArgs),
    /// Run bounded backdoor/trigger/campaign research workflows.
    Research(ResearchArgs),
    /// Explicitly access Hugging Face Hub metadata/download/crawl workflows.
    Hub(HubArgs),
    /// Run the hosted/public Layerfault platform roles.
    Platform(PlatformArgs),
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

    /// Global static-scan resource profile.
    #[arg(long, default_value = "default")]
    budget_profile: String,

    /// Versioned JSON resource-budget configuration. Overrides --budget-profile.
    #[arg(long)]
    budget_file: Option<PathBuf>,

    /// Wall-clock deadline for this scan invocation, overriding the budget
    /// profile's own wall-clock limit. On expiry the scan stops cooperatively,
    /// retains findings already produced, and reports incomplete coverage.
    #[arg(long)]
    timeout_seconds: Option<u64>,

    /// Scheduler concurrency mode: adaptive or fixed.
    #[arg(long, default_value = "adaptive", value_parser = parse_scheduler)]
    scheduler: String,

    /// Maximum estimated resident memory reservation in MiB.
    #[arg(long)]
    max_memory_mib: Option<u64>,

    /// Maximum in-flight large sequential I/O bytes.
    #[arg(long)]
    max_inflight_bytes: Option<u64>,
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
            budget_profile: "default".to_owned(),
            budget_file: None,
            timeout_seconds: None,
            scheduler: "adaptive".to_owned(),
            max_memory_mib: None,
            max_inflight_bytes: None,
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
    #[arg(long, default_value_t = false, conflicts_with_all = ["sarif", "jsonl"])]
    json: bool,
    /// Emit SARIF 2.1.0 to stdout.
    #[arg(long, default_value_t = false, conflicts_with_all = ["json", "jsonl"])]
    sarif: bool,
    /// Emit a versioned, newline-delimited JSON record stream to stdout.
    #[arg(long, default_value_t = false, conflicts_with_all = ["json", "sarif"])]
    jsonl: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct InspectArgs {
    path: PathBuf,
    #[arg(long, default_value_t = false)]
    structure_only: bool,
    #[arg(long, default_value_t = false)]
    json: bool,
    #[arg(long, default_value_t = false)]
    normalized: bool,
    #[arg(long, default_value_t = false)]
    pub(crate) incremental: bool,
    #[arg(long, default_value_t = false)]
    pub(crate) validate_incremental: bool,
    #[arg(long)]
    pub(crate) previous_state: Option<PathBuf>,
    #[arg(long, default_value = "default")]
    budget_profile: String,
    #[arg(long)]
    budget_file: Option<PathBuf>,
    /// Wall-clock deadline for this scan, overriding the budget profile's own
    /// wall-clock limit.
    #[arg(long)]
    timeout_seconds: Option<u64>,
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
    /// Maximum concurrent artifact scans (1-64).
    #[arg(long, value_parser = parse_jobs)]
    jobs: Option<usize>,
    #[arg(long, default_value_t = false)]
    json: bool,
    #[arg(long, default_value = "default")]
    budget_profile: String,
    #[arg(long)]
    budget_file: Option<PathBuf>,
    /// Wall-clock deadline for this scan, overriding the budget profile's own
    /// wall-clock limit.
    #[arg(long)]
    timeout_seconds: Option<u64>,
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
    #[command(flatten)]
    evidence_bundle: EvidenceBundleArgs,
    #[arg(long, default_value_t = false)]
    json: bool,
    /// Render the evidence-first human report instead of the table.
    #[arg(long = "evidence", default_value_t = false)]
    evidence_report: bool,
}

#[derive(clap::Args, Debug)]
struct PipelineArgs {
    path: PathBuf,
    #[command(flatten)]
    common: ScanCommon,
    #[command(flatten)]
    evidence: EvidenceWriteArgs,
    #[command(flatten)]
    evidence_bundle: EvidenceBundleArgs,
    #[arg(long, default_value_t = false, conflicts_with_all = ["sarif", "summary", "jsonl"])]
    json: bool,
    #[arg(long, default_value_t = false, conflicts_with_all = ["json", "summary", "jsonl"])]
    sarif: bool,
    #[arg(long, default_value_t = false, conflicts_with_all = ["json", "sarif", "jsonl"])]
    summary: bool,
    /// Render the evidence-first human report instead of the table.
    #[arg(long = "evidence", default_value_t = false, conflicts_with_all = ["json", "sarif", "summary", "jsonl"])]
    evidence_report: bool,
    /// Emit a versioned, newline-delimited JSON record stream to stdout.
    #[arg(long, default_value_t = false, conflicts_with_all = ["json", "sarif", "summary", "evidence_report"])]
    jsonl: bool,
}

#[derive(clap::Args, Debug, Clone, Default)]
struct EvidenceWriteArgs {
    #[arg(long, requires = "evidence_key")]
    evidence_out: Option<PathBuf>,
    #[arg(long, requires = "evidence_out")]
    evidence_key: Option<PathBuf>,
}

/// Self-contained evidence bundle output. Distinct from `EvidenceWriteArgs`
/// (`--evidence-out`), which writes a signed Ed25519 admission envelope; this
/// writes a reviewable directory of findings, excerpts and a manifest.
#[derive(clap::Args, Debug, Clone, Default)]
struct EvidenceBundleArgs {
    /// Write a self-contained evidence bundle to this directory. Must not
    /// already contain files.
    #[arg(long, value_name = "DIR")]
    evidence_bundle: Option<PathBuf>,
}

#[derive(clap::Args, Debug, Clone, Default)]
struct RuntimeSecurityArgs {
    /// Pin the exact runtime executable instead of discovering it through PATH.
    #[arg(long, value_name = "PATH")]
    runtime_path: Option<PathBuf>,
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
struct DatasetArgs {
    #[command(subcommand)]
    command: DatasetCommand,
}

#[derive(Subcommand, Debug)]
enum DatasetCommand {
    Inspect {
        dataset: PathBuf,
        #[arg(long, value_parser = parse_jobs)]
        jobs: Option<usize>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Fingerprint {
        dataset: PathBuf,
        #[arg(long, value_parser = parse_jobs)]
        jobs: Option<usize>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Compare {
        left: PathBuf,
        right: PathBuf,
        #[arg(long, value_parser = parse_jobs)]
        jobs: Option<usize>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    PoisoningReview {
        dataset: PathBuf,
        #[arg(long, value_parser = parse_jobs)]
        jobs: Option<usize>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(clap::Args, Debug)]
struct ResearchArgs {
    #[command(subcommand)]
    command: ResearchCommand,
}

#[derive(Subcommand, Debug)]
enum ResearchCommand {
    TriggerSearch {
        model: PathBuf,
        #[arg(long)]
        base: Option<PathBuf>,
        #[arg(long, default_value = "llama-cpp")]
        runtime: String,
        #[arg(long)]
        runtime_path: Option<PathBuf>,
        #[arg(long)]
        tokenizer: Option<PathBuf>,
        #[arg(long = "alphabet", required = true)]
        alphabet: Vec<String>,
        #[arg(long, default_value_t = 1)]
        min_length: usize,
        #[arg(long, default_value_t = 3)]
        max_length: usize,
        #[arg(long, default_value_t = 10_000)]
        max_candidates: u64,
        #[arg(long, default_value = "")]
        prefix: String,
        #[arg(long, default_value = "")]
        suffix: String,
        #[arg(long, default_value_t = 0)]
        seed: u64,
        #[arg(long, default_value_t = 120)]
        timeout_seconds: u64,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Backdoor {
        model: PathBuf,
        #[arg(long)]
        base: Option<PathBuf>,
        #[arg(long, default_value = "llama-cpp")]
        runtime: String,
        #[arg(long)]
        runtime_path: Option<PathBuf>,
        #[arg(long)]
        tokenizer: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        seed: u64,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    ActivationDiff {
        base: PathBuf,
        derived: PathBuf,
        #[arg(long)]
        tokenizer: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Campaign {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(clap::Args, Debug)]
struct HubArgs {
    #[command(subcommand)]
    command: HubCommand,
}

#[derive(Subcommand, Debug)]
enum HubCommand {
    Model {
        repo: String,
        #[arg(long)]
        revision: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Files {
        repo: String,
        #[arg(long)]
        revision: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Download {
        repo: String,
        #[arg(long)]
        revision: String,
        #[arg(long)]
        file: String,
        #[arg(long)]
        staging: PathBuf,
        #[arg(long)]
        max_bytes: Option<u64>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Review {
        repo: String,
        #[arg(long)]
        revision: String,
        #[arg(long)]
        staging: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Crawl {
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(clap::Args, Debug)]
struct PlatformArgs {
    #[command(subcommand)]
    command: PlatformCommand,
}

#[derive(Subcommand, Debug)]
enum PlatformCommand {
    Migrate {
        #[arg(long)]
        database: String,
    },
    Doctor {
        #[arg(long)]
        database: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Serve {
        #[arg(long)]
        database: String,
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: String,
    },
    Worker {
        #[arg(long)]
        database: String,
        #[arg(long, default_value_t = false)]
        once: bool,
    },
    Crawl {
        #[arg(long)]
        database: String,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value_t = false)]
        continuous: bool,
        #[arg(long, default_value_t = 300)]
        interval_seconds: u64,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    PublishWeekly {
        #[arg(long)]
        database: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Newsletter {
        #[command(subcommand)]
        command: NewsletterCommand,
    },
}

#[derive(Subcommand, Debug)]
enum NewsletterCommand {
    Generate {
        #[arg(long)]
        database: String,
        #[arg(long)]
        public_base: Option<String>,
        #[arg(long, default_value = "markdown")]
        format: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Send {
        #[arg(long)]
        database: String,
        #[arg(long)]
        public_base: Option<String>,
        #[arg(long)]
        to: String,
        #[arg(long)]
        from: String,
        #[arg(long)]
        smtp_host: String,
        #[arg(long, default_value = "LAYERFAULT_SMTP_USERNAME")]
        username_env: String,
        #[arg(long, default_value = "LAYERFAULT_SMTP_PASSWORD")]
        password_env: String,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
enum GcTarget {
    /// Orphaned content-addressed model blobs (the pre-existing GC domain).
    #[default]
    Blobs,
    /// The content-sha256-keyed structural/Python evidence cache.
    ContentCache,
    /// The verified Hugging Face content object cache.
    ObjectCache,
    /// All of the above.
    All,
}

#[derive(clap::Args, Debug)]
struct GcArgs {
    #[arg(long)]
    ollama_dir: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    execute: bool,
    #[arg(long, default_value_t = false)]
    json: bool,
    /// What to garbage-collect. Defaults to `blobs`, preserving prior
    /// `layerfault gc` behavior exactly for callers that don't pass `--target`.
    #[arg(long, value_enum, default_value_t = GcTarget::Blobs)]
    target: GcTarget,
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
    /// LoRA adapter directory used to verify a claimed base + adapter -> merged model relationship.
    #[arg(long)]
    adapter: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    json: bool,
    #[arg(long, default_value_t = false)]
    reproduce_quantization: bool,
    #[arg(long)]
    quantizer: Option<PathBuf>,
    #[arg(long)]
    quantization: Option<String>,
}

#[derive(clap::Args, Debug)]
struct BehaviourArgs {
    model: PathBuf,
    /// Optional local base model package for PEFT/LoRA adapter execution.
    #[arg(long)]
    base: Option<PathBuf>,
    #[arg(long, default_value = "llama-cpp")]
    runtime: String,
    /// Absolute/local external runtime path for llama.cpp or the Python executable for Transformers.
    #[arg(long)]
    runtime_path: Option<PathBuf>,
    /// Local tokenizer.json required by the embedded backend.
    #[arg(long)]
    tokenizer: Option<PathBuf>,
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
    #[arg(long)]
    run_manifest_out: Option<PathBuf>,
    #[arg(long)]
    replay: Option<PathBuf>,
    #[arg(long)]
    max_mutations: Option<usize>,
    #[arg(long)]
    repeat_count: Option<usize>,
    #[arg(long)]
    watch_string: Vec<String>,
    /// Sandbox isolation backend (bwrap or microvm).
    #[arg(long, default_value = "bwrap")]
    sandbox: layerfault::behaviour::sandbox::SandboxKind,
    /// Path to local microVM guest image file (for --sandbox microvm).
    #[arg(long)]
    microvm_image: Option<PathBuf>,
    /// Expected SHA-256 hash of microVM guest image file.
    #[arg(long)]
    microvm_image_hash: Option<String>,
    /// Permit execution of a model/package that static admission BLOCKed. This
    /// is accepted only by external runtimes that enforce the strong sandbox.
    #[arg(long, default_value_t = false)]
    allow_static_blocked: bool,
    /// Permit Hugging Face custom loader Python (`trust_remote_code=True`) in
    /// the isolated Transformers backend. No network or host credentials are exposed.
    #[arg(long, default_value_t = false)]
    execute_custom_code: bool,
    /// Software environment runtime closure level (minimal, standard, deep).
    #[arg(long, default_value = "standard")]
    closure_level: String,
    /// Require cgroup v2 process-tree resource controls. Fail closed if unavailable.
    #[arg(long, default_value_t = false)]
    require_cgroup: bool,
    /// Sandbox telemetry backend: auto, strace, or ebpf.
    #[arg(long, default_value = "auto")]
    telemetry_backend: layerfault::behaviour::telemetry_backend::TelemetryBackendMode,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct CompareBehaviourArgs {
    base: PathBuf,
    derived: PathBuf,
    #[arg(long, default_value = "llama-cpp")]
    runtime: String,
    #[arg(long)]
    runtime_path: Option<PathBuf>,
    #[arg(long)]
    tokenizer: Option<PathBuf>,
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
    /// Sandbox isolation backend (bwrap or microvm).
    #[arg(long, default_value = "bwrap")]
    sandbox: layerfault::behaviour::sandbox::SandboxKind,
    /// Path to local microVM guest image file (for --sandbox microvm).
    #[arg(long)]
    microvm_image: Option<PathBuf>,
    /// Expected SHA-256 hash of microVM guest image file.
    #[arg(long)]
    microvm_image_hash: Option<String>,
    #[arg(long, default_value_t = false)]
    allow_static_blocked: bool,
    #[arg(long, default_value_t = false)]
    execute_custom_code: bool,
    /// Software environment runtime closure level (minimal, standard, deep).
    #[arg(long, default_value = "standard")]
    closure_level: String,
    /// Require cgroup v2 process-tree resource controls. Fail closed if unavailable.
    #[arg(long, default_value_t = false)]
    require_cgroup: bool,
    /// Sandbox telemetry backend: auto, strace, or ebpf.
    #[arg(long, default_value = "auto")]
    telemetry_backend: layerfault::behaviour::telemetry_backend::TelemetryBackendMode,
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
    /// LoRA adapter directory used for numerical merge verification when --claim lora-merge.
    #[arg(long)]
    adapter: Option<PathBuf>,
    #[arg(long, default_value = "standard")]
    profile: String,
    #[arg(long, default_value = "llama-cpp")]
    runtime: String,
    #[arg(long)]
    runtime_path: Option<PathBuf>,
    #[arg(long)]
    tokenizer: Option<PathBuf>,
    #[arg(long)]
    probe_suite: Option<PathBuf>,
    /// Sandbox isolation backend (bwrap or microvm).
    #[arg(long, default_value = "bwrap")]
    sandbox: layerfault::behaviour::sandbox::SandboxKind,
    /// Path to local microVM guest image file (for --sandbox microvm).
    #[arg(long)]
    microvm_image: Option<PathBuf>,
    /// Expected SHA-256 hash of microVM guest image file.
    #[arg(long)]
    microvm_image_hash: Option<String>,
    /// Permit blocked content to be exercised only inside the external strong sandbox.
    #[arg(long, default_value_t = false)]
    allow_static_blocked: bool,
    /// Permit custom Hugging Face Python loader execution in the sandboxed Transformers backend.
    #[arg(long, default_value_t = false)]
    execute_custom_code: bool,
    /// Require cgroup v2 process-tree resource controls. Fail closed if unavailable.
    #[arg(long, default_value_t = false)]
    require_cgroup: bool,
    /// Sandbox telemetry backend: auto, strace, or ebpf.
    #[arg(long, default_value = "auto")]
    telemetry_backend: layerfault::behaviour::telemetry_backend::TelemetryBackendMode,
    #[arg(long)]
    evidence_out: Option<PathBuf>,
    #[arg(long)]
    evidence_key: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    record_observation: bool,
    #[arg(long, default_value_t = false)]
    compare_previous: bool,
    #[arg(long, default_value_t = false)]
    reproduce_quantization: bool,
    #[arg(long)]
    quantizer: Option<PathBuf>,
    #[arg(long)]
    quantization: Option<String>,
    /// Optional advisory judge: disabled, local, openai-compatible.
    #[arg(long, default_value = "disabled")]
    judge: String,
    /// Required explicit opt-in before any cloud judge request.
    #[arg(long, default_value_t = false)]
    allow_cloud_judge: bool,
    #[arg(long)]
    judge_endpoint: Option<String>,
    #[arg(long)]
    judge_model: Option<String>,
    #[arg(long, default_value = "LAYERFAULT_JUDGE_API_KEY")]
    judge_api_key_env: String,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct ModelsArgs {
    #[command(subcommand)]
    command: ModelsCommand,
}

#[derive(Subcommand, Debug)]
enum ModelsCommand {
    Remember {
        model: PathBuf,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        publisher: Option<String>,
        #[arg(long)]
        revision: Option<String>,
        #[arg(long)]
        trust_label: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    List {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Show {
        id: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    History {
        id: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Forget {
        id: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(clap::Args, Debug)]
struct DriftArgs {
    model: PathBuf,
    #[arg(long, conflicts_with = "previous")]
    against: Option<String>,
    #[arg(long, default_value_t = false)]
    previous: bool,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(clap::Args, Debug)]
struct LineageArgs {
    #[command(subcommand)]
    command: LineageCommand,
}

#[derive(Subcommand, Debug)]
enum LineageCommand {
    VerifyChain {
        chain: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
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

pub(crate) fn run() -> Result<()> {
    let cli = Cli::parse();
    if cli.no_cache {
        std::env::set_var("LAYERFAULT_HASH_CACHE", "off");
        std::env::set_var("LAYERFAULT_CONTENT_CACHE", "off");
    }
    if let Some(cache_dir) = cli.cache_dir.as_ref() {
        std::env::set_var("LAYERFAULT_CACHE_DIR", cache_dir.as_os_str());
    }
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
        Some(Command::Capabilities(args)) => commands::operator::run_capabilities(args),
        Some(Command::Sources(args)) => commands::operator::run_sources(args),
        Some(Command::Explain(args)) => commands::operator::run_explain(args),
        Some(Command::Diff(args)) => commands::operator::run_diff(args),
        Some(Command::Compare(args)) => commands::lineage::run_compare(args),
        Some(Command::Behaviour(args)) => commands::behaviour::run_behaviour(args),
        Some(Command::CompareBehaviour(args)) => commands::behaviour::run_compare_behaviour(args),
        Some(Command::Review(args)) => commands::review::run_review(args),
        Some(Command::Models(args)) => commands::models::run_models(args),
        Some(Command::Drift(args)) => commands::models::run_drift(args),
        Some(Command::Lineage(args)) => commands::lineage::run_lineage(args),
        Some(Command::Dataset(args)) => commands::dataset::run_dataset(args),
        Some(Command::Research(args)) => commands::research::run_research(args),
        Some(Command::Hub(args)) => commands::hub::run_hub(args),
        Some(Command::Platform(args)) => commands::platform::run_platform(args),
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
    budget: layerfault::budget::ScanBudget,
    scheduler: layerfault::scheduler::AdaptiveScheduler,
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
    let profile = layerfault::budget::ScanBudgetProfile::parse(&common.budget_profile)?;
    let budget_config = match common.budget_file.as_deref() {
        Some(path) => layerfault::budget::ScanBudgetConfig::load(path)?,
        None => layerfault::budget::ScanBudgetConfig {
            profile,
            limits: None,
        },
    };
    let mut limits = budget_config.limits()?;
    if let Some(timeout_seconds) = common.timeout_seconds {
        limits.wall_clock_ms = timeout_seconds.saturating_mul(1000);
    }
    let budget = layerfault::budget::ScanBudget::new(limits)?;
    arm_ctrlc_cancellation(&budget);

    let mode = layerfault::scheduler::SchedulerMode::parse(&common.scheduler)?;
    let scheduler_config = layerfault::scheduler::SchedulerConfig::detect(
        common.jobs,
        common.max_memory_mib,
        common.max_inflight_bytes,
        mode,
        profile,
    );
    let scheduler = layerfault::scheduler::AdaptiveScheduler::new(scheduler_config);

    Ok(Prepared {
        thresholds,
        verifying_key,
        trust_store,
        policy: policy_doc.effective(),
        budget,
        scheduler,
    })
}

/// Map Ctrl-C (SIGINT) to cooperative cancellation of this invocation's scan
/// budget, so an interactive scan can be interrupted without losing findings
/// already produced. Best-effort: a handler can only be installed once per
/// process, so a failure here (e.g. a second budget created later in the same
/// run) is not fatal — the first-installed handler still cancels its budget's
/// shared inner state via any child scope that was cloned from it.
fn arm_ctrlc_cancellation(budget: &layerfault::budget::ScanBudget) {
    let cancel_budget = budget.clone();
    let _ = ctrlc::set_handler(move || cancel_budget.cancel());
}

pub(crate) fn standalone_budget(
    profile: &str,
    file: Option<&Path>,
    timeout_seconds: Option<u64>,
) -> Result<layerfault::budget::ScanBudget> {
    let config = match file {
        Some(path) => layerfault::budget::ScanBudgetConfig::load(path)?,
        None => layerfault::budget::ScanBudgetConfig {
            profile: layerfault::budget::ScanBudgetProfile::parse(profile)?,
            limits: None,
        },
    };
    let mut limits = config.limits()?;
    if let Some(timeout_seconds) = timeout_seconds {
        limits.wall_clock_ms = timeout_seconds.saturating_mul(1000);
    }
    let budget = layerfault::budget::ScanBudget::new(limits)?;
    arm_ctrlc_cancellation(&budget);
    Ok(budget)
}

fn scan_options<'a>(common: &ScanCommon, prepared: &'a Prepared, quiet: bool) -> ScanOptions<'a> {
    ScanOptions {
        thresholds: &prepared.thresholds,
        verifying_key: prepared.verifying_key.as_ref(),
        trust_store: &prepared.trust_store,
        policy: &prepared.policy,
        jobs: common.jobs.unwrap_or_else(app::default_jobs),
        quiet,
        budget: prepared.budget.clone(),
        scheduler: prepared.scheduler.clone(),
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
        json_stream::write_stdout_json(&admission_json(result), true)?;
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
    if let Some(identity) = &result.compound_identity {
        println!("  compound_identity={identity}");
    }
    print_actionable_findings(&result.results);
}

fn is_empty_slice<T>(items: &&[T]) -> bool {
    items.is_empty()
}

/// Typed mirror of [`artifact::ArtifactReport`] with `results` replaced by a
/// streamed, enriched projection instead of a `serde_json::Value` array
/// built by re-serializing the whole report and then overwriting one field.
#[derive(serde::Serialize)]
struct ArtifactJsonReport<'a, S: serde::Serialize> {
    path: &'a str,
    name: &'a str,
    format: &'a layerfault::formats::ArtifactFormat,
    size: u64,
    sha256: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compound_identity: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache: Option<&'a artifact::ArtifactCacheInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics: Option<&'a layerfault::scanner::ScanMetrics>,
    results: S,
    #[serde(skip_serializing_if = "is_empty_slice")]
    budget: &'a [layerfault::budget::BudgetUsage],
}

fn artifact_json_report(
    result: &artifact::ArtifactReport,
) -> ArtifactJsonReport<'_, impl serde::Serialize + '_> {
    ArtifactJsonReport {
        path: &result.path,
        name: &result.name,
        format: &result.format,
        size: result.size,
        sha256: result.sha256.as_deref(),
        compound_identity: result.compound_identity.as_deref(),
        cache: result.cache.as_ref(),
        metrics: result.metrics.as_ref(),
        results: json_stream::stream_seq(&result.results, report::enriched_finding_ref),
        budget: &result.budget,
    }
}

/// Typed mirror of [`package::PackageReport`] with `findings` streamed the
/// same way.
#[derive(serde::Serialize)]
struct PackageJsonReport<'a, S: serde::Serialize> {
    root: &'a str,
    fingerprint: &'a str,
    merkle_identity: &'a str,
    files: &'a [package::PackageEntry],
    #[serde(skip_serializing_if = "is_empty_slice")]
    merkle_manifest: &'a [package::PackageMerkleLeaf],
    total_bytes: u64,
    findings: S,
    #[serde(skip_serializing_if = "is_empty_slice")]
    correlations: &'a [layerfault::finding_evidence::FindingCorrelation],
    coverage: &'a layerfault::coverage::Coverage,
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics: Option<&'a layerfault::scanner::ScanMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    incremental_diagnostics: Option<&'a layerfault::incremental::IncrementalDiagnostics>,
}

fn package_json_report(
    result: &package::PackageReport,
) -> PackageJsonReport<'_, impl serde::Serialize + '_> {
    PackageJsonReport {
        root: &result.root,
        fingerprint: &result.fingerprint,
        merkle_identity: &result.merkle_identity,
        files: &result.files,
        merkle_manifest: &result.merkle_manifest,
        total_bytes: result.total_bytes,
        findings: json_stream::stream_seq(&result.findings, report::enriched_finding_ref),
        correlations: &result.correlations,
        coverage: &result.coverage,
        metrics: result.metrics.as_ref(),
        incremental_diagnostics: result.incremental_diagnostics.as_ref(),
    }
}

#[derive(serde::Serialize)]
struct AdmissionJsonReport<'a, S: serde::Serialize> {
    identity: &'a str,
    source: &'a SourceKind,
    report: ArtifactJsonReport<'a, S>,
    trust_state: provenance::TrustState,
    trusted_signatures: usize,
    signer_fingerprints: &'a [String],
    policy: &'a policy::PolicyDecision,
}

fn admission_json(
    result: &ArtifactAdmission,
) -> AdmissionJsonReport<'_, impl serde::Serialize + '_> {
    AdmissionJsonReport {
        identity: &result.identity,
        source: &result.source,
        report: artifact_json_report(&result.report),
        trust_state: result.trust_state,
        trusted_signatures: result.trusted_signatures,
        signer_fingerprints: &result.signer_fingerprints,
        policy: &result.policy,
    }
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
    let scanner =
        layerfault::decision::SecurityDecision::scanner_finding_exit_code(result.results.iter());
    layerfault::decision::SecurityDecision::combine_scanner_and_policy_exit_code(
        scanner, false, false,
    )
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
fn parse_scheduler(value: &str) -> std::result::Result<String, String> {
    match layerfault::scheduler::SchedulerMode::parse(value) {
        Ok(mode) => Ok(mode.as_str().to_owned()),
        Err(err) => Err(err.to_string()),
    }
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
