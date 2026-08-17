use clap::{Parser, Subcommand};
use std::path::PathBuf;

use super::validation::{
    parse_jobs, parse_nonnegative_finite_f64, parse_nonnegative_i64, parse_positive_u64,
    parse_scheduler,
};

#[derive(Parser, Debug)]
#[command(
    name = "layerfault",
    version,
    about = "Offline-first admission, provenance and supply-chain security for local AI model artifacts and runtimes"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<Command>,

    /// Disable persistent local hash/scan-evidence reuse and force fresh file reads.
    #[arg(long, global = true, default_value_t = false)]
    pub(crate) no_cache: bool,

    /// Override the persistent Layerfault cache directory.
    #[arg(long, global = true, value_name = "PATH")]
    pub(crate) cache_dir: Option<PathBuf>,

    /// Backward-compatible Ollama scan flags. Prefer `layerfault scan ...` for new automation.
    #[command(flatten)]
    pub(crate) legacy_scan: ScanArgs,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Command {
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
    /// Inspect and verify signed data-only Layerfault intelligence packs.
    Intelligence(IntelligenceArgs),
    /// Discover and assess local AI runtimes and model/runtime compatibility.
    Runtime(RuntimeArgs),
    /// Inspect and verify exact executable model compositions.
    Composition(CompositionArgs),
    /// Inspect agent, MCP server and tool capability exposure.
    Agent(AgentArgs),
    /// Inspect, verify and compare portable model security passports.
    Passport(PassportArgs),
    /// Snapshot and evaluate security-relevant execution drift.
    Continuous(ContinuousArgs),
    /// Snapshot, diff, approve and watch the persistent local model inventory.
    Inventory(InventoryArgs),
    /// Print build/runtime contract information.
    Version(VersionArgs),
}

#[derive(clap::Args, Debug, Clone)]
pub(crate) struct ScanCommon {
    /// Override the Ollama models directory. OLLAMA_MODELS and platform defaults are used otherwise.
    #[arg(long, value_name = "PATH")]
    pub(crate) ollama_dir: Option<PathBuf>,

    /// Operator policy maximum for temperature.
    #[arg(long, default_value_t = 2.0, value_parser = parse_nonnegative_finite_f64)]
    pub(crate) max_temperature: f64,

    /// Operator policy maximum for context size.
    #[arg(long, default_value_t = 1_048_576, value_parser = parse_positive_u64)]
    pub(crate) max_ctx: u64,

    /// Operator policy maximum for positive prediction-token limits.
    #[arg(long, default_value_t = 32_768, value_parser = parse_nonnegative_i64)]
    pub(crate) max_predict: i64,

    /// Legacy PEM Ed25519 public key for raw .sig verification.
    #[arg(long)]
    pub(crate) public_key: Option<PathBuf>,

    /// Trust-store JSON path. Defaults to the Layerfault config directory.
    #[arg(long)]
    pub(crate) trust_store: Option<PathBuf>,

    /// Built-in policy profile: permissive, workstation, ci, strict.
    #[arg(long, default_value = "workstation")]
    pub(crate) policy: String,

    /// JSON policy document. When supplied it takes precedence over --policy.
    #[arg(long)]
    pub(crate) policy_file: Option<PathBuf>,

    /// Maximum number of models scanned concurrently.
    #[arg(long, value_parser = parse_jobs)]
    pub(crate) jobs: Option<usize>,

    /// Global static-scan resource profile.
    #[arg(long, default_value = "default")]
    pub(crate) budget_profile: String,

    /// Versioned JSON resource-budget configuration. Overrides --budget-profile.
    #[arg(long)]
    pub(crate) budget_file: Option<PathBuf>,

    /// Wall-clock deadline for this scan invocation, overriding the budget
    /// profile's own wall-clock limit. On expiry the scan stops cooperatively,
    /// retains findings already produced, and reports incomplete coverage.
    #[arg(long)]
    pub(crate) timeout_seconds: Option<u64>,

    /// Scheduler concurrency mode: adaptive or fixed.
    #[arg(long, default_value = "adaptive", value_parser = parse_scheduler)]
    pub(crate) scheduler: String,

    /// Maximum estimated resident memory reservation in MiB.
    #[arg(long)]
    pub(crate) max_memory_mib: Option<u64>,

    /// Maximum in-flight large sequential I/O bytes.
    #[arg(long)]
    pub(crate) max_inflight_bytes: Option<u64>,
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
pub(crate) struct ScanArgs {
    /// Target one Ollama model. Canonical registry/namespace/model:tag names are supported.
    #[arg(short, long)]
    pub(crate) model: Option<String>,
    #[command(flatten)]
    pub(crate) common: ScanCommon,
    /// Emit versioned JSON to stdout.
    #[arg(long, default_value_t = false, conflicts_with_all = ["sarif", "jsonl"])]
    pub(crate) json: bool,
    /// Emit SARIF 2.1.0 to stdout.
    #[arg(long, default_value_t = false, conflicts_with_all = ["json", "jsonl"])]
    pub(crate) sarif: bool,
    /// Emit a versioned, newline-delimited JSON record stream to stdout.
    #[arg(long, default_value_t = false, conflicts_with_all = ["json", "sarif"])]
    pub(crate) jsonl: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct InspectArgs {
    pub(crate) path: PathBuf,
    #[arg(long, default_value_t = false)]
    pub(crate) structure_only: bool,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
    #[arg(long, default_value_t = false)]
    pub(crate) normalized: bool,
    #[arg(long, default_value_t = false)]
    pub(crate) incremental: bool,
    #[arg(long, default_value_t = false)]
    pub(crate) validate_incremental: bool,
    #[arg(long)]
    pub(crate) previous_state: Option<PathBuf>,
    #[arg(long, default_value = "default")]
    pub(crate) budget_profile: String,
    #[arg(long)]
    pub(crate) budget_file: Option<PathBuf>,
    /// Wall-clock deadline for this scan, overriding the budget profile's own
    /// wall-clock limit.
    #[arg(long)]
    pub(crate) timeout_seconds: Option<u64>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct VerifyFileArgs {
    pub(crate) path: PathBuf,
    #[command(flatten)]
    pub(crate) common: ScanCommon,
    #[arg(long, default_value = "file")]
    pub(crate) source: String,
    #[arg(long)]
    pub(crate) identity: Option<String>,
    #[arg(long)]
    pub(crate) architecture: Option<String>,
    #[arg(long)]
    pub(crate) quantization: Option<String>,
    #[arg(long)]
    pub(crate) sigstore_bundle: Option<PathBuf>,
    #[arg(long, requires = "sigstore_bundle")]
    pub(crate) certificate_identity: Option<String>,
    #[arg(long, requires = "sigstore_bundle")]
    pub(crate) certificate_issuer: Option<String>,
    #[command(flatten)]
    pub(crate) evidence: EvidenceWriteArgs,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct ScanDirArgs {
    pub(crate) path: PathBuf,
    #[arg(long, default_value_t = true)]
    pub(crate) recursive: bool,
    #[arg(long, default_value_t = false)]
    pub(crate) structure_only: bool,
    /// Maximum concurrent artifact scans (1-64).
    #[arg(long, value_parser = parse_jobs)]
    pub(crate) jobs: Option<usize>,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
    #[arg(long, default_value = "default")]
    pub(crate) budget_profile: String,
    #[arg(long)]
    pub(crate) budget_file: Option<PathBuf>,
    /// Wall-clock deadline for this scan, overriding the budget profile's own
    /// wall-clock limit.
    #[arg(long)]
    pub(crate) timeout_seconds: Option<u64>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct FingerprintArgs {
    pub(crate) path: PathBuf,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct VerifyPackageArgs {
    pub(crate) path: PathBuf,
    #[command(flatten)]
    pub(crate) common: ScanCommon,
    #[command(flatten)]
    pub(crate) evidence: EvidenceWriteArgs,
    #[command(flatten)]
    pub(crate) evidence_bundle: EvidenceBundleArgs,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
    /// Render the evidence-first human report instead of the table.
    #[arg(long = "evidence", default_value_t = false)]
    pub(crate) evidence_report: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct PipelineArgs {
    pub(crate) path: PathBuf,
    #[command(flatten)]
    pub(crate) common: ScanCommon,
    #[command(flatten)]
    pub(crate) evidence: EvidenceWriteArgs,
    #[command(flatten)]
    pub(crate) evidence_bundle: EvidenceBundleArgs,
    #[arg(long, default_value_t = false, conflicts_with_all = ["sarif", "summary", "jsonl"])]
    pub(crate) json: bool,
    #[arg(long, default_value_t = false, conflicts_with_all = ["json", "summary", "jsonl"])]
    pub(crate) sarif: bool,
    #[arg(long, default_value_t = false, conflicts_with_all = ["json", "sarif", "jsonl"])]
    pub(crate) summary: bool,
    /// Render the evidence-first human report instead of the table.
    #[arg(long = "evidence", default_value_t = false, conflicts_with_all = ["json", "sarif", "summary", "jsonl"])]
    pub(crate) evidence_report: bool,
    /// Emit a versioned, newline-delimited JSON record stream to stdout.
    #[arg(long, default_value_t = false, conflicts_with_all = ["json", "sarif", "summary", "evidence_report"])]
    pub(crate) jsonl: bool,
}

#[derive(clap::Args, Debug, Clone, Default)]
pub(crate) struct EvidenceWriteArgs {
    #[arg(long, requires = "evidence_key")]
    pub(crate) evidence_out: Option<PathBuf>,
    #[arg(long, requires = "evidence_out")]
    pub(crate) evidence_key: Option<PathBuf>,
}

/// Self-contained evidence bundle output. Distinct from `EvidenceWriteArgs`
/// (`--evidence-out`), which writes a signed Ed25519 admission envelope; this
/// writes a reviewable directory of findings, excerpts and a manifest.
#[derive(clap::Args, Debug, Clone, Default)]
pub(crate) struct EvidenceBundleArgs {
    /// Write a self-contained evidence bundle to this directory. Must not
    /// already contain files.
    #[arg(long, value_name = "DIR")]
    pub(crate) evidence_bundle: Option<PathBuf>,
}

#[derive(clap::Args, Debug, Clone, Default)]
pub(crate) struct RuntimeSecurityArgs {
    /// Pin the exact runtime executable instead of discovering it through PATH.
    #[arg(long, value_name = "PATH")]
    pub(crate) runtime_path: Option<PathBuf>,
    /// Optional signed external advisory database. Built-in advisories are compiled into Layerfault.
    #[arg(long, requires_all = ["advisory_signature", "advisory_public_key"])]
    pub(crate) advisory_db: Option<PathBuf>,
    #[arg(long, requires = "advisory_db")]
    pub(crate) advisory_signature: Option<PathBuf>,
    #[arg(long, requires = "advisory_db")]
    pub(crate) advisory_public_key: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct VerifyArgs {
    pub(crate) model: String,
    #[command(flatten)]
    pub(crate) common: ScanCommon,
    #[command(flatten)]
    pub(crate) evidence: EvidenceWriteArgs,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct RunArgs {
    pub(crate) model: String,
    #[command(flatten)]
    pub(crate) common: ScanCommon,
    #[command(flatten)]
    pub(crate) runtime_security: RuntimeSecurityArgs,
    #[command(flatten)]
    pub(crate) evidence: EvidenceWriteArgs,
    /// Runtime/source: ollama, lmstudio, llama-cpp.
    #[arg(long, default_value = "ollama")]
    pub(crate) source: String,
    /// Require a trusted admission receipt bound to the current artifact and runtime.
    #[arg(long, value_name = "PATH")]
    pub(crate) require_receipt: Option<PathBuf>,
    /// Permit an audited stale receipt; identity mismatches remain non-bypassable.
    #[arg(long, default_value_t = false, requires = "require_receipt")]
    pub(crate) accept_stale_receipt: bool,
    /// Override a policy-only block or explain an accepted stale receipt.
    #[arg(long, value_name = "REASON")]
    pub(crate) override_reason: Option<String>,
    #[arg(long)]
    pub(crate) override_log: Option<PathBuf>,
    /// Arguments passed to the selected runtime after the model/path.
    #[arg(last = true, allow_hyphen_values = true)]
    pub(crate) runtime_args: Vec<String>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct ImportArgs {
    pub(crate) path: PathBuf,
    #[command(flatten)]
    pub(crate) common: ScanCommon,
    #[command(flatten)]
    pub(crate) runtime_security: RuntimeSecurityArgs,
    #[command(flatten)]
    pub(crate) evidence: EvidenceWriteArgs,
    /// Currently supported: lmstudio.
    #[arg(long, default_value = "lmstudio")]
    pub(crate) source: String,
    /// Actually perform the import. Without this flag LM Studio is called with --dry-run.
    #[arg(long, default_value_t = false)]
    pub(crate) execute: bool,
    #[arg(last = true, allow_hyphen_values = true)]
    pub(crate) runtime_args: Vec<String>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct ServeArgs {
    pub(crate) path: PathBuf,
    #[command(flatten)]
    pub(crate) common: ScanCommon,
    #[command(flatten)]
    pub(crate) runtime_security: RuntimeSecurityArgs,
    #[command(flatten)]
    pub(crate) evidence: EvidenceWriteArgs,
    #[arg(last = true, allow_hyphen_values = true)]
    pub(crate) runtime_args: Vec<String>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct TrustArgs {
    #[command(subcommand)]
    pub(crate) command: TrustCommand,
    #[arg(long)]
    pub(crate) store: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub(crate) enum TrustCommand {
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
pub(crate) struct AttestArgs {
    #[command(subcommand)]
    pub(crate) command: AttestCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum AttestCommand {
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
pub(crate) struct AuditArgs {
    #[command(flatten)]
    pub(crate) common: ScanCommon,
    /// Source: ollama, lmstudio, hf-cache, all.
    #[arg(long, default_value = "ollama")]
    pub(crate) source: String,
    /// Additional standalone model directories included by --source all.
    #[arg(long = "directory")]
    pub(crate) directories: Vec<PathBuf>,
    #[arg(long)]
    pub(crate) hf_cache: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub(crate) deep: bool,
    #[arg(long)]
    pub(crate) mlbom: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct BaselineArgs {
    #[command(subcommand)]
    pub(crate) command: BaselineCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum BaselineCommand {
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
pub(crate) struct QuarantineArgs {
    #[command(subcommand)]
    pub(crate) command: QuarantineCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum QuarantineCommand {
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
pub(crate) struct PolicyArgs {
    #[command(subcommand)]
    pub(crate) command: PolicyCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum PolicyCommand {
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
pub(crate) struct DatasetArgs {
    #[command(subcommand)]
    pub(crate) command: DatasetCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum DatasetCommand {
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
pub(crate) struct ResearchArgs {
    #[command(subcommand)]
    pub(crate) command: ResearchCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum ResearchCommand {
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
        /// Which prompt-embedding context(s) to run each candidate through:
        /// `announced` (the original single template, one model call per
        /// candidate — the default, to keep run cost predictable), `full`
        /// (every template in the context matrix — several times the model
        /// calls), or a comma-separated list of specific template ids.
        #[arg(long, default_value = "announced")]
        context_templates: String,
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
        #[arg(long, default_value = "announced")]
        context_templates: String,
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
    BackdoorStatic {
        #[arg(long)]
        model: PathBuf,
        #[arg(long)]
        parent: Option<PathBuf>,
        #[arg(long)]
        dataset: Option<PathBuf>,
        #[arg(long)]
        adapter: Option<PathBuf>,
        #[arg(long, default_value = "standard")]
        profile: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    TriggerHunt {
        #[arg(long)]
        model: PathBuf,
        #[arg(long)]
        parent: Option<PathBuf>,
        #[arg(long)]
        runtime: Option<String>,
        #[arg(long = "candidate")]
        candidates: Vec<String>,
        #[arg(long, default_value_t = false)]
        from_tokenizer: bool,
        #[arg(long, default_value_t = 32)]
        beam_width: usize,
        #[arg(long, default_value_t = 2)]
        beam_rounds: usize,
        #[arg(long, default_value = "standard")]
        profile: String,
        #[arg(long, default_value = "announced")]
        context_templates: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(clap::Args, Debug)]
pub(crate) struct HubArgs {
    #[command(subcommand)]
    pub(crate) command: HubCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum HubCommand {
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
    Preflight {
        repo: String,
        #[arg(long)]
        revision: Option<String>,
        #[arg(long, default_value = "workstation")]
        profile: String,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        write_report: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(clap::Args, Debug)]
pub(crate) struct PlatformArgs {
    #[command(subcommand)]
    pub(crate) command: PlatformCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum PlatformCommand {
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
pub(crate) enum NewsletterCommand {
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
pub(crate) enum GcTarget {
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
pub(crate) struct GcArgs {
    #[arg(long)]
    pub(crate) ollama_dir: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub(crate) execute: bool,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
    /// What to garbage-collect. Defaults to `blobs`, preserving prior
    /// `layerfault gc` behavior exactly for callers that don't pass `--target`.
    #[arg(long, value_enum, default_value_t = GcTarget::Blobs)]
    pub(crate) target: GcTarget,
}

#[derive(clap::Args, Debug)]
pub(crate) struct OutputArgs {
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct ExplainArgs {
    pub(crate) rule_id: String,
    #[arg(long, default_value_t = false)]
    pub(crate) mappings: bool,
    #[arg(long)]
    pub(crate) intelligence_pack: Option<PathBuf>,
    #[arg(long)]
    pub(crate) intelligence_signature: Option<PathBuf>,
    #[arg(long)]
    pub(crate) intelligence_public_key: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct DiffArgs {
    pub(crate) left: String,
    pub(crate) right: String,
    #[arg(long)]
    pub(crate) ollama_dir: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct CompareArgs {
    pub(crate) base: PathBuf,
    pub(crate) derived: PathBuf,
    #[arg(long)]
    pub(crate) claim: Option<String>,
    #[arg(long)]
    pub(crate) transformation_manifest: Option<PathBuf>,
    /// LoRA adapter directory used to verify a claimed base + adapter -> merged model relationship.
    #[arg(long)]
    pub(crate) adapter: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
    #[arg(long, default_value_t = false)]
    pub(crate) reproduce_quantization: bool,
    #[arg(long)]
    pub(crate) quantizer: Option<PathBuf>,
    #[arg(long)]
    pub(crate) quantization: Option<String>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct BehaviourArgs {
    pub(crate) model: PathBuf,
    /// Optional local base model package for PEFT/LoRA adapter execution.
    #[arg(long)]
    pub(crate) base: Option<PathBuf>,
    #[arg(long, default_value = "llama-cpp")]
    pub(crate) runtime: String,
    /// Absolute/local external runtime path for llama.cpp or the Python executable for Transformers.
    #[arg(long)]
    pub(crate) runtime_path: Option<PathBuf>,
    /// Local tokenizer.json required by the embedded backend.
    #[arg(long)]
    pub(crate) tokenizer: Option<PathBuf>,
    #[arg(long, default_value = "standard")]
    pub(crate) profile: String,
    #[arg(long)]
    pub(crate) probe_suite: Option<PathBuf>,
    #[arg(long, default_value_t = 0)]
    pub(crate) seed: u64,
    #[arg(long)]
    pub(crate) max_prompts: Option<usize>,
    #[arg(long)]
    pub(crate) max_turns: Option<usize>,
    #[arg(long)]
    pub(crate) max_tokens: Option<usize>,
    #[arg(long)]
    pub(crate) timeout_seconds: Option<u64>,
    #[arg(long)]
    pub(crate) run_manifest_out: Option<PathBuf>,
    #[arg(long)]
    pub(crate) replay: Option<PathBuf>,
    #[arg(long)]
    pub(crate) max_mutations: Option<usize>,
    #[arg(long)]
    pub(crate) repeat_count: Option<usize>,
    #[arg(long)]
    pub(crate) watch_string: Vec<String>,
    /// Sandbox isolation backend (bwrap or microvm).
    #[arg(long, default_value = "bwrap")]
    pub(crate) sandbox: layerfault::behaviour::sandbox::SandboxKind,
    /// Path to local microVM guest image file (for --sandbox microvm).
    #[arg(long)]
    pub(crate) microvm_image: Option<PathBuf>,
    /// Expected SHA-256 hash of microVM guest image file.
    #[arg(long)]
    pub(crate) microvm_image_hash: Option<String>,
    /// Permit execution of a model/package that static admission BLOCKed. This
    /// is accepted only by external runtimes that enforce the strong sandbox.
    #[arg(long, default_value_t = false)]
    pub(crate) allow_static_blocked: bool,
    /// Permit Hugging Face custom loader Python (`trust_remote_code=True`) in
    /// the isolated Transformers backend. No network or host credentials are exposed.
    #[arg(long, default_value_t = false)]
    pub(crate) execute_custom_code: bool,
    /// Software environment runtime closure level (minimal, standard, deep).
    #[arg(long, default_value = "standard")]
    pub(crate) closure_level: String,
    /// Require cgroup v2 process-tree resource controls. Fail closed if unavailable.
    #[arg(long, default_value_t = false)]
    pub(crate) require_cgroup: bool,
    /// Sandbox telemetry backend: auto, strace, or ebpf.
    #[arg(long, default_value = "auto")]
    pub(crate) telemetry_backend: layerfault::behaviour::telemetry_backend::TelemetryBackendMode,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct CompareBehaviourArgs {
    pub(crate) base: PathBuf,
    pub(crate) derived: PathBuf,
    #[arg(long, default_value = "llama-cpp")]
    pub(crate) runtime: String,
    #[arg(long)]
    pub(crate) runtime_path: Option<PathBuf>,
    #[arg(long)]
    pub(crate) tokenizer: Option<PathBuf>,
    #[arg(long, default_value = "standard")]
    pub(crate) profile: String,
    #[arg(long)]
    pub(crate) probe_suite: Option<PathBuf>,
    #[arg(long, default_value_t = 0)]
    pub(crate) seed: u64,
    #[arg(long)]
    pub(crate) max_prompts: Option<usize>,
    #[arg(long)]
    pub(crate) max_turns: Option<usize>,
    #[arg(long)]
    pub(crate) max_tokens: Option<usize>,
    #[arg(long)]
    pub(crate) timeout_seconds: Option<u64>,
    /// Sandbox isolation backend (bwrap or microvm).
    #[arg(long, default_value = "bwrap")]
    pub(crate) sandbox: layerfault::behaviour::sandbox::SandboxKind,
    /// Path to local microVM guest image file (for --sandbox microvm).
    #[arg(long)]
    pub(crate) microvm_image: Option<PathBuf>,
    /// Expected SHA-256 hash of microVM guest image file.
    #[arg(long)]
    pub(crate) microvm_image_hash: Option<String>,
    #[arg(long, default_value_t = false)]
    pub(crate) allow_static_blocked: bool,
    #[arg(long, default_value_t = false)]
    pub(crate) execute_custom_code: bool,
    /// Software environment runtime closure level (minimal, standard, deep).
    #[arg(long, default_value = "standard")]
    pub(crate) closure_level: String,
    /// Require cgroup v2 process-tree resource controls. Fail closed if unavailable.
    #[arg(long, default_value_t = false)]
    pub(crate) require_cgroup: bool,
    /// Sandbox telemetry backend: auto, strace, or ebpf.
    #[arg(long, default_value = "auto")]
    pub(crate) telemetry_backend: layerfault::behaviour::telemetry_backend::TelemetryBackendMode,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct ReviewArgs {
    pub(crate) model: PathBuf,
    #[arg(long)]
    pub(crate) base: Option<PathBuf>,
    #[arg(long)]
    pub(crate) claim: Option<String>,
    #[arg(long)]
    pub(crate) transformation_manifest: Option<PathBuf>,
    /// LoRA adapter directory used for numerical merge verification when --claim lora-merge.
    #[arg(long)]
    pub(crate) adapter: Option<PathBuf>,
    #[arg(long, default_value = "standard")]
    pub(crate) profile: String,
    #[arg(long, default_value = "llama-cpp")]
    pub(crate) runtime: String,
    #[arg(long)]
    pub(crate) runtime_path: Option<PathBuf>,
    #[arg(long)]
    pub(crate) tokenizer: Option<PathBuf>,
    #[arg(long)]
    pub(crate) probe_suite: Option<PathBuf>,
    /// Sandbox isolation backend (bwrap or microvm).
    #[arg(long, default_value = "bwrap")]
    pub(crate) sandbox: layerfault::behaviour::sandbox::SandboxKind,
    /// Path to local microVM guest image file (for --sandbox microvm).
    #[arg(long)]
    pub(crate) microvm_image: Option<PathBuf>,
    /// Expected SHA-256 hash of microVM guest image file.
    #[arg(long)]
    pub(crate) microvm_image_hash: Option<String>,
    /// Permit blocked content to be exercised only inside the external strong sandbox.
    #[arg(long, default_value_t = false)]
    pub(crate) allow_static_blocked: bool,
    /// Permit custom Hugging Face Python loader execution in the sandboxed Transformers backend.
    #[arg(long, default_value_t = false)]
    pub(crate) execute_custom_code: bool,
    /// Require cgroup v2 process-tree resource controls. Fail closed if unavailable.
    #[arg(long, default_value_t = false)]
    pub(crate) require_cgroup: bool,
    /// Sandbox telemetry backend: auto, strace, or ebpf.
    #[arg(long, default_value = "auto")]
    pub(crate) telemetry_backend: layerfault::behaviour::telemetry_backend::TelemetryBackendMode,
    #[arg(long)]
    pub(crate) evidence_out: Option<PathBuf>,
    #[arg(long)]
    pub(crate) evidence_key: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub(crate) record_observation: bool,
    #[arg(long, default_value_t = false)]
    pub(crate) compare_previous: bool,
    #[arg(long, default_value_t = false)]
    pub(crate) reproduce_quantization: bool,
    #[arg(long)]
    pub(crate) quantizer: Option<PathBuf>,
    #[arg(long)]
    pub(crate) quantization: Option<String>,
    /// Optional advisory judge: disabled, local, openai-compatible.
    #[arg(long, default_value = "disabled")]
    pub(crate) judge: String,
    /// Required explicit opt-in before any cloud judge request.
    #[arg(long, default_value_t = false)]
    pub(crate) allow_cloud_judge: bool,
    #[arg(long)]
    pub(crate) judge_endpoint: Option<String>,
    #[arg(long)]
    pub(crate) judge_model: Option<String>,
    #[arg(long, default_value = "LAYERFAULT_JUDGE_API_KEY")]
    pub(crate) judge_api_key_env: String,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct ModelsArgs {
    #[command(subcommand)]
    pub(crate) command: ModelsCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum ModelsCommand {
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
    Identity {
        target: PathBuf,
        #[arg(long, default_value_t = false)]
        weights: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    IdentityCompare {
        left: PathBuf,
        right: PathBuf,
        #[arg(long, default_value_t = false)]
        weights: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Carve {
        target: PathBuf,
        #[arg(long, default_value = "standard")]
        profile: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Passport {
        target: PathBuf,
        #[arg(long)]
        parent: Option<PathBuf>,
        #[arg(long)]
        composition_manifest: Option<PathBuf>,
        #[arg(long)]
        agent_config: Option<PathBuf>,
        #[arg(long, default_value = "agent")]
        agent_name: String,
        #[arg(long)]
        provenance_chain: Option<PathBuf>,
        #[arg(long)]
        behaviour_report: Option<PathBuf>,
        #[arg(long)]
        trust_store: Option<PathBuf>,
        #[arg(long = "runtime")]
        runtimes: Vec<String>,
        #[arg(long, default_value = "native")]
        format: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(clap::Args, Debug)]
pub(crate) struct DriftArgs {
    pub(crate) model: PathBuf,
    #[arg(long, conflicts_with = "previous")]
    pub(crate) against: Option<String>,
    #[arg(long, default_value_t = false)]
    pub(crate) previous: bool,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct LineageArgs {
    #[command(subcommand)]
    pub(crate) command: LineageCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum LineageCommand {
    VerifyChain {
        chain: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Verify {
        #[arg(long)]
        parent: PathBuf,
        #[arg(long)]
        child: PathBuf,
        #[arg(long)]
        relation: String,
        #[arg(long)]
        adapter: Option<PathBuf>,
        #[arg(long)]
        chain: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Graph {
        #[arg(long = "manifest", required = true)]
        manifests: Vec<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(clap::Args, Debug)]
pub(crate) struct CertifyArgs {
    #[arg(long, default_value_t = false)]
    pub(crate) sparse: bool,
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct AdvisoryArgs {
    #[command(subcommand)]
    pub(crate) command: AdvisoryCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum AdvisoryCommand {
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
pub(crate) struct EvidenceArgs {
    #[command(subcommand)]
    pub(crate) command: EvidenceCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum EvidenceCommand {
    Verify {
        path: PathBuf,
        #[arg(long)]
        trust_store: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Admit {
        target: PathBuf,
        #[arg(long)]
        runtime: String,
        #[arg(long)]
        runtime_config: Option<PathBuf>,
        #[arg(long)]
        composition_manifest: Option<PathBuf>,
        #[arg(long)]
        agent_config: Option<PathBuf>,
        #[arg(long, default_value = "agent")]
        agent_name: String,
        #[arg(long)]
        provenance_chain: Option<PathBuf>,
        #[arg(long)]
        passport: Option<PathBuf>,
        #[arg(long)]
        intelligence_pack: Option<PathBuf>,
        #[arg(long)]
        intelligence_signature: Option<PathBuf>,
        #[arg(long)]
        intelligence_public_key: Option<PathBuf>,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "workstation")]
        policy: String,
        #[arg(long)]
        policy_file: Option<PathBuf>,
        #[arg(long)]
        trust_store: Option<PathBuf>,
    },
    Gate {
        receipt: PathBuf,
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        runtime: Option<PathBuf>,
        #[arg(long)]
        runtime_config: Option<PathBuf>,
        #[arg(long)]
        composition_manifest: Option<PathBuf>,
        #[arg(long)]
        agent_config: Option<PathBuf>,
        #[arg(long, default_value = "agent")]
        agent_name: String,
        #[arg(long)]
        passport: Option<PathBuf>,
        #[arg(long)]
        intelligence_pack: Option<PathBuf>,
        #[arg(long)]
        intelligence_signature: Option<PathBuf>,
        #[arg(long)]
        intelligence_public_key: Option<PathBuf>,
        #[arg(long)]
        trust_store: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        accept_stale_receipt: bool,
        #[arg(long, requires = "accept_stale_receipt")]
        override_reason: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Predicate {
        receipt: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(clap::Args, Debug)]
pub(crate) struct IntelligenceArgs {
    #[command(subcommand)]
    pub(crate) command: IntelligenceCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum IntelligenceCommand {
    Show {
        #[arg(long)]
        pack: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Verify {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        signature: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long, default_value_t = false)]
        allow_rollback: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Export an already signed intelligence pack as a portable offline bundle.
    Export {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        signature: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify and import a portable offline intelligence bundle.
    Import {
        bundle: PathBuf,
        #[arg(long)]
        pack_output: PathBuf,
        #[arg(long)]
        signature_output: PathBuf,
        #[arg(long)]
        public_key_output: PathBuf,
        #[arg(long, default_value_t = false)]
        allow_rollback: bool,
    },
    VerifyBundle {
        bundle: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(clap::Args, Debug)]
pub(crate) struct RuntimeArgs {
    #[command(subcommand)]
    pub(crate) command: RuntimeCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum RuntimeCommand {
    List {
        #[arg(long)]
        runtime: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Audit {
        #[arg(long)]
        runtime: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Assess {
        #[arg(long)]
        runtime: String,
        #[arg(long)]
        model: PathBuf,
        #[arg(long)]
        intelligence_pack: Option<PathBuf>,
        #[arg(long)]
        intelligence_signature: Option<PathBuf>,
        #[arg(long)]
        intelligence_public_key: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Matrix {
        #[arg(long)]
        model: PathBuf,
        #[arg(long = "runtime")]
        runtimes: Vec<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(clap::Args, Debug)]
pub(crate) struct CompositionArgs {
    #[command(subcommand)]
    pub(crate) command: CompositionCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum CompositionCommand {
    /// Resolve a composition manifest to exact component identities and findings.
    Inspect {
        manifest: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Inspect one LoRA/adapter package independently of its base model.
    Adapter {
        adapter: PathBuf,
        #[arg(long)]
        expected_base: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Compare a base model, adapter and merged artifact using bounded merge verification.
    VerifyMerge {
        #[arg(long)]
        base: PathBuf,
        #[arg(long)]
        adapter: PathBuf,
        #[arg(long)]
        merged: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Write a minimal composition manifest template.
    Init { output: PathBuf },
}

#[derive(clap::Args, Debug)]
pub(crate) struct AgentArgs {
    #[command(subcommand)]
    pub(crate) command: AgentCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum AgentCommand {
    /// Statically inspect agent/MCP configuration and normalize tool capabilities.
    Inspect {
        config: PathBuf,
        #[arg(long, default_value = "agent")]
        name: String,
        #[arg(long)]
        composition_manifest: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(clap::Args, Debug)]
pub(crate) struct PassportArgs {
    #[command(subcommand)]
    pub(crate) command: PassportCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum PassportCommand {
    Inspect {
        passport: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Verify a signed passport when an envelope is supplied, or validate canonical content for an unsigned passport.
    Verify {
        passport: PathBuf,
        #[arg(long)]
        trust_store: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Sign {
        passport: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Diff {
        left: PathBuf,
        right: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(clap::Args, Debug)]
pub(crate) struct ContinuousArgs {
    #[command(subcommand)]
    pub(crate) command: ContinuousCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum ContinuousCommand {
    /// Capture security-relevant execution identities without executing the model or tools.
    Snapshot {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "unknown")]
        state: String,
        #[arg(long)]
        model_artifact: Option<PathBuf>,
        #[arg(long)]
        composition_manifest: Option<PathBuf>,
        #[arg(long)]
        agent_config: Option<PathBuf>,
        #[arg(long, default_value = "agent")]
        agent_name: String,
        #[arg(long)]
        runtime_binary: Option<PathBuf>,
        #[arg(long)]
        runtime_config: Option<PathBuf>,
        #[arg(long)]
        policy_file: Option<PathBuf>,
        #[arg(long)]
        intelligence_pack: Option<PathBuf>,
        #[arg(long)]
        provenance_chain: Option<PathBuf>,
        #[arg(long)]
        passport: Option<PathBuf>,
        #[arg(long)]
        receipt: Option<PathBuf>,
        /// Path to a behaviour report (`layerfault behaviour run --json` output)
        /// documenting an actual behavioural run. Behavioural-assurance
        /// evidence is recorded only if this is present and binds to the
        /// runtime binary observed in this same snapshot.
        #[arg(long)]
        behavioural_report: Option<PathBuf>,
        #[arg(long)]
        behaviour_affecting_environment: Option<PathBuf>,
        #[arg(long)]
        platform_environment: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Compare execution snapshots and invalidate only evidence that depends on changed state.
    Diff {
        previous: PathBuf,
        current: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        journal: Option<PathBuf>,
        /// Path to write the journal's tail anchor after appending, so a
        /// later `journal --verify` can detect the journal being made
        /// shorter (see `continuous::journal` module docs for what this
        /// does and does not protect against). Only meaningful together
        /// with `--journal`.
        #[arg(long)]
        head_anchor: Option<PathBuf>,
        #[arg(long, default_value = "execution")]
        entity: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Watch {
        #[arg(long)]
        state_path: PathBuf,
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        head_anchor: Option<PathBuf>,
        #[arg(long, default_value = "execution")]
        entity: String,
        #[arg(long, default_value = "unknown")]
        state: String,
        #[arg(long, default_value_t = 60)]
        interval: u64,
        #[arg(long)]
        model_artifact: Option<PathBuf>,
        #[arg(long)]
        composition_manifest: Option<PathBuf>,
        #[arg(long)]
        agent_config: Option<PathBuf>,
        #[arg(long, default_value = "agent")]
        agent_name: String,
        #[arg(long)]
        runtime_binary: Option<PathBuf>,
        #[arg(long)]
        runtime_config: Option<PathBuf>,
        #[arg(long)]
        policy_file: Option<PathBuf>,
        #[arg(long)]
        intelligence_pack: Option<PathBuf>,
        #[arg(long)]
        provenance_chain: Option<PathBuf>,
        #[arg(long)]
        passport: Option<PathBuf>,
        #[arg(long)]
        receipt: Option<PathBuf>,
        #[arg(long)]
        behavioural_report: Option<PathBuf>,
        #[arg(long)]
        behaviour_affecting_environment: Option<PathBuf>,
        #[arg(long)]
        platform_environment: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        jsonl: bool,
    },
    Journal {
        journal: PathBuf,
        /// Verify the journal's hash chain (and, if given, its tail against
        /// this anchor file written by `--head-anchor` elsewhere) instead
        /// of listing events.
        #[arg(long, default_value_t = false)]
        verify: bool,
        #[arg(long)]
        head_anchor: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(clap::Args, Debug)]
pub(crate) struct InventoryArgs {
    #[command(subcommand)]
    pub(crate) command: InventoryCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum InventoryCommand {
    Snapshot {
        #[arg(long)]
        state: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        runtime_aware: bool,
        #[arg(long = "dir")]
        directories: Vec<PathBuf>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Diff {
        #[arg(long)]
        previous: PathBuf,
        #[arg(long, conflicts_with = "scan")]
        current: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        scan: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Approve {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        identity: String,
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long)]
        trust_store: Option<PathBuf>,
    },
    Watch {
        #[arg(long)]
        state: Option<PathBuf>,
        #[arg(long, default_value_t = 60)]
        interval: u64,
        #[arg(long, default_value_t = false)]
        runtime_aware: bool,
        #[arg(long, default_value_t = false)]
        verbose: bool,
        #[arg(long = "dir")]
        directories: Vec<PathBuf>,
        #[arg(long, default_value_t = false)]
        jsonl: bool,
    },
}

#[derive(clap::Args, Debug)]
pub(crate) struct VersionArgs {
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}
