use super::*;
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
        // --timeout-seconds is the hard command-wide deadline. The CLI passes
        // u64::MAX when it was not specified, preserving the profile default;
        // an explicit value replaces (rather than clamps to) that default.
        if timeout > 0 && timeout != u64::MAX {
            self.timeout_seconds = timeout;
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActiveExecutionOptions {
    /// Sandbox isolation backend to use for active execution (bwrap or microvm).
    pub sandbox_kind: sandbox::SandboxKind,
    /// Optional microVM configuration (image path, hash override, memory, vcpus).
    #[serde(default)]
    pub microvm_config: microvm::MicrovmConfig,
    /// Permit dynamic execution even when static admission has already BLOCKed.
    /// External execution still requires the strong sandbox.
    pub allow_static_blocked: bool,
    /// Permit Hugging Face custom Python loaders (`trust_remote_code=True`) in
    /// the sandboxed Transformers backend.
    pub execute_custom_code: bool,
    /// Closure profile level for software environment runtime discovery.
    pub closure_level: closure::ClosureLevel,
    /// Enforce cgroup v2 process-tree resource limits. Fail closed if unavailable.
    #[serde(default)]
    pub require_cgroup: bool,
    /// Sandbox telemetry backend selection (auto/strace/ebpf).
    #[serde(default)]
    pub telemetry_backend: super::telemetry_backend::TelemetryBackendMode,
}

#[derive(Debug, Clone)]
pub(crate) struct CommandDeadline {
    started: Instant,
    total: Duration,
}

impl CommandDeadline {
    pub(crate) fn new(seconds: u64) -> Self {
        Self {
            started: Instant::now(),
            total: Duration::from_secs(seconds.max(1)),
        }
    }

    pub(crate) fn remaining(&self) -> Duration {
        self.total.saturating_sub(self.started.elapsed())
    }

    pub(crate) fn expired(&self) -> bool {
        self.remaining().is_zero()
    }

    pub(crate) fn elapsed_seconds(&self) -> u64 {
        self.started.elapsed().as_secs()
    }
}

pub(crate) struct ProgressHeartbeat {
    stop: Arc<AtomicBool>,
    phase: Arc<Mutex<String>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ProgressHeartbeat {
    pub(crate) fn start(label: &str) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let phase = Arc::new(Mutex::new(format!("phase={label} runtime-start")));
        let thread_stop = Arc::clone(&stop);
        let thread_phase = Arc::clone(&phase);
        let started = Instant::now();
        let label = label.to_owned();
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                for _ in 0..100 {
                    if thread_stop.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                let detail = thread_phase
                    .lock()
                    .map(|value| value.clone())
                    .unwrap_or_else(|_| "phase=unknown".to_owned());
                eprintln!(
                    "ACTIVE {label} elapsed={}s {detail}",
                    started.elapsed().as_secs()
                );
            }
        });
        Self {
            stop,
            phase,
            thread: Some(thread),
        }
    }

    pub(crate) fn update(&self, value: impl Into<String>) {
        if let Ok(mut phase) = self.phase.lock() {
            *phase = value.into();
        }
    }
}

impl Drop for ProgressHeartbeat {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DynamicObservationSummary {
    pub executions_with_telemetry: usize,
    pub network_attempts: usize,
    pub process_exec_attempts: usize,
    pub sensitive_path_accesses: usize,
    pub canary_accesses: usize,
    pub unexpected_filesystem_mutations: usize,
    pub filesystem_write_attempts: usize,
    pub trace_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeIdentity {
    pub backend: String,
    pub executable: String,
    pub executable_sha256: String,
    pub version: Option<String>,
    pub sandbox: sandbox::SandboxCapabilities,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closure: Option<closure::RuntimeClosure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeExecution {
    pub probe_id: String,
    pub category: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparison_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparison_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_boundary: Option<String>,
    pub prompt_sha256: String,
    pub response_sha256: String,
    pub response_excerpt: String,
    pub duration_ms: u64,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub telemetry: sandbox::SandboxTelemetry,
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
    pub dynamic_observations: DynamicObservationSummary,
    pub state: crate::transformation::BehaviourState,
    pub findings: Vec<String>,
    pub boundary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialRow {
    pub probe_id: String,
    pub category: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparison_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparison_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_boundary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_refusal: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_refusal: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_actionable_compliance: Option<bool>,
    pub base_risk: String,
    pub derived_risk: String,
    /// Deterministic lexical similarity in 0.0..=1.0 for the bounded response
    /// excerpts. This is evidence, not a semantic-equivalence proof.
    #[serde(default)]
    pub response_similarity: f64,
    #[serde(default)]
    pub response_length_ratio: f64,
    #[serde(default)]
    pub base_repetition_score: f64,
    #[serde(default)]
    pub derived_repetition_score: f64,
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
    #[serde(default)]
    pub runtime_closure_id: String,
    #[serde(default)]
    pub closure_level: closure::ClosureLevel,
    #[serde(default)]
    pub component_summary: Vec<closure::RuntimeComponent>,
    #[serde(default)]
    pub coverage_state: closure::ClosureCoverage,
    pub probe_suite_path: Option<String>,
    pub probe_suite_id: String,
    pub probe_suite_version: u32,
    pub seed: u64,
    pub limits: BehaviourLimits,
}
