use crate::provenance::TrustState;
use crate::scanner::{Confidence, FindingClass, LayerScanResult, ScanStatus};
use crate::trust::glob_match;
use anyhow::{anyhow, bail, Context, Result};
use std::path::Path;

const MAX_POLICY_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProfile {
    Permissive,
    Workstation,
    Ci,
    Strict,
}

impl PolicyProfile {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "permissive" => Ok(Self::Permissive),
            "workstation" => Ok(Self::Workstation),
            "ci" => Ok(Self::Ci),
            "strict" => Ok(Self::Strict),
            other => Err(anyhow!(
                "Unknown policy profile '{other}'. Use permissive, workstation, ci, or strict"
            )),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Suppression {
    pub rule_id: String,
    #[serde(default = "default_model_pattern")]
    pub model: String,
    pub reason: String,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub expires_unix: Option<u64>,
}

fn default_model_pattern() -> String {
    "*".to_owned()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyDocument {
    pub version: u32,
    pub profile: PolicyProfile,
    #[serde(default)]
    pub require_trusted_attestation: Option<bool>,
    #[serde(default)]
    pub block_unknown_layers: Option<bool>,
    #[serde(default)]
    pub block_on_warnings: Option<bool>,
    #[serde(default)]
    pub allowed_model_patterns: Vec<String>,
    #[serde(default)]
    pub denied_rule_ids: Vec<String>,
    #[serde(default)]
    pub suppressions: Vec<Suppression>,
    #[serde(default)]
    pub allowed_sources: Vec<String>,
    #[serde(default)]
    pub allowed_formats: Vec<String>,
    #[serde(default)]
    pub allowed_architectures: Vec<String>,
    #[serde(default)]
    pub allowed_quantizations: Vec<String>,
    #[serde(default)]
    pub max_model_bytes: Option<u64>,
    #[serde(default)]
    pub minimum_trusted_signatures: Option<usize>,
    #[serde(default)]
    pub required_signer_fingerprints: Vec<String>,
    #[serde(default)]
    pub block_finding_classes: Vec<FindingClass>,
    #[serde(default)]
    pub block_confidence_at_or_above: Option<Confidence>,
}

impl Default for PolicyDocument {
    fn default() -> Self {
        Self {
            version: 1,
            profile: PolicyProfile::Workstation,
            require_trusted_attestation: None,
            block_unknown_layers: None,
            block_on_warnings: None,
            allowed_model_patterns: Vec::new(),
            denied_rule_ids: Vec::new(),
            suppressions: Vec::new(),
            allowed_sources: Vec::new(),
            allowed_formats: Vec::new(),
            allowed_architectures: Vec::new(),
            allowed_quantizations: Vec::new(),
            max_model_bytes: None,
            minimum_trusted_signatures: None,
            required_signer_fingerprints: Vec::new(),
            block_finding_classes: Vec::new(),
            block_confidence_at_or_above: None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EffectivePolicy {
    pub profile: PolicyProfile,
    pub require_trusted_attestation: bool,
    pub block_unknown_layers: bool,
    pub block_on_warnings: bool,
    pub allowed_model_patterns: Vec<String>,
    pub denied_rule_ids: Vec<String>,
    pub suppressions: Vec<Suppression>,
    pub allowed_sources: Vec<String>,
    pub allowed_formats: Vec<String>,
    pub allowed_architectures: Vec<String>,
    pub allowed_quantizations: Vec<String>,
    pub max_model_bytes: Option<u64>,
    pub minimum_trusted_signatures: usize,
    pub required_signer_fingerprints: Vec<String>,
    pub block_finding_classes: Vec<FindingClass>,
    pub block_confidence_at_or_above: Option<Confidence>,
}

#[derive(Debug, Clone, Default)]
pub struct PolicyContext {
    pub source: Option<String>,
    pub format: Option<String>,
    pub architecture: Option<String>,
    pub quantization: Option<String>,
    pub model_size: Option<u64>,
    pub trusted_signatures: usize,
    pub signer_fingerprints: Vec<String>,
    pub now_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PolicyAction {
    Allow,
    Warn,
    Block,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicyDecision {
    pub profile: PolicyProfile,
    pub action: PolicyAction,
    pub reasons: Vec<String>,
    pub suppressed_rule_ids: Vec<String>,
}

impl PolicyDocument {
    pub fn builtin(profile: PolicyProfile) -> Self {
        Self {
            profile,
            ..Self::default()
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let file = crate::safeio::open_readonly_nofollow(path)?;
        let bytes = crate::safeio::read_all_from_file(&file, MAX_POLICY_BYTES)?;
        let doc: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("Policy '{}' is not valid JSON", path.display()))?;
        doc.validate()?;
        Ok(doc)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(anyhow!("Unsupported policy version {}", self.version));
        }
        for pattern in &self.allowed_model_patterns {
            if pattern.trim().is_empty() || pattern.contains("..") || pattern.contains('\\') {
                return Err(anyhow!("Unsafe model pattern '{pattern}'"));
            }
        }
        if self
            .minimum_trusted_signatures
            .is_some_and(|value| value > 32)
        {
            return Err(anyhow!("minimum_trusted_signatures cannot exceed 32"));
        }
        for list in [
            &self.allowed_sources,
            &self.allowed_formats,
            &self.allowed_architectures,
            &self.allowed_quantizations,
        ] {
            if list.iter().any(|value| value.trim().is_empty()) {
                return Err(anyhow!("Policy allowlists cannot contain empty values"));
            }
        }
        for fingerprint in &self.required_signer_fingerprints {
            if !fingerprint.starts_with("sha256:") || fingerprint.len() != 71 {
                return Err(anyhow!(
                    "Required signer fingerprint '{fingerprint}' is not canonical sha256"
                ));
            }
        }
        for suppression in &self.suppressions {
            if suppression.rule_id.trim().is_empty() {
                return Err(anyhow!("Policy suppression has an empty rule_id"));
            }
            if suppression.reason.trim().len() < 8 {
                return Err(anyhow!(
                    "Suppression for '{}' requires a meaningful reason (at least 8 characters)",
                    suppression.rule_id
                ));
            }
            if suppression.expires_unix == Some(0) {
                return Err(anyhow!("Suppression expiry cannot be zero"));
            }
        }
        Ok(())
    }

    pub fn effective(&self) -> EffectivePolicy {
        let (require_trusted, block_unknown, block_warn) = match self.profile {
            PolicyProfile::Permissive => (false, false, false),
            PolicyProfile::Workstation => (false, false, false),
            PolicyProfile::Ci => (false, true, false),
            PolicyProfile::Strict => (true, true, true),
        };
        EffectivePolicy {
            profile: self.profile,
            require_trusted_attestation: self
                .require_trusted_attestation
                .unwrap_or(require_trusted),
            block_unknown_layers: self.block_unknown_layers.unwrap_or(block_unknown),
            block_on_warnings: self.block_on_warnings.unwrap_or(block_warn),
            allowed_model_patterns: self.allowed_model_patterns.clone(),
            denied_rule_ids: self.denied_rule_ids.clone(),
            suppressions: self.suppressions.clone(),
            allowed_sources: normalize(&self.allowed_sources),
            allowed_formats: normalize(&self.allowed_formats),
            allowed_architectures: normalize(&self.allowed_architectures),
            allowed_quantizations: normalize(&self.allowed_quantizations),
            max_model_bytes: self.max_model_bytes,
            minimum_trusted_signatures: self
                .minimum_trusted_signatures
                .unwrap_or(usize::from(require_trusted)),
            required_signer_fingerprints: self.required_signer_fingerprints.clone(),
            block_finding_classes: self.block_finding_classes.clone(),
            block_confidence_at_or_above: self.block_confidence_at_or_above,
        }
    }
}

impl EffectivePolicy {
    pub fn evaluate(
        &self,
        model: &str,
        results: &[LayerScanResult],
        trust_state: TrustState,
    ) -> PolicyDecision {
        let mut context = PolicyContext {
            source: Some("ollama".to_owned()),
            trusted_signatures: usize::from(trust_state == TrustState::Trusted),
            now_unix: crate::paths::now_unix(),
            ..PolicyContext::default()
        };
        if trust_state == TrustState::LocallyVerified {
            context.trusted_signatures = 0;
        }
        self.evaluate_with_context(model, results, trust_state, &context)
    }

    pub fn evaluate_with_context(
        &self,
        model: &str,
        results: &[LayerScanResult],
        trust_state: TrustState,
        context: &PolicyContext,
    ) -> PolicyDecision {
        let mut block_reasons = Vec::new();
        let mut warn_reasons = Vec::new();
        let mut suppressed = Vec::new();
        if !self.allowed_model_patterns.is_empty()
            && !self
                .allowed_model_patterns
                .iter()
                .any(|pattern| glob_match(pattern, model))
        {
            block_reasons.push(format!(
                "Model identity '{model}' is outside the policy allowlist"
            ));
        }
        check_allowed(
            "source",
            context.source.as_deref(),
            &self.allowed_sources,
            &mut block_reasons,
        );
        check_allowed(
            "format",
            context.format.as_deref(),
            &self.allowed_formats,
            &mut block_reasons,
        );
        check_allowed(
            "architecture",
            context.architecture.as_deref(),
            &self.allowed_architectures,
            &mut block_reasons,
        );
        check_allowed(
            "quantization",
            context.quantization.as_deref(),
            &self.allowed_quantizations,
            &mut block_reasons,
        );
        if let (Some(limit), Some(size)) = (self.max_model_bytes, context.model_size) {
            if size > limit {
                block_reasons.push(format!(
                    "Model size {size} exceeds policy maximum {limit} bytes"
                ));
            }
        }
        if self.require_trusted_attestation && trust_state != TrustState::Trusted {
            block_reasons.push(format!(
                "Trusted attestation is required, current provenance state is {trust_state:?}"
            ));
        }
        if context.trusted_signatures < self.minimum_trusted_signatures {
            block_reasons.push(format!(
                "Policy requires at least {} trusted signature(s), observed {}",
                self.minimum_trusted_signatures, context.trusted_signatures
            ));
        }
        if !self.required_signer_fingerprints.is_empty()
            && !self.required_signer_fingerprints.iter().any(|required| {
                context
                    .signer_fingerprints
                    .iter()
                    .any(|actual| actual.eq_ignore_ascii_case(required))
            })
        {
            block_reasons.push(
                "None of the policy-pinned signer fingerprints attested this artifact".to_owned(),
            );
        }

        for result in results {
            let rule = rule_id(result);
            if self
                .denied_rule_ids
                .iter()
                .any(|denied| denied.eq_ignore_ascii_case(&rule))
            {
                block_reasons.push(format!("Denied rule {rule} matched"));
                continue;
            }
            if self.block_finding_classes.contains(&result.finding_class)
                && result.status != ScanStatus::Pass
            {
                block_reasons.push(format!(
                    "Finding class {:?} is blocking by policy ({rule})",
                    result.finding_class
                ));
                continue;
            }
            if result.status == ScanStatus::Pass {
                continue;
            }
            if suppression_allowed(result)
                && self
                    .suppressions
                    .iter()
                    .any(|entry| suppression_matches(entry, &rule, model, context.now_unix))
            {
                suppressed.push(rule);
                continue;
            }
            if self.block_unknown_layers
                && result.check_type == crate::scanner::CheckType::LayerPolicy
                && result.detail.as_deref().is_some_and(|detail| {
                    detail.contains("Unknown layer media type")
                        || detail.contains("Unknown artifact format")
                })
            {
                block_reasons.push("Unknown artifact/layer type is forbidden by policy".to_owned());
                continue;
            }
            if self.block_confidence_at_or_above.is_some_and(|threshold| {
                confidence_rank(result.confidence) >= confidence_rank(threshold)
            }) {
                block_reasons.push(format!(
                    "{rule} meets configured blocking confidence threshold"
                ));
                continue;
            }
            match result.status {
                ScanStatus::Fail => block_reasons.push(format!(
                    "{}: {}",
                    rule,
                    result
                        .detail
                        .as_deref()
                        .unwrap_or("blocking scanner finding")
                )),
                ScanStatus::Warn if self.block_on_warnings => {
                    block_reasons.push(format!("{} warning is blocking under this profile", rule))
                }
                ScanStatus::Warn => warn_reasons.push(format!(
                    "{}: {}",
                    rule,
                    result.detail.as_deref().unwrap_or("scanner warning")
                )),
                ScanStatus::Pass => {}
            }
        }
        suppressed.sort();
        suppressed.dedup();
        block_reasons.sort();
        block_reasons.dedup();
        warn_reasons.sort();
        warn_reasons.dedup();
        let (action, reasons) = if !block_reasons.is_empty() {
            (PolicyAction::Block, block_reasons)
        } else if !warn_reasons.is_empty() {
            (PolicyAction::Warn, warn_reasons)
        } else {
            (PolicyAction::Allow, Vec::new())
        };
        PolicyDecision {
            profile: self.profile,
            action,
            reasons,
            suppressed_rule_ids: suppressed,
        }
    }
}

fn suppression_matches(entry: &Suppression, rule: &str, model: &str, now: u64) -> bool {
    entry.rule_id.eq_ignore_ascii_case(rule)
        && glob_match(&entry.model, model)
        && !entry.reason.trim().is_empty()
        && entry.expires_unix.is_none_or(|expiry| now <= expiry)
}

fn normalize(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

fn check_allowed(label: &str, value: Option<&str>, allowed: &[String], reasons: &mut Vec<String>) {
    if allowed.is_empty() {
        return;
    }
    match value {
        Some(value)
            if allowed
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(value)) => {}
        Some(value) => reasons.push(format!(
            "Artifact {label} '{value}' is not allowed by policy"
        )),
        None => reasons.push(format!(
            "Policy requires a known/allowed {label}, but Layerfault could not determine it"
        )),
    }
}

fn confidence_rank(value: Confidence) -> u8 {
    match value {
        Confidence::Low => 1,
        Confidence::Medium => 2,
        Confidence::High => 3,
    }
}

pub fn rule_id(result: &LayerScanResult) -> String {
    for matched in &result.matches {
        if let Some(rest) = matched.strip_prefix('[') {
            if let Some((candidate, _)) = rest.split_once(']') {
                if !candidate.trim().is_empty() {
                    return candidate.trim().to_owned();
                }
            }
        }
    }
    format!("LF-{:?}", result.check_type).to_ascii_uppercase()
}

fn suppression_allowed(result: &LayerScanResult) -> bool {
    if result.status == ScanStatus::Fail {
        return matches!(
            result.finding_class,
            FindingClass::ContentIndicator | FindingClass::Policy | FindingClass::Compatibility
        );
    }
    !matches!(
        result.finding_class,
        FindingClass::Integrity
            | FindingClass::Structural
            | FindingClass::Operational
            | FindingClass::Attestation
    )
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct OverrideRecord {
    pub version: u32,
    pub created_unix: u64,
    pub model: String,
    pub reason: String,
    pub profile: PolicyProfile,
    pub trust_state: crate::provenance::TrustState,
    pub scanner_exit_code: i32,
}

pub fn record_policy_override(
    record: &OverrideRecord,
    path: Option<&Path>,
) -> Result<std::path::PathBuf> {
    use std::fs::OpenOptions;
    use std::io::Write;
    if record.reason.trim().len() < 8 {
        return Err(anyhow!(
            "Policy override reason must be at least 8 characters"
        ));
    }
    let path = match path {
        Some(path) => path.to_path_buf(),
        None => crate::paths::config_dir()?.join("override-audit.jsonl"),
    };
    // `Path::parent()` returns `Some("")` for a bare relative filename (not
    // `None`), so the empty-parent case must be folded into "." explicitly.
    let parent = match path.parent() {
        None => bail!("Override log path has no parent"),
        Some(parent) if parent.as_os_str().is_empty() => Path::new("."),
        Some(parent) => parent,
    };
    crate::paths::ensure_private_dir(parent)?;
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(anyhow!(
                "Refusing to append to symlinked override log '{}'",
                path.display()
            ))
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(anyhow!(
                "Override log '{}' is not a regular file",
                path.display()
            ))
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("Unable to open override audit log '{}'", path.display()))?;
    let mut line = serde_json::to_vec(record)?;
    line.push(b'\n');
    file.write_all(&line)?;
    file.sync_data()?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::CheckType;
    fn finding(status: ScanStatus, class: FindingClass, id: &str) -> LayerScanResult {
        LayerScanResult {
            layer_digest: "sha256:test".to_owned(),
            media_type: "test".to_owned(),
            check_type: CheckType::HeuristicSignature,
            status,
            finding_class: class,
            confidence: Confidence::High,
            detail: Some("test finding".to_owned()),
            matches: vec![format!("[{id}] match")],
            duration_ms: 0,
        }
    }
    #[test]
    fn strict_requires_trusted_attestation() {
        let policy = PolicyDocument::builtin(PolicyProfile::Strict).effective();
        assert_eq!(
            policy
                .evaluate("registry/model:latest", &[], TrustState::Unsigned)
                .action,
            PolicyAction::Block
        );
    }
    #[test]
    fn structural_failures_cannot_be_suppressed() {
        let mut doc = PolicyDocument::builtin(PolicyProfile::Workstation);
        doc.suppressions.push(Suppression {
            rule_id: "X-1".to_owned(),
            model: "*".to_owned(),
            reason: "accepted for testing".to_owned(),
            owner: None,
            reference: None,
            expires_unix: None,
        });
        let decision = doc.effective().evaluate(
            "model:latest",
            &[finding(ScanStatus::Fail, FindingClass::Structural, "X-1")],
            TrustState::Unsigned,
        );
        assert_eq!(decision.action, PolicyAction::Block);
    }
    #[test]
    fn signer_pin_requires_policy_context_match() {
        let required = format!("sha256:{}", "a".repeat(64));
        let mut doc = PolicyDocument::builtin(PolicyProfile::Workstation);
        doc.required_signer_fingerprints.push(required.clone());
        let policy = doc.effective();
        let context = PolicyContext {
            trusted_signatures: 1,
            signer_fingerprints: vec![format!("sha256:{}", "b".repeat(64))],
            now_unix: crate::paths::now_unix(),
            ..PolicyContext::default()
        };
        assert_eq!(
            policy
                .evaluate_with_context("model", &[], TrustState::Trusted, &context)
                .action,
            PolicyAction::Block
        );
        let context = PolicyContext {
            trusted_signatures: 1,
            signer_fingerprints: vec![required],
            now_unix: crate::paths::now_unix(),
            ..PolicyContext::default()
        };
        assert_eq!(
            policy
                .evaluate_with_context("model", &[], TrustState::Trusted, &context)
                .action,
            PolicyAction::Allow
        );
    }

    #[test]
    fn expired_suppression_is_ignored() {
        let mut doc = PolicyDocument::builtin(PolicyProfile::Workstation);
        doc.suppressions.push(Suppression {
            rule_id: "T3-001".to_owned(),
            model: "*".to_owned(),
            reason: "temporary accepted fixture".to_owned(),
            owner: Some("test".to_owned()),
            reference: None,
            expires_unix: Some(1),
        });
        let policy = doc.effective();
        let context = PolicyContext {
            now_unix: 2,
            ..PolicyContext::default()
        };
        let decision = policy.evaluate_with_context(
            "model",
            &[finding(
                ScanStatus::Fail,
                FindingClass::ContentIndicator,
                "T3-001",
            )],
            TrustState::Unsigned,
            &context,
        );
        assert_eq!(decision.action, PolicyAction::Block);
    }
}
