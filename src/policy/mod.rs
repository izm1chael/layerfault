use crate::provenance::TrustState;
use crate::scanner::{Confidence, FindingClass, LayerScanResult, ScanStatus};
use crate::trust::glob_match;
use anyhow::{anyhow, Context, Result};
use std::path::Path;

const MAX_POLICY_BYTES: u64 = 2 * 1024 * 1024;

mod builtin;
mod evaluate;
mod load;
mod override_log;
mod types;

pub use override_log::{record_policy_override, OverrideRecord};
pub use types::{
    BackdoorSignalAction, EffectivePolicy, PolicyAction, PolicyContext, PolicyDecision,
    PolicyDocument, PolicyProfile, Suppression,
};

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
        let (
            require_trusted,
            block_unknown,
            block_warn,
            complete,
            current_intel,
            intel_age,
            block_exploit,
            require_compat,
            allow_custom,
            pinned_remote,
            receipt,
            identity,
            lineage,
            backdoor,
        ) = match self.profile {
            PolicyProfile::Permissive => (
                false,
                false,
                false,
                false,
                false,
                None,
                false,
                false,
                true,
                false,
                false,
                false,
                false,
                BackdoorSignalAction::Ignore,
            ),
            PolicyProfile::Workstation => (
                false,
                false,
                false,
                false,
                false,
                None,
                false,
                false,
                true,
                false,
                false,
                false,
                false,
                BackdoorSignalAction::Ignore,
            ),
            PolicyProfile::Ci => (
                false,
                true,
                false,
                false,
                false,
                None,
                false,
                false,
                true,
                false,
                false,
                false,
                false,
                BackdoorSignalAction::Ignore,
            ),
            PolicyProfile::Strict => (
                true,
                true,
                true,
                false,
                false,
                None,
                false,
                false,
                true,
                false,
                false,
                false,
                false,
                BackdoorSignalAction::Ignore,
            ),
            PolicyProfile::PersonalLocal => (
                false,
                false,
                false,
                false,
                false,
                None,
                true,
                false,
                false,
                false,
                false,
                false,
                false,
                BackdoorSignalAction::Warn,
            ),
            PolicyProfile::Research => (
                false,
                false,
                false,
                false,
                false,
                None,
                true,
                false,
                true,
                false,
                false,
                false,
                false,
                BackdoorSignalAction::Warn,
            ),
            PolicyProfile::Enterprise => (
                false,
                true,
                false,
                true,
                true,
                Some(30),
                true,
                true,
                false,
                true,
                false,
                true,
                false,
                BackdoorSignalAction::Warn,
            ),
            PolicyProfile::Production => (
                false,
                true,
                false,
                true,
                true,
                Some(30),
                true,
                true,
                false,
                true,
                true,
                true,
                true,
                BackdoorSignalAction::BlockMultiSignal,
            ),
            PolicyProfile::AirGapped => (
                false,
                true,
                false,
                true,
                false,
                None,
                true,
                true,
                false,
                true,
                true,
                true,
                true,
                BackdoorSignalAction::BlockMultiSignal,
            ),
            PolicyProfile::HighAssurance => (
                true,
                true,
                true,
                true,
                true,
                Some(14),
                true,
                true,
                false,
                true,
                true,
                true,
                true,
                BackdoorSignalAction::BlockAnyReproducibleTrigger,
            ),
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
            require_complete_coverage: self.require_complete_coverage.unwrap_or(complete),
            require_current_intelligence: self
                .require_current_intelligence
                .unwrap_or(current_intel),
            max_intelligence_age_days: self.max_intelligence_age_days.or(intel_age),
            block_known_runtime_exploitability: self
                .block_known_runtime_exploitability
                .unwrap_or(block_exploit),
            require_runtime_compatibility: self
                .require_runtime_compatibility
                .unwrap_or(require_compat),
            allow_custom_code: self.allow_custom_code.unwrap_or(allow_custom),
            require_pinned_remote_revision: self
                .require_pinned_remote_revision
                .unwrap_or(pinned_remote),
            require_admission_receipt: self.require_admission_receipt.unwrap_or(receipt),
            require_layered_identity: self.require_layered_identity.unwrap_or(identity),
            require_lineage_for_derived_models: self
                .require_lineage_for_derived_models
                .unwrap_or(lineage),
            backdoor_signal_action: self.backdoor_signal_action.unwrap_or(backdoor),
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
        let mut policy_evidence = Vec::new();
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
            let finding_ids: Vec<String> = result.finding_id.iter().cloned().collect();
            let mut note_policy_evidence = |reason: &str| {
                policy_evidence.push(crate::finding_evidence::policy_reason(
                    result.subject.clone().unwrap_or_else(|| {
                        crate::finding_evidence::EvidenceSubject::identity(
                            &result.layer_digest,
                            &result.media_type,
                        )
                    }),
                    reason,
                    &finding_ids,
                    std::slice::from_ref(&rule),
                ));
            };
            if self
                .denied_rule_ids
                .iter()
                .any(|denied| denied.eq_ignore_ascii_case(&rule))
            {
                let reason = format!("Denied rule {rule} matched");
                note_policy_evidence(&reason);
                block_reasons.push(reason);
                continue;
            }
            if self.block_finding_classes.contains(&result.finding_class)
                && result.status != ScanStatus::Pass
            {
                let reason = format!(
                    "Finding class {:?} is blocking by policy ({rule})",
                    result.finding_class
                );
                note_policy_evidence(&reason);
                block_reasons.push(reason);
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
                let reason = format!("{rule} meets configured blocking confidence threshold");
                note_policy_evidence(&reason);
                block_reasons.push(reason);
                continue;
            }
            match result.status {
                ScanStatus::Fail => {
                    let reason = format!(
                        "{}: {}",
                        rule,
                        result
                            .detail
                            .as_deref()
                            .unwrap_or("blocking scanner finding")
                    );
                    note_policy_evidence(&reason);
                    block_reasons.push(reason);
                }
                ScanStatus::Warn if self.block_on_warnings => {
                    let reason = format!("{} warning is blocking under this profile", rule);
                    note_policy_evidence(&reason);
                    block_reasons.push(reason);
                }
                ScanStatus::Warn => {
                    let reason = format!(
                        "{}: {}",
                        rule,
                        result.detail.as_deref().unwrap_or("scanner warning")
                    );
                    note_policy_evidence(&reason);
                    warn_reasons.push(reason);
                }
                ScanStatus::Pass => {}
            }
        }
        if self.require_complete_coverage && context.coverage_complete != Some(true) {
            block_reasons.push("Policy requires complete scanner coverage".to_owned());
        }
        if self.require_current_intelligence {
            if context.intelligence_verified != Some(true) {
                block_reasons
                    .push("Policy requires verified current security intelligence".to_owned());
            }
            if let Some(max_days) = self.max_intelligence_age_days {
                match context.intelligence_age_days {
                    Some(age) if age <= max_days => {}
                    Some(age) => block_reasons.push(format!("Security intelligence age {age} days exceeds policy maximum {max_days} days")),
                    None => block_reasons.push("Policy requires a known security intelligence age".to_owned()),
                }
            }
        }
        if self.block_known_runtime_exploitability
            && context.runtime_exploitability_blocking == Some(true)
        {
            block_reasons.push(
                "Selected runtime has known blocking exploitability for this model/context"
                    .to_owned(),
            );
        }
        if self.require_runtime_compatibility
            && !matches!(
                context.runtime_compatibility,
                Some(crate::runtime_security::CompatibilityState::Compatible)
            )
        {
            block_reasons
                .push("Policy requires positively established runtime compatibility".to_owned());
        }
        let finding_custom_code = results.iter().any(|result| {
            matches!(
                rule_id(result).as_str(),
                "LF-PACKAGE-CODE" | "LF-CODE-AUTO-MAP" | "LF-CONFIG-DYNAMIC-IMPORT"
            )
        });
        if !self.allow_custom_code
            && (context.custom_code_present == Some(true) || finding_custom_code)
        {
            block_reasons.push("Custom executable model code is forbidden by policy".to_owned());
        }
        let remote_source = context.source.as_deref().is_some_and(|source| {
            matches!(
                source.to_ascii_lowercase().as_str(),
                "huggingface" | "hugging-face" | "hf" | "hub" | "remote" | "import"
            )
        });
        if self.require_pinned_remote_revision
            && remote_source
            && context.remote_revision_pinned != Some(true)
        {
            block_reasons.push(
                "Policy requires immutable revision pinning for remote/imported artifacts"
                    .to_owned(),
            );
        }
        if self.require_admission_receipt && context.admission_receipt_present != Some(true) {
            block_reasons.push("Policy requires a valid admission receipt".to_owned());
        }
        if self.require_layered_identity && context.layered_identity_complete != Some(true) {
            block_reasons.push("Policy requires complete layered model identity".to_owned());
        }
        if self.require_lineage_for_derived_models
            && context.derived_model == Some(true)
            && !matches!(
                context.lineage_consistency,
                Some(crate::model::lineage::LineageConsistency::Consistent)
            )
        {
            block_reasons
                .push("Policy requires consistent verified lineage for derived models".to_owned());
        }
        match self.backdoor_signal_action {
            BackdoorSignalAction::Ignore => {}
            BackdoorSignalAction::Warn => {
                if context.backdoor_static_signals > 0
                    || context.reproducible_trigger_signals > 0
                    || context.backdoor_multi_signal
                {
                    warn_reasons.push(
                        "Backdoor forensic signals are present; empirical review is required"
                            .to_owned(),
                    );
                }
            }
            BackdoorSignalAction::BlockMultiSignal => {
                if context.backdoor_multi_signal
                    || results
                        .iter()
                        .any(|r| rule_id(r) == "LF-CORR-BACKDOOR-MULTI-SIGNAL")
                {
                    block_reasons.push(
                        "Multi-signal backdoor correlation is blocking under this profile"
                            .to_owned(),
                    );
                }
            }
            BackdoorSignalAction::BlockAnyReproducibleTrigger => {
                if context.backdoor_multi_signal
                    || context.reproducible_trigger_signals > 0
                    || results.iter().any(|r| {
                        matches!(
                            rule_id(r).as_str(),
                            "LF-CORR-BACKDOOR-MULTI-SIGNAL" | "LF-BACKDOOR-TRIGGER-REPRODUCIBLE"
                        )
                    })
                {
                    block_reasons.push("Reproducible trigger or multi-signal backdoor evidence is blocking under this profile".to_owned());
                }
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
        policy_evidence.sort_by(|a, b| a.description.cmp(&b.description));
        policy_evidence.dedup_by(|a, b| a.description == b.description);
        PolicyDecision {
            profile: self.profile,
            action,
            reasons,
            suppressed_rule_ids: suppressed,
            evidence: if action == PolicyAction::Allow {
                Vec::new()
            } else {
                policy_evidence
            },
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

/// Resolve a finding's stable rule identity.
///
/// The explicit `rule_id` field is authoritative. The legacy path — parsing a
/// `[RULE-ID]` prefix out of `matches`, then falling back to the check type —
/// remains for findings built as plain struct literals, so migrated and
/// unmigrated detectors resolve identically.
pub fn rule_id(result: &LayerScanResult) -> String {
    if let Some(id) = result
        .rule_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return id.to_owned();
    }
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
            ..Default::default()
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
