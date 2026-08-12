use super::*;

pub struct EvidenceBudget {
    remaining: usize,
    exhausted: bool,
}

impl Default for EvidenceBudget {
    fn default() -> Self {
        Self {
            remaining: MAX_EVIDENCE_BYTES_PER_REPORT,
            exhausted: false,
        }
    }
}

impl EvidenceBudget {
    pub fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            exhausted: false,
        }
    }

    /// Claim budget for one evidence record. Returns false when the report-wide
    /// limit is reached; the caller must then record a coverage/limit note
    /// rather than silently dropping the evidence.
    pub fn claim(&mut self, bytes: usize) -> bool {
        if bytes > self.remaining {
            self.exhausted = true;
            return false;
        }
        self.remaining -= bytes;
        true
    }

    pub fn exhausted(&self) -> bool {
        self.exhausted
    }
}

// ---------------------------------------------------------------------------
// Sanitisation and redaction
// ---------------------------------------------------------------------------

/// Result of sanitising untrusted artifact content for display.
#[derive(Debug, Clone)]
pub struct FindingBuilder {
    rule_id: String,
    check_type: CheckType,
    status: ScanStatus,
    finding_class: FindingClass,
    confidence: Confidence,
    layer_digest: String,
    media_type: String,
    detail: Option<String>,
    matches: Vec<String>,
    subject: Option<EvidenceSubject>,
    evidence: Vec<FindingEvidence>,
    evidence_reason: Option<String>,
    not_applicable: bool,
    truncated: bool,
    duration_ms: u64,
}

impl FindingBuilder {
    pub fn new(rule_id: &str, check_type: CheckType, status: ScanStatus) -> Self {
        Self {
            rule_id: rule_id.to_owned(),
            check_type,
            status,
            finding_class: FindingClass::Informational,
            confidence: Confidence::Medium,
            layer_digest: String::new(),
            media_type: String::new(),
            detail: None,
            matches: Vec::new(),
            subject: None,
            evidence: Vec::new(),
            evidence_reason: None,
            not_applicable: false,
            truncated: false,
            duration_ms: 0,
        }
    }

    #[must_use]
    pub fn class(mut self, class: FindingClass) -> Self {
        self.finding_class = class;
        self
    }

    #[must_use]
    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    #[must_use]
    pub fn digest(mut self, digest: &str) -> Self {
        self.layer_digest = digest.to_owned();
        self
    }

    #[must_use]
    pub fn media_type(mut self, media_type: &str) -> Self {
        self.media_type = media_type.to_owned();
        self
    }

    #[must_use]
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Append an extra `matches` entry. The rule-tagged entry is added
    /// automatically by `finish`.
    #[must_use]
    pub fn match_note(mut self, note: impl Into<String>) -> Self {
        self.matches.push(note.into());
        self
    }

    #[must_use]
    pub fn subject(mut self, subject: EvidenceSubject) -> Self {
        self.subject = Some(subject);
        self
    }

    #[must_use]
    pub fn evidence(mut self, evidence: FindingEvidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    #[must_use]
    pub fn evidence_all(mut self, evidence: impl IntoIterator<Item = FindingEvidence>) -> Self {
        self.evidence.extend(evidence);
        self
    }

    /// Record why direct evidence could not be safely extracted. Required for
    /// any non-PASS finding that carries no evidence records.
    #[must_use]
    pub fn evidence_unavailable(mut self, reason: impl Into<String>) -> Self {
        self.evidence_reason = Some(reason.into());
        self
    }

    /// Declare that evidence is meaningless for this rule (informational or
    /// PASS-only outcomes).
    #[must_use]
    pub fn evidence_not_applicable(mut self) -> Self {
        self.not_applicable = true;
        self
    }

    #[must_use]
    pub fn truncated(mut self, truncated: bool) -> Self {
        self.truncated |= truncated;
        self
    }

    #[must_use]
    pub fn started(mut self, started: Instant) -> Self {
        self.duration_ms = crate::scanner::duration_ms(started);
        self
    }

    #[must_use]
    pub fn duration_ms(mut self, duration_ms: u64) -> Self {
        self.duration_ms = duration_ms;
        self
    }

    /// Apply bounds, derive evidence state, compute the deterministic identity
    /// and emit the finding.
    pub fn finish(mut self) -> LayerScanResult {
        let subject = self.subject.clone().unwrap_or_else(|| {
            if self.layer_digest.is_empty() {
                EvidenceSubject::default()
            } else {
                EvidenceSubject::identity(&self.layer_digest, &self.media_type)
            }
        });

        for record in &mut self.evidence {
            if record.subject == EvidenceSubject::default() {
                record.subject = subject.clone();
            }
        }
        self.evidence.sort_by_key(FindingEvidence::sort_key);
        self.evidence
            .dedup_by(|a, b| a.sort_key() == b.sort_key() && a.excerpt == b.excerpt);

        if self.evidence.len() > MAX_EVIDENCE_PER_FINDING {
            self.evidence.truncate(MAX_EVIDENCE_PER_FINDING);
            self.truncated = true;
        }
        let mut budget = MAX_EVIDENCE_BYTES_PER_FINDING;
        let mut kept = Vec::with_capacity(self.evidence.len());
        for record in self.evidence.drain(..) {
            let cost = record.payload_bytes();
            if cost > budget {
                self.truncated = true;
                break;
            }
            budget -= cost;
            kept.push(record);
        }
        self.evidence = kept;

        let evidence_state = if self.not_applicable {
            EvidenceState::NotApplicable
        } else if self.evidence.is_empty() {
            EvidenceState::Unavailable
        } else if self.truncated || self.evidence.iter().any(|record| record.truncated) {
            EvidenceState::Partial
        } else {
            EvidenceState::Available
        };

        let evidence_reason = match evidence_state {
            EvidenceState::Unavailable => Some(self.evidence_reason.clone().unwrap_or_else(|| {
                "Detector did not record structured evidence for this condition".to_owned()
            })),
            EvidenceState::Partial => Some(self.evidence_reason.clone().unwrap_or_else(|| {
                "Evidence was bounded by Layerfault's hostile-input collection limits".to_owned()
            })),
            _ => self.evidence_reason.clone(),
        };

        let mut matches = Vec::with_capacity(self.matches.len() + 1);
        matches.push(format!(
            "[{}] {}",
            self.rule_id,
            self.matches
                .first()
                .cloned()
                .unwrap_or_else(|| self.rule_id.clone())
        ));
        matches.extend(self.matches.iter().skip(1).cloned());

        let finding_id = compute_finding_id(
            &self.rule_id,
            &subject,
            self.check_type.clone(),
            self.status,
            &self.evidence,
        );

        LayerScanResult {
            layer_digest: self.layer_digest,
            media_type: self.media_type,
            check_type: self.check_type,
            status: self.status,
            finding_class: self.finding_class,
            confidence: self.confidence,
            detail: self.detail.map(|value| sanitize_text(&value)),
            matches,
            duration_ms: self.duration_ms,
            rule_id: Some(self.rule_id),
            subject: Some(subject),
            evidence: self.evidence,
            evidence_state: Some(evidence_state),
            evidence_reason,
            finding_id: Some(finding_id),
        }
    }
}
