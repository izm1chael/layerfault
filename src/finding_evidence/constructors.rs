use super::*;

pub fn source_excerpt(
    subject: EvidenceSubject,
    line_start: u64,
    line_end: u64,
    matched: &str,
    excerpt: &str,
) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::SourceExcerpt,
        subject,
        "Text content matched a security-relevant primitive",
    )
    .at(EvidenceLocation::Text {
        line_start,
        line_end,
        column_start: None,
        column_end: None,
    })
    .matched(matched)
    .excerpt(excerpt)
}

/// Configuration evidence: a JSON/config key and its observed value.
pub fn config_value(
    subject: EvidenceSubject,
    key: &str,
    value: serde_json::Value,
    description: &str,
) -> FindingEvidence {
    FindingEvidence::new(EvidenceKind::ConfigValue, subject, description)
        .at(EvidenceLocation::Metadata {
            key: sanitize_text(key),
        })
        .structured(serde_json::json!({ "key": key, "value": value }))
}

/// Model-metadata evidence: a metadata key and its bounded value.
pub fn metadata_value(
    subject: EvidenceSubject,
    key: &str,
    value: &str,
    description: &str,
) -> FindingEvidence {
    FindingEvidence::new(EvidenceKind::MetadataValue, subject, description)
        .at(EvidenceLocation::Metadata {
            key: sanitize_text(key),
        })
        .excerpt(value)
}

/// Byte-range evidence for binary artifacts.
pub fn byte_range_evidence(
    subject: EvidenceSubject,
    offset: u64,
    length: u64,
    description: &str,
) -> FindingEvidence {
    FindingEvidence::new(EvidenceKind::ByteRange, subject, description)
        .at(EvidenceLocation::ByteRange { offset, length })
}

/// A parsed executable object embedded inside an artifact.
pub fn binary_object(
    subject: EvidenceSubject,
    offset: u64,
    length: u64,
    facts: serde_json::Value,
) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::BinaryObject,
        subject,
        "Executable object structure parsed at the recorded offset",
    )
    .at(EvidenceLocation::ByteRange { offset, length })
    .structured(facts)
}

/// A violated structural invariant, with the declared and actual values.
pub fn structural_invariant(
    subject: EvidenceSubject,
    condition: &str,
    facts: serde_json::Value,
) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::StructuralInvariant,
        subject,
        &format!("Structural invariant violated: {condition}"),
    )
    .structured(facts)
}

/// Static serialization evidence resolved from bounded opcode analysis.
///
/// This never comes from deserializing the stream.
pub fn serialization_opcode(
    subject: EvidenceSubject,
    opcode_index: u64,
    byte_offset: u64,
    facts: serde_json::Value,
) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::SerializationOpcode,
        subject,
        "Static opcode analysis resolved a serialization reference",
    )
    .at(EvidenceLocation::Serialization {
        opcode_index,
        byte_offset,
    })
    .structured(facts)
}

/// Both sides of an integrity comparison.
pub fn hash_mismatch(subject: EvidenceSubject, declared: &str, observed: &str) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::HashMismatch,
        subject,
        "Declared and observed artifact digests differ",
    )
    .structured(serde_json::json!({ "declared": declared, "observed": observed }))
}

/// A package symlink and the target it declares.
pub fn symlink_target(
    subject: EvidenceSubject,
    relative_path: &str,
    target: Option<&str>,
) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::SymlinkTarget,
        subject,
        "Package member is a symbolic link",
    )
    .at(EvidenceLocation::Member {
        member: sanitize_text(relative_path),
    })
    .structured(serde_json::json!({
        "package_relative_path": relative_path,
        "target": target.unwrap_or("<unreadable>"),
    }))
}

/// A package or archive member described by identity rather than content.
pub fn file_member(subject: EvidenceSubject, facts: serde_json::Value) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::FileMember,
        subject,
        "Package member recorded by identity",
    )
    .structured(facts)
}

/// A tensor-level fact from a structured model format.
pub fn tensor_metadata(
    subject: EvidenceSubject,
    tensor: &str,
    facts: serde_json::Value,
) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::TensorMetadata,
        subject,
        "Tensor declaration recorded from the parsed model header",
    )
    .at(EvidenceLocation::Tensor {
        tensor: sanitize_text(tensor),
    })
    .structured(facts)
}

/// Signature/trust state evidence. Never contains private key material.
pub fn signature_evidence(subject: EvidenceSubject, facts: serde_json::Value) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::SignatureEvidence,
        subject,
        "Signature verification state recorded",
    )
    .structured(facts)
}

/// Provenance/trust-policy evidence.
pub fn provenance_evidence(subject: EvidenceSubject, facts: serde_json::Value) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::ProvenanceEvidence,
        subject,
        "Provenance state recorded",
    )
    .structured(facts)
}

/// Runtime version and advisory comparison evidence.
pub fn advisory_match(subject: EvidenceSubject, facts: serde_json::Value) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::AdvisoryMatch,
        subject,
        "Runtime version compared against an advisory range",
    )
    .structured(facts)
}

/// Policy evidence. References the underlying findings rather than restating
/// the technical facts, so policy never appears to have discovered them.
pub fn policy_reason(
    subject: EvidenceSubject,
    reason: &str,
    finding_ids: &[String],
    rule_ids: &[String],
) -> FindingEvidence {
    FindingEvidence::new(EvidenceKind::PolicyReason, subject, reason)
        .structured(serde_json::json!({ "finding_ids": finding_ids, "rule_ids": rule_ids }))
}

/// A bounded observation captured by the behaviour sandbox.
pub fn behaviour_observation(
    subject: EvidenceSubject,
    kind: EvidenceKind,
    description: &str,
    facts: serde_json::Value,
) -> FindingEvidence {
    FindingEvidence::new(kind, subject, description).structured(facts)
}

/// A record of scanning that could not be completed.
pub fn coverage_gap(subject: EvidenceSubject, reason: &str) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::CoverageGap,
        subject,
        "Inspection coverage was incomplete",
    )
    .structured(serde_json::json!({ "reason": reason }))
}

/// A relationship between two package members.
pub fn path_relationship(
    subject: EvidenceSubject,
    description: &str,
    facts: serde_json::Value,
) -> FindingEvidence {
    FindingEvidence::new(EvidenceKind::PathRelationship, subject, description).structured(facts)
}

// ---------------------------------------------------------------------------
// Finding construction
// ---------------------------------------------------------------------------
