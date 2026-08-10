use crate::finding_evidence::{structural_invariant, EvidenceSubject, FindingBuilder};
use crate::formats::gguf::{self, Endian, GgufInventory};
use crate::scanner::{
    duration_ms, CheckType, Confidence, FindingClass, HeuristicsScanner, LayerScanResult,
    ScanStatus,
};
use anyhow::Result;
use std::fs::File;
use std::time::Instant;

pub struct MetadataScanner;

impl MetadataScanner {
    pub fn scan_file(
        file: &File,
        file_len: u64,
        layer_digest: &str,
        media_type: &str,
    ) -> Result<LayerScanResult> {
        Ok(Self::scan_file_results(file, file_len, layer_digest, media_type)?.remove(0))
    }

    pub fn scan_file_results(
        file: &File,
        file_len: u64,
        layer_digest: &str,
        media_type: &str,
    ) -> Result<Vec<LayerScanResult>> {
        let started = Instant::now();
        let parsed = match gguf::parse_file(file, file_len) {
            Ok(parsed) => parsed,
            Err(error) => {
                let subject = EvidenceSubject::identity(layer_digest, media_type)
                    .with_sha256(Some(layer_digest.to_owned()));
                let mut builder =
                    FindingBuilder::new("T15-STRUCT", CheckType::GGUFMetadata, ScanStatus::Fail)
                        .class(FindingClass::Structural)
                        .confidence(Confidence::High)
                        .digest(layer_digest)
                        .media_type(media_type)
                        .subject(subject.clone())
                        .detail(format!("Invalid or unsafe GGUF structure: {error}"))
                        .match_note("GGUF structural validation failed".to_owned())
                        .duration_ms(duration_ms(started));
                builder = match gguf_structural_evidence(&subject, &error.to_string()) {
                    Some(evidence) => builder.evidence(evidence),
                    None => builder.evidence_unavailable(
                        "the parser identified a structural failure but this build could not \
                         extract a precise tensor/offset attribution from it",
                    ),
                };
                return Ok(vec![builder.finish()]);
            }
        };
        results_from_inventory(parsed, layer_digest, media_type, started)
    }
}

fn results_from_inventory(
    parsed: GgufInventory,
    layer_digest: &str,
    media_type: &str,
    started: Instant,
) -> Result<Vec<LayerScanResult>> {
    let status = if parsed.warnings.is_empty() {
        ScanStatus::Pass
    } else {
        ScanStatus::Warn
    };
    let class = if parsed.warnings.is_empty() {
        FindingClass::Structural
    } else {
        FindingClass::Compatibility
    };
    let detail =
        Some(format!(
        "GGUF v{} {}-endian structure validated: {} tensor(s), {} metadata field(s), alignment {}",
        parsed.version,
        if parsed.endian == Endian::Little { "little" } else { "big" },
        parsed.tensor_count,
        parsed.metadata_count,
        parsed.alignment
    ));
    let subject = EvidenceSubject::identity(layer_digest, media_type)
        .with_sha256(Some(layer_digest.to_owned()));
    let structural_rule = parsed
        .warnings
        .first()
        .and_then(|first| extract_bracket_tag(first))
        .unwrap_or_else(|| "LF-GGUF-STRUCT-VALID".to_owned());
    let mut structural_builder =
        FindingBuilder::new(&structural_rule, CheckType::GGUFMetadata, status)
            .class(class)
            .confidence(Confidence::High)
            .digest(layer_digest)
            .media_type(media_type)
            .subject(subject.clone())
            .duration_ms(duration_ms(started));
    if let Some(detail) = detail {
        structural_builder = structural_builder.detail(detail);
    }
    for warning in &parsed.warnings {
        structural_builder = structural_builder.match_note(warning.clone());
    }
    structural_builder = if parsed.warnings.is_empty() {
        structural_builder.evidence_not_applicable()
    } else {
        structural_builder.evidence_unavailable(
            "GGUF structural warnings are compatibility/coverage notes without a single \
             attributable tensor or byte position",
        )
    };
    let mut results = vec![structural_builder.finish()];
    // Prompt/template/system metadata has an independent collection budget so
    // verbose descriptions cannot evict the security-critical text view.
    if !parsed.priority_text.is_empty() {
        results.push(HeuristicsScanner::scan_template_content_for_media(
            &parsed.priority_text,
            layer_digest,
            media_type,
            duration_ms(started),
        )?);
    }
    if !parsed.collected_text.is_empty() {
        results.push(HeuristicsScanner::scan_content_for_media(
            &parsed.collected_text,
            layer_digest,
            media_type,
            duration_ms(started),
        )?);
    }
    Ok(results)
}

/// Public compatibility entry point retained for fuzz/property tests.
pub fn validate_gguf_bytes(bytes: &[u8]) -> Result<()> {
    gguf::validate_gguf_bytes(bytes)
}

fn extract_bracket_tag(text: &str) -> Option<String> {
    let rest = text.strip_prefix('[')?;
    let (tag, _) = rest.split_once(']')?;
    (!tag.trim().is_empty()).then(|| tag.trim().to_owned())
}

/// Extract structural evidence from the GGUF parser's own tensor-range error
/// text.
///
/// These four message shapes are generated exclusively by
/// `validate_tensor_ranges` in `src/formats/gguf.rs`, not by attacker-supplied
/// content, so parsing this fixed, self-authored format is not "reconstructing
/// evidence from prose" — it recovers structured facts the parser already
/// computed but only had a place to put in a `bail!` message. If a future
/// error shape doesn't match, evidence is honestly reported unavailable rather
/// than guessed.
#[allow(clippy::question_mark)]
fn gguf_structural_evidence(
    subject: &EvidenceSubject,
    error_text: &str,
) -> Option<crate::finding_evidence::FindingEvidence> {
    let tensor = error_text
        .split_once("tensor '")
        .and_then(|(_, rest)| rest.split_once('\''))
        .map(|(name, _)| name.to_owned())?;

    let facts = if let Some(rest) =
        error_text.strip_prefix(&format!("tensor '{tensor}' begins at relative offset "))
    {
        let (offset, rest) = split_number(rest)?;
        let file_length = rest
            .strip_prefix(" beyond tensor-data length ")
            .and_then(|r| split_number(r).map(|(v, _)| v))?;
        serde_json::json!({
            "tensor": tensor,
            "declared_offset": offset,
            "file_length": file_length,
            "condition": "tensor begins beyond the tensor-data section",
        })
    } else if let Some(rest) = error_text.strip_prefix(&format!("tensor '{tensor}' range ")) {
        let (start, rest) = split_number(rest)?;
        let (end, rest) = rest.strip_prefix("..").and_then(split_number)?;
        let file_length = rest
            .strip_prefix(" exceeds tensor-data length ")
            .and_then(|r| split_number(r).map(|(v, _)| v))?;
        serde_json::json!({
            "tensor": tensor,
            "declared_offset": start,
            "declared_end": end,
            "file_length": file_length,
            "condition": "tensor range exceeds the tensor-data section",
        })
    } else if let Some(rest) =
        error_text.strip_prefix(&format!("tensor '{tensor}' calculated range ends at "))
    {
        let (end, rest) = split_number(rest)?;
        let next = rest
            .strip_prefix(", overlapping next tensor at ")
            .and_then(|r| split_number(r).map(|(v, _)| v))?;
        serde_json::json!({
            "tensor": tensor,
            "declared_end": end,
            "overlapping_offset": next,
            "condition": "tensor range overlaps the next tensor",
        })
    } else if let Some(rest) = error_text.strip_prefix(&format!(
        "tensor '{tensor}' overlaps another tensor at offset "
    )) {
        let (offset, _) = split_number(rest)?;
        serde_json::json!({
            "tensor": tensor,
            "declared_offset": offset,
            "condition": "tensor range overlaps another tensor",
        })
    } else {
        return None;
    };

    let condition = facts["condition"]
        .as_str()
        .unwrap_or("structural invariant violated")
        .to_owned();
    Some(structural_invariant(subject.clone(), &condition, facts))
}

fn split_number(text: &str) -> Option<(u64, &str)> {
    let digits: String = text.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    let value = digits.parse().ok()?;
    Some((value, &text[digits.len()..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_gguf_fails() {
        assert!(validate_gguf_bytes(b"GGUF\x03\x00\x00\x00").is_err());
    }

    #[test]
    fn overlap_error_text_yields_structural_evidence() {
        let subject = EvidenceSubject::identity("sha256:abc", "model/gguf");
        let text = "tensor 'blk.17.attn_q.weight' overlaps another tensor at offset 928173";
        let evidence = gguf_structural_evidence(&subject, text).expect("evidence");
        assert_eq!(
            evidence.structured.as_ref().unwrap()["tensor"],
            "blk.17.attn_q.weight"
        );
        assert_eq!(
            evidence.structured.as_ref().unwrap()["declared_offset"],
            928173
        );
    }

    #[test]
    fn range_exceeds_error_text_yields_structural_evidence() {
        let subject = EvidenceSubject::identity("sha256:abc", "model/gguf");
        let text =
            "tensor 'blk.17.attn_q.weight' range 928173..936365 exceeds tensor-data length 930000";
        let evidence = gguf_structural_evidence(&subject, text).expect("evidence");
        let facts = evidence.structured.as_ref().unwrap();
        assert_eq!(facts["declared_offset"], 928173);
        assert_eq!(facts["declared_end"], 936365);
        assert_eq!(facts["file_length"], 930000);
    }

    #[test]
    fn unrecognized_error_text_yields_no_fabricated_evidence() {
        let subject = EvidenceSubject::identity("sha256:abc", "model/gguf");
        assert!(gguf_structural_evidence(&subject, "some other parser failure").is_none());
    }
}
