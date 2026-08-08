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
                return Ok(vec![LayerScanResult {
                    layer_digest: layer_digest.to_owned(),
                    media_type: media_type.to_owned(),
                    check_type: CheckType::GGUFMetadata,
                    status: ScanStatus::Fail,
                    finding_class: FindingClass::Structural,
                    confidence: Confidence::High,
                    detail: Some(format!("Invalid or unsafe GGUF structure: {error}")),
                    matches: vec!["[T15-STRUCT] GGUF structural validation failed".to_owned()],
                    duration_ms: duration_ms(started),
                }]);
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
    let structural = LayerScanResult {
        layer_digest: layer_digest.to_owned(),
        media_type: media_type.to_owned(),
        check_type: CheckType::GGUFMetadata,
        status,
        finding_class: class,
        confidence: Confidence::High,
        detail,
        matches: parsed.warnings.clone(),
        duration_ms: duration_ms(started),
    };
    let mut results = vec![structural];
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_gguf_fails() {
        assert!(validate_gguf_bytes(b"GGUF\x03\x00\x00\x00").is_err());
    }
}
