use super::*;

pub fn overall_status(results: &[LayerScanResult]) -> ScanStatus {
    if results
        .iter()
        .any(|result| result.status == ScanStatus::Fail)
    {
        ScanStatus::Fail
    } else if results
        .iter()
        .any(|result| result.status == ScanStatus::Warn)
    {
        ScanStatus::Warn
    } else {
        ScanStatus::Pass
    }
}

pub(super) fn short_digest(digest: &str) -> String {
    let without_prefix = digest
        .strip_prefix("sha256:")
        .or_else(|| digest.strip_prefix("sha512:"))
        .unwrap_or(digest);
    without_prefix.chars().take(16).collect()
}

pub(super) fn check_type_label(check_type: &CheckType) -> &'static str {
    match check_type {
        CheckType::IntegrityHash => "IntegrityHash",
        CheckType::HeuristicSignature => "HeuristicSignature",
        CheckType::ParameterThreshold => "ParameterThreshold",
        CheckType::BinarySteganography => "EmbeddedExecutable",
        CheckType::Provenance => "LocalAttestation",
        CheckType::GGUFMetadata => "GGUFStructure",
        CheckType::SafetensorsStructure => "SafetensorsStructure",
        CheckType::OnnxStructure => "OnnxStructure",
        CheckType::TensorFlowStructure => "TensorFlowStructure",
        CheckType::TfliteStructure => "TfliteStructure",
        CheckType::KerasStructure => "KerasStructure",
        CheckType::PackageSecurity => "PackageSecurity",
        CheckType::RuntimeAdvisory => "RuntimeAdvisory",
        CheckType::ExecutionBinding => "ExecutionBinding",
        CheckType::SignedEvidence => "SignedEvidence",
        CheckType::LayerPolicy => "LayerPolicy",
        CheckType::ScanError => "ScanError",
        CheckType::PickleStructure => "PickleStructure",
        CheckType::NpyStructure => "NpyStructure",
    }
}

pub(super) fn finding_class_label(class: &FindingClass) -> &'static str {
    match class {
        FindingClass::Integrity => "Integrity",
        FindingClass::Structural => "Structural",
        FindingClass::ContentIndicator => "Content",
        FindingClass::Policy => "Policy",
        FindingClass::Attestation => "Attestation",
        FindingClass::Compatibility => "Compatibility",
        FindingClass::Operational => "Operational",
        FindingClass::Informational => "Info",
    }
}

pub(super) fn confidence_label(confidence: &Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "Low",
        Confidence::Medium => "Medium",
        Confidence::High => "High",
    }
}

pub(super) fn status_label(status: &ScanStatus) -> String {
    match status {
        ScanStatus::Pass => "PASS".green().to_string(),
        ScanStatus::Warn => "WARN".yellow().to_string(),
        ScanStatus::Fail => "FAIL".red().to_string(),
    }
}
