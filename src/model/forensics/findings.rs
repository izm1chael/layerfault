use super::{CarvedObject, RegionKind};
use crate::finding_evidence::{EvidenceKind, EvidenceSubject, FindingBuilder, FindingEvidence};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
pub fn build(identity: &str, objects: &[CarvedObject], incomplete: bool) -> Vec<LayerScanResult> {
    let subject = EvidenceSubject::identity(identity, "application/octet-stream")
        .with_sha256(Some(identity.into()));
    let mut out = Vec::new();
    for o in objects {
        let unclaimed = matches!(
            o.region_kind,
            RegionKind::Gap | RegionKind::Trailing | RegionKind::Alignment
        );
        let (rule, status) =
            if o.object_type == "ELF" || o.object_type == "PE" || o.object_type == "Mach-O" {
                if unclaimed {
                    ("LF-FORENSIC-UNCLAIMED-EXECUTABLE", ScanStatus::Fail)
                } else {
                    ("LF-FORENSIC-TENSOR-EMBEDDED-OBJECT", ScanStatus::Warn)
                }
            } else if matches!(o.object_type.as_str(), "ZIP" | "GZIP" | "7z" | "RAR") {
                if unclaimed {
                    ("LF-FORENSIC-UNCLAIMED-ARCHIVE", ScanStatus::Warn)
                } else if !o.evidence_only {
                    ("LF-FORENSIC-TENSOR-EMBEDDED-OBJECT", ScanStatus::Warn)
                } else {
                    continue;
                }
            } else {
                continue;
            };
        out.push(
            FindingBuilder::new(rule, CheckType::TensorForensics, status)
                .class(FindingClass::ContentIndicator)
                .confidence(o.confidence)
                .subject(subject.clone())
                .detail(format!(
                    "{} signature at byte {} in {:?} region",
                    o.object_type, o.offset, o.region_kind
                ))
                .evidence(
                    FindingEvidence::new(
                        EvidenceKind::CarvedObject,
                        subject.clone(),
                        "bounded embedded-object signature",
                    )
                    .structured(serde_json::json!(o)),
                )
                .finish(),
        )
    }
    if incomplete {
        out.push(
            FindingBuilder::new(
                "LF-FORENSIC-COVERAGE-INCOMPLETE",
                CheckType::TensorForensics,
                ScanStatus::Warn,
            )
            .class(FindingClass::Informational)
            .confidence(Confidence::High)
            .subject(subject)
            .detail("tensor forensic region coverage was incomplete")
            .finish(),
        )
    }
    out
}
