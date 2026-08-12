//! Newline-delimited JSON (JSONL) output for very large multi-model scans.
//!
//! Each line is one independently-parseable record, written and flushed as
//! soon as it is produced, so a consumer can stream-process a scan without
//! waiting for the complete document. This is additive: it never replaces
//! the ordinary pretty `--json` document, and record shapes are versioned
//! independently of the pretty-JSON contract.

use crate::app::EvaluatedReport;
use crate::coverage::Coverage;
use crate::finding_evidence::FindingCorrelation;
use crate::report::{self, EnrichedFinding};
use crate::scanner::{LayerScanResult, ScanStatus};
use anyhow::Result;
use serde::Serialize;
use std::io::Write;

/// Bumped only on incompatible changes to the record shapes below.
pub const JSONL_PROTOCOL_VERSION: u32 = 1;

#[derive(Serialize)]
struct ScanHeaderRecord {
    kind: &'static str,
    record_version: u32,
    tool_version: &'static str,
    schema_version: &'static str,
    started_unix: u64,
}

#[derive(Serialize)]
struct SubjectRecord<'a> {
    kind: &'static str,
    record_version: u32,
    model: &'a str,
    overall_status: ScanStatus,
}

#[derive(Serialize)]
struct FindingRecord<'a> {
    kind: &'static str,
    record_version: u32,
    model: &'a str,
    #[serde(flatten)]
    finding: EnrichedFinding<'a>,
}

#[derive(Serialize)]
struct CorrelationRecord<'a> {
    kind: &'static str,
    record_version: u32,
    model: &'a str,
    #[serde(flatten)]
    correlation: &'a FindingCorrelation,
}

#[derive(Serialize)]
struct CoverageRecord<'a> {
    kind: &'static str,
    record_version: u32,
    model: &'a str,
    #[serde(flatten)]
    coverage: &'a Coverage,
}

#[derive(Serialize)]
struct ScanFooterRecord {
    kind: &'static str,
    record_version: u32,
    overall_status: ScanStatus,
    exit_code: i32,
    finished_unix: u64,
}

fn write_line<W: Write, T: Serialize>(writer: &mut W, record: &T) -> Result<()> {
    serde_json::to_writer(&mut *writer, record)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

/// One scanned subject's worth of JSONL input: its findings plus, where the
/// caller has already computed them, correlations and coverage. Callers that
/// haven't computed correlations/coverage on this path simply pass empty
/// slices / `None`; the corresponding record kinds are omitted for that
/// subject rather than fabricated.
pub struct JsonlSubject<'a> {
    pub model: &'a str,
    pub findings: &'a [LayerScanResult],
    pub correlations: &'a [FindingCorrelation],
    pub coverage: Option<&'a Coverage>,
}

fn combine_status(a: ScanStatus, b: ScanStatus) -> ScanStatus {
    match (a, b) {
        (ScanStatus::Fail, _) | (_, ScanStatus::Fail) => ScanStatus::Fail,
        (ScanStatus::Warn, _) | (_, ScanStatus::Warn) => ScanStatus::Warn,
        _ => ScanStatus::Pass,
    }
}

/// Stream a full scan as newline-delimited JSON records: one `scan_header`,
/// then per subject a `subject` record, its `finding` records, any
/// `correlation`/`coverage` records, and finally one `scan_footer`.
pub fn emit_jsonl<W: Write>(
    mut writer: W,
    subjects: &[JsonlSubject<'_>],
    overall_status: ScanStatus,
    exit_code: i32,
) -> Result<()> {
    write_line(
        &mut writer,
        &ScanHeaderRecord {
            kind: "scan_header",
            record_version: JSONL_PROTOCOL_VERSION,
            tool_version: env!("CARGO_PKG_VERSION"),
            schema_version: "1.0",
            started_unix: crate::paths::now_unix(),
        },
    )?;

    for subject in subjects {
        write_line(
            &mut writer,
            &SubjectRecord {
                kind: "subject",
                record_version: JSONL_PROTOCOL_VERSION,
                model: subject.model,
                overall_status: report::overall_status(subject.findings),
            },
        )?;
        for finding in subject.findings {
            write_line(
                &mut writer,
                &FindingRecord {
                    kind: "finding",
                    record_version: JSONL_PROTOCOL_VERSION,
                    model: subject.model,
                    finding: report::enriched_finding_ref(finding),
                },
            )?;
        }
        for correlation in subject.correlations {
            write_line(
                &mut writer,
                &CorrelationRecord {
                    kind: "correlation",
                    record_version: JSONL_PROTOCOL_VERSION,
                    model: subject.model,
                    correlation,
                },
            )?;
        }
        if let Some(coverage) = subject.coverage {
            write_line(
                &mut writer,
                &CoverageRecord {
                    kind: "coverage",
                    record_version: JSONL_PROTOCOL_VERSION,
                    model: subject.model,
                    coverage,
                },
            )?;
        }
    }

    write_line(
        &mut writer,
        &ScanFooterRecord {
            kind: "scan_footer",
            record_version: JSONL_PROTOCOL_VERSION,
            overall_status,
            exit_code,
            finished_unix: crate::paths::now_unix(),
        },
    )?;
    Ok(())
}

fn emit_stdout_jsonl(
    subjects: &[JsonlSubject<'_>],
    overall_status: ScanStatus,
    exit_code: i32,
) -> Result<()> {
    let stdout = std::io::stdout();
    let lock = stdout.lock();
    emit_jsonl(lock, subjects, overall_status, exit_code)
}

/// Emit an Ollama-store scan (`layerfault scan --jsonl`) as JSONL. This path
/// doesn't compute correlations/coverage today, so those record kinds are
/// simply absent for each subject rather than fabricated.
pub fn emit_evaluated_jsonl(reports: &[EvaluatedReport]) -> Result<()> {
    let subjects: Vec<JsonlSubject<'_>> = reports
        .iter()
        .map(|evaluated| JsonlSubject {
            model: &evaluated.report.model_name,
            findings: &evaluated.report.results,
            correlations: &[],
            coverage: None,
        })
        .collect();
    let overall = subjects
        .iter()
        .map(|subject| report::overall_status(subject.findings))
        .fold(ScanStatus::Pass, combine_status);
    let exit_code = crate::app::policy_exit_code(reports);
    emit_stdout_jsonl(&subjects, overall, exit_code)
}

/// Emit a single-target pipeline scan (`layerfault pipeline --jsonl`) as
/// JSONL.
pub fn emit_pipeline_jsonl(
    target: &str,
    findings: &[LayerScanResult],
    correlations: &[FindingCorrelation],
    exit_code: i32,
) -> Result<()> {
    let subjects = [JsonlSubject {
        model: target,
        findings,
        correlations,
        coverage: None,
    }];
    let overall = report::overall_status(findings);
    emit_stdout_jsonl(&subjects, overall, exit_code)
}
