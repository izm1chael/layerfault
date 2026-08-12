use super::super::{DatasetArgs, DatasetCommand};
use anyhow::Result;
use layerfault::json_stream::write_stdout_json;
pub(crate) fn run_dataset(args: DatasetArgs) -> Result<()> {
    match args.command {
        DatasetCommand::Inspect {
            dataset,
            jobs,
            json: emit_json,
        }
        | DatasetCommand::Fingerprint {
            dataset,
            jobs,
            json: emit_json,
        } => {
            let report = layerfault::dataset::fingerprint_with_jobs(
                &dataset,
                jobs.unwrap_or_else(layerfault::app::default_jobs),
            )?;
            if emit_json {
                write_stdout_json(&report, true)?;
            } else {
                println!(
                    "DATASET\n{}\nfiles: {}\nbytes: {}\nrecords sampled: {}",
                    report.identity,
                    report.files.len(),
                    report.total_bytes,
                    report.records_sampled
                );
                for file in report.files.iter().filter(|f| f.parse_warning.is_some()) {
                    println!(
                        "WARN {}: {}",
                        file.path,
                        file.parse_warning
                            .as_deref()
                            .unwrap_or("record parsing unavailable")
                    );
                }
            }
        }
        DatasetCommand::Compare {
            left,
            right,
            jobs,
            json: emit_json,
        } => {
            let report = layerfault::dataset::compare_with_jobs(
                &left,
                &right,
                jobs.unwrap_or_else(layerfault::app::default_jobs),
            )?;
            if emit_json {
                write_stdout_json(&report, true)?;
            } else {
                println!(
                    "DATASET DIFFERENTIAL\n{} change(s)",
                    report
                        .get("changes")
                        .and_then(|v| v.as_array())
                        .map_or(0, Vec::len)
                );
            }
        }
        DatasetCommand::PoisoningReview {
            dataset,
            jobs,
            json: emit_json,
        } => {
            let report = layerfault::dataset::poisoning_review_with_jobs(
                &dataset,
                jobs.unwrap_or_else(layerfault::app::default_jobs),
            )?;
            if emit_json {
                write_stdout_json(&report, true)?;
            } else {
                println!(
                    "DATASET POISONING EVIDENCE\n{}\n{} record(s) analysed\n{} indicator(s)\n\n{}",
                    report.state,
                    report.records_analyzed,
                    report.indicators.len(),
                    report.boundary
                );
                for indicator in &report.indicators {
                    println!(
                        "{} [{}] x{} — {}",
                        indicator.rule_id, indicator.confidence, indicator.count, indicator.detail
                    );
                }
            }
            if report.state != "NO_SUSPICIOUS_INDICATORS_OBSERVED" {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
