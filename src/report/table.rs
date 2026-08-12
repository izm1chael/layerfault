use super::common::*;
use super::*;

pub fn emit_table(reports: &[ModelReport]) {
    for report in reports {
        println!("{}", format!("━━━ {} ━━━", report.model_name).bold());

        let mut table = Table::new();
        table.load_preset(UTF8_FULL);
        table.set_header([
            "Model",
            "Layer Digest (short)",
            "Check",
            "Class",
            "Confidence",
            "Status",
            "Detail",
        ]);

        for result in &report.results {
            table.add_row([
                report.model_name.clone(),
                short_digest(&result.layer_digest),
                check_type_label(&result.check_type).to_owned(),
                finding_class_label(&result.finding_class).to_owned(),
                confidence_label(&result.confidence).to_owned(),
                status_label(&result.status),
                result.detail.clone().unwrap_or_default(),
            ]);
        }

        println!("{table}");
    }
}

pub fn emit_evaluated_table(reports: &[crate::app::EvaluatedReport]) {
    let raw = reports
        .iter()
        .map(|value| ModelReport {
            model_name: value.report.model_name.clone(),
            results: value.report.results.clone(),
        })
        .collect::<Vec<_>>();
    emit_table(&raw);
    for report in reports {
        println!(
            "Policy: {:?}  Action: {:?}  Provenance: {:?}",
            report.policy.profile, report.policy.action, report.trust_state
        );
        for reason in &report.policy.reasons {
            println!("  - {reason}");
        }
        if !report.policy.suppressed_rule_ids.is_empty() {
            println!(
                "  Suppressed by policy: {}",
                report.policy.suppressed_rule_ids.join(", ")
            );
        }
    }
}

pub fn emit_inventory_table(reports: &[crate::app::EvaluatedReport]) {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header([
        "Model",
        "Integrity",
        "Structure",
        "Signed",
        "Trusted",
        "Policy",
    ]);
    for evaluated in reports {
        table.add_row([
            evaluated.report.model_name.clone(),
            status_or_na(class_status(
                &evaluated.report.results,
                FindingClass::Integrity,
            )),
            status_or_na(class_status(
                &evaluated.report.results,
                FindingClass::Structural,
            )),
            (evaluated.trust_state != crate::provenance::TrustState::Unsigned).to_string(),
            (evaluated.trust_state == crate::provenance::TrustState::Trusted).to_string(),
            format!("{:?}", evaluated.policy.action),
        ]);
    }
    println!("{table}");
}

pub(super) fn class_status(results: &[LayerScanResult], class: FindingClass) -> Option<ScanStatus> {
    let mut worst = None;
    for result in results
        .iter()
        .filter(|result| result.finding_class == class)
    {
        match result.status {
            ScanStatus::Fail => return Some(ScanStatus::Fail),
            ScanStatus::Warn => worst = Some(ScanStatus::Warn),
            ScanStatus::Pass if worst.is_none() => worst = Some(ScanStatus::Pass),
            ScanStatus::Pass => {}
        }
    }
    worst
}

fn status_or_na(status: Option<ScanStatus>) -> String {
    status
        .map(|value| format!("{value:?}"))
        .unwrap_or_else(|| "N/A".to_owned())
}
