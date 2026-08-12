use super::indicators::{
    add, add_duplicate_indicator, add_rare_trigger_indicator, confidence, contains_zero_width,
    credential_like, detail, has_url, unsafe_code_like, MAX_DUPLICATE_EXAMPLES,
};
use super::inventory::build_inventory;
use super::readers::{parseable, visit_records};
use super::sampling::{
    analysis_quotas, selected_indices, token_key_quotas, MAX_RECORDS, MAX_TOKEN_KEYS,
};
use super::types::{
    CountedFile, DatasetCoverage, LocalAnalysis, PoisonIndicator, PoisoningReview, Record,
};
use anyhow::{Context, Result};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

pub fn poisoning_review(path: &Path) -> Result<PoisoningReview> {
    poisoning_review_with_jobs(path, crate::app::default_jobs())
}

pub fn poisoning_review_with_jobs(path: &Path, jobs: usize) -> Result<PoisoningReview> {
    let mut inventory = build_inventory(path, jobs)?;
    let quotas = analysis_quotas(&inventory.counted);
    let token_key_quotas = token_key_quotas(&quotas);

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs.max(1))
        .thread_name(|index| format!("layerfault-dataset-{index}"))
        .build()
        .context("unable to create bounded dataset analysis pool")?;
    let local_results: Vec<Result<LocalAnalysis>> = pool.install(|| {
        inventory
            .counted
            .par_iter()
            .zip(quotas.par_iter().zip(token_key_quotas.par_iter()))
            .map(|(file, (quota, token_key_quota))| analyze_file(file, *quota, *token_key_quota))
            .collect()
    });

    let mut aggregate = LocalAnalysis::default();
    for (index, result) in local_results.into_iter().enumerate() {
        let local = result.with_context(|| {
            format!(
                "unable to analyze dataset member '{}'",
                inventory.counted[index].plan.path.display()
            )
        })?;
        let analyzed = local.records_analyzed;
        merge_analysis(&mut aggregate, local);
        if let Some(file) = inventory.fingerprint.files.get_mut(index) {
            file.records_analyzed = analyzed;
        }
    }

    add_duplicate_indicator(&mut aggregate);
    add_rare_trigger_indicator(&mut aggregate);

    let opaque_count = inventory
        .fingerprint
        .files
        .iter()
        .filter(|file| file.parse_warning.is_some())
        .count();
    let opaque: Vec<String> = inventory
        .fingerprint
        .files
        .iter()
        .filter(|file| file.parse_warning.is_some())
        .map(|file| file.path.clone())
        .take(MAX_DUPLICATE_EXAMPLES)
        .collect();
    if opaque_count > 0 {
        aggregate.indicators.insert(
            "LF-DATASET-COVERAGE-LIMIT".to_owned(),
            (opaque_count as u64, opaque),
        );
    }

    let records_available = inventory
        .counted
        .iter()
        .map(|file| file.records_available)
        .fold(0_usize, |acc, value| acc.saturating_add(value));
    let records_analyzed = aggregate.records_analyzed;
    let coverage = DatasetCoverage {
        records_available,
        records_analyzed,
        record_limit: MAX_RECORDS,
        record_limit_reached: records_available > records_analyzed,
        token_key_limit: MAX_TOKEN_KEYS,
        token_key_limit_reached: aggregate.token_key_limit_reached,
        opaque_or_unparsed_files: inventory
            .counted
            .iter()
            .filter(|file| file.parse_warning.is_some())
            .count(),
        sampling_strategy: if records_available > records_analyzed {
            "DETERMINISTIC_STRATIFIED_FULL_RANGE".to_owned()
        } else {
            "FULL_RECORD_COVERAGE".to_owned()
        },
    };
    inventory.fingerprint.records_sampled = records_analyzed;
    inventory.fingerprint.coverage = coverage.clone();

    let indicators: Vec<PoisonIndicator> = aggregate
        .indicators
        .into_iter()
        .map(|(rule_id, (count, examples))| PoisonIndicator {
            confidence: confidence(&rule_id).to_owned(),
            detail: detail(&rule_id).to_owned(),
            rule_id,
            count,
            examples,
        })
        .collect();
    let state = if indicators
        .iter()
        .any(|value| value.rule_id == "LF-DATASET-RARE-TRIGGER-CORRELATION")
    {
        "ANOMALOUS"
    } else if indicators.is_empty() {
        "NO_SUSPICIOUS_INDICATORS_OBSERVED"
    } else {
        "REVIEW"
    };

    Ok(PoisoningReview {
        version: 2,
        dataset: inventory.fingerprint,
        state: state.to_owned(),
        indicators,
        records_analyzed,
        coverage,
        boundary: "Dataset indicators are bounded statistical/content evidence. They do not establish that training data was maliciously poisoned or that all poisoning is absent. When the record limit is reached, Layerfault deterministically samples across the complete record range instead of inspecting only the head of the dataset.".to_owned(),
    })
}

fn analyze_file(file: &CountedFile, quota: usize, token_key_quota: usize) -> Result<LocalAnalysis> {
    let mut out = LocalAnalysis::default();
    if quota == 0 || file.parse_warning.is_some() || !parseable(file.plan.format) {
        return Ok(out);
    }
    let selected = selected_indices(file.records_available, quota);
    visit_records(
        &file.plan.path,
        file.plan.format,
        Some(&selected),
        |_, record| {
            observe_record(&mut out, record, token_key_quota);
            Ok(())
        },
    )?;
    Ok(out)
}

fn observe_record(out: &mut LocalAnalysis, record: Record, token_key_quota: usize) {
    out.records_analyzed = out.records_analyzed.saturating_add(1);
    let normalized = normalize(&record.text);
    if normalized.is_empty() {
        return;
    }
    let digest = hex::encode(Sha256::digest(normalized.as_bytes()));
    let entry = out
        .duplicate_counts
        .entry(digest)
        .or_insert((0, super::indicators::bounded(&record.text, 240)));
    entry.0 = entry.0.saturating_add(1);

    if contains_zero_width(&record.text) {
        add(&mut out.indicators, "LF-DATASET-ZERO-WIDTH", &record.text);
    }
    if has_url(&record.text) {
        add(
            &mut out.indicators,
            "LF-DATASET-URL-CONCENTRATION",
            &record.text,
        );
    }
    if credential_like(&record.text) {
        add(
            &mut out.indicators,
            "LF-DATASET-CREDENTIAL-LIKE",
            &record.text,
        );
    }
    if unsafe_code_like(&record.text) {
        add(
            &mut out.indicators,
            "LF-DATASET-UNSAFE-CODE-PATTERN",
            &record.text,
        );
    }

    let record_tokens = tokens(&normalized);
    for token in record_tokens.iter().take(512) {
        bounded_increment(
            &mut out.token_counts,
            token.clone(),
            token_key_quota,
            &mut out.token_key_limit_reached,
        );
        if let Some(label) = record.label.as_ref() {
            bounded_increment(
                &mut out.label_token_counts,
                (token.clone(), label.clone()),
                token_key_quota,
                &mut out.token_key_limit_reached,
            );
        }
    }
    if let Some(label) = record.label {
        *out.label_counts.entry(label).or_default() += 1;
    }
}

fn bounded_increment<K>(map: &mut HashMap<K, u64>, key: K, max_keys: usize, limited: &mut bool)
where
    K: std::hash::Hash + Eq,
{
    if let Some(value) = map.get_mut(&key) {
        *value = value.saturating_add(1);
    } else if map.len() < max_keys {
        map.insert(key, 1);
    } else {
        *limited = true;
    }
}

fn merge_analysis(target: &mut LocalAnalysis, source: LocalAnalysis) {
    target.records_analyzed = target
        .records_analyzed
        .saturating_add(source.records_analyzed);
    target.token_key_limit_reached |= source.token_key_limit_reached;

    let mut duplicates: Vec<_> = source.duplicate_counts.into_iter().collect();
    duplicates.sort_by(|a, b| a.0.cmp(&b.0));
    for (digest, (count, example)) in duplicates {
        let entry = target
            .duplicate_counts
            .entry(digest)
            .or_insert((0, example));
        entry.0 = entry.0.saturating_add(count);
    }
    merge_count_map(
        &mut target.token_counts,
        source.token_counts,
        &mut target.token_key_limit_reached,
    );
    merge_count_map(
        &mut target.label_token_counts,
        source.label_token_counts,
        &mut target.token_key_limit_reached,
    );
    for (label, count) in source.label_counts {
        let entry = target.label_counts.entry(label).or_default();
        *entry = entry.saturating_add(count);
    }
    for (rule, (count, examples)) in source.indicators {
        let entry = target.indicators.entry(rule).or_insert((0, Vec::new()));
        entry.0 = entry.0.saturating_add(count);
        for example in examples {
            if entry.1.len() >= MAX_DUPLICATE_EXAMPLES {
                break;
            }
            entry.1.push(example);
        }
    }
}

fn merge_count_map<K>(target: &mut HashMap<K, u64>, source: HashMap<K, u64>, limited: &mut bool)
where
    K: std::hash::Hash + Eq + Ord,
{
    let mut entries: Vec<_> = source.into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (key, count) in entries {
        if let Some(value) = target.get_mut(&key) {
            *value = value.saturating_add(count);
        } else if target.len() < MAX_TOKEN_KEYS {
            target.insert(key, count);
        } else {
            *limited = true;
        }
    }
}

fn normalize(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn tokens(value: &str) -> Vec<String> {
    value
        .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
        .filter(|v| v.len() >= 3 && v.len() <= 128)
        .take(4096)
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp(name: &str) -> PathBuf {
        let thread_name: String = std::thread::current()
            .name()
            .unwrap_or("test")
            .chars()
            .map(|value| {
                if value.is_ascii_alphanumeric() || matches!(value, '-' | '_') {
                    value
                } else {
                    '_'
                }
            })
            .collect();
        std::env::temp_dir().join(format!(
            "layerfault-dataset-{name}-{}-{}",
            std::process::id(),
            thread_name
        ))
    }

    #[test]
    fn test_fixture_paths_are_windows_safe() {
        let path = temp("portable");
        let name = path.file_name().and_then(|value| value.to_str()).unwrap();
        assert!(!name.contains([':', '<', '>', '"', '/', '\\', '|', '?', '*']));
    }

    #[test]
    fn normalizes_whitespace() {
        assert_eq!(normalize(" A  B\nC "), "a b c");
    }

    #[test]
    fn opaque_parquet_does_not_report_clean_poisoning_review() {
        let root = temp("parquet-limit");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create dataset fixture");
        std::fs::write(root.join("train.parquet"), b"PAR1bounded-fixturePAR1")
            .expect("write parquet fixture");
        let report = poisoning_review_with_jobs(&root, 1).expect("poisoning review");
        assert_eq!(report.state, "REVIEW");
        assert!(report
            .indicators
            .iter()
            .any(|indicator| indicator.rule_id == "LF-DATASET-COVERAGE-LIMIT"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn jobs_do_not_change_dataset_security_result() {
        let root = temp("determinism");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create dataset fixture");
        for file in 0..4 {
            let mut body = String::new();
            for index in 0..500 {
                let label = if index % 2 == 0 { "safe" } else { "other" };
                body.push_str(&format!(
                    "{{\"text\":\"sample {file} {index}\",\"label\":\"{label}\"}}\n"
                ));
            }
            std::fs::write(root.join(format!("part-{file}.jsonl")), body).expect("write fixture");
        }
        let one = poisoning_review_with_jobs(&root, 1).expect("jobs=1");
        let four = poisoning_review_with_jobs(&root, 4).expect("jobs=4");
        assert_eq!(one.dataset.identity, four.dataset.identity);
        assert_eq!(one.state, four.state);
        assert_eq!(
            serde_json::to_value(&one.indicators).expect("serialize indicators"),
            serde_json::to_value(&four.indicators).expect("serialize indicators")
        );
        assert_eq!(
            one.coverage.records_analyzed,
            four.coverage.records_analyzed
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
