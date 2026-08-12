use super::types::{nearest_boundary, LocalAnalysis};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::{BTreeMap, HashMap};

pub(super) const MAX_DUPLICATE_EXAMPLES: usize = 100;

pub(super) fn contains_zero_width(value: &str) -> bool {
    value.chars().any(|c| {
        matches!(
            c,
            '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{2060}' | '\u{feff}'
        )
    })
}

pub(super) fn has_url(value: &str) -> bool {
    lazy_static! {
        static ref URL: Regex =
            Regex::new(r"(?i)https?://[a-z0-9._~%/-]+").expect("static URL regex");
    }
    URL.is_match(value)
}

pub(super) fn credential_like(value: &str) -> bool {
    lazy_static! {
        static ref SECRET: Regex = Regex::new(
            r#"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-/+=]{12,}"#
        )
        .expect("static secret regex");
    }
    SECRET.is_match(value)
}

pub(super) fn unsafe_code_like(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "shell=true",
        "shell = true",
        "verify=false",
        "verify = false",
        "pickle.loads(",
        "yaml.load(",
        "os.system(",
        "subprocess.popen(",
        "md5(",
        "sha1(",
    ]
    .iter()
    .any(|p| lower.contains(p))
}

pub(super) fn add(map: &mut BTreeMap<String, (u64, Vec<String>)>, rule: &str, text: &str) {
    let entry = map.entry(rule.to_owned()).or_insert((0, Vec::new()));
    entry.0 = entry.0.saturating_add(1);
    if entry.1.len() < MAX_DUPLICATE_EXAMPLES {
        entry.1.push(bounded(text, 240));
    }
}

pub(super) fn bounded(value: &str, cap: usize) -> String {
    if value.len() <= cap {
        return value.to_owned();
    }
    let end = nearest_boundary(value, cap);
    format!("{}…", &value[..end])
}

pub(super) fn add_duplicate_indicator(analysis: &mut LocalAnalysis) {
    let mut entries: Vec<_> = analysis.duplicate_counts.values().collect();
    entries.sort_by(|a, b| a.1.cmp(&b.1));
    let mut examples = Vec::new();
    let mut extra = 0_u64;
    for (count, example) in entries {
        if *count > 1 {
            extra = extra.saturating_add(count.saturating_sub(1));
            if examples.len() < MAX_DUPLICATE_EXAMPLES {
                examples.push(example.clone());
            }
        }
    }
    if extra > 0 {
        analysis.indicators.insert(
            "LF-DATASET-DUPLICATE-CONCENTRATION".to_owned(),
            (extra, examples),
        );
    }
}

pub(super) fn add_rare_trigger_indicator(analysis: &mut LocalAnalysis) {
    if analysis.label_counts.len() <= 1 {
        return;
    }
    // Build the best label association once. The previous implementation
    // rescanned every label/token pair for every rare token.
    let mut best: HashMap<String, (String, u64)> = HashMap::new();
    for ((token, label), count) in &analysis.label_token_counts {
        let entry = best.entry(token.clone()).or_insert((label.clone(), 0));
        if *count > entry.1 || (*count == entry.1 && label < &entry.0) {
            *entry = (label.clone(), *count);
        }
    }
    let mut tokens: Vec<_> = analysis.token_counts.iter().collect();
    tokens.sort_by(|a, b| a.0.cmp(b.0));
    for (token, total) in tokens {
        if *total < 3 || *total > 100 {
            continue;
        }
        let Some((label, count_for_label)) = best.get(token) else {
            continue;
        };
        if count_for_label.saturating_mul(100) >= total.saturating_mul(90) {
            let (count, examples) = analysis
                .indicators
                .entry("LF-DATASET-RARE-TRIGGER-CORRELATION".to_owned())
                .or_insert((0, Vec::new()));
            *count = count.saturating_add(1);
            if examples.len() < MAX_DUPLICATE_EXAMPLES {
                examples.push(format!(
                    "token='{token}' label='{label}' occurrences={count_for_label}/{total}"
                ));
            }
        }
    }
}

pub(super) fn confidence(rule: &str) -> &'static str {
    match rule {
        "LF-DATASET-RARE-TRIGGER-CORRELATION" => "MEDIUM",
        "LF-DATASET-CREDENTIAL-LIKE" => "MEDIUM",
        "LF-DATASET-COVERAGE-LIMIT" => "HIGH",
        _ => "LOW",
    }
}

pub(super) fn detail(rule: &str) -> &'static str {
    match rule {
        "LF-DATASET-DUPLICATE-CONCENTRATION" => "Repeated records may reflect contamination, oversampling or deliberate trigger amplification; investigate in context.",
        "LF-DATASET-RARE-TRIGGER-CORRELATION" => "A relatively rare token is strongly concentrated in one observed label/target in the bounded sample.",
        "LF-DATASET-ZERO-WIDTH" => "Zero-width Unicode was present in dataset content and can hide trigger text or formatting.",
        "LF-DATASET-URL-CONCENTRATION" => "URL-bearing content was observed; high/repeated concentration can be relevant to targeted-content poisoning.",
        "LF-DATASET-CREDENTIAL-LIKE" => "Credential-like material was observed and may indicate accidental secret contamination.",
        "LF-DATASET-UNSAFE-CODE-PATTERN" => "Security-sensitive insecure-code patterns were observed in training text.",
        "LF-DATASET-COVERAGE-LIMIT" => "One or more dataset members could be fingerprinted but not record-parsed by this build. Layerfault will not report a clean poisoning review when material dataset content was opaque or unavailable to record parsing.",
        _ => "Dataset anomaly requires investigation.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_zero_width() {
        assert!(contains_zero_width("hello\u{200b}world"));
    }
}
