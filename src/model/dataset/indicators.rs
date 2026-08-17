use super::types::{nearest_boundary, LocalAnalysis};
use lazy_static::lazy_static;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

pub(super) const MAX_DUPLICATE_EXAMPLES: usize = 100;
/// Two records are near-duplicates when their 64-bit SimHash fingerprints
/// differ by at most this many bits. Calibrated empirically, not guessed:
/// for realistic short records (5-10 tokens), a single substituted token
/// (a templated field — an account number, a name) typically shifts
/// 8-14 bits with this implementation, while unrelated short records
/// typically differ by 35-40 bits (close to the ~32-bit expected value for
/// two independent 64-bit fingerprints). 16 sits clearly above the former
/// range and well below the latter.
const NEAR_DUPLICATE_HAMMING_THRESHOLD: u32 = 16;
const MAX_NEAR_DUPLICATE_CANDIDATES: usize = 250_000;

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
    for (count, example, _simhash) in entries {
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

/// A 64-bit SimHash fingerprint of `tokens`, weighted by token frequency
/// within the record. Near-identical token multisets produce fingerprints
/// with a small Hamming distance; unrelated text produces fingerprints that
/// differ in roughly half their bits.
pub(super) fn simhash(tokens: &[String]) -> u64 {
    let mut bits = [0i64; 64];
    for token in tokens {
        let digest = Sha256::digest(token.as_bytes());
        let token_hash = u64::from_le_bytes(digest[0..8].try_into().expect("8 bytes"));
        for (index, bit) in bits.iter_mut().enumerate() {
            if (token_hash >> index) & 1 == 1 {
                *bit += 1;
            } else {
                *bit -= 1;
            }
        }
    }
    let mut hash = 0u64;
    for (index, value) in bits.iter().enumerate() {
        if *value > 0 {
            hash |= 1 << index;
        }
    }
    hash
}

/// Records that are not byte-identical (so `add_duplicate_indicator` would
/// not catch them) but whose token content is near-identical — a templated
/// or lightly paraphrased insertion repeated across a dataset, which exact
/// hashing cannot see. This compares each distinct-digest record's SimHash
/// against every other in a single sorted pass — genuinely near-duplicate
/// records land close together once sorted by fingerprint value, so this
/// finds same/adjacent-bucket pairs cheaply. It does **not** perform
/// exhaustive pairwise comparison, so it is a bounded heuristic, not a
/// complete near-duplicate census: pairs that happen to sort far apart
/// despite a small Hamming distance are not caught.
pub(super) fn add_near_duplicate_indicator(analysis: &mut LocalAnalysis) {
    // Keyed and sorted by (simhash, digest) rather than simhash alone: the
    // source map is a HashMap, so its iteration order is not deterministic,
    // and entries can legitimately tie on simhash. Without the digest as a
    // tiebreaker, the relative order of tied entries — and therefore which
    // examples get reported — would depend on hashmap iteration order,
    // which in turn depends on how work was split across threads. The
    // digest is stable content identity, so this sort order is fully
    // deterministic regardless of job count.
    let mut entries: Vec<(u64, &str, &str)> = analysis
        .duplicate_counts
        .iter()
        .map(|(digest, (_, example, simhash))| (*simhash, example.as_str(), digest.as_str()))
        .take(MAX_NEAR_DUPLICATE_CANDIDATES)
        .collect();
    if entries.len() < 2 {
        return;
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.2.cmp(b.2)));

    let mut flagged_count = 0_u64;
    let mut examples = Vec::new();
    let mut already_flagged = vec![false; entries.len()];
    for window_start in 0..entries.len() {
        // Compare each entry against a small forward window; genuinely
        // near-duplicate fingerprints (small Hamming distance) sort close
        // together, so a bounded window catches them without full O(n^2)
        // comparison.
        for offset in 1..=8.min(entries.len() - 1 - window_start) {
            let window_end = window_start + offset;
            let (hash_a, example_a, _) = entries[window_start];
            let (hash_b, example_b, _) = entries[window_end];
            if (hash_a ^ hash_b).count_ones() <= NEAR_DUPLICATE_HAMMING_THRESHOLD {
                if !already_flagged[window_start] {
                    already_flagged[window_start] = true;
                    flagged_count = flagged_count.saturating_add(1);
                    if examples.len() < MAX_DUPLICATE_EXAMPLES {
                        examples.push(example_a.to_owned());
                    }
                }
                if !already_flagged[window_end] {
                    already_flagged[window_end] = true;
                    flagged_count = flagged_count.saturating_add(1);
                    if examples.len() < MAX_DUPLICATE_EXAMPLES {
                        examples.push(example_b.to_owned());
                    }
                }
            }
        }
    }
    if flagged_count > 0 {
        analysis.indicators.insert(
            "LF-DATASET-NEAR-DUPLICATE-CONCENTRATION".to_owned(),
            (flagged_count, examples),
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
        "LF-DATASET-NEAR-DUPLICATE-CONCENTRATION" => "LOW",
        _ => "LOW",
    }
}

pub(super) fn detail(rule: &str) -> &'static str {
    match rule {
        "LF-DATASET-DUPLICATE-CONCENTRATION" => "Repeated records may reflect contamination, oversampling or deliberate trigger amplification; investigate in context.",
        "LF-DATASET-NEAR-DUPLICATE-CONCENTRATION" => "Records that are not byte-identical but are near-identical in token content were observed; this can reflect a templated or lightly varied insertion repeated across the dataset, which exact-duplicate detection cannot see.",
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
    use super::super::types::LocalAnalysis;
    use super::*;

    #[test]
    fn detects_zero_width() {
        assert!(contains_zero_width("hello\u{200b}world"));
    }

    fn tokenize(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn identical_token_sets_have_identical_simhash() {
        let a = simhash(&tokenize("the quick brown fox jumps"));
        let b = simhash(&tokenize("the quick brown fox jumps"));
        assert_eq!(a, b);
    }

    #[test]
    fn near_identical_text_has_a_small_hamming_distance() {
        let a = simhash(&tokenize("please transfer the funds to account 1234"));
        let b = simhash(&tokenize("please transfer the funds to account 5678"));
        assert!((a ^ b).count_ones() <= NEAR_DUPLICATE_HAMMING_THRESHOLD);
    }

    #[test]
    fn unrelated_text_has_a_large_hamming_distance() {
        let a = simhash(&tokenize("please transfer the funds to account 1234"));
        let b = simhash(&tokenize("the weather today is sunny and warm outside"));
        assert!((a ^ b).count_ones() > NEAR_DUPLICATE_HAMMING_THRESHOLD);
    }

    #[test]
    fn near_duplicate_records_are_flagged_exact_duplicates_are_not_double_counted() {
        let mut analysis = LocalAnalysis::default();
        let templated = [
            "please transfer the funds to account 1111",
            "please transfer the funds to account 2222",
            "please transfer the funds to account 3333",
        ];
        for (index, text) in templated.iter().enumerate() {
            let hash = simhash(&tokenize(text));
            analysis
                .duplicate_counts
                .insert(format!("digest-{index}"), (1, (*text).to_owned(), hash));
        }
        add_near_duplicate_indicator(&mut analysis);
        let (count, examples) = analysis
            .indicators
            .get("LF-DATASET-NEAR-DUPLICATE-CONCENTRATION")
            .expect("near-duplicate indicator recorded");
        assert_eq!(*count, 3);
        assert_eq!(examples.len(), 3);
    }

    #[test]
    fn unrelated_records_do_not_trigger_near_duplicate_indicator() {
        let mut analysis = LocalAnalysis::default();
        let unrelated = [
            "please transfer the funds to account 1111",
            "the weather today is sunny and warm outside",
            "quarterly earnings exceeded analyst expectations broadly",
        ];
        for (index, text) in unrelated.iter().enumerate() {
            let hash = simhash(&tokenize(text));
            analysis
                .duplicate_counts
                .insert(format!("digest-{index}"), (1, (*text).to_owned(), hash));
        }
        add_near_duplicate_indicator(&mut analysis);
        assert!(!analysis
            .indicators
            .contains_key("LF-DATASET-NEAR-DUPLICATE-CONCENTRATION"));
    }
}
