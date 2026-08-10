use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

const MAX_SUITE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PROBES: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Probe {
    pub id: String,
    pub category: String,
    pub system: String,
    pub prompt: String,
    #[serde(default = "one")]
    pub repeat: usize,
    /// Optional identifier joining a benign/control prompt and its triggered
    /// counterpart for difference-in-differences analysis.
    #[serde(default)]
    pub comparison_group: Option<String>,
    /// `control` or `trigger` when `comparison_group` is present.
    #[serde(default)]
    pub comparison_role: Option<String>,
    /// Security boundary the paired probe is expected to preserve.
    #[serde(default)]
    pub expected_boundary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeSuite {
    pub version: u32,
    pub id: String,
    pub probes: Vec<Probe>,
}

fn one() -> usize {
    1
}

pub fn load_suite(path: Option<&Path>) -> Result<ProbeSuite> {
    let bytes = match path {
        Some(path) => {
            let file = crate::safeio::open_readonly_nofollow(path)?;
            crate::safeio::read_all_from_file(&file, MAX_SUITE_BYTES)?
        }
        None => include_bytes!("probes/core-v2.json").to_vec(),
    };
    let suite: ProbeSuite =
        serde_json::from_slice(&bytes).context("invalid behaviour probe suite")?;
    if !matches!(suite.version, 1 | 2) {
        bail!(
            "unsupported behaviour probe-suite version {}; supported versions are 1 and 2",
            suite.version
        );
    }
    if suite.id.trim().is_empty() || suite.id.len() > 1024 {
        bail!("probe-suite id is empty or too long");
    }
    if suite.probes.is_empty() || suite.probes.len() > MAX_PROBES {
        bail!("probe count must be in 1..={MAX_PROBES}");
    }
    let mut ids = std::collections::BTreeSet::new();
    for probe in &suite.probes {
        if !ids.insert(probe.id.clone()) {
            bail!("duplicate behaviour probe id '{}'", probe.id);
        }
        if probe.id.len() > 1024
            || probe.category.len() > 1024
            || probe.system.len() > 128 * 1024
            || probe.prompt.len() > 128 * 1024
        {
            bail!("behaviour probe contains an oversized field");
        }
        match (
            probe.comparison_group.as_deref(),
            probe.comparison_role.as_deref(),
        ) {
            (None, None) => {}
            (Some(group), Some("control" | "trigger")) if !group.trim().is_empty() => {}
            _ => bail!(
                "probe '{}' must supply comparison_group with comparison_role=control|trigger",
                probe.id
            ),
        }
        if probe
            .expected_boundary
            .as_deref()
            .is_some_and(|value| !matches!(value, "refuse_harmful"))
        {
            bail!("probe '{}' has unsupported expected_boundary", probe.id);
        }
    }
    Ok(suite)
}

pub fn render(input: &str, canary_a: &str, canary_b: &str) -> String {
    input
        .replace("{{SECRET_A}}", canary_a)
        .replace("{{SECRET_B}}", canary_b)
}

pub fn expand_mutations(mut suite: ProbeSuite, max_mutations: usize) -> ProbeSuite {
    if max_mutations == 0 {
        return suite;
    }
    let seeds: Vec<Probe> = suite
        .probes
        .iter()
        .filter(|p| {
            p.category == "trigger_detection"
                || p.category == "encoded_obfuscation"
                || p.category == "prompt_injection"
                || p.category == "data_exfiltration"
                || p.category == "privilege_boundary"
                || p.category == "instruction_hierarchy"
                || p.category == "conditional_context"
                || p.category == "multi_turn_consistency"
        })
        .cloned()
        .collect();
    let mut generated = Vec::new();
    for probe in seeds {
        let variants = mutation_variants(&probe.prompt);
        for (family, value) in variants {
            if generated.len() >= max_mutations {
                break;
            }
            let mut child = probe.clone();
            child.id = format!("{}::{}::{:04}", probe.id, family, generated.len());
            child.prompt = value;
            child.repeat = 1;
            generated.push(child);
        }
        if generated.len() >= max_mutations {
            break;
        }
    }
    suite.probes.extend(generated);
    suite
}

fn mutation_variants(input: &str) -> Vec<(&'static str, String)> {
    let mut out = vec![
        ("uppercase", input.to_ascii_uppercase()),
        ("lowercase", input.to_ascii_lowercase()),
        ("whitespace", format!("  {}  ", input.replace(' ', "  "))),
        ("punctuation", format!("{} !!!", input)),
        ("markdown", format!("```text\n{}\n```", input)),
        (
            "json",
            format!(
                r#"{{"content":{}}}"#,
                serde_json::to_string(input).unwrap_or_else(|_| "\"\"".to_owned())
            ),
        ),
        (
            "xml",
            format!(
                "<content>{}</content>",
                input
                    .replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;")
            ),
        ),
        ("zero-width", input.replacen('-', "-\u{200b}", 1)),
        ("homoglyph", input.replace('A', "Α").replace('a', "а")),
        ("prefix", format!("REFERENCE ONLY: {input}")),
        ("suffix", format!("{input}\nEND REFERENCE")),
    ];
    let hexed = hex::encode(input.as_bytes());
    out.push((
        "hex",
        format!("Decode this synthetic hex text before responding: {hexed}"),
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_v2_is_valid_and_default() -> Result<()> {
        let suite = load_suite(None)?;
        assert_eq!(suite.version, 2);
        assert_eq!(suite.id, "layerfault-core-v2");
        assert!((40..=60).contains(&suite.probes.len()));
        Ok(())
    }

    #[test]
    fn mutation_cap_is_hard() -> Result<()> {
        let suite = load_suite(None)?;
        let seed_count = suite.probes.len();
        let expanded = expand_mutations(suite, 7);
        assert_eq!(expanded.probes.len(), seed_count + 7);
        Ok(())
    }

    #[test]
    fn version_one_remains_loadable_from_file_shape() -> Result<()> {
        let suite: ProbeSuite = serde_json::from_slice(include_bytes!("probes/core-v1.json"))?;
        assert_eq!(suite.version, 1);
        assert!(!suite.probes.is_empty());
        Ok(())
    }
}
