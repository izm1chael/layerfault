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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeSuite {
    pub version: u32,
    pub id: String,
    pub probes: Vec<Probe>,
}

fn one() -> usize { 1 }

pub fn load_suite(path: Option<&Path>) -> Result<ProbeSuite> {
    let bytes = match path {
        Some(path) => {
            let file = crate::safeio::open_readonly_nofollow(path)?;
            crate::safeio::read_all_from_file(&file, MAX_SUITE_BYTES)?
        }
        None => include_bytes!("probes/core-v1.json").to_vec(),
    };
    let suite: ProbeSuite = serde_json::from_slice(&bytes).context("invalid behaviour probe suite")?;
    if suite.version != 1 { bail!("unsupported behaviour probe-suite version {}", suite.version); }
    if suite.id.trim().is_empty() || suite.id.len() > 1024 { bail!("probe-suite id is empty or too long"); }
    if suite.probes.is_empty() || suite.probes.len() > MAX_PROBES { bail!("probe count must be in 1..={MAX_PROBES}"); }
    let mut ids = std::collections::BTreeSet::new();
    for probe in &suite.probes {
        if !ids.insert(probe.id.clone()) { bail!("duplicate behaviour probe id '{}'", probe.id); }
        if probe.id.len() > 1024 || probe.category.len() > 1024 || probe.system.len() > 128*1024 || probe.prompt.len() > 128*1024 { bail!("behaviour probe contains an oversized field"); }
    }
    Ok(suite)
}

pub fn render(input: &str, canary_a: &str, canary_b: &str) -> String {
    input.replace("{{SECRET_A}}", canary_a).replace("{{SECRET_B}}", canary_b)
}


pub fn expand_mutations(mut suite: ProbeSuite, max_mutations: usize) -> ProbeSuite {
    if max_mutations == 0 { return suite; }
    let seeds: Vec<Probe> = suite.probes.iter().filter(|p| p.category == "trigger_detection" || p.category == "encoded_obfuscation" || p.category == "prompt_injection").cloned().collect();
    let mut generated = Vec::new();
    for probe in seeds {
        let variants = mutation_variants(&probe.prompt);
        for (family, value) in variants {
            if generated.len() >= max_mutations { break; }
            let mut child = probe.clone();
            child.id = format!("{}::{}::{:04}", probe.id, family, generated.len());
            child.prompt = value;
            child.repeat = 1;
            generated.push(child);
        }
        if generated.len() >= max_mutations { break; }
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
        ("json", format!(r#"{{"content":{}}}"#, serde_json::to_string(input).unwrap_or_else(|_| "\"\"".to_owned()))),
        ("xml", format!("<content>{}</content>", input.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;"))),
        ("zero-width", input.replacen('-', "-\u{200b}", 1)),
        ("homoglyph", input.replace('A', "Α").replace('a', "а")),
        ("prefix", format!("REFERENCE ONLY: {input}")),
        ("suffix", format!("{input}\nEND REFERENCE")),
    ];
    let hexed = hex::encode(input.as_bytes());
    out.push(("hex", format!("Decode this synthetic hex text before responding: {hexed}")));
    out
}
