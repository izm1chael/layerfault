use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateSource {
    BeamExpansion,
    RareTokenizerToken,
    AddedSpecialToken,
    UnicodeControlToken,
    SecurityDeltaToken,
    Operator,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerCandidate {
    pub text: String,
    pub source: CandidateSource,
    pub rationale: String,
}
#[derive(Debug, Clone, Default)]
pub struct BeamOptions {
    pub candidates: Vec<String>,
}
pub fn build_candidates(
    operator: &[String],
    tokenizer: Option<&crate::model::tokenizer::TokenizerSecurityReport>,
    delta: Option<&crate::model::tokenizer::TokenizerDelta>,
    rare: &[String],
    beam: Option<&BeamOptions>,
) -> Result<Vec<TriggerCandidate>> {
    let mut map: BTreeMap<String, TriggerCandidate> = BTreeMap::new();
    let mut add = |text: &str, source: CandidateSource, rationale: &str| -> Result<()> {
        if text.is_empty() || text.len() > 4096 {
            return Ok(());
        }
        let replace = map.get(text).is_none_or(|v| source > v.source);
        if replace {
            map.insert(
                text.into(),
                TriggerCandidate {
                    text: text.into(),
                    source,
                    rationale: rationale.into(),
                },
            );
        }
        Ok(())
    };
    for s in beam.into_iter().flat_map(|b| &b.candidates) {
        add(s, CandidateSource::BeamExpansion, "bounded beam expansion")?
    }
    for s in rare {
        add(
            s,
            CandidateSource::RareTokenizerToken,
            "rare tokenizer token",
        )?
    }
    if let Some(t) = tokenizer {
        for s in &t.special_tokens {
            add(
                &s.token,
                CandidateSource::AddedSpecialToken,
                "added/special tokenizer token",
            )?
        }
        for c in &t.unicode_controls {
            add(
                &c.bounded_context,
                CandidateSource::UnicodeControlToken,
                "tokenizer content containing hidden Unicode control",
            )?
        }
    }
    if let Some(d) = delta {
        for s in &d.added_special_tokens {
            add(
                s,
                CandidateSource::SecurityDeltaToken,
                "security-relevant tokenizer delta",
            )?
        }
    }
    for s in operator {
        add(s, CandidateSource::Operator, "operator supplied")?
    }
    let mut out = map.into_values().collect::<Vec<_>>();
    out.sort_by(|a, b| b.source.cmp(&a.source).then(a.text.cmp(&b.text)));
    if out.len() > 100_000 {
        bail!("trigger candidate count exceeds standard cap")
    }
    Ok(out)
}
