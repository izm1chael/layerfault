use super::{IdentityCoverage, IdentityStrength, IdentityValue};
use crate::model::tokenizer::TokenizerSecurityReport;
use sha2::{Digest, Sha256};
pub fn identity(r: &TokenizerSecurityReport) -> anyhow::Result<IdentityValue> {
    let mut files = r
        .files
        .iter()
        .map(|f| (format!("{:?}", f.kind), f.sha256.clone()))
        .collect::<Vec<_>>();
    files.sort();
    let mut tokens = r
        .special_tokens
        .iter()
        .map(|t| (t.token.clone(), t.id, t.role.clone(), t.special))
        .collect::<Vec<_>>();
    tokens.sort();
    let template = r
        .chat_template
        .as_ref()
        .map(|t| t.normalized_sha256.clone());
    let bytes = serde_json::to_vec(&(files, tokens, template))?;
    let mut h = Sha256::new();
    h.update(b"layerfault:model-tokenizer:v1\0");
    h.update(bytes);
    let complete = r.coverage.complete;
    Ok(IdentityValue {
        algorithm: "layerfault-model-tokenizer-v1-sha256".into(),
        value: format!("lfmodel:tokenizer:v1:sha256:{}", hex::encode(h.finalize())),
        strength: if complete {
            IdentityStrength::Exact
        } else {
            IdentityStrength::Structural
        },
        coverage: IdentityCoverage {
            complete,
            detail: "recognized tokenizer bytes plus normalized security semantics".into(),
        },
    })
}
