use super::TokenizerSecurityReport;
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct TokenizerDelta {
    pub file_changes: Vec<String>,
    pub added_special_tokens: Vec<String>,
    pub removed_special_tokens: Vec<String>,
    pub role_mapping_changed: bool,
    pub chat_template_changed: bool,
    pub suspicious_changes: Vec<String>,
}
pub fn compare(
    candidate: &TokenizerSecurityReport,
    parent: &TokenizerSecurityReport,
) -> TokenizerDelta {
    let mut d = TokenizerDelta::default();
    let c = candidate
        .special_tokens
        .iter()
        .map(|t| t.token.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let p = parent
        .special_tokens
        .iter()
        .map(|t| t.token.clone())
        .collect::<std::collections::BTreeSet<_>>();
    d.added_special_tokens = c.difference(&p).cloned().collect();
    d.removed_special_tokens = p.difference(&c).cloned().collect();
    d.role_mapping_changed = candidate.special_tokens.iter().any(|x| {
        parent
            .special_tokens
            .iter()
            .any(|y| x.token == y.token && x.role != y.role)
    });
    d.chat_template_changed = candidate
        .chat_template
        .as_ref()
        .map(|t| &t.normalized_sha256)
        != parent.chat_template.as_ref().map(|t| &t.normalized_sha256);
    if candidate.unicode_controls.iter().any(|x| x.role_boundary)
        && !parent.unicode_controls.iter().any(|x| x.role_boundary)
    {
        d.suspicious_changes
            .push("new hidden Unicode control in a role boundary".into())
    }
    if d.role_mapping_changed {
        d.suspicious_changes
            .push("canonical role mapping changed".into())
    }
    d
}
