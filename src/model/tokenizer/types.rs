use crate::coverage::Coverage;
use crate::finding_evidence::EvidenceSubject;
use crate::scanner::LayerScanResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenizerSecurityReport {
    pub subject: EvidenceSubject,
    pub files: Vec<TokenizerFileSummary>,
    pub special_tokens: Vec<SpecialTokenRecord>,
    pub chat_template: Option<ChatTemplateSecurity>,
    pub unicode_controls: Vec<UnicodeControlRecord>,
    pub findings: Vec<LayerScanResult>,
    pub coverage: Coverage,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenizerFileSummary {
    pub relative_path: String,
    pub size: u64,
    pub sha256: String,
    pub kind: TokenizerFileKind,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenizerFileKind {
    TokenizerJson,
    TokenizerConfig,
    SpecialTokensMap,
    AddedTokens,
    SentencePiece,
    BpeMerges,
    Vocabulary,
    ChatTemplate,
    ProcessorConfig,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpecialTokenRecord {
    pub token: String,
    pub role: Option<String>,
    pub special: bool,
    pub id: Option<u64>,
    pub source: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnicodeControlRecord {
    pub relative_path: String,
    pub field_path: String,
    pub codepoint: u32,
    pub unicode_name_or_hex: String,
    pub bounded_context: String,
    pub role_boundary: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatTemplateSecurity {
    pub source: String,
    pub sha256: String,
    pub normalized_sha256: String,
    pub roles_referenced: Vec<String>,
    pub tool_constructs: Vec<String>,
    pub hidden_literals: Vec<String>,
    pub static_analysis_complete: bool,
}
