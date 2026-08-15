#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisCompleteness {
    Complete,
    Partial,
    Unknown,
}

impl AnalysisCompleteness {
    pub fn permits_clean_pass(self) -> bool {
        matches!(self, Self::Complete)
    }
}
