//! Scanner self-assurance and higher-level analysis completeness contracts.

pub mod certify;
pub mod completeness;
pub mod disposition;
pub mod parser_differential;
pub mod pickle;

pub use completeness::AnalysisCompleteness;
pub use disposition::AssessmentDisposition;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completeness_controls_clean_pass() {
        assert!(AnalysisCompleteness::Complete.permits_clean_pass());
        assert!(!AnalysisCompleteness::Partial.permits_clean_pass());
        assert!(!AnalysisCompleteness::Unknown.permits_clean_pass());
    }

    #[test]
    fn dispositions_serde_round_trip() {
        for value in [
            AssessmentDisposition::Clear,
            AssessmentDisposition::Informational,
            AssessmentDisposition::Review,
            AssessmentDisposition::Block,
            AssessmentDisposition::Unknown,
        ] {
            let encoded = serde_json::to_string(&value).expect("serialize");
            let decoded: AssessmentDisposition =
                serde_json::from_str(&encoded).expect("deserialize");
            assert_eq!(decoded, value);
        }
    }
}
