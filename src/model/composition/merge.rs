use super::{MergeAssessment, MergeVerificationState};
use anyhow::Result;
use std::path::Path;

pub fn verify_lora(base: &Path, adapter: &Path, merged: &Path) -> Result<MergeAssessment> {
    let base_identity = crate::safeio::sha256_path(base).ok();
    let merged_identity = crate::safeio::sha256_path(merged).ok();
    let adapter_report = crate::model::lora::inspect_adapter(adapter, None)?;
    let adapter_identity = crate::safeio::sha256_path(Path::new(&adapter_report.adapter_file)).ok();
    match crate::model::lora::verify_merge(base, adapter, merged) {
        Ok(report) => {
            let state = map_state(
                &report.state,
                report.tensors.len(),
                report.unsupported.len(),
                report.non_target_changed.len(),
            );
            Ok(MergeAssessment {
                state,
                base_identity,
                adapter_identity,
                merged_identity,
                verified_tensors: report.tensors.len() as u64,
                unsupported_tensors: report.unsupported.len() as u64,
                changed_non_target_tensors: report.non_target_changed.len() as u64,
                detail: report.boundary,
            })
        }
        Err(error) => Ok(MergeAssessment {
            state: MergeVerificationState::UnableToVerify,
            base_identity,
            adapter_identity,
            merged_identity,
            verified_tensors: 0,
            unsupported_tensors: 0,
            changed_non_target_tensors: 0,
            detail: error.to_string(),
        }),
    }
}

fn map_state(
    raw: &str,
    verified: usize,
    unsupported: usize,
    non_target_changed: usize,
) -> MergeVerificationState {
    if non_target_changed > 0
        || raw.eq_ignore_ascii_case("inconsistent")
        || raw.eq_ignore_ascii_case("failed")
    {
        return MergeVerificationState::Inconsistent;
    }
    if raw.eq_ignore_ascii_case("verified") && unsupported == 0 {
        return MergeVerificationState::Verified;
    }
    if verified > 0 && unsupported > 0 {
        return MergeVerificationState::PartiallyConsistent;
    }
    if verified > 0 {
        return MergeVerificationState::Consistent;
    }
    if unsupported > 0 {
        return MergeVerificationState::UnableToVerify;
    }
    MergeVerificationState::Unknown
}
