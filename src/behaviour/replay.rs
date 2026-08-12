use super::*;
pub fn replay_manifest(
    report: &BehaviourReport,
    probe_suite_path: Option<&Path>,
) -> BehaviourReplayManifest {
    let (closure_id, closure_lvl, components, coverage) = match &report.runtime.closure {
        Some(c) => (
            c.closure_id.clone(),
            c.level,
            c.components.clone(),
            c.coverage.clone(),
        ),
        None => (
            String::new(),
            closure::ClosureLevel::Minimal,
            Vec::new(),
            closure::ClosureCoverage::default(),
        ),
    };
    BehaviourReplayManifest {
        version: 1,
        model_path: report.model_path.clone(),
        model_identity: report.model_identity.clone(),
        runtime_path: report.runtime.executable.clone(),
        runtime_sha256: report.runtime.executable_sha256.clone(),
        runtime_closure_id: closure_id,
        closure_level: closure_lvl,
        component_summary: components,
        coverage_state: coverage,
        probe_suite_path: probe_suite_path.map(|p| p.display().to_string()),
        probe_suite_id: report.probe_suite_id.clone(),
        probe_suite_version: report.probe_suite_version,
        seed: report.seed,
        limits: report.limits.clone(),
    }
}

pub fn load_replay(path: &Path) -> Result<BehaviourReplayManifest> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let bytes = crate::safeio::read_all_from_file(&file, 4 * 1024 * 1024)?;
    let manifest: BehaviourReplayManifest = serde_json::from_slice(&bytes)?;
    if manifest.version != 1 {
        bail!(
            "unsupported behaviour replay manifest version {}",
            manifest.version
        );
    }
    Ok(manifest)
}
