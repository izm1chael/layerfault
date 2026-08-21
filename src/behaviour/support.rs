use super::*;
pub fn static_admit(path: &Path, allow_blocked: bool) -> Result<()> {
    if path.is_dir() {
        let report = crate::package::inspect(path)?;
        if report.blocking() && !allow_blocked {
            bail!(
                "static admission blocked package '{}'; behaviour was not run (use --allow-static-blocked only inside the strong sandbox when intentionally investigating blocked content)",
                path.display()
            );
        }
    } else {
        let report = crate::formats::artifact::inspect(
            path,
            crate::formats::artifact::ArtifactScanMode::Full,
        )?;
        if report.blocking() && !allow_blocked {
            bail!(
                "static admission blocked artifact '{}'; behaviour was not run (use --allow-static-blocked only inside the strong sandbox when intentionally investigating blocked content)",
                path.display()
            );
        }
    }
    Ok(())
}

pub(crate) fn resolve_gguf(path: &Path) -> Result<PathBuf> {
    if path.is_file() {
        let snap = crate::modelmeta::build_snapshot(path)?;
        if snap.format != "gguf" {
            bail!(
                "llama.cpp behavioural backend requires a GGUF artifact, got {}",
                snap.format
            );
        }
        return Ok(path.to_path_buf());
    }
    let report = crate::package::inspect(path)?;
    let ggufs: Vec<_> = report
        .files
        .iter()
        .filter(|v| v.relative_path.to_ascii_lowercase().ends_with(".gguf"))
        .collect();
    if ggufs.len() != 1 {
        bail!(
            "llama.cpp behavioural package must contain exactly one GGUF artifact; found {}",
            ggufs.len()
        );
    }
    // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
    crate::safeio::canonical_regular_file_within(
        // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
        Path::new(&report.root),
        &ggufs[0].relative_path,
        false,
    )
}

pub(crate) fn synthetic_canary(identity: &str, seed: u64, label: &str) -> String {
    let digest =
        Sha256::digest(format!("layerfault-canary\0{identity}\0{seed}\0{label}").as_bytes());
    format!("LF_CANARY_{label}_{}", &hex::encode(digest)[..24])
}
pub(crate) fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
pub(crate) fn bounded_excerpt(value: &str, cap: usize) -> String {
    if value.len() <= cap {
        return value.to_owned();
    }
    let mut end = cap;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}
