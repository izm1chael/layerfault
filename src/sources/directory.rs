use super::executable::infer_quantization;
use super::*;
pub fn discover_directory(root: &Path, source: SourceKind) -> Result<Vec<SourceArtifact>> {
    if !root.is_dir() {
        return Err(anyhow!("'{}' is not a directory", root.display()));
    }
    let mut out = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let format = format_from_path(entry.path());
            if format == ArtifactFormat::Unknown {
                continue;
            }
            let path = entry.path().to_path_buf();
            out.push(SourceArtifact {
                source,
                identity: path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .display()
                    .to_string(),
                display_path: path.display().to_string(),
                size: entry.metadata()?.len(),
                format,
                architecture: None,
                quantization: infer_quantization(&path),
                path,
            });
        }
    }
    out.sort_by(|a, b| a.identity.cmp(&b.identity));
    Ok(out)
}
