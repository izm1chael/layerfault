use crate::audit;
use crate::manifest;
use crate::paths;
use anyhow::{anyhow, Context, Result};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct QuarantineEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanner_exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_action: Option<String>,
    #[serde(default)]
    pub finding_ids: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuarantineRecord {
    pub version: u32,
    pub id: String,
    pub model: String,
    pub manifest_digest: String,
    pub created_unix: u64,
    pub original_manifest_relative: String,
    pub moved_blob_digests: Vec<String>,
    pub shared_blob_digests: Vec<String>,
    pub moved_aux_files: Vec<String>,
    #[serde(default)]
    pub evidence: QuarantineEvidence,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct QuarantineExport {
    pub quarantine_id: String,
    pub output: String,
    pub files: usize,
    pub bytes: u64,
    pub included_blobs: bool,
    pub signed: bool,
}

pub fn root(base_dir: &Path) -> PathBuf {
    base_dir.join(".layerfault-quarantine")
}

pub fn quarantine_model(base_dir: &Path, selector: &str) -> Result<QuarantineRecord> {
    quarantine_model_with_evidence(base_dir, selector, QuarantineEvidence::default())
}

pub fn quarantine_model_with_evidence(
    base_dir: &Path,
    selector: &str,
    evidence: QuarantineEvidence,
) -> Result<QuarantineRecord> {
    let model_ref = manifest::find_model(base_dir, selector)?;
    let model = manifest::load_model(&model_ref)?;
    let references = audit::reference_map(base_dir)?;
    let relative_manifest = model_ref
        .manifest_path
        .strip_prefix(base_dir)
        .with_context(|| "Manifest path is outside the Ollama model store")?
        .to_path_buf();
    let id = format!(
        "{}-{}",
        model
            .digest
            .split_once(':')
            .map(|(_, digest)| digest.chars().take(16).collect::<String>())
            .unwrap_or_else(|| "manifest".to_owned()),
        paths::now_unix()
    );
    validate_id(&id)?;
    let qdir = root(base_dir).join(&id);
    if qdir.exists() {
        return Err(anyhow!("Quarantine id collision at '{}'", qdir.display()));
    }
    paths::ensure_private_dir(&qdir)?;
    paths::ensure_private_dir(&qdir.join("blobs"))?;

    let mut moved_blob_digests = Vec::new();
    let mut shared_blob_digests = Vec::new();
    for layer in model.descriptors() {
        let refs = references.by_digest.get(&layer.digest);
        if refs.is_some_and(|models| models.len() > 1) {
            shared_blob_digests.push(layer.digest.clone());
        } else {
            moved_blob_digests.push(layer.digest.clone());
        }
    }
    moved_blob_digests.sort();
    moved_blob_digests.dedup();
    shared_blob_digests.sort();
    shared_blob_digests.dedup();

    let mut operations = Vec::<(PathBuf, PathBuf)>::new();
    for digest in &moved_blob_digests {
        let src = manifest::resolve_blob_path(base_dir, digest)?;
        if src.exists() {
            let dst = qdir.join("blobs").join(
                src.file_name()
                    .ok_or_else(|| anyhow!("Blob path has no filename"))?,
            );
            operations.push((src, dst));
        }
    }

    let moved_aux_files = discover_aux_files(base_dir, &model.digest)?;
    for name in &moved_aux_files {
        operations.push((
            base_dir.join("blobs").join(name),
            qdir.join("blobs").join(name),
        ));
    }

    let record = QuarantineRecord {
        version: 1,
        id: id.clone(),
        model: model.name,
        manifest_digest: model.digest,
        created_unix: paths::now_unix(),
        original_manifest_relative: relative_manifest.to_string_lossy().into_owned(),
        moved_blob_digests,
        shared_blob_digests,
        moved_aux_files,
        evidence,
    };
    let record_path = qdir.join("record.json");
    paths::write_private(&record_path, &serde_json::to_vec_pretty(&record)?)?;

    // Move the manifest last so a failed preparation does not leave a visible
    // manifest pointing at blobs that have not yet been moved.
    operations.push((model_ref.manifest_path.clone(), qdir.join("manifest")));

    if let Err(error) = apply_moves(&operations) {
        let _ = fs::remove_dir_all(&qdir);
        return Err(error);
    }
    Ok(record)
}

fn discover_aux_files(base_dir: &Path, digest: &str) -> Result<Vec<String>> {
    let blobs = base_dir.join("blobs");
    if !blobs.is_dir() {
        return Ok(Vec::new());
    }
    let stem = digest.replace(':', "-");
    let mut out = Vec::new();
    let entries = fs::read_dir(blobs)?; // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let attestation = name == format!("{stem}.attestation.json")
            || (name.starts_with(&format!("{stem}.attestation.")) && name.ends_with(".json"));
        if attestation || name == format!("{stem}.sig") {
            out.push(name);
        }
    }
    out.sort();
    Ok(out)
}

pub fn load_record(base_dir: &Path, id: &str) -> Result<QuarantineRecord> {
    validate_id(id)?;
    let path = root(base_dir).join(id).join("record.json");
    let file = crate::safeio::open_readonly_nofollow(&path)?;
    let bytes = crate::safeio::read_all_from_file(&file, MAX_RECORD_BYTES)?;
    let record: QuarantineRecord = serde_json::from_slice(&bytes)
        .with_context(|| format!("Invalid quarantine record '{}'", path.display()))?;
    validate_record(&record)?;
    if record.id != id {
        return Err(anyhow!("Quarantine record identity mismatch"));
    }
    Ok(record)
}

pub fn list(base_dir: &Path) -> Result<Vec<QuarantineRecord>> {
    let qroot = root(base_dir);
    if !qroot.is_dir() {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    let entries = fs::read_dir(qroot)?; // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().into_owned();
        if let Ok(record) = load_record(base_dir, &id) {
            records.push(record);
        }
    }
    records.sort_by(|left, right| right.created_unix.cmp(&left.created_unix));
    Ok(records)
}

pub fn restore(base_dir: &Path, id: &str, force: bool) -> Result<QuarantineRecord> {
    let record = load_record(base_dir, id)?;
    let qdir = root(base_dir).join(id);
    let manifest_dst = base_dir.join(&record.original_manifest_relative);
    if manifest_dst.exists() && !force {
        return Err(anyhow!(
            "Manifest '{}' already exists; use --force only after confirming it is safe to replace",
            manifest_dst.display()
        ));
    }
    if let Some(parent) = manifest_dst.parent() {
        fs::create_dir_all(parent)?;
    }

    let replacement_root = qdir.join("replaced");
    let mut operations = Vec::<(PathBuf, PathBuf)>::new();
    for digest in &record.moved_blob_digests {
        let dst = manifest::resolve_blob_path(base_dir, digest)?;
        let filename = dst
            .file_name()
            .ok_or_else(|| anyhow!("Blob destination has no filename"))?;
        let src = qdir.join("blobs").join(filename);
        if src.exists() {
            if dst.exists() {
                if !force {
                    return Err(anyhow!(
                        "Blob '{}' already exists; refusing restore without --force",
                        dst.display()
                    ));
                }
                operations.push((dst.clone(), replacement_root.join("blobs").join(filename)));
            }
            operations.push((src, dst));
        }
    }
    for name in &record.moved_aux_files {
        let src = qdir.join("blobs").join(name);
        let dst = base_dir.join("blobs").join(name);
        if src.exists() {
            if dst.exists() {
                if !force {
                    return Err(anyhow!(
                        "Auxiliary file '{}' already exists; refusing restore without --force",
                        dst.display()
                    ));
                }
                operations.push((dst.clone(), replacement_root.join("blobs").join(name)));
            }
            operations.push((src, dst));
        }
    }

    if manifest_dst.exists() {
        operations.push((manifest_dst.clone(), replacement_root.join("manifest")));
    }
    operations.push((qdir.join("manifest"), manifest_dst));
    apply_moves(&operations)?;
    fs::remove_dir_all(&qdir)?;
    Ok(record)
}

pub fn export_evidence(
    base_dir: &Path,
    id: &str,
    output: &Path,
    include_blobs: bool,
    private_key: Option<&Path>,
) -> Result<QuarantineExport> {
    let record = load_record(base_dir, id)?;
    if output.exists() {
        return Err(anyhow!(
            "Evidence output '{}' already exists",
            output.display()
        ));
    }
    paths::ensure_private_dir(output)?;
    let qdir = root(base_dir).join(id);
    let mut exported = Vec::<PathBuf>::new();
    copy_regular(&qdir.join("record.json"), &output.join("record.json"))?;
    exported.push(output.join("record.json"));
    copy_regular(&qdir.join("manifest"), &output.join("manifest"))?;
    exported.push(output.join("manifest"));

    let aux_out = output.join("aux");
    if !record.moved_aux_files.is_empty() {
        paths::ensure_private_dir(&aux_out)?;
    }
    for name in &record.moved_aux_files {
        let dst = aux_out.join(name);
        copy_regular(&qdir.join("blobs").join(name), &dst)?;
        exported.push(dst);
    }

    if include_blobs {
        let blob_out = output.join("blobs");
        paths::ensure_private_dir(&blob_out)?;
        for digest in &record.moved_blob_digests {
            let filename = digest.replace(':', "-");
            let dst = blob_out.join(&filename);
            copy_regular(&qdir.join("blobs").join(&filename), &dst)?;
            exported.push(dst);
        }
    }

    exported.sort();
    let mut sum_lines = Vec::new();
    let mut total_bytes = 0_u64;
    for path in &exported {
        let (digest, bytes) = hash_file(path)?;
        total_bytes = total_bytes.saturating_add(bytes);
        let relative = path.strip_prefix(output).unwrap_or(path);
        sum_lines.push(format!("{}  {}", digest, relative.display()));
    }
    let sums = sum_lines.join("\n") + "\n";
    paths::write_private(&output.join("SHA256SUMS"), sums.as_bytes())?;
    total_bytes = total_bytes.saturating_add(sums.len() as u64);

    let mut signed = false;
    if let Some(key_path) = private_key {
        let key_file = crate::safeio::open_readonly_nofollow(key_path)?;
        let key_bytes = crate::safeio::read_all_from_file(&key_file, 128 * 1024)?;
        let pem = std::str::from_utf8(&key_bytes)
            .map_err(|_| anyhow!("Private key PEM must be valid UTF-8"))?;
        let signing = SigningKey::from_pkcs8_pem(pem)
            .context("Unable to parse Ed25519 PKCS#8 private key")?;
        let signature = signing.sign(sums.as_bytes());
        let envelope = serde_json::json!({
            "version": 1,
            "algorithm": "ed25519",
            "key_fingerprint": crate::trust::fingerprint(&signing.verifying_key()),
            "sha256sums_sha256": format!("sha256:{}", hex::encode(Sha256::digest(sums.as_bytes()))),
            "signature_hex": hex::encode(signature.to_bytes()),
            "created_unix": paths::now_unix()
        });
        let bytes = serde_json::to_vec_pretty(&envelope)?;
        paths::write_private(&output.join("evidence-signature.json"), &bytes)?;
        total_bytes = total_bytes.saturating_add(bytes.len() as u64);
        signed = true;
    }

    Ok(QuarantineExport {
        quarantine_id: id.to_owned(),
        output: output.display().to_string(),
        files: exported.len() + 1 + if signed { 1 } else { 0 },
        bytes: total_bytes,
        included_blobs: include_blobs,
        signed,
    })
}

pub fn purge(base_dir: &Path, id: &str) -> Result<QuarantineRecord> {
    let record = load_record(base_dir, id)?;
    let qdir = root(base_dir).join(id);
    fs::remove_dir_all(&qdir)
        .with_context(|| format!("Unable to purge quarantine '{}'", qdir.display()))?;
    Ok(record)
}

fn copy_regular(src: &Path, dst: &Path) -> Result<()> {
    let file = crate::safeio::open_readonly_nofollow(src)
        .with_context(|| format!("Unable to open evidence source '{}'", src.display()))?;
    if let Some(parent) = dst.parent() {
        paths::ensure_private_dir(parent)?;
    }
    let mut reader = file;
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut out = options
        .open(dst)
        .with_context(|| format!("Unable to create evidence file '{}'", dst.display()))?;
    let mut buf = vec![0_u8; 1024 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])?;
    }
    out.sync_all()?;
    Ok(())
}

fn hash_file(path: &Path) -> Result<(String, u64)> {
    let mut file = crate::safeio::open_readonly_nofollow(path)?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buf = vec![0_u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total = total.saturating_add(n as u64);
    }
    Ok((hex::encode(hasher.finalize()), total))
}

fn apply_moves(operations: &[(PathBuf, PathBuf)]) -> Result<()> {
    let mut completed = Vec::<(PathBuf, PathBuf)>::new();
    for (src, dst) in operations {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Err(error) = fs::rename(src, dst) {
            for (done_src, done_dst) in completed.iter().rev() {
                let _ = fs::rename(done_dst, done_src);
            }
            return Err(anyhow!(
                "Unable to move '{}' to '{}': {error}",
                src.display(),
                dst.display()
            ));
        }
        completed.push((src.clone(), dst.clone()));
    }
    Ok(())
}

fn validate_record(record: &QuarantineRecord) -> Result<()> {
    if record.version != 1 {
        return Err(anyhow!(
            "Unsupported quarantine record version {}",
            record.version
        ));
    }
    validate_id(&record.id)?;
    manifest::validate_digest(&record.manifest_digest)?;
    let relative = Path::new(&record.original_manifest_relative); // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path -- validated below to Normal relative components only
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(anyhow!(
            "Quarantine record contains an unsafe manifest path"
        ));
    }
    for digest in record
        .moved_blob_digests
        .iter()
        .chain(record.shared_blob_digests.iter())
    {
        manifest::validate_digest(digest)?;
    }
    for name in &record.moved_aux_files {
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains('/')
            || name.contains('\\')
        {
            return Err(anyhow!(
                "Quarantine record contains unsafe auxiliary filename '{name}'"
            ));
        }
    }
    Ok(())
}

fn validate_id(id: &str) -> Result<()> {
    if id.is_empty()
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(anyhow!("Unsafe quarantine id '{id}'"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantine_ids_are_path_safe() {
        assert!(validate_id("abcdef-123").is_ok());
        assert!(validate_id("../../escape").is_err());
    }

    #[test]
    fn evidence_is_backward_compatible() {
        let record: QuarantineRecord = serde_json::from_value(serde_json::json!({
            "version":1,"id":"abc-1","model":"m:latest","manifest_digest":format!("sha256:{}", "0".repeat(64)),
            "created_unix":1,"original_manifest_relative":"manifests/a/b/c/d","moved_blob_digests":[],"shared_blob_digests":[],"moved_aux_files":[]
        })).unwrap();
        assert!(record.evidence.reason.is_none());
    }
}
