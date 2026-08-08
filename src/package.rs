use crate::formats::{artifact, ArtifactFormat};
use crate::safeio::{open_readonly_nofollow, read_all_from_file};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

const MAX_TEXT_SCAN_BYTES: u64 = 4 * 1024 * 1024;
const MAX_BINARY_PREFIX_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, serde::Serialize)]
pub struct PackageEntry {
    pub relative_path: String,
    pub kind: String,
    pub size: u64,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PackageReport {
    pub root: String,
    pub fingerprint: String,
    pub files: Vec<PackageEntry>,
    pub total_bytes: u64,
    pub findings: Vec<LayerScanResult>,
}

impl PackageReport {
    pub fn blocking(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.status == ScanStatus::Fail)
    }
}

pub fn inspect(root: &Path) -> Result<PackageReport> {
    let metadata = std::fs::symlink_metadata(root)
        .with_context(|| format!("Unable to inspect package root '{}'", root.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow!("Package root '{}' is a symlink; supply the real package directory so identity and scan boundaries are explicit", root.display()));
    }
    if !metadata.is_dir() {
        return Err(anyhow!("'{}' is not a directory", root.display()));
    }

    let root = root
        .canonicalize()
        .with_context(|| format!("Unable to canonicalize package root '{}'", root.display()))?;
    let mut paths = Vec::<PathBuf>::new();
    let mut findings = Vec::new();

    for entry in WalkDir::new(&root).follow_links(false) {
        let entry = entry?;
        if entry.depth() == 0 {
            continue;
        }
        let rel = safe_relative(&root, entry.path())?;
        if ignored_path(&rel) {
            continue;
        }
        if entry.file_type().is_symlink() {
            let target = std::fs::read_link(entry.path()).ok();
            findings.push(finding(
                &format!("package:{}", rel),
                CheckType::PackageSecurity,
                ScanStatus::Fail,
                FindingClass::Structural,
                Confidence::High,
                "LF-PACKAGE-SYMLINK",
                format!("Package contains symlink '{}' -> '{}'; model packages are fingerprinted and scanned without following links", rel, target.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "<unreadable>".to_owned())),
            ));
            continue;
        }
        if entry.file_type().is_file() {
            paths.push(entry.into_path());
        }
    }

    paths.sort_by_key(|path| safe_relative(&root, path).unwrap_or_default());
    let mut files = Vec::new();
    let mut total_bytes = 0_u64;

    for path in paths {
        let rel = safe_relative(&root, &path)?;
        let file = open_readonly_nofollow(&path)?;
        let size = file.metadata()?.len();
        total_bytes = total_bytes.saturating_add(size);
        let digest = hash_sha256(&file)?;
        let kind = classify(&path);
        files.push(PackageEntry {
            relative_path: rel.clone(),
            kind: kind.to_owned(),
            size,
            sha256: Some(digest.clone()),
        });
        findings.extend(scan_package_file(&path, &rel, &file, size, &digest)?);
        let after = hash_sha256(&file)?;
        if after != digest {
            findings.push(finding(
                &digest,
                CheckType::PackageSecurity,
                ScanStatus::Fail,
                FindingClass::Integrity,
                Confidence::High,
                "LF-PACKAGE-RACE",
                format!(
                    "Package file '{}' changed while it was being scanned: {} -> {}",
                    rel, digest, after
                ),
            ));
        }
    }

    correlate_custom_code(&root, &files, &mut findings)?;

    let fingerprint = package_fingerprint(&files);
    findings.sort_by(|a, b| {
        a.matches
            .cmp(&b.matches)
            .then_with(|| a.layer_digest.cmp(&b.layer_digest))
    });

    Ok(PackageReport {
        root: root.display().to_string(),
        fingerprint,
        files,
        total_bytes,
        findings,
    })
}

pub fn fingerprint(root: &Path) -> Result<String> {
    Ok(inspect(root)?.fingerprint)
}

pub fn inspect_member(display_path: &Path, content_path: &Path) -> Result<Vec<LayerScanResult>> {
    let file = open_readonly_nofollow(content_path)?;
    let size = file.metadata()?.len();
    let digest = hash_sha256(&file)?;
    let rel = display_path.display().to_string();
    let mut findings = scan_package_file(display_path, &rel, &file, size, &digest)?;
    let after = hash_sha256(&file)?;
    if after != digest {
        findings.push(finding(
            &digest,
            CheckType::PackageSecurity,
            ScanStatus::Fail,
            FindingClass::Integrity,
            Confidence::High,
            "LF-PACKAGE-RACE",
            format!(
                "Package member '{}' changed while it was being scanned: {} -> {}",
                rel, digest, after
            ),
        ));
    }
    Ok(findings)
}

fn package_fingerprint(files: &[PackageEntry]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault-package-identity\0");
    for entry in files {
        hasher.update(entry.relative_path.as_bytes());
        hasher.update([0]);
        hasher.update(entry.kind.as_bytes());
        hasher.update([0]);
        hasher.update(entry.size.to_string().as_bytes());
        hasher.update([0]);
        hasher.update(entry.sha256.as_deref().unwrap_or("missing").as_bytes());
        hasher.update([0xff]);
    }
    format!("lfpkg:sha256:{}", hex::encode(hasher.finalize()))
}

fn scan_package_file(
    path: &Path,
    rel: &str,
    file: &std::fs::File,
    size: u64,
    digest: &str,
) -> Result<Vec<LayerScanResult>> {
    let mut out = Vec::new();
    let format = ArtifactFormat::detect(path, &prefix(file, 8)?);
    if format != ArtifactFormat::Unknown {
        match artifact::inspect_opened_file(path, file, format, artifact::ArtifactScanMode::Full) {
            Ok(report) => out.extend(report.results),
            Err(error) => out.push(finding(
                digest,
                CheckType::PackageSecurity,
                ScanStatus::Fail,
                FindingClass::Structural,
                Confidence::High,
                "LF-PACKAGE-ARTIFACT",
                format!(
                    "Artifact '{}' failed package validation safely: {error}",
                    rel
                ),
            )),
        }
        return Ok(out);
    }

    let lower = rel.to_ascii_lowercase();
    let ext = path
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if is_unsafe_serialization(&lower, &ext, file)? {
        out.push(finding(
            digest,
            CheckType::PackageSecurity,
            ScanStatus::Fail,
            FindingClass::ContentIndicator,
            Confidence::High,
            "LF-SERIALIZATION-UNSAFE",
            format!("Package file '{}' uses or strongly resembles an unsafe code-capable serialization format; Layerfault never deserializes it", rel),
        ));
    } else if ext == "bin" {
        out.push(finding(
            digest,
            CheckType::PackageSecurity,
            ScanStatus::Warn,
            FindingClass::Compatibility,
            Confidence::Medium,
            "LF-SERIALIZATION-BIN",
            format!("Legacy .bin artifact '{}' is opaque to Layerfault; verify the producer and loading path before use", rel),
        ));
    }

    if is_native_or_script(&ext, &lower) {
        out.push(finding(
            digest,
            CheckType::PackageSecurity,
            ScanStatus::Warn,
            FindingClass::ContentIndicator,
            Confidence::High,
            "LF-PACKAGE-CODE",
            format!("Package contains executable/custom-code artifact '{}'; weight-only packages normally do not require executable content", rel),
        ));
    }

    if is_text_candidate(&ext, &lower) {
        if size > MAX_TEXT_SCAN_BYTES {
            out.push(finding(
                digest,
                CheckType::PackageSecurity,
                ScanStatus::Warn,
                FindingClass::Compatibility,
                Confidence::High,
                "LF-PACKAGE-TEXT-LIMIT",
                format!("Text/config file '{}' is {} bytes and exceeds Layerfault's {}-byte bounded content scan; the complete file is still hashed", rel, size, MAX_TEXT_SCAN_BYTES),
            ));
        } else {
            let bytes = read_all_from_file(file, MAX_TEXT_SCAN_BYTES)?;
            if let Ok(text) = std::str::from_utf8(&bytes) {
                scan_text(rel, digest, text, &mut out);
                if ext == "json" {
                    scan_json(rel, digest, text, &mut out);
                }
            }
        }
    }

    if out.is_empty() {
        out.push(finding(
            digest,
            CheckType::PackageSecurity,
            ScanStatus::Pass,
            FindingClass::Informational,
            Confidence::High,
            "LF-PACKAGE-FILE",
            format!(
                "Package file '{}' hashed; no high-confidence package-security indicator matched",
                rel
            ),
        ));
    }
    Ok(out)
}

fn scan_json(rel: &str, digest: &str, text: &str, out: &mut Vec<LayerScanResult>) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    let mut keys = BTreeSet::new();
    collect_json_keys(&value, &mut keys);
    if keys.contains("auto_map") {
        out.push(finding(digest, CheckType::PackageSecurity, ScanStatus::Warn, FindingClass::ContentIndicator, Confidence::High, "LF-CODE-AUTO-MAP", format!("'{}' contains Hugging Face auto_map metadata that can route loading through custom model code", rel)));
    }
    if keys.contains("trust_remote_code") && json_contains_true_for_key(&value, "trust_remote_code")
    {
        out.push(finding(digest, CheckType::PackageSecurity, ScanStatus::Warn, FindingClass::ContentIndicator, Confidence::High, "LF-CODE-REMOTE-TRUST", format!("'{}' explicitly enables trust_remote_code; custom code should be reviewed before loading", rel)));
    }
}

fn scan_text(rel: &str, digest: &str, text: &str, out: &mut Vec<LayerScanResult>) {
    let lower = text.to_ascii_lowercase();
    let documentation = is_documentation_path(rel);
    let dangerous = [
        ("os.system(", "LF-CODE-OS-SYSTEM"),
        ("subprocess.popen", "LF-CODE-SUBPROCESS"),
        ("subprocess.run", "LF-CODE-SUBPROCESS"),
        ("eval(", "LF-CODE-EVAL"),
        ("exec(", "LF-CODE-EXEC"),
        ("ctypes.cdll", "LF-CODE-CTYPES"),
        ("socket.socket", "LF-CODE-NETWORK"),
        ("requests.get(", "LF-CODE-NETWORK"),
        ("requests.post(", "LF-CODE-NETWORK"),
        ("urllib.request", "LF-CODE-NETWORK"),
    ];
    for (needle, rule) in dangerous {
        if !documentation && lower.contains(needle) {
            out.push(finding(digest, CheckType::PackageSecurity, ScanStatus::Warn, FindingClass::ContentIndicator, Confidence::High, rule, format!("Custom code/config '{}' contains security-relevant primitive '{}'; review is required before enabling custom code", rel, needle)));
        }
    }
    let jinja = [
        "__class__",
        "__mro__",
        "__subclasses__",
        "__globals__",
        "cycler.__init__",
        "namespace.__init__",
    ];
    if jinja.iter().any(|needle| lower.contains(needle))
        && (rel.to_ascii_lowercase().contains("template") || lower.contains("{{"))
    {
        out.push(finding(digest, CheckType::PackageSecurity, ScanStatus::Warn, FindingClass::ContentIndicator, Confidence::High, "LF-TEMPLATE-INTROSPECTION", format!("Template/config '{}' contains Python/Jinja introspection primitives; review template execution context before use", rel)));
    }
}

fn is_documentation_path(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    lower.split('/').any(|part| part == "docs")
        || lower.ends_with(".md")
        || lower.ends_with(".rst")
        || lower
            .rsplit('/')
            .next()
            .is_some_and(|name| name.starts_with("readme"))
}

fn correlate_custom_code(
    root: &Path,
    files: &[PackageEntry],
    findings: &mut Vec<LayerScanResult>,
) -> Result<()> {
    let mut auto_map = false;
    let mut remote_trust = false;
    let mut modules = BTreeSet::new();
    for entry in files {
        if !entry.relative_path.to_ascii_lowercase().ends_with(".json") {
            continue;
        }
        let path = root.join(&entry.relative_path);
        let bytes = read_all_from_file(&open_readonly_nofollow(&path)?, MAX_TEXT_SCAN_BYTES)?;
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        collect_custom_loader_metadata(&value, &mut auto_map, &mut remote_trust, &mut modules);
    }
    if !auto_map || !remote_trust {
        return Ok(());
    }

    for module in modules {
        let module_path = format!("{}.py", module.replace('.', "/"));
        let Some(entry) = files
            .iter()
            .find(|entry| entry.relative_path.eq_ignore_ascii_case(&module_path))
        else {
            continue;
        };
        let path = root.join(&entry.relative_path);
        let file = open_readonly_nofollow(&path)?;
        let bytes = read_all_from_file(&file, MAX_TEXT_SCAN_BYTES)?;
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        let Some(operation) = module_scope_operation(text) else {
            continue;
        };
        findings.push(finding(
            entry.sha256.as_deref().unwrap_or("module"),
            CheckType::PackageSecurity,
            ScanStatus::Fail,
            FindingClass::ContentIndicator,
            Confidence::High,
            "LF-CODE-IMPORT-SIDE-EFFECT",
            format!(
                "Hugging Face auto_map/trust_remote_code routes loading through '{}', which performs '{}' at module scope",
                entry.relative_path, operation
            ),
        ));
    }
    Ok(())
}

fn collect_custom_loader_metadata(
    value: &serde_json::Value,
    auto_map: &mut bool,
    remote_trust: &mut bool,
    modules: &mut BTreeSet<String>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if key.eq_ignore_ascii_case("auto_map") {
                    *auto_map = true;
                    collect_module_strings(value, modules);
                }
                if key.eq_ignore_ascii_case("trust_remote_code")
                    && value == &serde_json::Value::Bool(true)
                {
                    *remote_trust = true;
                }
                collect_custom_loader_metadata(value, auto_map, remote_trust, modules);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_custom_loader_metadata(value, auto_map, remote_trust, modules);
            }
        }
        _ => {}
    }
}

fn collect_module_strings(value: &serde_json::Value, modules: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::String(value) => {
            if let Some((module, _)) = value.rsplit_once('.') {
                if module.len() <= 4096
                    && module.split('.').all(|part| {
                        !part.is_empty()
                            && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    })
                {
                    modules.insert(module.to_owned());
                }
            }
        }
        serde_json::Value::Object(map) => {
            for value in map.values() {
                collect_module_strings(value, modules);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_module_strings(value, modules);
            }
        }
        _ => {}
    }
}

fn module_scope_operation(text: &str) -> Option<&'static str> {
    for line in text.lines().take(100_000) {
        let trimmed = line.trim_start();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || line.starts_with(' ')
            || line.starts_with('\t')
        {
            continue;
        }
        if trimmed.starts_with("def ") || trimmed.starts_with("class ") || trimmed.starts_with('@')
        {
            continue;
        }
        for (needle, operation) in [
            ("os.system(", "os.system"),
            ("subprocess.run(", "subprocess.run"),
            ("subprocess.popen(", "subprocess.Popen"),
            ("exec(", "exec"),
            ("eval(", "eval"),
            ("socket.socket(", "socket.socket"),
            ("requests.", "requests network access"),
            ("urllib.request", "urllib network access"),
            ("ctypes.", "ctypes native loading"),
            (".write_text(", "Path.write_text"),
            (".write_bytes(", "Path.write_bytes"),
            (".unlink(", "Path.unlink"),
            (".remove(", "remove"),
            (".rename(", "rename"),
        ] {
            if trimmed.contains(needle) {
                return Some(operation);
            }
        }
    }
    None
}

fn collect_json_keys(value: &serde_json::Value, keys: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                keys.insert(key.to_ascii_lowercase());
                collect_json_keys(value, keys);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_json_keys(value, keys);
            }
        }
        _ => {}
    }
}

fn json_contains_true_for_key(value: &serde_json::Value, key: &str) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(candidate, value)| {
            (candidate.eq_ignore_ascii_case(key) && value == &serde_json::Value::Bool(true))
                || json_contains_true_for_key(value, key)
        }),
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| json_contains_true_for_key(value, key)),
        _ => false,
    }
}

fn is_unsafe_serialization(lower: &str, ext: &str, file: &std::fs::File) -> Result<bool> {
    if unsafe_serialization_name(lower) {
        return Ok(true);
    }
    if lower.ends_with("pytorch_model.bin") || ext == "bin" {
        let bytes = prefix(file, MAX_BINARY_PREFIX_BYTES as usize)?;
        if bytes.first().is_some_and(|b| *b == 0x80)
            || find_bytes(&bytes, b"data.pkl")
            || find_bytes(&bytes, b"pickle")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn unsafe_serialization_name(lower: &str) -> bool {
    let filename = lower.rsplit('/').next().unwrap_or(lower);
    let mut candidate = filename;
    for _ in 0..8 {
        if matches!(
            Path::new(candidate)
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or(""),
            "pkl" | "pickle" | "joblib" | "pt" | "pth" | "ckpt"
        ) {
            return true;
        }
        let Some(stripped) = strip_compression_suffix(candidate) else {
            break;
        };
        candidate = stripped;
    }
    false
}

fn strip_compression_suffix(value: &str) -> Option<&str> {
    for suffix in [
        ".gz", ".bz2", ".xz", ".lzma", ".z", ".zlib", ".deflate", ".zst",
    ] {
        if let Some(stripped) = value.strip_suffix(suffix) {
            return Some(stripped);
        }
    }
    None
}

fn is_native_or_script(ext: &str, lower: &str) -> bool {
    matches!(
        ext,
        "py" | "sh" | "ps1" | "bat" | "cmd" | "exe" | "dll" | "so" | "dylib" | "node" | "jar"
    ) || lower.ends_with("setup.py")
}

fn is_text_candidate(ext: &str, lower: &str) -> bool {
    matches!(
        ext,
        "json"
            | "txt"
            | "md"
            | "py"
            | "sh"
            | "ps1"
            | "toml"
            | "yaml"
            | "yml"
            | "jinja"
            | "jinja2"
            | "tmpl"
    ) || lower.ends_with("requirements.txt")
        || lower.ends_with("modelfile")
}

fn classify(path: &Path) -> &'static str {
    let lower = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let ext = path
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ArtifactFormat::detect(path, &[]) != ArtifactFormat::Unknown {
        "model-artifact"
    } else if matches!(ext.as_str(), "py" | "sh" | "ps1" | "bat" | "cmd") {
        "code"
    } else if matches!(ext.as_str(), "so" | "dll" | "dylib" | "exe") {
        "native"
    } else if unsafe_serialization_name(&lower) || lower.ends_with("pytorch_model.bin") {
        "serialization"
    } else if matches!(ext.as_str(), "json" | "toml" | "yaml" | "yml") {
        "config"
    } else {
        "other"
    }
}

fn ignored_path(rel: &str) -> bool {
    rel.split('/').any(|part| {
        matches!(
            part,
            ".git" | "target" | "__pycache__" | ".cache" | ".venv" | "venv"
        )
    })
}

fn safe_relative(root: &Path, path: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(root)
        .with_context(|| format!("'{}' escaped package root", path.display()))?;
    let mut out = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(value) => {
                let value = value.to_str().ok_or_else(|| anyhow!("Package-relative path contains non-UTF-8 component; canonical package identities require portable UTF-8 member names"))?;
                out.push(value.to_owned());
            }
            _ => return Err(anyhow!("Unsafe package-relative path '{}'", rel.display())),
        }
    }
    Ok(out.join("/"))
}

fn prefix(file: &std::fs::File, limit: usize) -> Result<Vec<u8>> {
    let mut cloned = file.try_clone()?;
    cloned.seek(SeekFrom::Start(0))?;
    let mut bytes = vec![0_u8; limit];
    let n = cloned.read(&mut bytes)?;
    bytes.truncate(n);
    Ok(bytes)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn hash_sha256(file: &std::fs::File) -> Result<String> {
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn finding(
    digest: &str,
    check_type: CheckType,
    status: ScanStatus,
    class: FindingClass,
    confidence: Confidence,
    rule: &str,
    detail: String,
) -> LayerScanResult {
    LayerScanResult {
        layer_digest: digest.to_owned(),
        media_type: "application/vnd.layerfault.package".to_owned(),
        check_type,
        status,
        finding_class: class,
        confidence,
        detail: Some(detail),
        matches: vec![format!("[{rule}] package finding")],
        duration_ms: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn package_fingerprint_is_path_stable() -> Result<()> {
        let a = std::env::temp_dir().join(format!("layerfault-package-a-{}", std::process::id()));
        let b = std::env::temp_dir().join(format!("layerfault-package-b-{}", std::process::id()));
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
        fs::create_dir_all(&a)?;
        fs::create_dir_all(&b)?;
        fs::write(a.join("config.json"), b"{\"architectures\":[\"Test\"]}")?;
        fs::write(b.join("config.json"), b"{\"architectures\":[\"Test\"]}")?;
        assert_eq!(fingerprint(&a)?, fingerprint(&b)?);
        fs::write(b.join("config.json"), b"{\"architectures\":[\"Changed\"]}")?;
        assert_ne!(fingerprint(&a)?, fingerprint(&b)?);
        let _ = fs::remove_dir_all(a);
        let _ = fs::remove_dir_all(b);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_member_name_is_rejected() -> Result<()> {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let root =
            std::env::temp_dir().join(format!("layerfault-package-nonutf8-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let name = OsString::from_vec(vec![b'm', b'o', b'd', b'e', b'l', 0xff]);
        fs::write(root.join(name), b"fixture")?;
        assert!(inspect(&root).is_err());
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn unsafe_serialization_blocks() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("layerfault-package-pickle-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(root.join("model.pkl"), [0x80_u8, 4, 1, 2, 3])?;
        let report = inspect(&root)?;
        assert!(report.findings.iter().any(|f| f
            .matches
            .iter()
            .any(|m| m.contains("LF-SERIALIZATION-UNSAFE"))
            && f.status == ScanStatus::Fail));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn nested_compressed_joblib_is_blocked_without_deserialization() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-double-compressed-joblib-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("exploit_double_compression.joblib.gz.bz2"),
            b"BZh91AY&SYbounded-fixture",
        )?;
        let report = inspect(&root)?;
        assert!(report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Fail
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-SERIALIZATION-UNSAFE"))
        }));
        assert!(report
            .files
            .iter()
            .any(|entry| entry.kind == "serialization"));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn compression_suffix_without_serialization_inner_name_does_not_block() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-compressed-data-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("weights.dat.gz.bz2"),
            b"BZh91AY&SYbounded-fixture",
        )?;
        let report = inspect(&root)?;
        assert!(!report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Fail
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-SERIALIZATION-UNSAFE"))
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn documentation_examples_do_not_emit_code_primitive_findings() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("layerfault-package-docs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("README.md"),
            b"The example calls os.system(...) and exec(...).",
        )?;
        let report = inspect(&root)?;
        assert!(!report.findings.iter().any(|finding| {
            finding
                .matches
                .iter()
                .any(|value| value.contains("LF-CODE-OS-SYSTEM") || value.contains("LF-CODE-EXEC"))
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn custom_loader_module_scope_side_effect_blocks() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-custom-code-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("config.json"),
            br#"{"auto_map":{"AutoModel":"modeling_example.Example"},"trust_remote_code":true}"#,
        )?;
        fs::write(
            root.join("modeling_example.py"),
            b"os.system('echo imported')\n",
        )?;
        let report = inspect(&root)?;
        assert!(report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Fail
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-CODE-IMPORT-SIDE-EFFECT"))
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn custom_loader_function_side_effect_remains_warning() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-custom-function-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("config.json"),
            br#"{"auto_map":{"AutoModel":"modeling_example.Example"},"trust_remote_code":true}"#,
        )?;
        fs::write(
            root.join("modeling_example.py"),
            b"def load():\n    os.system('echo called')\n",
        )?;
        let report = inspect(&root)?;
        assert!(!report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Fail
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-CODE-IMPORT-SIDE-EFFECT"))
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Warn
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-CODE-OS-SYSTEM"))
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }
}
