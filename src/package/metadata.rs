use super::*;

const MAX_AUTO_MAP_ENTRIES: usize = 32;
/// Maximum characters retained for a captured JSON key path or value.
const MAX_JSON_EVIDENCE_CHARS: usize = 512;

#[derive(Default, Debug, Clone)]
pub(super) struct PackageMemberEvidence {
    pub(super) relative_path: String,
    pub(super) auto_map: bool,
    pub(super) remote_trust: bool,
    pub(super) modules: BTreeSet<String>,
    pub(super) module_scope_operation: Option<&'static str>,
    pub(super) json_parse_error: Option<String>,
    /// Exact `auto_map` key paths and the symbols they reference, so a finding
    /// can show `auto_map.AutoModel = "modeling_custom.CustomModel"` rather
    /// than merely asserting that custom code mapping exists.
    pub(super) auto_map_entries: std::collections::BTreeMap<String, String>,
    /// The exact key that enabled remote code.
    pub(super) remote_trust_key: Option<String>,
}
pub(super) fn capture_custom_code_evidence(
    rel: &str,
    file: &std::fs::File,
) -> Result<PackageMemberEvidence> {
    let mut evidence = PackageMemberEvidence {
        relative_path: rel.to_owned(),
        ..PackageMemberEvidence::default()
    };
    let lower = rel.to_ascii_lowercase();
    if lower.ends_with(".json") {
        if let Err(error) = stream_custom_loader_metadata(file, &mut evidence) {
            evidence.json_parse_error = Some(error.to_string());
        }
    } else if lower.ends_with(".py") {
        evidence.module_scope_operation = module_scope_operation_file(file)?;
    }
    Ok(evidence)
}

#[derive(Clone, Copy)]
pub(super) enum JsonMetadataContext {
    Normal,
    AutoMap,
    RemoteTrust,
}

pub(super) struct JsonMetadataSeed<'a> {
    evidence: &'a mut PackageMemberEvidence,
    context: JsonMetadataContext,
    /// Dotted JSON key path to the value currently being visited, so evidence
    /// can name the exact location (`auto_map.AutoModel`) rather than the file.
    key_path: String,
}

impl<'de> DeserializeSeed<'de> for JsonMetadataSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonMetadataVisitor {
            evidence: self.evidence,
            context: self.context,
            key_path: self.key_path,
        })
    }
}

pub(super) struct JsonMetadataVisitor<'a> {
    evidence: &'a mut PackageMemberEvidence,
    context: JsonMetadataContext,
    key_path: String,
}

impl<'de> Visitor<'de> for JsonMetadataVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("arbitrary JSON metadata")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        if matches!(self.context, JsonMetadataContext::RemoteTrust) && value {
            self.evidence.remote_trust = true;
            if self.evidence.remote_trust_key.is_none() {
                self.evidence.remote_trust_key = Some(bounded_json_text(&self.key_path));
            }
        }
        Ok(())
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        if matches!(self.context, JsonMetadataContext::AutoMap) {
            collect_module_reference(value, &mut self.evidence.modules);
            if self.evidence.auto_map_entries.len() < MAX_AUTO_MAP_ENTRIES {
                self.evidence
                    .auto_map_entries
                    .insert(bounded_json_text(&self.key_path), bounded_json_text(value));
            }
        }
        Ok(())
    }

    fn visit_string<E: serde::de::Error>(
        self,
        value: String,
    ) -> std::result::Result<Self::Value, E> {
        self.visit_str(&value)
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut index = 0_usize;
        while seq
            .next_element_seed(JsonMetadataSeed {
                evidence: &mut *self.evidence,
                context: self.context,
                key_path: format!("{}[{index}]", self.key_path),
            })?
            .is_some()
        {
            index = index.saturating_add(1);
        }
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            let context = if key.eq_ignore_ascii_case("auto_map") {
                self.evidence.auto_map = true;
                JsonMetadataContext::AutoMap
            } else if key.eq_ignore_ascii_case("trust_remote_code") {
                JsonMetadataContext::RemoteTrust
            } else {
                self.context
            };
            let key_path = if self.key_path.is_empty() {
                key.clone()
            } else {
                format!("{}.{key}", self.key_path)
            };
            map.next_value_seed(JsonMetadataSeed {
                evidence: &mut *self.evidence,
                context,
                key_path,
            })?;
        }
        Ok(())
    }
}

pub(super) fn stream_custom_loader_metadata(
    file: &std::fs::File,
    evidence: &mut PackageMemberEvidence,
) -> Result<()> {
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut de = serde_json::Deserializer::from_reader(BufReader::new(reader));
    JsonMetadataSeed {
        evidence,
        context: JsonMetadataContext::Normal,
        key_path: String::new(),
    }
    .deserialize(&mut de)
    .map_err(|error| anyhow!(error))?;
    de.end().map_err(|error| anyhow!(error))?;
    Ok(())
}

/// Bound a captured JSON key or value before it becomes evidence.
pub(super) fn bounded_json_text(value: &str) -> String {
    if value.chars().count() <= MAX_JSON_EVIDENCE_CHARS {
        return value.to_owned();
    }
    value.chars().take(MAX_JSON_EVIDENCE_CHARS).collect()
}

pub(super) fn collect_module_reference(value: &str, modules: &mut BTreeSet<String>) {
    if let Some((module, _)) = value.rsplit_once('.') {
        if module.len() <= 4096
            && module.split('.').all(|part| {
                !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            })
        {
            modules.insert(module.to_owned());
        }
    }
}

pub(super) fn module_scope_operation_file(file: &std::fs::File) -> Result<Option<&'static str>> {
    #[derive(Clone, Copy)]
    enum LineState {
        Pending,
        Eligible,
        Ignored,
    }

    fn classify_prefix(prefix: &[u8]) -> Option<LineState> {
        let first = prefix.first().copied()?;
        if matches!(first, b' ' | b'\t' | b'#' | b'@') {
            return Some(LineState::Ignored);
        }
        for declaration in [b"def ".as_slice(), b"class ".as_slice()] {
            if declaration.starts_with(prefix) {
                return if declaration == prefix {
                    Some(LineState::Ignored)
                } else {
                    None
                };
            }
        }
        Some(LineState::Eligible)
    }

    fn push_operation_byte(tail: &mut Vec<u8>, byte: u8) -> Option<&'static str> {
        const MAX_NEEDLE: usize = 32;
        tail.push(byte.to_ascii_lowercase());
        if tail.len() > MAX_NEEDLE {
            let drop = tail.len() - MAX_NEEDLE;
            tail.drain(..drop);
        }
        for (needle, operation) in [
            (b"os.system(".as_slice(), "os.system"),
            (b"subprocess.run(".as_slice(), "subprocess.run"),
            (b"subprocess.popen(".as_slice(), "subprocess.Popen"),
            (b"exec(".as_slice(), "exec"),
            (b"eval(".as_slice(), "eval"),
            (b"socket.socket(".as_slice(), "socket.socket"),
            (b"requests.".as_slice(), "requests network access"),
            (b"urllib.request".as_slice(), "urllib network access"),
            (b"ctypes.".as_slice(), "ctypes native loading"),
            (b".write_text(".as_slice(), "Path.write_text"),
            (b".write_bytes(".as_slice(), "Path.write_bytes"),
            (b".unlink(".as_slice(), "Path.unlink"),
            (b".remove(".as_slice(), "remove"),
            (b".rename(".as_slice(), "rename"),
        ] {
            if tail.ends_with(needle) {
                return Some(operation);
            }
        }
        None
    }

    let mut reader = BufReader::new(file.try_clone()?);
    reader.seek(SeekFrom::Start(0))?;
    let mut state = LineState::Pending;
    let mut prefix = Vec::<u8>::with_capacity(8);
    let mut tail = Vec::<u8>::with_capacity(32);
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            break;
        }
        let consumed = buf.len();
        for &byte in buf {
            if byte == b'\n' || byte == b'\r' {
                state = LineState::Pending;
                prefix.clear();
                tail.clear();
                continue;
            }
            match state {
                LineState::Ignored => {}
                LineState::Eligible => {
                    if let Some(operation) = push_operation_byte(&mut tail, byte) {
                        return Ok(Some(operation));
                    }
                }
                LineState::Pending => {
                    if prefix.len() < 8 {
                        prefix.push(byte);
                    }
                    if let Some(classified) = classify_prefix(&prefix) {
                        state = classified;
                        if matches!(state, LineState::Eligible) {
                            for prior in prefix.drain(..) {
                                if let Some(operation) = push_operation_byte(&mut tail, prior) {
                                    return Ok(Some(operation));
                                }
                            }
                        }
                    }
                }
            }
        }
        reader.consume(consumed);
    }
    Ok(None)
}
pub(super) fn correlate_custom_code(
    files: &[PackageEntry],
    evidence: &[PackageMemberEvidence],
    findings: &mut Vec<LayerScanResult>,
) {
    let mut modules = BTreeSet::new();
    let mut package_remote_trust = false;
    for item in evidence {
        if item.auto_map {
            modules.extend(item.modules.iter().cloned());
        }
        package_remote_trust |= item.remote_trust;
    }
    if !modules.is_empty() {
        for module in modules {
            let module_path = format!("{}.py", module.replace('.', "/"));
            let Some(entry) = files
                .iter()
                .find(|entry| entry.relative_path.eq_ignore_ascii_case(&module_path))
            else {
                continue;
            };
            let Some(item) = evidence.iter().find(|item| {
                item.relative_path
                    .eq_ignore_ascii_case(&entry.relative_path)
            }) else {
                continue;
            };
            let Some(operation) = item.module_scope_operation else {
                continue;
            };
            let trust_context = if package_remote_trust {
                "; package metadata also sets trust_remote_code=true"
            } else {
                "; this code becomes importable when the caller enables trust_remote_code at runtime"
            };
            let digest = entry.sha256.as_deref().unwrap_or("module");
            let subject = member_subject(&entry.relative_path, digest, Some(entry.size));
            findings.push(
            finding(
                digest,
                CheckType::PackageSecurity,
                ScanStatus::Fail,
                FindingClass::ContentIndicator,
                Confidence::High,
                "LF-CODE-IMPORT-SIDE-EFFECT",
                format!(
                    "Hugging Face auto_map routes loading through '{}', which performs '{}' at module scope{}",
                    entry.relative_path, operation, trust_context
                ),
            )
            .subject(subject.clone())
            // The relationship itself is the evidence: a configuration
            // reference resolving to a module that acts at import time.
            .evidence(crate::finding_evidence::path_relationship(
                subject,
                "auto_map reference resolves to a module with import-time behaviour",
                serde_json::json!({
                    "referenced_module": module,
                    "resolved_module_path": entry.relative_path,
                    "module_scope_operation": operation,
                    "package_trust_remote_code": package_remote_trust,
                }),
            ))
            .finish(),
        );
        }
    }

    // Python to native binary capability correlation
    let py_native_loads: Vec<_> = findings
        .iter()
        .filter(|f| f.matches.iter().any(|m| m.contains("LF-PY-NATIVE-LOAD")))
        .cloned()
        .collect();

    for py_finding in py_native_loads {
        let py_rel = py_finding
            .subject
            .as_ref()
            .and_then(|s| s.package_relative_path.as_deref())
            .unwrap_or("")
            .to_owned();
        if py_rel.is_empty() {
            continue;
        }

        for ev in &py_finding.evidence {
            if let Some(ref structured) = ev.structured {
                let call_target = structured["call_target"]
                    .as_str()
                    .unwrap_or("native_loader");
                let command_evidence = structured["command_evidence"].as_str();

                if let Some(target_arg) = command_evidence {
                    let cleaned_arg = target_arg.trim_matches(&['\'', '"', ' ', '.'][..]);
                    let basename = std::path::Path::new(cleaned_arg)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or(cleaned_arg);

                    if let Some(native_entry) = files.iter().find(|e| {
                        let e_base = std::path::Path::new(&e.relative_path)
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or(&e.relative_path);
                        e_base.eq_ignore_ascii_case(basename)
                            || e.relative_path.eq_ignore_ascii_case(cleaned_arg)
                    }) {
                        let native_rel = &native_entry.relative_path;
                        let native_digest = native_entry.sha256.as_deref().unwrap_or("native");

                        let py_subject =
                            member_subject(&py_rel, py_finding.layer_digest.as_str(), None);
                        let native_subject =
                            member_subject(native_rel, native_digest, Some(native_entry.size));

                        let detail = format!(
                            "Python script '{py_rel}' loads native library '{native_rel}' via '{call_target}'; native library possesses capability imports"
                        );

                        findings.push(
                            finding(
                                py_finding.layer_digest.as_str(),
                                CheckType::PackageSecurity,
                                ScanStatus::Warn,
                                FindingClass::ContentIndicator,
                                Confidence::High,
                                "LF-CORR-CUSTOM-LOADER-NATIVE",
                                detail,
                            )
                            .subject(py_subject.clone())
                            .evidence(crate::finding_evidence::path_relationship(
                                py_subject,
                                &format!("{py_rel} -> {call_target} -> {native_rel}"),
                                serde_json::json!({
                                    "python_script": py_rel,
                                    "loader_call": call_target,
                                    "native_library": native_rel,
                                    "target_arg": target_arg,
                                    "target_subject": native_subject.canonical_name(),
                                }),
                            ))
                            .finish(),
                        );
                    }
                }
            }
        }
    }
}
