use super::*;

pub(super) fn scan_json_evidence(
    rel: &str,
    digest: &str,
    evidence: &PackageMemberEvidence,
    out: &mut Vec<LayerScanResult>,
) {
    let subject = member_subject(rel, digest, None);
    if evidence.auto_map {
        let referenced = evidence
            .auto_map_entries
            .values()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let detail = if referenced.is_empty() {
            format!("'{rel}' contains Hugging Face auto_map metadata that can route loading through custom model code")
        } else {
            format!("'{rel}' maps model loading to custom code via auto_map: {referenced}")
        };
        let mut builder = finding(
            digest,
            CheckType::PackageSecurity,
            ScanStatus::Warn,
            FindingClass::ContentIndicator,
            Confidence::High,
            "LF-CODE-AUTO-MAP",
            detail,
        )
        .subject(subject.clone());
        for (key, value) in &evidence.auto_map_entries {
            builder = builder.evidence(config_value(
                subject.clone(),
                key,
                serde_json::Value::String(value.clone()),
                "Configuration maps a model loading entry point to publisher-supplied code",
            ));
        }
        if evidence.auto_map_entries.is_empty() {
            builder = builder.evidence_unavailable(
                "auto_map was present but no string symbol reference was resolved from it",
            );
        }
        out.push(builder.finish());
    }
    if evidence.remote_trust {
        let key = evidence
            .remote_trust_key
            .clone()
            .unwrap_or_else(|| "trust_remote_code".to_owned());
        out.push(
            finding(
                digest,
                CheckType::PackageSecurity,
                ScanStatus::Warn,
                FindingClass::ContentIndicator,
                Confidence::High,
                "LF-CODE-REMOTE-TRUST",
                format!("'{rel}' sets {key} = true; custom code should be reviewed before loading"),
            )
            .subject(subject.clone())
            .evidence(config_value(
                subject.clone(),
                &key,
                serde_json::Value::Bool(true),
                "Configuration explicitly permits execution of publisher-supplied code",
            ))
            .finish(),
        );
    }
    if let Some(error) = evidence.json_parse_error.as_deref() {
        out.push(
            finding(
                digest,
                CheckType::PackageSecurity,
                ScanStatus::Warn,
                FindingClass::Structural,
                Confidence::High,
                "LF-PACKAGE-JSON-INVALID",
                format!("JSON/config '{rel}' could not be parsed completely: {error}"),
            )
            .subject(subject.clone())
            .evidence(crate::finding_evidence::structural_invariant(
                subject,
                "configuration could not be fully parsed",
                serde_json::json!({ "parser_error": error }),
            ))
            .finish(),
        );
    }
}

pub(super) fn scan_text_streaming(
    rel: &str,
    digest: &str,
    file: &std::fs::File,
    out: &mut Vec<LayerScanResult>,
) -> Result<()> {
    let documentation = is_documentation_path(rel);
    // Tokenizer/vocabulary payloads are data dictionaries, not executable
    // source.  They can legitimately contain source-code-shaped tokens such as
    // `exec(` or `os.system(`.  Continue streaming the entire file and run
    // targeted JSON/HF metadata extraction, but do not promote vocabulary
    // entries to custom-code findings.
    let vocabulary_data = is_tokenizer_vocabulary_path(rel);
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
        // Shell
        ("eval ", "LF-SHELL-EVAL"),
        ("exec ", "LF-SHELL-EXEC"),
        (". /", "LF-SHELL-DOT-SOURCE"),
        ("| bash", "LF-SHELL-CURL-PIPE"),
        ("| sh", "LF-SHELL-CURL-PIPE"),
        ("|bash", "LF-SHELL-CURL-PIPE"),
        ("|sh", "LF-SHELL-CURL-PIPE"),
        // PowerShell
        ("invoke-expression", "LF-PS-INVOKE-EXPRESSION"),
        ("iex ", "LF-PS-INVOKE-EXPRESSION"),
        ("-encodedcommand", "LF-PS-ENCODED-COMMAND"),
        ("downloadstring(", "LF-PS-DOWNLOAD"),
        ("downloadfile(", "LF-PS-DOWNLOAD"),
        ("invoke-webrequest", "LF-PS-DOWNLOAD"),
        // JavaScript/TypeScript. `eval(` above (LF-CODE-EVAL) already covers
        // JS's dynamic-evaluation case; it is intentionally not duplicated
        // under a JS-specific rule id here.
        ("child_process", "LF-JS-CHILD-PROCESS"),
        ("execsync(", "LF-JS-CHILD-PROCESS"),
        ("require('child_process')", "LF-JS-REQUIRE-CHILD-PROCESS"),
    ];
    let jinja = [
        "__class__",
        "__mro__",
        "__subclasses__",
        "__globals__",
        "cycler.__init__",
        "namespace.__init__",
    ];
    let mut hits = MatchCollector::default();
    let mut jinja_seen = false;
    let mut template_marker_seen = rel.to_ascii_lowercase().contains("template");
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut chunk = vec![0_u8; TEXT_STREAM_CHUNK_BYTES];
    let mut carry = Vec::<u8>::new();
    // Absolute file offset of `window[0]`, and the 1-based line number at that
    // offset. Both advance by the freshly consumed bytes only, so the replayed
    // overlap region is never counted twice.
    let mut window_start = 0_u64;
    let mut window_start_line = 1_u64;
    loop {
        let count = reader.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        let mut window = Vec::with_capacity(carry.len() + count);
        window.extend_from_slice(&carry);
        window.extend_from_slice(&chunk[..count]);
        let lower = String::from_utf8_lossy(&window).to_ascii_lowercase();
        if !documentation && !vocabulary_data {
            for (needle, rule) in dangerous {
                for (offset, _) in lower.match_indices(needle) {
                    // `lower` is a lossy decode, so its byte offsets can differ
                    // from the raw window's on invalid UTF-8. Clamp instead of
                    // trusting the index.
                    let local = offset.min(window.len());
                    let absolute = window_start.saturating_add(local as u64);
                    let line =
                        window_start_line.saturating_add(count_newlines(&window[..local]) as u64);
                    hits.record(rule, needle, absolute, line);
                }
            }
        }
        if !vocabulary_data {
            jinja_seen |= jinja.iter().any(|needle| lower.contains(needle));
            template_marker_seen |= lower.contains("{{");
            for needle in jinja {
                for (offset, _) in lower.match_indices(needle) {
                    let local = offset.min(window.len());
                    let absolute = window_start.saturating_add(local as u64);
                    let line =
                        window_start_line.saturating_add(count_newlines(&window[..local]) as u64);
                    hits.record("LF-TEMPLATE-INTROSPECTION", needle, absolute, line);
                }
            }
        }
        let keep = window.len().min(TEXT_STREAM_OVERLAP_BYTES);
        let consumed = window.len() - keep;
        window_start_line =
            window_start_line.saturating_add(count_newlines(&window[..consumed]) as u64);
        window_start = window_start.saturating_add(consumed as u64);
        carry.clear();
        carry.extend_from_slice(&window[window.len() - keep..]);
    }

    let subject = member_subject(rel, digest, file.metadata().ok().map(|meta| meta.len()));
    for rule in hits.rules() {
        if rule == "LF-TEMPLATE-INTROSPECTION" {
            continue;
        }
        let primitive = match rule {
            "LF-CODE-OS-SYSTEM" => "os.system",
            "LF-CODE-SUBPROCESS" => "subprocess",
            "LF-CODE-EVAL" => "eval",
            "LF-CODE-EXEC" => "exec",
            "LF-CODE-CTYPES" => "ctypes",
            "LF-CODE-NETWORK" => "network access",
            "LF-SHELL-EVAL" => "shell eval",
            "LF-SHELL-EXEC" => "shell exec",
            "LF-SHELL-DOT-SOURCE" => "shell dot-source",
            "LF-SHELL-CURL-PIPE" => "curl/wget piped to a shell",
            "LF-PS-INVOKE-EXPRESSION" => "PowerShell Invoke-Expression",
            "LF-PS-ENCODED-COMMAND" => "PowerShell -EncodedCommand",
            "LF-PS-DOWNLOAD" => "PowerShell remote download",
            "LF-JS-CHILD-PROCESS" => "child_process",
            "LF-JS-REQUIRE-CHILD-PROCESS" => "require('child_process')",
            _ => "security-sensitive primitive",
        };
        let matches = hits.take(rule);
        let detail = format!(
            "Custom code/config '{}' contains security-relevant primitive '{}' at {}; the entire file was streamed and review is required before enabling custom code",
            rel,
            primitive,
            describe_lines(&matches)
        );
        out.push(
            finding(
                digest,
                CheckType::PackageSecurity,
                ScanStatus::Warn,
                FindingClass::ContentIndicator,
                Confidence::High,
                rule,
                detail,
            )
            .subject(subject.clone())
            .evidence_all(excerpt_evidence(&subject, file, &matches))
            .truncated(hits.truncated(rule))
            .finish(),
        );
    }
    if jinja_seen || template_marker_seen {
        let mut reader = file.try_clone()?;
        reader.seek(SeekFrom::Start(0))?;
        let mut file_bytes = Vec::new();
        reader
            .take(1024_u64 * 1024_u64)
            .read_to_end(&mut file_bytes)?;
        {
            // Package text scanning already treats malformed UTF-8 lossily. Keep the
            // semantic pass aligned with that behavior, especially when the bounded
            // prefix ends in the middle of a multibyte character.
            let content_str = String::from_utf8_lossy(&file_bytes);
            let limits = crate::template_static::TemplateLimits::default();
            let analysis = crate::template_static::analyze_template(&content_str, rel, &limits);
            if !analysis.findings.is_empty() {
                for f in &analysis.findings {
                    let rule_id = f.rule.rule_id();
                    let mut matches = hits.take(rule_id);
                    if matches.is_empty() {
                        let ev_matches = hits.take("LF-TEMPLATE-INTROSPECTION");
                        matches = ev_matches;
                    }
                    let detail = format!("Template/config '{}': {}", rel, f.detail);
                    let ev_msg = format!("{} matched in template content", rule_id);
                    let ev_list = if !matches.is_empty() {
                        excerpt_evidence(&subject, file, &matches)
                    } else {
                        vec![crate::finding_evidence::FindingEvidence::new(
                            crate::finding_evidence::EvidenceKind::SourceExcerpt,
                            subject.clone(),
                            &ev_msg,
                        )
                        .at(crate::finding_evidence::EvidenceLocation::ByteRange {
                            offset: f.span.offset,
                            length: f.span.length.max(1),
                        })
                        .excerpt(&f.excerpt)]
                    };
                    out.push(
                        finding(
                            digest,
                            CheckType::PackageSecurity,
                            ScanStatus::Warn,
                            FindingClass::ContentIndicator,
                            Confidence::High,
                            rule_id,
                            detail,
                        )
                        .subject(subject.clone())
                        .evidence_all(ev_list)
                        .finish(),
                    );
                }
            } else if jinja_seen && template_marker_seen {
                let matches = hits.take("LF-TEMPLATE-INTROSPECTION");
                let detail = format!(
                    "Template/config '{}' contains Python/Jinja introspection primitives at {}; review template execution context before use",
                    rel,
                    describe_lines(&matches)
                );
                out.push(
                    finding(
                        digest,
                        CheckType::PackageSecurity,
                        ScanStatus::Warn,
                        FindingClass::ContentIndicator,
                        Confidence::High,
                        "LF-TEMPLATE-INTROSPECTION",
                        detail,
                    )
                    .subject(subject.clone())
                    .evidence_all(excerpt_evidence(&subject, file, &matches))
                    .finish(),
                );
            }
        }
    }
    Ok(())
}

/// One accepted primitive match inside a package member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TextMatch {
    needle: &'static str,
    offset: u64,
    line: u64,
}

/// Bounded, deduplicated, deterministic collection of primitive matches.
///
/// Chunks are replayed with an 8 KiB overlap so a primitive straddling a chunk
/// boundary is still found. That means the same match can be seen twice, so
/// acceptance is keyed on the absolute file offset rather than the position
/// inside the current window.
#[derive(Default)]
pub(super) struct MatchCollector {
    matches: std::collections::BTreeMap<&'static str, Vec<TextMatch>>,
    suppressed: std::collections::BTreeMap<&'static str, usize>,
}

impl MatchCollector {
    fn record(&mut self, rule: &'static str, needle: &'static str, offset: u64, line: u64) {
        let entries = self.matches.entry(rule).or_default();
        if entries.iter().any(|entry| entry.offset == offset) {
            return;
        }
        if entries.len() >= MAX_EVIDENCE_PER_FINDING {
            *self.suppressed.entry(rule).or_default() += 1;
            return;
        }
        entries.push(TextMatch {
            needle,
            offset,
            line,
        });
    }

    fn rules(&self) -> Vec<&'static str> {
        self.matches.keys().copied().collect()
    }

    fn take(&self, rule: &str) -> Vec<TextMatch> {
        let mut out = self.matches.get(rule).cloned().unwrap_or_default();
        out.sort_by_key(|entry| entry.offset);
        out
    }

    fn truncated(&self, rule: &str) -> bool {
        self.suppressed.get(rule).copied().unwrap_or(0) > 0
    }
}

pub(super) fn count_newlines(bytes: &[u8]) -> usize {
    bytes.iter().filter(|byte| **byte == b'\n').count()
}

pub(super) fn describe_lines(matches: &[TextMatch]) -> String {
    if matches.is_empty() {
        return "an undetermined position".to_owned();
    }
    let rendered = matches
        .iter()
        .take(4)
        .map(|entry| format!("line {}", entry.line))
        .collect::<Vec<_>>()
        .join(", ");
    if matches.len() > 4 {
        format!("{rendered} and {} more", matches.len() - 4)
    } else {
        rendered
    }
}

/// Build bounded source excerpts for accepted matches.
///
/// Each excerpt is a small positional re-read of the member, never a full load:
/// a hostile multi-gigabyte file yields at most `EXCERPT_READ_BYTES` per match.
pub(super) fn excerpt_evidence(
    subject: &EvidenceSubject,
    file: &std::fs::File,
    matches: &[TextMatch],
) -> Vec<crate::finding_evidence::FindingEvidence> {
    matches
        .iter()
        .filter_map(|entry| {
            let (text, _) = read_excerpt_window(file, entry.offset, entry.line).ok()?;
            // The location names the line the primitive is actually on. The
            // excerpt carries surrounding context, but pointing a reviewer at
            // the first context line would misreport where the match is.
            Some(source_excerpt(
                subject.clone(),
                entry.line,
                entry.line,
                entry.needle,
                &text,
            ))
        })
        .collect()
}

pub(super) fn read_excerpt_window(
    file: &std::fs::File,
    offset: u64,
    line: u64,
) -> Result<(String, u64)> {
    let half = (EXCERPT_READ_BYTES / 2) as u64;
    let start = offset.saturating_sub(half);
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(start))?;
    let mut buffer = vec![0_u8; EXCERPT_READ_BYTES];
    let read = reader.read(&mut buffer)?;
    buffer.truncate(read);
    let decoded = String::from_utf8_lossy(&buffer).into_owned();

    // Locate the match inside the window, then keep a few lines either side.
    let local = usize::try_from(offset.saturating_sub(start)).unwrap_or(0);
    let local = local.min(decoded.len());
    let before = &decoded[..floor_boundary(&decoded, local)];
    let leading_newlines = count_newlines(before.as_bytes()) as u64;

    let mut prefix_lines: Vec<&str> = before.split('\n').collect();
    // A window that does not start at the file start may begin mid-line; drop
    // that partial line rather than presenting it as a complete one.
    if start > 0 && !prefix_lines.is_empty() {
        prefix_lines.remove(0);
    }
    let context = EXCERPT_CONTEXT_LINES as usize;
    let kept_before = prefix_lines.len().min(context);
    let prefix = prefix_lines[prefix_lines.len() - kept_before..].join("\n");

    let after = &decoded[floor_boundary(&decoded, local)..];
    let suffix_lines: Vec<&str> = after.split('\n').take(context + 1).collect();
    let suffix = suffix_lines.join("\n");

    let mut text = String::new();
    if !prefix.is_empty() {
        text.push_str(&prefix);
        text.push('\n');
    }
    text.push_str(&suffix);

    // The reported first line is the match line minus the context actually kept.
    let _ = leading_newlines;
    let first_line = line.saturating_sub(kept_before as u64).max(1);
    Ok((text, first_line))
}

pub(super) fn floor_boundary(value: &str, mut index: usize) -> usize {
    if index >= value.len() {
        return value.len();
    }
    while index > 0 && !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

pub(super) fn prefix(file: &std::fs::File, limit: usize) -> Result<Vec<u8>> {
    let mut cloned = file.try_clone()?;
    cloned.seek(SeekFrom::Start(0))?;
    let mut bytes = vec![0_u8; limit];
    let n = cloned.read(&mut bytes)?;
    bytes.truncate(n);
    Ok(bytes)
}
