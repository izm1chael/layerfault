use super::*;

pub struct SanitizedExcerpt {
    pub text: String,
    pub redactions: u32,
    pub truncated: bool,
}

lazy_static! {
    /// Credential shapes worth suppressing. This is deliberately a short,
    /// high-signal list rather than a general DLP engine: the goal is to prove
    /// the security condition without reproducing the credential.
    static ref SECRET_PATTERNS: Vec<(Regex, usize)> = vec![
        (
            Regex::new(r"(?i)authorization\s*:\s*(?:bearer|basic|token)\s+([A-Za-z0-9._\-+/=]{8,})")
                .expect("static authorization pattern"),
            1,
        ),
        (
            Regex::new(r"(?s)-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----.*?-----END [A-Z ]{0,40}PRIVATE KEY-----")
                .expect("static private key pattern"),
            0,
        ),
        (
            Regex::new(r"\b(?:hf_|ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{16,}\b")
                .expect("static vendor token pattern"),
            0,
        ),
        (
            Regex::new(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b").expect("static github pat pattern"),
            0,
        ),
        (
            Regex::new(r"\bsk-[A-Za-z0-9_\-]{16,}\b").expect("static sk token pattern"),
            0,
        ),
        (
            Regex::new(r"\bglpat-[A-Za-z0-9_\-]{16,}\b").expect("static gitlab pat pattern"),
            0,
        ),
        (
            Regex::new(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b").expect("static slack token pattern"),
            0,
        ),
        (
            Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("static aws key id pattern"),
            0,
        ),
        (
            Regex::new(r#"(?i)\baws_secret_access_key\s*[=:]\s*["']?([A-Za-z0-9/+=]{30,})"#)
                .expect("static aws secret pattern"),
            1,
        ),
        (
            Regex::new(r#"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*["']([^"'\r\n]{4,})["']"#)
                .expect("static assignment pattern"),
            1,
        ),
        (
            Regex::new(r"\bLF_CANARY_[A-Za-z0-9_]+\b").expect("static canary pattern"),
            0,
        ),
    ];
}

/// Replace credential-shaped values with a stable SHA-256 fingerprint.
///
/// The fingerprint keeps the value correlatable across findings and revisions
/// without reproducing it. Returns the rewritten text and the redaction count.
pub fn redact_secrets(input: &str) -> (String, u32) {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for (pattern, group) in SECRET_PATTERNS.iter() {
        for captures in pattern.captures_iter(input) {
            let target = if *group == 0 {
                captures.get(0)
            } else {
                captures.get(*group).or_else(|| captures.get(0))
            };
            if let Some(matched) = target {
                if matched.start() < matched.end() {
                    spans.push((matched.start(), matched.end()));
                }
            }
        }
    }
    if spans.is_empty() {
        return (input.to_owned(), 0);
    }
    spans.sort_unstable();

    let mut rendered = String::with_capacity(input.len());
    let mut cursor = 0usize;
    let mut redactions = 0u32;
    for (start, end) in spans {
        if start < cursor {
            continue;
        }
        rendered.push_str(&input[cursor..start]);
        rendered.push_str(&secret_placeholder(&input[start..end]));
        cursor = end;
        redactions = redactions.saturating_add(1);
    }
    rendered.push_str(&input[cursor..]);
    (rendered, redactions)
}

/// Stable placeholder for a suppressed secret.
pub fn secret_placeholder(value: &str) -> String {
    let fingerprint = hex::encode(Sha256::digest(value.as_bytes()));
    format!("<redacted sha256:{}>", &fingerprint[..16])
}

/// Escape control characters, ANSI/CSI escape sequences, embedded NULs and
/// invisible/bidi characters so untrusted artifact content cannot inject
/// terminal control sequences into human-readable output.
///
/// Characters are escaped rather than deleted: the reviewer still sees that
/// something was there, and JSON consumers get a faithful, safely encoded value.
pub fn sanitize_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\n' | '\t' => out.push(ch),
            '\r' => out.push_str("\\r"),
            '\u{0}' => out.push_str("\\0"),
            c if is_invisible_or_bidi(c) => {
                out.push_str(&format!("\\u{{{:04x}}}", c as u32));
            }
            c if (c as u32) < 0x20 || (0x7f..=0x9f).contains(&(c as u32)) => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// True for zero-width, soft-hyphen and bidirectional-override characters used
/// to hide content from human reviewers.
pub fn is_invisible_or_bidi(ch: char) -> bool {
    matches!(
        ch,
        '\u{00ad}'
            | '\u{200b}'
            | '\u{200c}'
            | '\u{200d}'
            | '\u{2060}'
            | '\u{feff}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

/// Sanitise, redact and bound untrusted content for use as an excerpt.
pub fn sanitize_excerpt(input: &str) -> SanitizedExcerpt {
    sanitize_excerpt_bounded(input, MAX_EXCERPT_LINES, MAX_EXCERPT_BYTES)
}

/// Sanitise, redact and bound untrusted content with explicit limits.
///
/// Clamping happens before escaping expansion is measured, so a hostile input
/// consisting of one enormous line can never produce an unbounded excerpt.
pub fn sanitize_excerpt_bounded(
    input: &str,
    max_lines: usize,
    max_bytes: usize,
) -> SanitizedExcerpt {
    let mut truncated = false;

    // Bound the raw input first so a multi-gigabyte line is never fully
    // escaped, redacted or copied. Allow headroom for escape expansion while
    // keeping the working set small.
    let raw_budget = max_bytes.saturating_mul(2).max(max_bytes);
    let mut clamped = if input.len() > raw_budget {
        truncated = true;
        let boundary = floor_char_boundary(input, raw_budget);
        &input[..boundary]
    } else {
        input
    };

    if max_lines > 0 {
        let mut newlines = 0usize;
        let mut cut = None;
        for (index, byte) in clamped.as_bytes().iter().enumerate() {
            if *byte == b'\n' {
                newlines += 1;
                if newlines >= max_lines {
                    cut = Some(index);
                    break;
                }
            }
        }
        if let Some(index) = cut {
            if index + 1 < clamped.len() {
                truncated = true;
            }
            clamped = &clamped[..index];
        }
    }

    let (redacted, redactions) = redact_secrets(clamped);
    let mut text = sanitize_text(&redacted);
    if text.len() > max_bytes {
        truncated = true;
        let boundary = floor_char_boundary(&text, max_bytes);
        text.truncate(boundary);
    }

    SanitizedExcerpt {
        text,
        redactions,
        truncated,
    }
}

/// Recursively sanitise strings inside a structured evidence payload.
pub(super) fn sanitize_json(value: serde_json::Value, depth: usize) -> serde_json::Value {
    const MAX_DEPTH: usize = 8;
    const MAX_ITEMS: usize = 64;
    if depth >= MAX_DEPTH {
        return serde_json::Value::String("<depth limit reached>".to_owned());
    }
    match value {
        serde_json::Value::String(text) => {
            let sanitized = sanitize_excerpt_bounded(&text, 0, MAX_EXCERPT_BYTES);
            serde_json::Value::String(sanitized.text)
        }
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .into_iter()
                .take(MAX_ITEMS)
                .map(|item| sanitize_json(item, depth + 1))
                .collect(),
        ),
        serde_json::Value::Object(fields) => serde_json::Value::Object(
            fields
                .into_iter()
                .take(MAX_ITEMS)
                .map(|(key, item)| (sanitize_text(&key), sanitize_json(item, depth + 1)))
                .collect(),
        ),
        other => other,
    }
}

fn floor_char_boundary(input: &str, mut index: usize) -> usize {
    if index >= input.len() {
        return input.len();
    }
    while index > 0 && !input.is_char_boundary(index) {
        index -= 1;
    }
    index
}

// ---------------------------------------------------------------------------
// Evidence constructors
// ---------------------------------------------------------------------------
