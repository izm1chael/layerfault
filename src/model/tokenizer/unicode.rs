use super::UnicodeControlRecord;
fn suspicious(c: char) -> bool {
    crate::finding_evidence::is_invisible_or_bidi(c)
        || matches!(c,'\u{200b}'|'\u{200c}'|'\u{200d}'|'\u{2060}'|'\u{feff}'|'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')
}
pub fn scan_text(
    path: &str,
    field: &str,
    text: &str,
    role_boundary: bool,
) -> Vec<UnicodeControlRecord> {
    text.char_indices()
        .filter(|&(_, c)| suspicious(c))
        .map(|(i, c)| {
            let start = i.saturating_sub(32);
            let end = (i + c.len_utf8() + 32).min(text.len());
            let context = text
                .get(start..end)
                .unwrap_or("")
                .chars()
                .take(96)
                .collect();
            UnicodeControlRecord {
                relative_path: path.into(),
                field_path: field.into(),
                codepoint: c as u32,
                unicode_name_or_hex: format!("U+{:04X}", c as u32),
                bounded_context: context,
                role_boundary,
            }
        })
        .take(1024)
        .collect()
}
