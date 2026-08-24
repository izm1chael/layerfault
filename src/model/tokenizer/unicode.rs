use super::UnicodeControlRecord;
fn bidi_control(c: char) -> bool {
    matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

fn suspicious(c: char, role_boundary: bool) -> bool {
    // Joiners and zero-width spaces are ordinary vocabulary content in many
    // writing systems. Reporting each occurrence from tokenizer.json turns a
    // legitimate multilingual tokenizer into hundreds of false warnings.
    // They matter when they alter a role boundary, while bidi controls remain
    // relevant anywhere because they can change how tokenizer metadata is
    // displayed to a reviewer.
    (role_boundary && crate::finding_evidence::is_invisible_or_bidi(c)) || bidi_control(c)
}
pub fn scan_text(
    path: &str,
    field: &str,
    text: &str,
    role_boundary: bool,
) -> Vec<UnicodeControlRecord> {
    text.char_indices()
        .filter(|&(_, c)| suspicious(c, role_boundary))
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

#[cfg(test)]
mod tests {
    use super::scan_text;

    #[test]
    fn ordinary_multilingual_joiners_do_not_create_findings() {
        assert!(scan_text("tokenizer.json", "vocab", "क\u{200d}ष ه\u{200c}", false).is_empty());
    }

    #[test]
    fn role_boundary_joiners_remain_visible() {
        let controls = scan_text(
            "tokenizer_config.json",
            "chat_template",
            "<\u{200d}|user|>",
            true,
        );
        assert_eq!(controls.len(), 1);
        assert!(controls[0].role_boundary);
        assert_eq!(controls[0].codepoint, 0x200d);
    }

    #[test]
    fn bidi_controls_remain_visible_outside_role_boundaries() {
        let controls = scan_text("tokenizer.json", "vocab", "safe\u{202e}hidden", false);
        assert_eq!(controls.len(), 1);
        assert!(!controls[0].role_boundary);
        assert_eq!(controls[0].codepoint, 0x202e);
    }
}
