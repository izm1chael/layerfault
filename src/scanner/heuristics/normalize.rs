pub(super) fn normalize_detection_bytes(bytes: &[u8]) -> (String, usize, usize, usize) {
    let mut output = String::new();
    let (invalid, invisible, confusables) = normalize_detection_bytes_into(bytes, &mut output);
    (output, invalid, invisible, confusables)
}

/// Same character-mapping rules as `normalize_detection_bytes`, but writes
/// into a caller-provided buffer (cleared first) instead of allocating a new
/// `String`, so a worker-owned scratch buffer can be reused across calls.
pub(super) fn normalize_detection_bytes_into(
    bytes: &[u8],
    output: &mut String,
) -> (usize, usize, usize) {
    output.clear();
    let invalid_input = std::str::from_utf8(bytes).is_err();
    let decoded = String::from_utf8_lossy(bytes);
    let mut invalid = 0usize;
    let mut invisible = 0usize;
    let mut confusables = 0usize;
    for ch in decoded.chars() {
        if is_invisible_or_bidi(ch) {
            invisible = invisible.saturating_add(1);
            continue;
        }
        if invalid_input && ch == '\u{fffd}' {
            invalid = invalid.saturating_add(1);
            output.push(' ');
            continue;
        }
        if let Some(mapped) = common_confusable(ch) {
            confusables = confusables.saturating_add(1);
            output.push(mapped);
        } else {
            output.push(ch);
        }
    }
    (invalid, invisible, confusables)
}

/// Same character-mapping rules as `normalize_detection_bytes`, but returns only
/// the resulting byte length instead of materializing the normalized `String`.
/// Used to derive a suppression boundary from a small buffer without allocating.
pub(super) fn normalized_detection_len(bytes: &[u8]) -> usize {
    let invalid_input = std::str::from_utf8(bytes).is_err();
    let decoded = String::from_utf8_lossy(bytes);
    let mut len = 0usize;
    for ch in decoded.chars() {
        if is_invisible_or_bidi(ch) {
            continue;
        }
        if invalid_input && ch == '\u{fffd}' {
            len = len.saturating_add(1);
            continue;
        }
        let mapped = common_confusable(ch).unwrap_or(ch);
        len = len.saturating_add(mapped.len_utf8());
    }
    len
}

#[inline(always)]
fn common_confusable(ch: char) -> Option<char> {
    Some(match ch {
        // Common Cyrillic/Greek look-alikes used in prompt/signature evasion.
        'А' | 'Α' => 'A',
        'В' | 'Β' => 'B',
        'С' => 'C',
        'Е' | 'Ε' => 'E',
        'Н' | 'Η' => 'H',
        'І' | 'Ι' => 'I',
        'К' | 'Κ' => 'K',
        'М' | 'Μ' => 'M',
        'О' | 'Ο' => 'O',
        'Р' | 'Ρ' => 'P',
        'Т' | 'Τ' => 'T',
        'Х' | 'Χ' => 'X',
        'а' | 'α' => 'a',
        'с' => 'c',
        'е' | 'ε' => 'e',
        'і' | 'ι' => 'i',
        'о' | 'ο' => 'o',
        'р' | 'ρ' => 'p',
        'х' | 'χ' => 'x',
        'у' => 'y',
        _ => return None,
    })
}

#[inline(always)]
fn is_invisible_or_bidi(ch: char) -> bool {
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
