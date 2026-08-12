use super::{accumulator::ScanAccumulator, signatures::*};
use crate::scanner::STREAM_CHUNK_BYTES;

#[derive(Default)]
pub(super) struct DecodeBudget {
    pub(super) bytes: usize,
    pub(super) candidates: usize,
    pub(super) exhausted: bool,
}

pub(super) fn scan_decoded_candidates(
    content: &str,
    accumulator: &mut ScanAccumulator,
    budget: &mut DecodeBudget,
    depth: usize,
) {
    if depth >= MAX_DECODE_DEPTH || budget.exhausted {
        return;
    }
    let mut decoded = Vec::<(&'static str, String)>::new();
    for captures in BASE64_CANDIDATE.captures_iter(content) {
        if budget.candidates >= MAX_DECODE_CANDIDATES {
            budget.exhausted = true;
            break;
        }
        let Some(value) = captures.get(1) else {
            continue;
        };
        if let Some(bytes) = decode_base64_bounded(
            value.as_str(),
            MAX_DECODED_BYTES.saturating_sub(budget.bytes),
        ) {
            if let Ok(text) = String::from_utf8(bytes) {
                decoded.push(("base64", text));
            }
        }
        budget.candidates = budget.candidates.saturating_add(1);
    }
    for captures in HEX_CANDIDATE.captures_iter(content) {
        if budget.candidates >= MAX_DECODE_CANDIDATES {
            budget.exhausted = true;
            break;
        }
        let Some(value) = captures.get(1) else {
            continue;
        };
        let compact: String = value
            .as_str()
            .chars()
            .filter(|ch| ch.is_ascii_hexdigit())
            .collect();
        let remaining = MAX_DECODED_BYTES.saturating_sub(budget.bytes);
        if compact.len() / 2 <= remaining {
            if let Ok(bytes) = hex::decode(compact) {
                if let Ok(text) = String::from_utf8(bytes) {
                    decoded.push(("hex", text));
                }
            }
        } else {
            budget.exhausted = true;
        }
        budget.candidates = budget.candidates.saturating_add(1);
    }
    // ROT13 preserves length and has no framing marker. Apply it only to bounded
    // textual windows and only retain it if the decoded signature set actually
    // matches; this avoids generating report noise from arbitrary prose.
    if content.len() <= STREAM_CHUNK_BYTES && budget.candidates < MAX_DECODE_CANDIDATES {
        decoded.push(("rot13", rot13(content)));
        budget.candidates = budget.candidates.saturating_add(1);
    }
    for (encoding, text) in decoded {
        if text.is_empty() {
            continue;
        }
        if budget.bytes.saturating_add(text.len()) > MAX_DECODED_BYTES {
            budget.exhausted = true;
            break;
        }
        budget.bytes = budget.bytes.saturating_add(text.len());
        accumulator.scan_decoded_text(&text, encoding);
        scan_decoded_candidates(&text, accumulator, budget, depth + 1);
    }
}

fn decode_base64_bounded(input: &str, remaining: usize) -> Option<Vec<u8>> {
    if input.len() < 8
        || input.len()
            > remaining
                .saturating_mul(4)
                .saturating_div(3)
                .saturating_add(8)
    {
        return None;
    }
    let mut out = Vec::with_capacity((input.len() / 4).saturating_mul(3).min(remaining));
    let mut quartet = [0u8; 4];
    let mut used = 0usize;
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => 64,
            _ => return None,
        };
        quartet[used] = value;
        used += 1;
        if used == 4 {
            if quartet[0] == 64 || quartet[1] == 64 || (quartet[2] == 64 && quartet[3] != 64) {
                return None;
            }
            let word = ((quartet[0] as u32) << 18)
                | ((quartet[1] as u32) << 12)
                | ((if quartet[2] == 64 { 0 } else { quartet[2] } as u32) << 6)
                | (if quartet[3] == 64 { 0 } else { quartet[3] } as u32);
            if out.len() >= remaining {
                return None;
            }
            out.push(((word >> 16) & 0xff) as u8);
            if quartet[2] != 64 {
                if out.len() >= remaining {
                    return None;
                }
                out.push(((word >> 8) & 0xff) as u8);
            }
            if quartet[3] != 64 {
                if out.len() >= remaining {
                    return None;
                }
                out.push((word & 0xff) as u8);
            }
            used = 0;
        }
    }
    if used != 0 {
        // Accept unpadded Base64 by filling the final quartet deterministically.
        if used == 1 {
            return None;
        }
        while used < 4 {
            quartet[used] = 64;
            used += 1;
        }
        let word = ((quartet[0] as u32) << 18)
            | ((quartet[1] as u32) << 12)
            | ((if quartet[2] == 64 { 0 } else { quartet[2] } as u32) << 6);
        if out.len() >= remaining {
            return None;
        }
        out.push(((word >> 16) & 0xff) as u8);
        if quartet[2] != 64 {
            if out.len() >= remaining {
                return None;
            }
            out.push(((word >> 8) & 0xff) as u8);
        }
    }
    Some(out)
}

fn rot13(input: &str) -> String {
    input
        .chars()
        .map(|ch| match ch {
            'a'..='m' => char::from_u32(ch as u32 + 13).unwrap_or(ch),
            'n'..='z' => char::from_u32(ch as u32 - 13).unwrap_or(ch),
            'A'..='M' => char::from_u32(ch as u32 + 13).unwrap_or(ch),
            'N'..='Z' => char::from_u32(ch as u32 - 13).unwrap_or(ch),
            _ => ch,
        })
        .collect()
}

pub(super) fn is_decoded_rescan_family(id: &str) -> bool {
    matches!(
        id.split_once('-').map(|(family, _)| family),
        Some("T1" | "T2" | "T3" | "T4" | "T5" | "T9")
    )
}

pub(super) fn is_t1_to_t6(id: &str) -> bool {
    matches!(
        id.split_once('-').map(|(family, _)| family),
        Some("T1" | "T2" | "T3" | "T4" | "T5" | "T6")
    )
}
