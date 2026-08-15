use crate::assurance::AnalysisCompleteness;
use anyhow::{bail, Result};

const MAX_SKELETON_OPCODES: usize = 2_000_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PickleOpcodeSkeleton {
    pub entries: Vec<OpcodeSkeletonEntry>,
    pub completeness: AnalysisCompleteness,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct OpcodeSkeletonEntry {
    pub byte_offset: u64,
    pub opcode: u8,
    pub class: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParserDifferential {
    pub matched: bool,
    pub primary_opcode_count: usize,
    pub skeleton_opcode_count: usize,
    pub first_mismatch: Option<u64>,
    pub completeness: AnalysisCompleteness,
}

fn fixed_width(op: u8) -> Option<usize> {
    match op {
        b'J' => Some(4),
        b'K' => Some(1),
        b'M' => Some(2),
        b'G' => Some(8),
        b'h' => Some(1),
        b'j' | b'q' | b'r' => Some(4),
        0x80 => Some(1),
        0x82 => Some(1),
        0x83 => Some(2),
        0x84 => Some(4),
        0x95 => Some(8),
        _ => None,
    }
}
fn class(op: u8) -> &'static str {
    match op {
        b'c' | b'i' | 0x93 => "global",
        b'R' | b'o' | 0x81 | 0x92 => "execute",
        b'P' | b'Q' => "persistent_id",
        0x82..=0x84 => "extension",
        b'.' => "stop",
        _ => "other",
    }
}

/// Independent structural reader used only as a disagreement detector. It
/// deliberately does not resolve stack semantics or declare a pickle safe.
pub fn skeleton(bytes: &[u8]) -> Result<PickleOpcodeSkeleton> {
    let mut entries = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if entries.len() >= MAX_SKELETON_OPCODES {
            bail!("pickle skeleton opcode cap exceeded");
        }
        let start = i;
        let op = bytes[i];
        i += 1;
        entries.push(OpcodeSkeletonEntry {
            byte_offset: start as u64,
            opcode: op,
            class: class(op).into(),
        });
        if op == b'.' {
            return Ok(PickleOpcodeSkeleton {
                entries,
                completeness: AnalysisCompleteness::Complete,
            });
        }
        if let Some(n) = fixed_width(op) {
            i = i
                .checked_add(n)
                .ok_or_else(|| anyhow::anyhow!("pickle skeleton overflow"))?;
            if i > bytes.len() {
                bail!("truncated pickle fixed argument")
            };
            continue;
        }
        match op {
            b'I' | b'L' | b'F' | b'S' | b'V' | b'p' | b'g' | b'P' => {
                let rest = &bytes[i..];
                let Some(n) = rest.iter().position(|b| *b == b'\n') else {
                    bail!("truncated pickle line")
                };
                i += n + 1;
            }
            b'c' | b'i' => {
                for _ in 0..2 {
                    let rest = &bytes[i..];
                    let Some(n) = rest.iter().position(|b| *b == b'\n') else {
                        bail!("truncated pickle global")
                    };
                    i += n + 1;
                }
            }
            b'T' | b'B' | b'X' => {
                if i + 4 > bytes.len() {
                    bail!("truncated pickle length")
                };
                let n = u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
                i += 4;
                i = i
                    .checked_add(n)
                    .ok_or_else(|| anyhow::anyhow!("pickle length overflow"))?;
                if i > bytes.len() {
                    bail!("truncated pickle payload")
                };
            }
            b'U' | b'C' | 0x8c => {
                if i >= bytes.len() {
                    bail!("truncated pickle length")
                };
                let n = bytes[i] as usize;
                i += 1;
                i = i
                    .checked_add(n)
                    .ok_or_else(|| anyhow::anyhow!("pickle length overflow"))?;
                if i > bytes.len() {
                    bail!("truncated pickle payload")
                };
            }
            0x8d | 0x8e | 0x96 => {
                if i + 8 > bytes.len() {
                    bail!("truncated pickle length")
                };
                let n = u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
                i += 8;
                let n =
                    usize::try_from(n).map_err(|_| anyhow::anyhow!("pickle argument too large"))?;
                i = i
                    .checked_add(n)
                    .ok_or_else(|| anyhow::anyhow!("pickle length overflow"))?;
                if i > bytes.len() {
                    bail!("truncated pickle payload")
                };
            }
            0x8a => {
                if i >= bytes.len() {
                    bail!("truncated pickle long")
                };
                let n = bytes[i] as usize;
                i += 1 + n;
                if i > bytes.len() {
                    bail!("truncated pickle long")
                };
            }
            0x8b => {
                if i + 4 > bytes.len() {
                    bail!("truncated pickle long")
                };
                let n = u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
                i += 4 + n;
                if i > bytes.len() {
                    bail!("truncated pickle long")
                };
            }
            _ => {}
        }
    }
    Ok(PickleOpcodeSkeleton {
        entries,
        completeness: AnalysisCompleteness::Partial,
    })
}

pub fn compare(bytes: &[u8], primary_opcode_count: usize) -> Result<ParserDifferential> {
    let s = skeleton(bytes)?;
    let matched =
        s.entries.len() == primary_opcode_count && s.completeness == AnalysisCompleteness::Complete;
    Ok(ParserDifferential {
        matched,
        primary_opcode_count,
        skeleton_opcode_count: s.entries.len(),
        first_mismatch: (!matched).then(|| s.entries.last().map(|e| e.byte_offset).unwrap_or(0)),
        completeness: s.completeness,
    })
}
