#[allow(unused_imports)]
use super::*;

pub const MAX_EXCERPT_LINES: usize = 9;
/// Maximum number of bytes retained in a single excerpt.
pub const MAX_EXCERPT_BYTES: usize = 4096;
/// Maximum evidence records attached to one finding.
pub const MAX_EVIDENCE_PER_FINDING: usize = 16;
/// Maximum total evidence payload bytes attached to one finding.
pub const MAX_EVIDENCE_BYTES_PER_FINDING: usize = 32 * 1024;
/// Maximum total evidence payload bytes emitted across one report.
pub const MAX_EVIDENCE_BYTES_PER_REPORT: usize = 4 * 1024 * 1024;
/// Maximum bytes retained for the literal matched value.
pub const MAX_MATCH_VALUE_BYTES: usize = 256;
/// Maximum bytes retained for a structured JSON evidence payload.
pub const MAX_STRUCTURED_BYTES: usize = 8 * 1024;
