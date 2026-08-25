//! Bounded static parser for fastText's `.bin` model binary format.
//!
//! Layerfault never links against or executes fastText. This module parses
//! the documented on-disk layout written by `FastText::saveModel` (magic,
//! version, `Args`, `Dictionary`, then either a dense or product-quantized
//! `input`/`output` matrix pair) using only checked arithmetic and bounded
//! reads, and validates declared sizes against the actual file length
//! instead of trusting them.
//!
//! Reference layout (from fastText's `src/fasttext.cc`, `src/args.cc`,
//! `src/dictionary.cc`, `src/matrix.cc`, `src/quantmatrix.cc`,
//! `src/productquantizer.cc`), all fields little-endian / native x86 layout:
//!
//! ```text
//! magic: i32 (793712314), version: i32
//! Args: 12 x i32, 1 x f64                                   (56 bytes)
//! Dictionary:
//!   size_: i32, nwords_: i32, nlabels_: i32, ntokens_: i64, pruneidx_size_: i64
//!   size_ x { word: NUL-terminated bytes, count: i64, type: i8 }
//!   pruneidx_size_ x { i32, i32 }
//! quant_: bool
//! input matrix: QMatrix if quant_ else DenseMatrix
//! qout: bool
//! output matrix: QMatrix if (quant_ && qout) else DenseMatrix
//!
//! DenseMatrix: m: i64, n: i64, data: m*n x f32
//! QMatrix: qnorm: bool, m: i64, n: i64, codesize: i32, codes: codesize x u8,
//!          pq: ProductQuantizer, [qnorm] { norm_codes: m x u8, npq: ProductQuantizer }
//! ProductQuantizer: dim: i32, nsubq: i32, dsub: i32, lastdsub: i32,
//!                    centroids: dim*256 x f32   (ksub = 2^nbits, nbits fixed at 8)
//! ```

use crate::finding_evidence::{structural_invariant, EvidenceSubject, FindingBuilder};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::Result;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::time::Instant;

const MAGIC: i32 = 793_712_314;
const MAX_SUPPORTED_VERSION: i32 = 12;
const KSUB: u64 = 256; // 2^nbits, nbits is fixed at 8 in fastText's ProductQuantizer
const MAX_DICT_REGION_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DICT_ENTRIES: i64 = 50_000_000;
const MAX_PRUNEIDX_ENTRIES: i64 = 50_000_000;
const MAX_WORD_LEN: usize = 8192;

pub fn scan(file: &File, size: u64, identity: &str, media: &str) -> Result<Vec<LayerScanResult>> {
    let started = Instant::now();
    let subject = EvidenceSubject::identity(identity, media).with_sha256(Some(identity.to_owned()));

    match parse(file, size) {
        Ok(summary) => Ok(vec![pass_finding(
            identity, media, subject, &summary, started,
        )]),
        Err(ParseOutcome::Malformed(reason)) => Ok(vec![FindingBuilder::new(
            "LF-FASTTEXT-STRUCT",
            CheckType::FastTextStructure,
            ScanStatus::Fail,
        )
        .class(FindingClass::Structural)
        .confidence(Confidence::High)
        .digest(identity)
        .media_type(media)
        .subject(subject.clone())
        .detail(format!("fastText .bin structure is malformed: {reason}"))
        .evidence(structural_invariant(
            subject,
            "fastText structural validation",
            serde_json::json!({ "outcome": "malformed", "reason": reason }),
        ))
        .started(started)
        .finish()]),
        Err(ParseOutcome::ExceedsBounds(reason)) => Ok(vec![FindingBuilder::new(
            "LF-FASTTEXT-LIMIT",
            CheckType::FastTextStructure,
            ScanStatus::Warn,
        )
        .class(FindingClass::Compatibility)
        .confidence(Confidence::High)
        .digest(identity)
        .media_type(media)
        .subject(subject.clone())
        .detail(format!(
            "fastText .bin declares sizes beyond this parser's safety bound: {reason}"
        ))
        .evidence(structural_invariant(
            subject,
            "fastText parser safety bound",
            serde_json::json!({ "outcome": "incomplete", "reason": reason }),
        ))
        .started(started)
        .finish()]),
    }
}

fn pass_finding(
    identity: &str,
    media: &str,
    subject: EvidenceSubject,
    summary: &ModelSummary,
    started: Instant,
) -> LayerScanResult {
    FindingBuilder::new(
        "LF-FASTTEXT-STRUCT",
        CheckType::FastTextStructure,
        ScanStatus::Pass,
    )
    .class(FindingClass::Structural)
    .confidence(Confidence::High)
    .digest(identity)
    .media_type(media)
    .subject(subject.clone())
    .detail(format!(
        "Valid fastText .bin model, version {}, {} dictionary entries, quantized={}",
        summary.version, summary.dict_size, summary.quantized
    ))
    .evidence(structural_invariant(
        subject,
        "fastText model header",
        serde_json::json!({
            "version": summary.version,
            "dim": summary.dim,
            "model": summary.model,
            "loss": summary.loss,
            "bucket": summary.bucket,
            "dict_size": summary.dict_size,
            "nwords": summary.nwords,
            "nlabels": summary.nlabels,
            "ntokens": summary.ntokens,
            "pruneidx_size": summary.pruneidx_size,
            "quantized": summary.quantized,
            "input_shape": summary.input_shape,
            "output_shape": summary.output_shape,
            "trailing_bytes": summary.trailing_bytes,
        }),
    ))
    .started(started)
    .finish()
}

struct ModelSummary {
    version: i32,
    dim: i32,
    model: i32,
    loss: i32,
    bucket: i32,
    dict_size: i32,
    nwords: i32,
    nlabels: i32,
    ntokens: i64,
    pruneidx_size: i64,
    quantized: bool,
    input_shape: (i64, i64),
    output_shape: (i64, i64),
    trailing_bytes: u64,
}

enum ParseOutcome {
    Malformed(String),
    ExceedsBounds(String),
}

fn parse(file: &File, size: u64) -> Result<ModelSummary, ParseOutcome> {
    let mut cur = Cursor::new(file, size);

    let magic = cur.read_i32()?;
    if magic != MAGIC {
        return Err(ParseOutcome::Malformed(format!(
            "magic {magic:#x} does not match fastText's expected {MAGIC:#x}"
        )));
    }
    let version = cur.read_i32()?;
    if version < 0 {
        return Err(ParseOutcome::Malformed(format!(
            "version {version} is negative"
        )));
    }
    if version > MAX_SUPPORTED_VERSION {
        return Err(ParseOutcome::ExceedsBounds(format!(
            "version {version} is newer than supported version {MAX_SUPPORTED_VERSION}"
        )));
    }

    // Args: 12 x i32, 1 x f64.
    let dim = cur.read_i32()?;
    let ws = cur.read_i32()?;
    let epoch = cur.read_i32()?;
    let min_count = cur.read_i32()?;
    let neg = cur.read_i32()?;
    let word_ngrams = cur.read_i32()?;
    let loss = cur.read_i32()?;
    let model = cur.read_i32()?;
    let bucket = cur.read_i32()?;
    let minn = cur.read_i32()?;
    let maxn = cur.read_i32()?;
    let lr_update_rate = cur.read_i32()?;
    let _t = cur.read_f64()?;
    let _ = (
        ws,
        epoch,
        min_count,
        neg,
        word_ngrams,
        minn,
        maxn,
        lr_update_rate,
    );

    let (dict_size, nwords, nlabels, ntokens, pruneidx_size) = parse_dictionary(file, &mut cur)?;

    let quant = cur.read_bool()?;
    let input_shape = parse_matrix(&mut cur, quant)?;
    let qout = cur.read_bool()?;
    let output_shape = parse_matrix(&mut cur, quant && qout)?;

    let trailing_bytes = size.saturating_sub(cur.pos);

    Ok(ModelSummary {
        version,
        dim,
        model,
        loss,
        bucket,
        dict_size,
        nwords,
        nlabels,
        ntokens,
        pruneidx_size,
        quantized: quant,
        input_shape,
        output_shape,
        trailing_bytes,
    })
}

/// Parse the `Dictionary` section. Its total byte length isn't declared
/// upfront, so entries are streamed through a bounded buffered reader. This
/// avoids allocating the entire dictionary while still enforcing a hard byte
/// ceiling independent of attacker-controlled entry counts.
fn parse_dictionary(
    file: &File,
    cur: &mut Cursor,
) -> Result<(i32, i32, i32, i64, i64), ParseOutcome> {
    let region_start = cur.pos;
    let mut reader = file
        .try_clone()
        .map_err(|error| ParseOutcome::Malformed(error.to_string()))?;
    reader
        .seek(SeekFrom::Start(region_start))
        .map_err(|error| ParseOutcome::Malformed(error.to_string()))?;
    let remaining = cur.size.saturating_sub(region_start);
    let mut r = DictionaryCursor::new(reader, remaining.min(MAX_DICT_REGION_BYTES), remaining);
    let size_ = r.read_i32()?;
    let nwords = r.read_i32()?;
    let nlabels = r.read_i32()?;
    let ntokens = r.read_i64()?;
    let pruneidx_size = r.read_i64()?;

    if size_ < 0 || size_ as i64 > MAX_DICT_ENTRIES {
        return Err(ParseOutcome::ExceedsBounds(format!(
            "dictionary declares {size_} entries, exceeding safety cap {MAX_DICT_ENTRIES}"
        )));
    }
    if !(-1..=MAX_PRUNEIDX_ENTRIES).contains(&pruneidx_size) {
        return Err(ParseOutcome::ExceedsBounds(format!(
            "dictionary declares {pruneidx_size} pruned indices, exceeding safety cap {MAX_PRUNEIDX_ENTRIES}"
        )));
    }

    for _ in 0..size_ {
        let word = r.read_cstring(MAX_WORD_LEN)?;
        let _count = r.read_i64()?;
        let entry_type = r.read_i8()?;
        if entry_type != 0 && entry_type != 1 {
            return Err(ParseOutcome::Malformed(format!(
                "dictionary entry {:?} has invalid type byte {entry_type} (expected 0=word or 1=label)",
                String::from_utf8_lossy(&word)
            )));
        }
    }
    for _ in 0..pruneidx_size.max(0) {
        let _first = r.read_i32()?;
        let _second = r.read_i32()?;
    }

    cur.pos = region_start
        .checked_add(r.pos)
        .ok_or_else(|| ParseOutcome::Malformed("dictionary region offset overflow".to_owned()))?;

    Ok((size_, nwords, nlabels, ntokens, pruneidx_size))
}

fn parse_matrix(cur: &mut Cursor, quantized: bool) -> Result<(i64, i64), ParseOutcome> {
    if quantized {
        parse_qmatrix(cur)
    } else {
        parse_dense_matrix(cur)
    }
}

fn parse_dense_matrix(cur: &mut Cursor) -> Result<(i64, i64), ParseOutcome> {
    let m = cur.read_i64()?;
    let n = cur.read_i64()?;
    let elements = non_negative_product(m, n)?;
    let bytes = elements.checked_mul(4).ok_or_else(|| {
        ParseOutcome::Malformed("dense matrix byte size overflowed u64".to_owned())
    })?;
    cur.skip(bytes)?;
    Ok((m, n))
}

fn parse_qmatrix(cur: &mut Cursor) -> Result<(i64, i64), ParseOutcome> {
    let qnorm = cur.read_bool()?;
    let m = cur.read_i64()?;
    let n = cur.read_i64()?;
    let codesize = cur.read_i32()?;
    if codesize < 0 {
        return Err(ParseOutcome::Malformed(format!(
            "quantized matrix codesize {codesize} is negative"
        )));
    }
    cur.skip(codesize as u64)?;
    let (pq_dim, pq_nsubq) = parse_product_quantizer(cur)?;
    if pq_dim as i64 != n {
        return Err(ParseOutcome::Malformed(format!(
            "quantized matrix width {n} disagrees with product quantizer dimension {pq_dim}"
        )));
    }
    let expected_codes = non_negative_product(m, i64::from(pq_nsubq))?;
    if codesize as u64 != expected_codes {
        return Err(ParseOutcome::Malformed(format!(
            "quantized matrix codesize {codesize} does not match rows*subquantizers {expected_codes}"
        )));
    }

    if qnorm {
        if m < 0 {
            return Err(ParseOutcome::Malformed(format!(
                "quantized matrix row count {m} is negative"
            )));
        }
        cur.skip(m as u64)?;
        let (norm_dim, norm_nsubq) = parse_product_quantizer(cur)?;
        if norm_dim != 1 || norm_nsubq != 1 {
            return Err(ParseOutcome::Malformed(format!(
                "norm product quantizer has shape ({norm_dim}, {norm_nsubq}), expected (1, 1)"
            )));
        }
    }

    Ok((m, n))
}

fn parse_product_quantizer(cur: &mut Cursor) -> Result<(i32, i32), ParseOutcome> {
    let dim = cur.read_i32()?;
    let nsubq = cur.read_i32()?;
    let dsub = cur.read_i32()?;
    let lastdsub = cur.read_i32()?;
    if dim <= 0 || nsubq <= 0 || dsub <= 0 || lastdsub <= 0 || lastdsub > dsub {
        return Err(ParseOutcome::Malformed(format!(
            "invalid product quantizer dimensions ({dim}, {nsubq}, {dsub}, {lastdsub})"
        )));
    }
    let expected_nsubq = dim.checked_add(dsub - 1).ok_or_else(|| {
        ParseOutcome::Malformed("product quantizer dimension overflow".to_owned())
    })? / dsub;
    let expected_lastdsub = dim
        .checked_sub((nsubq - 1).saturating_mul(dsub))
        .ok_or_else(|| ParseOutcome::Malformed("product quantizer shape underflow".to_owned()))?;
    if nsubq != expected_nsubq || lastdsub != expected_lastdsub {
        return Err(ParseOutcome::Malformed(format!(
            "inconsistent product quantizer dimensions ({dim}, {nsubq}, {dsub}, {lastdsub})"
        )));
    }
    let centroids = (dim as u64)
        .checked_mul(KSUB)
        .and_then(|v| v.checked_mul(4))
        .ok_or_else(|| {
            ParseOutcome::Malformed("product quantizer centroid size overflowed u64".to_owned())
        })?;
    cur.skip(centroids)?;
    Ok((dim, nsubq))
}

fn non_negative_product(m: i64, n: i64) -> Result<u64, ParseOutcome> {
    if m < 0 || n < 0 {
        return Err(ParseOutcome::Malformed(format!(
            "matrix shape ({m}, {n}) has a negative dimension"
        )));
    }
    (m as u64)
        .checked_mul(n as u64)
        .ok_or_else(|| ParseOutcome::Malformed("matrix element count overflowed u64".to_owned()))
}

/// Tracks a logical file offset and validates every read/skip against the
/// declared file size with checked arithmetic before performing it.
struct Cursor<'a> {
    file: &'a File,
    pos: u64,
    size: u64,
}

impl<'a> Cursor<'a> {
    fn new(file: &'a File, size: u64) -> Self {
        Self { file, pos: 0, size }
    }

    fn skip(&mut self, n: u64) -> Result<(), ParseOutcome> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| ParseOutcome::Malformed("offset overflowed u64".to_owned()))?;
        if end > self.size {
            return Err(ParseOutcome::Malformed(format!(
                "truncated: need {n} more bytes at offset {}, file has {} bytes",
                self.pos, self.size
            )));
        }
        self.pos = end;
        Ok(())
    }

    fn read_bytes(&mut self, n: u64) -> Result<Vec<u8>, ParseOutcome> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| ParseOutcome::Malformed("offset overflowed u64".to_owned()))?;
        if end > self.size {
            return Err(ParseOutcome::Malformed(format!(
                "truncated: need {n} more bytes at offset {}, file has {} bytes",
                self.pos, self.size
            )));
        }
        let mut buf = vec![0u8; n as usize];
        let mut reader = self
            .file
            .try_clone()
            .map_err(|error| ParseOutcome::Malformed(error.to_string()))?;
        reader
            .seek(SeekFrom::Start(self.pos))
            .map_err(|error| ParseOutcome::Malformed(error.to_string()))?;
        reader
            .read_exact(&mut buf)
            .map_err(|error| ParseOutcome::Malformed(error.to_string()))?;
        self.pos = end;
        Ok(buf)
    }

    fn read_i32(&mut self) -> Result<i32, ParseOutcome> {
        let b = self.read_bytes(4)?;
        Ok(i32::from_le_bytes(b.try_into().expect("4 bytes")))
    }

    fn read_i64(&mut self) -> Result<i64, ParseOutcome> {
        let b = self.read_bytes(8)?;
        Ok(i64::from_le_bytes(b.try_into().expect("8 bytes")))
    }

    fn read_f64(&mut self) -> Result<f64, ParseOutcome> {
        let b = self.read_bytes(8)?;
        Ok(f64::from_le_bytes(b.try_into().expect("8 bytes")))
    }

    fn read_bool(&mut self) -> Result<bool, ParseOutcome> {
        let b = self.read_bytes(1)?[0];
        match b {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(ParseOutcome::Malformed(format!(
                "expected a boolean byte (0 or 1), found {other}"
            ))),
        }
    }
}

struct DictionaryCursor {
    reader: BufReader<File>,
    pos: u64,
    limit: u64,
    source_remaining: u64,
}

impl DictionaryCursor {
    fn new(reader: File, limit: u64, source_remaining: u64) -> Self {
        Self {
            reader: BufReader::new(reader),
            pos: 0,
            limit,
            source_remaining,
        }
    }

    fn read_exact<const N: usize>(&mut self) -> Result<[u8; N], ParseOutcome> {
        let end = self.pos.checked_add(N as u64).ok_or_else(|| {
            ParseOutcome::Malformed("dictionary region offset overflowed".to_owned())
        })?;
        if end > self.limit {
            return if self.source_remaining > self.limit {
                Err(ParseOutcome::ExceedsBounds(format!(
                    "dictionary content exceeds the {} byte safety window",
                    self.limit
                )))
            } else {
                Err(ParseOutcome::Malformed(
                    "dictionary content is truncated at end of file".to_owned(),
                ))
            };
        }
        let mut bytes = [0u8; N];
        self.reader.read_exact(&mut bytes).map_err(|error| {
            ParseOutcome::Malformed(format!("truncated dictionary content: {error}"))
        })?;
        self.pos = end;
        Ok(bytes)
    }

    fn read_i32(&mut self) -> Result<i32, ParseOutcome> {
        Ok(i32::from_le_bytes(self.read_exact()?))
    }

    fn read_i64(&mut self) -> Result<i64, ParseOutcome> {
        Ok(i64::from_le_bytes(self.read_exact()?))
    }

    fn read_i8(&mut self) -> Result<i8, ParseOutcome> {
        Ok(self.read_exact::<1>()?[0] as i8)
    }

    fn read_cstring(&mut self, max_len: usize) -> Result<Vec<u8>, ParseOutcome> {
        let mut out = Vec::new();
        loop {
            if out.len() >= max_len {
                return Err(ParseOutcome::ExceedsBounds(format!(
                    "dictionary word exceeds max length {max_len} without a NUL terminator"
                )));
            }
            let byte = self.read_exact::<1>()?[0];
            if byte == 0 {
                return Ok(out);
            }
            out.push(byte);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn args_bytes(dim: i32) -> Vec<u8> {
        let mut out = Vec::new();
        // dim, ws, epoch, minCount, neg, wordNgrams, loss, model, bucket, minn, maxn, lrUpdateRate
        for value in [dim, 5, 5, 5, 5, 1, 1, 2, 2, 3, 6, 100] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.extend_from_slice(&0.05f64.to_le_bytes()); // t
        out
    }

    fn dictionary_bytes(words: &[(&str, i64, i8)], pruneidx: &[(i32, i32)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(words.len() as i32).to_le_bytes()); // size_
        out.extend_from_slice(&(words.len() as i32).to_le_bytes()); // nwords_
        out.extend_from_slice(&0i32.to_le_bytes()); // nlabels_
        out.extend_from_slice(&100i64.to_le_bytes()); // ntokens_
        let pruneidx_size = if pruneidx.is_empty() {
            -1
        } else {
            pruneidx.len() as i64
        };
        out.extend_from_slice(&pruneidx_size.to_le_bytes()); // pruneidx_size_
        for (word, count, entry_type) in words {
            out.extend_from_slice(word.as_bytes());
            out.push(0);
            out.extend_from_slice(&count.to_le_bytes());
            out.push(*entry_type as u8);
        }
        for (a, b) in pruneidx {
            out.extend_from_slice(&a.to_le_bytes());
            out.extend_from_slice(&b.to_le_bytes());
        }
        out
    }

    fn dense_matrix_bytes(m: i64, n: i64) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&m.to_le_bytes());
        out.extend_from_slice(&n.to_le_bytes());
        out.extend(std::iter::repeat_n(0u8, (m * n * 4) as usize));
        out
    }

    fn valid_model_bytes() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&12i32.to_le_bytes()); // version
        out.extend_from_slice(&args_bytes(100));
        out.extend_from_slice(&dictionary_bytes(
            &[("hello", 10, 0), ("world", 8, 0), ("__label__pos", 3, 1)],
            &[],
        ));
        out.push(0); // quant_ = false
        out.extend_from_slice(&dense_matrix_bytes(5, 100)); // input: nwords+bucket rows
        out.push(0); // qout = false
        out.extend_from_slice(&dense_matrix_bytes(1, 100)); // output
        out
    }

    fn write_temp(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("tempfile");
        file.write_all(bytes).expect("write");
        file
    }

    #[test]
    fn valid_model_parses_cleanly() {
        let bytes = valid_model_bytes();
        let file = write_temp(&bytes);
        let results = scan(
            file.as_file(),
            bytes.len() as u64,
            "sha256:fasttext-test",
            "application/x-fasttext-bin",
        )
        .expect("scan does not error");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ScanStatus::Pass);
        assert_eq!(crate::policy::rule_id(&results[0]), "LF-FASTTEXT-STRUCT");
    }

    #[test]
    fn wrong_magic_is_malformed() {
        let mut bytes = valid_model_bytes();
        bytes[0] ^= 0xff;
        let file = write_temp(&bytes);
        let results = scan(
            file.as_file(),
            bytes.len() as u64,
            "sha256:fasttext-test",
            "application/x-fasttext-bin",
        )
        .expect("scan does not error");
        assert_eq!(results[0].status, ScanStatus::Fail);
        assert_eq!(crate::policy::rule_id(&results[0]), "LF-FASTTEXT-STRUCT");
        assert!(!results[0].evidence.is_empty());
    }

    #[test]
    fn truncated_args_is_malformed() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC.to_le_bytes());
        bytes.extend_from_slice(&12i32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 10]); // far short of the 56-byte Args block
        let file = write_temp(&bytes);
        let results = scan(
            file.as_file(),
            bytes.len() as u64,
            "sha256:fasttext-test",
            "application/x-fasttext-bin",
        )
        .expect("scan does not error");
        assert_eq!(results[0].status, ScanStatus::Fail);
    }

    #[test]
    fn invalid_dictionary_entry_type_is_malformed() {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&12i32.to_le_bytes());
        out.extend_from_slice(&args_bytes(10));
        out.extend_from_slice(&dictionary_bytes(&[("bad", 1, 9)], &[]));
        let file = write_temp(&out);
        let results = scan(
            file.as_file(),
            out.len() as u64,
            "sha256:fasttext-test",
            "application/x-fasttext-bin",
        )
        .expect("scan does not error");
        assert_eq!(results[0].status, ScanStatus::Fail);
    }

    #[test]
    fn oversized_dictionary_size_hits_safety_bound() {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&12i32.to_le_bytes());
        out.extend_from_slice(&args_bytes(10));
        out.extend_from_slice(&(i32::MAX).to_le_bytes()); // size_
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&0i64.to_le_bytes());
        out.extend_from_slice(&0i64.to_le_bytes());
        let file = write_temp(&out);
        let results = scan(
            file.as_file(),
            out.len() as u64,
            "sha256:fasttext-test",
            "application/x-fasttext-bin",
        )
        .expect("scan does not error");
        assert_eq!(results[0].status, ScanStatus::Warn);
        assert_eq!(crate::policy::rule_id(&results[0]), "LF-FASTTEXT-LIMIT");
        assert!(!results[0].evidence.is_empty());
    }

    #[test]
    fn truncated_matrix_payload_is_malformed() {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&12i32.to_le_bytes());
        out.extend_from_slice(&args_bytes(10));
        out.extend_from_slice(&dictionary_bytes(&[("hi", 1, 0)], &[]));
        out.push(0); // quant_
        out.extend_from_slice(&100i64.to_le_bytes()); // m
        out.extend_from_slice(&10i64.to_le_bytes()); // n
        out.extend_from_slice(&[0u8; 16]); // far short of 100*10*4 bytes
        let file = write_temp(&out);
        let results = scan(
            file.as_file(),
            out.len() as u64,
            "sha256:fasttext-test",
            "application/x-fasttext-bin",
        )
        .expect("scan does not error");
        assert_eq!(results[0].status, ScanStatus::Fail);
    }

    #[test]
    fn quantized_model_parses_cleanly() {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&12i32.to_le_bytes());
        out.extend_from_slice(&args_bytes(4));
        out.extend_from_slice(&dictionary_bytes(&[("hi", 1, 0)], &[]));
        out.push(1); // quant_ = true

        // QMatrix: qnorm(false), m, n, codesize, codes, PQ{dim,nsubq,dsub,lastdsub,centroids}
        out.push(0); // qnorm_
        out.extend_from_slice(&3i64.to_le_bytes()); // m
        out.extend_from_slice(&4i64.to_le_bytes()); // n
        out.extend_from_slice(&3i32.to_le_bytes()); // codesize = rows * nsubq
        out.extend(std::iter::repeat_n(0u8, 3));
        out.extend_from_slice(&4i32.to_le_bytes()); // pq.dim
        out.extend_from_slice(&1i32.to_le_bytes()); // pq.nsubq
        out.extend_from_slice(&4i32.to_le_bytes()); // pq.dsub
        out.extend_from_slice(&4i32.to_le_bytes()); // pq.lastdsub
        out.extend(std::iter::repeat_n(0u8, 4 * 256 * 4)); // centroids

        out.push(0); // qout = false
        out.extend_from_slice(&dense_matrix_bytes(1, 4)); // output (dense, since qout=false)

        let file = write_temp(&out);
        let results = scan(
            file.as_file(),
            out.len() as u64,
            "sha256:fasttext-test",
            "application/x-fasttext-bin",
        )
        .expect("scan does not error");
        assert_eq!(results[0].status, ScanStatus::Pass);
    }

    #[test]
    fn future_version_is_incomplete_not_malformed() {
        let mut bytes = valid_model_bytes();
        bytes[4..8].copy_from_slice(&(MAX_SUPPORTED_VERSION + 1).to_le_bytes());
        let file = write_temp(&bytes);
        let results = scan(
            file.as_file(),
            bytes.len() as u64,
            "sha256:fasttext-test",
            "application/x-fasttext-bin",
        )
        .expect("scan does not error");
        assert_eq!(results[0].status, ScanStatus::Warn);
        assert_eq!(crate::policy::rule_id(&results[0]), "LF-FASTTEXT-LIMIT");
    }
}
