use super::{decode::*, evidence::*, normalize::*, signatures::*};
use crate::scanner::{
    duration_ms, scratch, CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus,
    STREAM_CHUNK_BYTES,
};
use anyhow::Result;
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::time::Instant;

#[derive(Default)]
pub(super) struct ScanAccumulator {
    hits: Vec<SignatureHit<'static>>,
    retained_per_signature: Vec<usize>,
    counted_per_signature: Vec<usize>,
    total_hits: usize,
    match_count_truncated: bool,
    any_fail: bool,
    attack_categories: HashSet<&'static str>,
    invalid_utf8_replacements: usize,
    invisible_removed: usize,
    confusables_mapped: usize,
    decoded_hits: usize,
    decode_truncated: bool,
}

impl ScanAccumulator {
    fn new() -> Self {
        Self {
            retained_per_signature: vec![0; SIGNATURES.len()],
            counted_per_signature: vec![0; SIGNATURES.len()],
            ..Self::default()
        }
    }

    fn record_normalization(
        &mut self,
        invalid_utf8_replacements: usize,
        invisible_removed: usize,
        confusables_mapped: usize,
    ) {
        self.invalid_utf8_replacements = self
            .invalid_utf8_replacements
            .saturating_add(invalid_utf8_replacements);
        self.invisible_removed = self.invisible_removed.saturating_add(invisible_removed);
        self.confusables_mapped = self.confusables_mapped.saturating_add(confusables_mapped);
    }

    fn scan_text(&mut self, content: &str, ignore_matches_ending_at_or_before: usize) {
        self.scan_text_inner(content, ignore_matches_ending_at_or_before, None, false);
    }

    pub(super) fn scan_decoded_text(&mut self, content: &str, encoding: &'static str) {
        self.scan_text_inner(content, 0, Some(encoding), true);
    }

    fn scan_text_inner(
        &mut self,
        content: &str,
        ignore_matches_ending_at_or_before: usize,
        decoded_via: Option<&'static str>,
        decoded_only: bool,
    ) {
        let matched_rules = SIGNATURE_SET.matches(content);
        for index in matched_rules.iter() {
            let compiled = &COMPILED_SIGNATURES[index];
            if decoded_only && !is_decoded_rescan_family(compiled.signature.id) {
                continue;
            }
            self.any_fail |= compiled.signature.severity == ScanStatus::Fail;
            if is_t1_to_t6(compiled.signature.id) {
                self.attack_categories.insert(compiled.signature.category);
            }
            if self.counted_per_signature[index] >= MAX_COUNTED_PER_SIGNATURE {
                self.match_count_truncated = true;
                continue;
            }
            for matched in compiled.regex.find_iter(content) {
                if matched.end() <= ignore_matches_ending_at_or_before {
                    continue;
                }
                if self.counted_per_signature[index] >= MAX_COUNTED_PER_SIGNATURE {
                    self.match_count_truncated = true;
                    break;
                }
                self.counted_per_signature[index] += 1;
                self.total_hits = self.total_hits.saturating_add(1);
                if decoded_via.is_some() {
                    self.decoded_hits = self.decoded_hits.saturating_add(1);
                }
                if self.hits.len() >= MAX_RETAINED_MATCHES
                    || self.retained_per_signature[index] >= MAX_RETAINED_PER_SIGNATURE
                {
                    continue;
                }
                self.retained_per_signature[index] += 1;
                self.hits.push(SignatureHit {
                    signature: compiled.signature,
                    context: redacted_context_window(content, matched.start(), matched.end()),
                    decoded_via,
                    text_offset: matched.start(),
                });
            }
        }
    }

    fn into_result(
        self,
        layer_digest: &str,
        media_type: &str,
        elapsed_ms: u64,
        bytes_scanned: usize,
    ) -> LayerScanResult {
        let matches: Vec<String> = self
            .hits
            .iter()
            .map(|hit| match hit.decoded_via {
                Some(encoding) => format!(
                    "[LF-HEUR-DECODED-MATCH] [{}] {} after bounded {} decode: '{}'",
                    hit.signature.id,
                    hit.signature.description,
                    encoding,
                    hit.context.trim()
                ),
                None => format!(
                    "[{}] {}: '{}'",
                    hit.signature.id,
                    hit.signature.description,
                    hit.context.trim()
                ),
            })
            .collect();
        let retained = matches.len();
        let suppressed = self.total_hits.saturating_sub(retained);
        let mut sorted_categories: Vec<&str> = self.attack_categories.iter().copied().collect();
        sorted_categories.sort_unstable();
        let normalization = if self.invalid_utf8_replacements > 0
            || self.invisible_removed > 0
            || self.confusables_mapped > 0
        {
            Some(format!(
                " normalized {} invalid UTF-8 sequence(s), removed {} invisible/bidi control character(s), and mapped {} common Unicode confusable(s) for detection;",
                self.invalid_utf8_replacements, self.invisible_removed, self.confusables_mapped
            ))
        } else {
            None
        };
        let counted = if self.match_count_truncated {
            format!("at least {}", self.total_hits)
        } else {
            self.total_hits.to_string()
        };
        let count_note = if self.match_count_truncated {
            " Match counting was capped per signature to bound adversarial CPU/report amplification."
        } else {
            ""
        };
        let evidence_note = if suppressed > 0 {
            format!(
                " {counted} match(es) observed; {retained} evidence item(s) retained and {suppressed} suppressed by bounded reporting.{count_note}"
            )
        } else if self.total_hits > 0 {
            format!(" {counted} match(es) observed.{count_note}")
        } else {
            String::new()
        };

        let (status, class, detail, confidence) = if self.total_hits == 0 {
            if self.decode_truncated {
                (
                    ScanStatus::Warn,
                    FindingClass::Operational,
                    Some(format!(
                        "Heuristic decode/rescan budget was exhausted after bounded analysis of {bytes_scanned} byte(s); coverage is incomplete.{}",
                        normalization.as_deref().unwrap_or_default()
                    )),
                    Confidence::High,
                )
            } else {
                (
                    ScanStatus::Pass,
                    FindingClass::ContentIndicator,
                    normalization.map(|value| format!(
                        "Heuristic scan completed after normalization;{value} no security signature matched."
                    )),
                    Confidence::High,
                )
            }
        } else if self.attack_categories.len() >= 3 {
            (
                ScanStatus::Fail,
                FindingClass::ContentIndicator,
                Some(format!(
                    "Corroborated multi-vector content attack: {} T1-T6 categories triggered ({}).{}{}",
                    self.attack_categories.len(),
                    sorted_categories.join(", "),
                    normalization.unwrap_or_default(),
                    evidence_note
                )),
                Confidence::High,
            )
        } else if self.any_fail {
            (
                ScanStatus::Fail,
                FindingClass::ContentIndicator,
                Some(format!(
                    "High-severity content indicator(s) matched.{}{}",
                    normalization.unwrap_or_default(),
                    evidence_note
                )),
                Confidence::Medium,
            )
        } else {
            (
                ScanStatus::Warn,
                FindingClass::ContentIndicator,
                Some(format!(
                    "Suspicious content/policy indicator(s) matched; review context before blocking.{}{}",
                    normalization.unwrap_or_default(),
                    evidence_note
                )),
                Confidence::Medium,
            )
        };

        let subject = crate::finding_evidence::EvidenceSubject::identity(layer_digest, media_type)
            .with_sha256(Some(layer_digest.to_owned()));
        // Multiple distinct signature families (T1-T14) can fire within one
        // scanned blob; this finding aggregates them the way it always has.
        // Evidence is still per-hit and per-rule via each record's own
        // `description`, and `rule_id` below picks the first hit's signature
        // for identity purposes, matching `policy::rule_id`'s pre-existing
        // first-bracket convention.
        let mut evidence: Vec<crate::finding_evidence::FindingEvidence> = self
            .hits
            .iter()
            .map(|hit| {
                let description = match hit.decoded_via {
                    Some(encoding) => format!(
                        "{} matched after bounded {} decode",
                        hit.signature.description, encoding
                    ),
                    None => hit.signature.description.to_owned(),
                };
                crate::finding_evidence::FindingEvidence::new(
                    crate::finding_evidence::EvidenceKind::SourceExcerpt,
                    subject.clone(),
                    &description,
                )
                .at(crate::finding_evidence::EvidenceLocation::ByteRange {
                    offset: hit.text_offset as u64,
                    length: hit.context.len() as u64,
                })
                .excerpt(&hit.context)
                .matched(hit.signature.id)
            })
            .collect();
        evidence.truncate(crate::finding_evidence::MAX_EVIDENCE_PER_FINDING);

        let rule_id = if self.hits.iter().any(|hit| hit.decoded_via.is_some()) {
            "LF-HEUR-DECODED-MATCH".to_owned()
        } else {
            self.hits
                .first()
                .map(|hit| hit.signature.id.to_owned())
                .unwrap_or_else(|| "LF-HEUR-CLEAR".to_owned())
        };

        let mut finding = LayerScanResult {
            layer_digest: layer_digest.to_owned(),
            media_type: media_type.to_owned(),
            check_type: CheckType::HeuristicSignature,
            status,
            finding_class: class,
            confidence,
            detail,
            matches,
            duration_ms: elapsed_ms,
            evidence,
            ..Default::default()
        };
        crate::finding_evidence::ensure_finding_identity(&mut finding, &rule_id);
        finding
    }
}

pub struct HeuristicsScanner;

impl HeuristicsScanner {
    pub fn scan_file(file: &File, layer_digest: &str, media_type: &str) -> Result<LayerScanResult> {
        let started = Instant::now();
        let len = file.metadata()?.len();
        let mut reader = file.try_clone()?;
        reader.seek(SeekFrom::Start(0))?;
        // Size the retained buffer to this file's actual length rather than always
        // pinning a full STREAM_CHUNK_BYTES per worker thread; see the matching
        // comment in ScanSession::run for why this matters for package scans.
        let mut buffer = scratch::take_read_buf(
            usize::try_from(len.max(1))
                .unwrap_or(usize::MAX)
                .min(STREAM_CHUNK_BYTES),
        );
        let mut raw_window = scratch::take_window_buf();
        let mut normalize_buf = scratch::take_normalize_buf();
        let mut carry = Vec::<u8>::new();
        let mut accumulator = ScanAccumulator::new();
        let mut decode_budget = DecodeBudget::default();
        let mut bytes_scanned = 0usize;

        let scan_result = (|| -> Result<()> {
            loop {
                let count = reader.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                bytes_scanned = bytes_scanned.saturating_add(count);
                // Normalize the overlap and new bytes as one window. Doing this before
                // splitting text avoids treating a valid multibyte UTF-8 scalar that
                // happens to cross the I/O boundary as malformed input.
                raw_window.clear();
                raw_window.extend_from_slice(&carry);
                raw_window.extend_from_slice(&buffer[..count]);
                let (invalid, invisible, confusables) =
                    normalize_detection_bytes_into(&raw_window, &mut normalize_buf);
                accumulator.record_normalization(invalid, invisible, confusables);

                // The normalized prefix can be a few bytes longer than the same prefix
                // inside `window` when `carry` ends midway through a UTF-8 scalar. Back
                // the suppression boundary up by four bytes so a cross-boundary match
                // cannot be hidden. At worst this recounts a tiny overlap; evidence is
                // bounded independently.
                let ignore_before = normalized_detection_len(&carry).saturating_sub(4);
                accumulator.scan_text(&normalize_buf, ignore_before);
                scan_decoded_candidates(&normalize_buf, &mut accumulator, &mut decode_budget, 0);
                update_carry(&mut carry, &buffer[..count]);
            }
            Ok(())
        })();

        scratch::return_read_buf(buffer);
        scratch::return_window_buf(raw_window);
        scratch::return_normalize_buf(normalize_buf);
        scan_result?;

        debug_assert_eq!(u64::try_from(bytes_scanned).unwrap_or(u64::MAX), len);
        accumulator.decode_truncated = decode_budget.exhausted;
        Ok(accumulator.into_result(
            layer_digest,
            media_type,
            duration_ms(started),
            bytes_scanned,
        ))
    }

    pub fn scan_content(
        content: &str,
        layer_digest: &str,
        duration_ms: u64,
    ) -> Result<LayerScanResult> {
        scan_content_for_media(
            content,
            layer_digest,
            "application/vnd.ollama.image.template",
            duration_ms,
        )
    }

    pub fn scan_content_for_media(
        content: &str,
        layer_digest: &str,
        media_type: &str,
        duration_ms: u64,
    ) -> Result<LayerScanResult> {
        scan_content_for_media(content, layer_digest, media_type, duration_ms)
    }

    pub fn scan_template_content_for_media(
        content: &str,
        layer_digest: &str,
        media_type: &str,
        duration_ms: u64,
    ) -> Result<LayerScanResult> {
        let mut base_result =
            scan_content_for_media(content, layer_digest, media_type, duration_ms)?;
        let limits = crate::template_static::TemplateLimits::default();
        let analysis = crate::template_static::analyze_template(content, media_type, &limits);
        let template_result = crate::template_static::build_layer_scan_result(
            analysis,
            layer_digest,
            media_type,
            duration_ms,
        );

        if template_result.status != ScanStatus::Pass {
            base_result.status = template_result.status;
            base_result.rule_id = template_result.rule_id;
            base_result.detail = template_result.detail;
            base_result.matches.extend(template_result.matches);
            base_result.evidence.extend(template_result.evidence);
            base_result.finding_id = template_result.finding_id;
        }

        Ok(base_result)
    }
}

#[allow(dead_code)]
pub(crate) fn scan_content(
    content: &str,
    layer_digest: &str,
    duration_ms: u64,
) -> Result<LayerScanResult> {
    scan_content_for_media(
        content,
        layer_digest,
        "application/vnd.ollama.image.template",
        duration_ms,
    )
}

pub(crate) fn scan_content_for_media(
    content: &str,
    layer_digest: &str,
    media_type: &str,
    duration_ms: u64,
) -> Result<LayerScanResult> {
    let (normalized, invalid, invisible, confusables) =
        normalize_detection_bytes(content.as_bytes());
    let mut accumulator = ScanAccumulator::new();
    accumulator.record_normalization(invalid, invisible, confusables);
    accumulator.scan_text(&normalized, 0);
    let mut decode_budget = DecodeBudget::default();
    scan_decoded_candidates(&normalized, &mut accumulator, &mut decode_budget, 0);
    accumulator.decode_truncated = decode_budget.exhausted;
    Ok(accumulator.into_result(layer_digest, media_type, duration_ms, content.len()))
}

fn update_carry(carry: &mut Vec<u8>, chunk: &[u8]) {
    if chunk.len() >= STREAM_OVERLAP_BYTES {
        carry.clear();
        carry.extend_from_slice(&chunk[chunk.len() - STREAM_OVERLAP_BYTES..]);
        return;
    }
    carry.extend_from_slice(chunk);
    if carry.len() > STREAM_OVERLAP_BYTES {
        let drop = carry.len() - STREAM_OVERLAP_BYTES;
        carry.drain(..drop);
    }
}
