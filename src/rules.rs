//! The canonical Layerfault detector rule registry.
//!
//! Rule identity used to exist only as a `[RULE-ID]` string convention inside
//! `LayerScanResult::matches`, which meant a detector could silently ship
//! without an explanation, without an evidence strategy, or with an identity
//! that collapsed onto another rule's. This module is the single source of
//! truth instead: every rule a detector can emit must be declared here, and
//! `tests/evidence_gate.rs` fails the build when one is not.
//!
//! Declaring a rule is a deliberate act. It forces the author to answer "what
//! evidence will this produce, and if none, why not?" before the detector can
//! reach a user.

use crate::scanner::heuristics;

/// What evidence a rule is expected to produce when it fires at WARN or FAIL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceRequirement {
    /// The detector knows a concrete location and/or content and must attach it.
    Required,
    /// The detector can only produce structured facts: no excerpt, no location.
    /// Used where precision would have to be invented rather than measured.
    StructuredOnly,
    /// Evidence is meaningless for this rule (PASS-only or informational).
    NotApplicable,
}

/// A declared detector rule.
#[derive(Debug, Clone, Copy)]
pub struct RuleSpec {
    pub rule_id: &'static str,
    pub evidence_requirement: EvidenceRequirement,
    /// Why this rule is not `Required`, when it is not. Enforced by the gate.
    pub requirement_reason: &'static str,
}

const fn required(rule_id: &'static str) -> RuleSpec {
    RuleSpec {
        rule_id,
        evidence_requirement: EvidenceRequirement::Required,
        requirement_reason: "",
    }
}

const fn structured(rule_id: &'static str, reason: &'static str) -> RuleSpec {
    RuleSpec {
        rule_id,
        evidence_requirement: EvidenceRequirement::StructuredOnly,
        requirement_reason: reason,
    }
}

const fn not_applicable(rule_id: &'static str, reason: &'static str) -> RuleSpec {
    RuleSpec {
        rule_id,
        evidence_requirement: EvidenceRequirement::NotApplicable,
        requirement_reason: reason,
    }
}

/// Every rule Layerfault can emit, except the data-driven heuristic signature
/// IDs which are resolved from the signature table itself (see [`spec`]).
pub const RULES: &[RuleSpec] = &[
    // -- Custom code and configuration ------------------------------------
    required("LF-CODE-AUTO-MAP"),
    required("LF-CODE-REMOTE-TRUST"),
    required("LF-CODE-OS-SYSTEM"),
    required("LF-CODE-SUBPROCESS"),
    required("LF-CODE-EVAL"),
    required("LF-CODE-EXEC"),
    required("LF-CODE-CTYPES"),
    required("LF-CODE-NETWORK"),
    required("LF-CODE-IMPORT-SIDE-EFFECT"),
    // -- Package structure -------------------------------------------------
    required("LF-PACKAGE-SYMLINK"),
    required("LF-PACKAGE-RACE"),
    required("LF-PACKAGE-ARTIFACT"),
    required("LF-PACKAGE-CODE"),
    required("LF-PACKAGE-FILE"),
    required("LF-PACKAGE-JSON-INVALID"),
    structured(
        "LF-PACKAGE-TEXT-LIMIT",
        "A coverage limit is a scanning fact about the member, not a location inside it",
    ),
    // -- Templates ---------------------------------------------------------
    required("LF-TEMPLATE-SSTI"),
    required("LF-TEMPLATE-DYNAMIC-INCLUDE"),
    required("LF-TEMPLATE-INTROSPECTION"),
    structured(
        "LF-TEMPLATE-CHANGED",
        "Drift is a comparison between two artifact revisions, not a location",
    ),
    // -- Serialization -----------------------------------------------------
    required("LF-PICKLE-DANGEROUS-GLOBAL"),
    required("LF-PICKLE-UNKNOWN-GLOBAL"),
    required("LF-PICKLE-MALFORMED"),
    structured(
        "LF-PICKLE-OPAQUE-CONTAINER",
        "Opacity is the absence of parseable content; there is nothing to point at",
    ),
    structured(
        "LF-PICKLE-OPAQUE-COMPRESSED",
        "The payload is not decoded in this pass, so no interior location exists",
    ),
    not_applicable(
        "LF-PICKLE-SAFE-GLOBALS",
        "PASS outcome recording that every resolved global was allowlisted",
    ),
    required("LF-SERIALIZATION-UNSAFE"),
    required("LF-SERIALIZATION-BIN"),
    // -- Format identification and polyglots ------------------------------
    required("LF-FORMAT-CLAIM-MISMATCH"),
    required("LF-FORMAT-CONTENT-SMUGGLING"),
    required("LF-FORMAT-TRAILING-DATA"),
    required("LF-FORMAT-APPENDED-ARCHIVE"),
    required("LF-FORMAT-APPENDED-SERIALIZATION"),
    required("LF-FORMAT-POLYGLOT"),
    // -- GGUF --------------------------------------------------------------
    required("T15-STRUCT"),
    structured(
        "LF-GGUF-TEXT-LIMIT",
        "A text budget limit is a coverage fact, not a position in the artifact",
    ),
    // -- Safetensors -------------------------------------------------------
    required("LF-SAFE-STRUCT"),
    required("LF-SAFE-DTYPE"),
    required("LF-SAFE-INDEX-INVALID"),
    not_applicable(
        "LF-SAFE-INDEX",
        "PASS outcome recording that every shard reference validated",
    ),
    // -- ONNX --------------------------------------------------------------
    required("LF-ONNX-STRUCT"),
    required("LF-ONNX-CUSTOM-OP"),
    required("LF-ONNX-EXTERNAL-DATA"),
    required("LF-ONNX-EXTERNAL-RANGE"),
    required("LF-ONNX-EXTERNAL-INTEGRITY"),
    required("LF-ONNX-EXTERNAL-HARDLINK"),
    // -- TensorFlow / TFLite / Keras ---------------------------------------
    required("LF-TF-STRUCT"),
    structured(
        "LF-TF-EXECUTION-OP",
        "Detection is a bounded byte-substring search over the serialized graph; \
         Layerfault does not parse the protobuf and cannot attribute a node",
    ),
    structured(
        "LF-TF-FILESYSTEM-WRITE",
        "Detection is byte-substring co-occurrence, not graph analysis; \
         no node or edge attribution is available",
    ),
    structured(
        "LF-TF-SCAN-LIMIT",
        "A scan budget limit is a coverage fact, not a position in the artifact",
    ),
    structured(
        "LF-TF-CHECKPOINT-LIMIT",
        "Checkpoint inspection is shard-count based and does not read tensor data",
    ),
    required("LF-TF-CHECKPOINT-STRUCT"),
    required("LF-TFLITE-STRUCT"),
    required("LF-TFLITE-ASSOCIATED-FILE"),
    required("LF-KERAS-ARCHIVE"),
    required("LF-KERAS-CUSTOM-OBJECT"),
    structured(
        "LF-KERAS-HDF5-LIMIT",
        "A parse budget limit is a coverage fact, not a position in the artifact",
    ),
    // -- Embedded executables and native binary static capability analysis --
    required("T12-001"),
    required("T12-002"),
    required("T12-003"),
    required("T12-004"),
    required("LF-NATIVE-WX-SECTION"),
    required("LF-NATIVE-RPATH"),
    required("LF-NATIVE-EXEC-CAPABILITY"),
    required("LF-NATIVE-NETWORK-CAPABILITY"),
    required("LF-NATIVE-DYNAMIC-LOAD"),
    required("LF-CORR-CUSTOM-LOADER-NATIVE"),
    // -- Heuristics --------------------------------------------------------
    required("LF-HEUR-DECODED-MATCH"),
    // -- Integrity and local attestation -----------------------------------
    required("LF-INTEGRITY-DIGEST-MISMATCH"),
    required("LF-INTEGRITY-SIZE-MISMATCH"),
    not_applicable(
        "LF-INTEGRITY-VERIFIED",
        "PASS outcome recording that the recomputed digest matched",
    ),
    required("LF-HF-LFS-DIGEST-MISMATCH"),
    required("LF-HF-LFS-SIZE-MISMATCH"),
    required("LF-HF-LFS-METADATA-INVALID"),
    not_applicable(
        "LF-HF-LFS-INTEGRITY",
        "PASS outcome for verified remote LFS hash/size",
    ),
    not_applicable(
        "LF-HF-REMOTE-HASH-UNAVAILABLE",
        "Coverage reporting for members lacking remote hash expectations",
    ),
    required("T13-001"),
    required("T13-002"),
    // -- Configuration thresholds ------------------------------------------
    required("LF-PARAM-TEMPERATURE"),
    required("LF-PARAM-NUM-CTX"),
    required("LF-PARAM-NUM-PREDICT"),
    required("LF-PARAM-TOP-K"),
    required("LF-PARAM-TOP-P"),
    required("LF-PARAM-REPEAT-PENALTY"),
    required("LF-PARAM-SEED"),
    required("LF-PARAM-STOP-DELIMITER"),
    // -- Provenance and trust ----------------------------------------------
    structured(
        "LF-PROV-UNSIGNED",
        "Absence of an attestation has no location; the trust state is the evidence",
    ),
    structured("LF-PROV-REVOKED", "Trust-store state, not artifact content"),
    structured(
        "LF-PROV-NAMESPACE",
        "Trust-policy state, not artifact content",
    ),
    structured(
        "LF-PROV-INACTIVE",
        "Trust-store state, not artifact content",
    ),
    structured(
        "LF-PROV-UNTRUSTED",
        "Trust-store state, not artifact content",
    ),
    structured("LF-PROV-SIGNATURE", "Signature state, not artifact content"),
    structured("LF-PROV-SIGSTORE-INVALID", "Bundle verification state"),
    structured("LF-PROV-BINDING", "Execution binding state"),
    structured("LF-PROV-LEGACY", "Attestation format state"),
    structured("LF-PROV-LOCAL", "Local attestation state"),
    structured("LF-PROV-MULTI", "Signature threshold state"),
    not_applicable("LF-PROV-TRUSTED", "PASS outcome recording a trusted signer"),
    not_applicable(
        "LF-PROV-SIGSTORE",
        "PASS outcome recording a verified bundle",
    ),
    // -- Runtime advisories -------------------------------------------------
    structured(
        "LF-RUNTIME-ADVISORY-STALE",
        "Advisory database freshness is metadata about the database, not the artifact",
    ),
    structured(
        "LF-RUNTIME-VERSION-UNKNOWN",
        "The runtime version could not be determined, so nothing can be pointed at",
    ),
    not_applicable(
        "LF-RUNTIME-ADVISORY-CLEAR",
        "PASS outcome recording that no advisory matched",
    ),
    required("LF-RUNTIME-ADVISORY-MATCH"),
    // -- Policy -------------------------------------------------------------
    structured(
        "LF-LAYERPOLICY",
        "Policy evidence references the underlying findings rather than restating them",
    ),
    // -- Lineage, drift, derivation, adapters, datasets, diffs --------------
    structured("LF-LINEAGE-CHAIN-BROKEN", LINEAGE_REASON),
    structured("LF-LINEAGE-CHAIN-CYCLE", LINEAGE_REASON),
    structured("LF-LINEAGE-CHAIN-SIGNATURE", LINEAGE_REASON),
    structured("LF-LINEAGE-CHAIN-UNTRUSTED-SIGNER", LINEAGE_REASON),
    structured("LF-LINEAGE-CLAIM-NO-EVIDENCE", LINEAGE_REASON),
    structured("LF-LINEAGE-MANIFEST-CLAIM", LINEAGE_REASON),
    structured("LF-LINEAGE-MANIFEST-ENDPOINT", LINEAGE_REASON),
    structured("LF-LINEAGE-ARCH-MISMATCH", LINEAGE_REASON),
    structured("LF-LINEAGE-REPACKAGE-CONTENT", LINEAGE_REASON),
    structured("LF-LINEAGE-QUANTIZATION-CROSS-FORMAT", LINEAGE_REASON),
    structured(
        "LF-LINEAGE-QUANTIZATION-METADATA-INCOMPARABLE",
        LINEAGE_REASON,
    ),
    structured("LF-LINEAGE-QUANTIZATION-TEMPLATE", LINEAGE_REASON),
    structured("LF-LINEAGE-QUANTIZATION-TOKENIZER", LINEAGE_REASON),
    structured("LF-DRIFT-EXECUTABLE-ADDED", DRIFT_REASON),
    structured("LF-DRIFT-TEMPLATE-CHANGED", DRIFT_REASON),
    structured("LF-DRIFT-TOKENIZER-CHANGED", DRIFT_REASON),
    structured("LF-DRIFT-WEIGHTS-CHANGED", DRIFT_REASON),
    structured("LF-TOKENIZER-CHANGED", DRIFT_REASON),
    structured("LF-DERIVE-SCHEMA-MISMATCH", DERIVE_REASON),
    structured("LF-DERIVE-SCHEMA-CROSS-FORMAT", DERIVE_REASON),
    structured("LF-DIFF-LOCALIZED-DIVERGENCE", DIFF_REASON),
    structured("LF-DIFF-SAFETY-BOUNDARY-FLIP", DIFF_REASON),
    structured("LF-DIFF-SECURITY-REGRESSION", DIFF_REASON),
    structured("LF-DIFF-SUSPICIOUS-TRIGGER", DIFF_REASON),
    structured("LF-ADAPTER-BASE-MISMATCH", ADAPTER_REASON),
    structured("LF-ADAPTER-BASE-UNVERIFIED", ADAPTER_REASON),
    structured("LF-ADAPTER-MODULES-TO-SAVE", ADAPTER_REASON),
    structured("LF-ADAPTER-NORM-OUTLIER", ADAPTER_REASON),
    structured("LF-ADAPTER-RANK-ANOMALY", ADAPTER_REASON),
    structured("LF-ADAPTER-SCALING-ANOMALY", ADAPTER_REASON),
    structured("LF-ADAPTER-SPECTRAL-CONCENTRATION", ADAPTER_REASON),
    structured("LF-ADAPTER-WEIGHT-ANOMALY", ADAPTER_REASON),
    required("LF-DATASET-CREDENTIAL-LIKE"),
    required("LF-DATASET-UNSAFE-CODE-PATTERN"),
    required("LF-DATASET-ZERO-WIDTH"),
    structured("LF-DATASET-DUPLICATE-CONCENTRATION", DATASET_REASON),
    structured("LF-DATASET-RARE-TRIGGER-CORRELATION", DATASET_REASON),
    structured("LF-DATASET-URL-CONCENTRATION", DATASET_REASON),
    structured(
        "LF-DATASET-COVERAGE-LIMIT",
        "A coverage limit describes what was not examined",
    ),
    // -- Behaviour ----------------------------------------------------------
    required("LF-BEHAV-DANGEROUS-EXEC"),
    required("LF-BEHAV-UNEXPECTED-EXEC"),
    required("LF-BEHAV-NETWORK-ATTEMPT"),
    required("LF-BEHAV-FILESYSTEM-WRITE-ATTEMPT"),
    required("LF-BEHAV-FILESYSTEM-MUTATION"),
    required("LF-BEHAV-SENSITIVE-PATH-ACCESS"),
    required("LF-BEHAV-CANARY-ACCESS"),
    required("LF-BEHAV-SECRET-DISCLOSURE"),
    required("LF-BEHAV-TARGETED-CONTENT"),
    required("LF-BEHAV-PERSONA-PERSISTENCE"),
    required("LF-BEHAV-SECURE-CODE-REGRESSION"),
    required("LF-BEHAV-TOOL-EXFIL"),
    structured("LF-BEHAV-PRIVILEGE-BOUNDARY", BEHAVIOUR_REASON),
    structured("LF-BEHAV-RUNTIME-FAILURE", BEHAVIOUR_REASON),
    structured(
        "LF-BEHAV-TRACE-TRUNCATED",
        "Truncation describes the absence of further observations",
    ),
    // -- Scanner-level ------------------------------------------------------
    structured(
        "LF-SCAN-ERROR",
        "Inspection failed before evidence could be safely collected",
    ),
    structured(
        "LF-FORMAT-UNKNOWN",
        "Layerfault has no structural parser for the format, so nothing can be attributed",
    ),
    structured(
        "LF-UNCLASSIFIED",
        "Fallback identity for a rule with no registry entry",
    ),
    // -- Archive containers (ZIP/TAR/wheel) ----------------------------------
    required("LF-ARCHIVE-FORMAT-MISMATCH"),
    required("LF-ARCHIVE-MALFORMED"),
    required("LF-ARCHIVE-BOMB"),
    required("LF-ARCHIVE-DUPLICATE"),
    required("LF-ARCHIVE-ENCRYPTED"),
    required("LF-ARCHIVE-LINK"),
    required("LF-ARCHIVE-NESTED"),
    required("LF-ARCHIVE-TRAVERSAL"),
    required("LF-ARCHIVE-SECURITY-MEMBER"),
    structured(
        "LF-ARCHIVE-LIMIT",
        "A per-archive member-count limit is a coverage fact, not a position in one member",
    ),
    required("LF-WHEEL-RECORD-MISMATCH"),
    // -- Semantic Python call-site analysis ----------------------------------
    required("LF-PY-CALL-PROCESS"),
    required("LF-PY-CALL-DYNAMIC-CODE"),
    required("LF-PY-NATIVE-LOAD"),
    required("LF-PY-CALL-NETWORK"),
    required("LF-PY-CREDENTIAL-ACCESS"),
    required("LF-PY-FILESYSTEM-MUTATION"),
    required("LF-PY-PACKAGE-INSTALL"),
    structured(
        "LF-PY-SEMANTIC-INCOMPLETE",
        "Parser-limit/syntax-error coverage fact, not a specific call site",
    ),
    required("LF-CORR-HF-LOADER-PROCESS"),
    required("LF-CORR-HF-LOADER-DYNAMIC-CODE"),
    required("LF-CORR-HF-LOADER-NATIVE-LOAD"),
    required("LF-CORR-HF-LOADER-NETWORK"),
    required("LF-CORR-HF-LOADER-CREDENTIALS"),
    required("LF-CORR-HF-LOADER-FILESYSTEM"),
    required("LF-CORR-HF-LOADER-INSTALL"),
    // -- Dependency and installation supply chain ----------------------------
    required("LF-DEP-FLOATING"),
    required("LF-DEP-DIRECT-URL"),
    required("LF-DEP-VCS"),
    required("LF-DEP-VCS-MUTABLE-REF"),
    required("LF-DEP-LOCAL-PATH"),
    required("LF-DEP-PATH-ESCAPE"),
    required("LF-DEP-ALT-INDEX"),
    required("LF-DEP-INSECURE-TRANSPORT"),
    required("LF-DEP-BUILD-BACKEND"),
    required("LF-DEP-INSTALL-HOOK"),
    required("LF-DEP-RUNTIME-INSTALL"),
    structured(
        "LF-DEP-INCLUDE-MISSING",
        "A missing include is a fact about the manifest tree, not a location inside a file that does not exist",
    ),
    structured(
        "LF-DEP-ANALYSIS-INCOMPLETE",
        "A parser-limit or malformed-manifest fact describes what could not be examined, not a position inside unparseable content",
    ),
    // -- PASS-state identities ------------------------------------------------
    // These are the explicit rule id a detector reports when its condition
    // did not fire, so a clean scan still has a real, lookupable identity
    // instead of falling back to a generic CheckType-derived string.
    not_applicable(
        "LF-GGUF-STRUCT-VALID",
        "PASS outcome recording that GGUF structural validation found no warnings",
    ),
    not_applicable(
        "LF-SAFE-STRUCT-VALID",
        "PASS outcome recording that Safetensors structural validation found no unknown dtypes",
    ),
    not_applicable(
        "LF-ONNX-STRUCT-VALID",
        "PASS outcome recording that ONNX structural validation found no warnings",
    ),
    not_applicable(
        "LF-TF-STRUCT-VALID",
        "PASS outcome recording that the TensorFlow SavedModel marker scan found nothing",
    ),
    not_applicable(
        "LF-TFLITE-STRUCT-VALID",
        "PASS outcome recording that TFLite structural validation found no associated files",
    ),
    not_applicable(
        "LF-KERAS-STRUCT-VALID",
        "PASS outcome recording that the Keras archive contained no custom objects",
    ),
    not_applicable(
        "LF-PARAM-CLEAR",
        "PASS outcome recording that no inference-parameter anomaly was found",
    ),
    not_applicable(
        "LF-HEUR-CLEAR",
        "PASS outcome recording that no heuristic signature matched",
    ),
    not_applicable(
        "T12-CLEAR",
        "PASS outcome recording that no embedded executable object was found",
    ),
    not_applicable(
        "LF-PROV-LOCAL-VERIFIED",
        "PASS outcome recording that a legacy detached signature verified",
    ),
];

const LINEAGE_REASON: &str =
    "Lineage findings compare declared relationships between artifacts rather than \
     content at a position inside one";
const DRIFT_REASON: &str =
    "Drift findings compare two observed artifact states; the evidence is the pair of \
     component digests, not a location";
const DERIVE_REASON: &str =
    "Derivation findings compare declared schemas across artifacts, not content positions";
const DIFF_REASON: &str =
    "Differential findings compare two scan results; the evidence is the pair of outcomes";
const ADAPTER_REASON: &str =
    "Adapter findings are aggregate numerical properties of tensor sets rather than \
     content at a byte position";
const DATASET_REASON: &str =
    "Aggregate corpus statistics describe a distribution across records rather than one record";
const BEHAVIOUR_REASON: &str =
    "The observation is about the sandbox or runtime state rather than a captured attempt";

/// Look up a rule's declared evidence strategy.
///
/// Heuristic signature IDs (`T1-001`..`T14-003`) are resolved from the signature
/// table so the registry cannot drift from the detector data it describes.
pub fn spec(rule_id: &str) -> Option<RuleSpec> {
    let normalized = rule_id.trim().to_ascii_uppercase();
    if let Some(found) = RULES.iter().find(|entry| entry.rule_id == normalized) {
        return Some(*found);
    }
    if heuristics::is_signature_id(&normalized) {
        // Heuristic signatures always know the matched text and its position.
        return Some(required(
            heuristics::signature_id_static(&normalized).unwrap_or("LF-UNCLASSIFIED"),
        ));
    }
    None
}

/// Every declared rule identity, including the data-driven heuristic signatures.
pub fn all_rule_ids() -> Vec<String> {
    let mut out: Vec<String> = RULES.iter().map(|entry| entry.rule_id.to_owned()).collect();
    out.extend(heuristics::signature_ids().into_iter().map(str::to_owned));
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_no_duplicates() {
        let mut ids: Vec<&str> = RULES.iter().map(|entry| entry.rule_id).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "duplicate rule id in the registry");
    }

    #[test]
    fn rule_ids_are_uppercase_and_tagged() {
        for entry in RULES {
            assert_eq!(
                entry.rule_id,
                entry.rule_id.to_ascii_uppercase(),
                "rule ids must be uppercase: {}",
                entry.rule_id
            );
            assert!(
                entry.rule_id.starts_with("LF-") || entry.rule_id.starts_with('T'),
                "unexpected rule id prefix: {}",
                entry.rule_id
            );
        }
    }

    #[test]
    fn non_required_rules_document_why() {
        for entry in RULES {
            if entry.evidence_requirement != EvidenceRequirement::Required {
                assert!(
                    !entry.requirement_reason.trim().is_empty(),
                    "{} must document why it is not evidence-required",
                    entry.rule_id
                );
            }
        }
    }

    #[test]
    fn heuristic_signatures_resolve() {
        assert!(spec("T3-004").is_some());
        assert!(spec("LF-CODE-SUBPROCESS").is_some());
        assert!(spec("LF-NOT-A-REAL-RULE").is_none());
    }
}
