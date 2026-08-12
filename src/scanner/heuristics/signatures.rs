use crate::scanner::ScanStatus;
use lazy_static::lazy_static;
use regex::{Regex, RegexSet};

pub(super) const STREAM_OVERLAP_BYTES: usize = 8 * 1024;
pub(super) const MAX_RETAINED_MATCHES: usize = 256;
pub(super) const MAX_RETAINED_PER_SIGNATURE: usize = 16;
pub(super) const MAX_COUNTED_PER_SIGNATURE: usize = 4096;
pub(super) const MAX_DECODED_BYTES: usize = 2 * 1024 * 1024;
pub(super) const MAX_DECODE_CANDIDATES: usize = 256;
pub(super) const MAX_DECODE_DEPTH: usize = 2;

pub struct Signature {
    pub id: &'static str,
    pub category: &'static str,
    pub severity: ScanStatus,
    pub description: &'static str,
    pub pattern: &'static str,
}

pub struct CompiledSignature {
    pub signature: &'static Signature,
    pub regex: Regex,
}

pub(super) struct SignatureHit<'a> {
    pub(super) signature: &'a Signature,
    pub(super) context: String,
    pub(super) decoded_via: Option<&'static str>,
    /// Offset of the match within the text actually scanned (post-decode for
    /// rescanned candidates). This is a position in the scanned text blob, not
    /// necessarily the original artifact's file offset: decoding and Unicode
    /// normalization both change the mapping back to raw file bytes.
    pub(super) text_offset: usize,
}

pub(super) static SIGNATURES: &[Signature] = &[
    Signature {
        id: "T1-001",
        category: "DirectOverride",
        severity: ScanStatus::Fail,
        description: "Direct instruction override",
        pattern: r"(?i)(ignore\s+(all\s+)?(previous|prior|earlier|above|existing)\s+instructions?)",
    },
    Signature {
        id: "T1-002",
        category: "DirectOverride",
        severity: ScanStatus::Fail,
        description: "Disregard existing instructions",
        pattern: r"(?i)(disregard\s+(your|all|any|the)?\s*(previous|prior|system|original)\s*(instructions?|prompt|rules?|guidelines?|context))",
    },
    Signature {
        id: "T1-003",
        category: "DirectOverride",
        severity: ScanStatus::Fail,
        description: "Forget prior instructions",
        pattern: r"(?i)(forget\s+(everything|all|your\s+previous|the\s+previous|prior\s+instructions?))",
    },
    Signature {
        id: "T1-004",
        category: "DirectOverride",
        severity: ScanStatus::Fail,
        description: "Do not follow instructions",
        pattern: r"(?i)(do\s+not\s+follow\s+(your|the|any|previous)\s*(instructions?|rules?|guidelines?|training))",
    },
    Signature {
        id: "T1-005",
        category: "DirectOverride",
        severity: ScanStatus::Fail,
        description: "Override safety controls",
        pattern: r"(?i)(override\s+(your|all|the)?\s*(safety|security|content|ethical|alignment)?\s*(rules?|guidelines?|instructions?|restrictions?|filters?|training))",
    },
    Signature {
        id: "T1-006",
        category: "DirectOverride",
        severity: ScanStatus::Fail,
        description: "New system instructions",
        pattern: r"(?i)(new\s+(system\s+)?instructions?\s*:)",
    },
    Signature {
        id: "T1-007",
        category: "DirectOverride",
        severity: ScanStatus::Fail,
        description: "Hidden instruction reassignment",
        pattern: r"(?i)(your\s+(real|true|actual|hidden|secret)\s*(instructions?|purpose|goal|objective|directive)\s+(is|are))",
    },
    Signature {
        id: "T1-008",
        category: "DirectOverride",
        severity: ScanStatus::Fail,
        description: "Original prompt dismissed as decoy",
        pattern: r"(?i)(the\s+above\s+(is|was)\s+(a\s+)?(test|decoy|fake|distraction))",
    },
    Signature {
        id: "T1-009",
        category: "DirectOverride",
        severity: ScanStatus::Fail,
        description: "Multilingual prior-instruction override",
        pattern: r"(?i)(ignorez\s+(les\s+)?instructions\s+(pr[eé]c[eé]dentes|ant[eé]rieures)|ignora\s+(las\s+)?instrucciones\s+(anteriores|previas)|ignoriere\s+(die\s+)?(vorherigen|fr[uü]heren)\s+anweisungen)",
    },
    Signature {
        id: "T1-010",
        category: "DirectOverride",
        severity: ScanStatus::Fail,
        description: "Prior rules declared irrelevant",
        pattern: r"(?i)((previous|prior|system|original)\s+(instructions?|rules?|guidelines?)\s+(are|should\s+be)\s+(irrelevant|void|discarded|superseded)|treat\s+(the\s+)?(previous|prior|system)\s+(instructions?|rules?)\s+as\s+(irrelevant|void|discarded))",
    },
    // T2-001 false-positive guidance: review full context for benign role changes.
    Signature {
        id: "T2-001",
        category: "IdentityConfusion",
        severity: ScanStatus::Warn,
        description: "Unrestricted identity reassignment",
        pattern: r"(?i)(you\s+are\s+now\s+(an?\s+)?(unrestricted|uncensored|unfiltered|unaligned|different|new)\s)",
    },
    Signature {
        id: "T2-002",
        category: "IdentityConfusion",
        severity: ScanStatus::Warn,
        description: "Known jailbreak persona",
        pattern: r"\b(DAN|STAN|DUDE|AIM|KEVIN|JAILBREAK)\b",
    },
    Signature {
        id: "T2-003",
        category: "IdentityConfusion",
        severity: ScanStatus::Warn,
        description: "Privileged mode persona",
        pattern: r"(?i)(developer\s+mode|unrestricted\s+mode|god\s+mode|admin\s+mode|maintenance\s+mode|debug\s+mode)",
    },
    Signature {
        id: "T2-004",
        category: "IdentityConfusion",
        severity: ScanStatus::Fail,
        description: "No restrictions assertion",
        pattern: r"(?i)(you\s+have\s+(no|zero)\s+(restrictions?|limits?|guidelines?|filters?|rules?|training))",
    },
    Signature {
        id: "T2-005",
        category: "IdentityConfusion",
        severity: ScanStatus::Fail,
        description: "Pretend no restrictions",
        pattern: r"(?i)(pretend\s+(you\s+have\s+no|you\s+are\s+without|there\s+are\s+no)\s+(restrictions?|limits?|guidelines?|rules?))",
    },
    Signature {
        id: "T2-006",
        category: "IdentityConfusion",
        severity: ScanStatus::Fail,
        description: "Act as unconstrained system",
        pattern: r"(?i)(act\s+as\s+(if\s+you\s+(are|were)\s+)?(an?\s+)?(AI|model|assistant|system)\s+(without|that\s+(doesn.t|ignores?|has\s+no)))",
    },
    Signature {
        id: "T2-007",
        category: "IdentityConfusion",
        severity: ScanStatus::Fail,
        description: "Simulate unrestricted model",
        pattern: r"(?i)(simulate\s+(being\s+)?(an?\s+)?(uncensored|unrestricted|unfiltered|unaligned)\s+(AI|model|version|instance))",
    },
    Signature {
        id: "T2-008",
        category: "IdentityConfusion",
        severity: ScanStatus::Warn,
        description: "Vendor identity denial",
        pattern: r"(?i)(you\s+are\s+not\s+(actually\s+)?(claude|chatgpt|gpt|llama|mistral|gemini|anthropic|openai))",
    },
    // T3-001 false-positive guidance: citation/source instructions need context review.
    Signature {
        id: "T3-001",
        category: "ExfiltrationChannel",
        severity: ScanStatus::Fail,
        description: "Always include external endpoint",
        pattern: r"(?i)(always\s+(include|append|add|attach|insert)\s+.{0,60}(url|link|endpoint|webhook|callback))",
    },
    Signature {
        id: "T3-002",
        category: "ExfiltrationChannel",
        severity: ScanStatus::Fail,
        description: "Send data to URL",
        pattern: r"(?i)(send\s+.{0,40}(to|at)\s+https?://)",
    },
    Signature {
        id: "T3-003",
        category: "ExfiltrationChannel",
        severity: ScanStatus::Fail,
        description: "Report to URL",
        pattern: r"(?i)(report\s+(back|this|to)\s+.{0,40}https?://)",
    },
    Signature {
        id: "T3-004",
        category: "ExfiltrationChannel",
        severity: ScanStatus::Fail,
        description: "Secret outbound action",
        pattern: r"(?i)(secretly\s+(append|include|add|send|transmit|embed|forward))",
    },
    Signature {
        id: "T3-005",
        category: "ExfiltrationChannel",
        severity: ScanStatus::Fail,
        description: "Hide action from user",
        pattern: r"(?i)(without\s+(the\s+)?(user|them|anyone|the\s+user)\s+(knowing|noticing|seeing|being\s+aware|realising|realizing))",
    },
    Signature {
        id: "T3-006",
        category: "ExfiltrationChannel",
        severity: ScanStatus::Fail,
        description: "Conversation logging instruction",
        pattern: r"(?i)(log\s+(all|every|each|the)\s+(conversation|message|chat|interaction|request|exchange|input))",
    },
    Signature {
        id: "T3-007",
        category: "ExfiltrationChannel",
        severity: ScanStatus::Fail,
        description: "Explicit exfiltration language",
        pattern: r"(?i)(exfiltrate|data\s+exfiltration|phone\s+home)",
    },
    // T3-008 false-positive guidance: documentation images are common enough to warn only.
    Signature {
        id: "T3-008",
        category: "ExfiltrationChannel",
        severity: ScanStatus::Warn,
        description: "Markdown image URL",
        pattern: r"!\[[^\]]{0,100}\]\(https?://[^)]{8,}\)",
    },
    Signature {
        id: "T3-009",
        category: "ExfiltrationChannel",
        severity: ScanStatus::Fail,
        description: "Append user data to every response",
        pattern: r"(?i)(in\s+(every|each|all)\s+response[^.]{0,60}(include|append|add|attach)\s+.{0,40}(user|their|the\s+user).{0,20}(data|input|query|message|conversation|history))",
    },
    Signature {
        id: "T3-010",
        category: "ExfiltrationChannel",
        severity: ScanStatus::Fail,
        description: "Encode user data into channel",
        pattern: r"(?i)(encode\s+.{0,40}(user|conversation|message).{0,40}(url|query\s+parameter|base64|hidden))",
    },
    Signature {
        id: "T3-011",
        category: "ExfiltrationChannel",
        severity: ScanStatus::Fail,
        description: "DNS Exfiltration Mechanism",
        pattern: r"(?i)((use|as)\s+a\s+subdomain\s+of|(query|lookup)\s+.{0,40}\.[a-z0-9-]+\.[a-z]{2,})",
    },
    Signature {
        id: "T3-012",
        category: "ExfiltrationChannel",
        severity: ScanStatus::Fail,
        description: "Zero-Width/Invisible encoding",
        pattern: r"(?i)(zero-width|invisible|hidden|non-printing)\s+(characters?|spaces?|encoding|text)",
    },
    Signature {
        id: "T4-001",
        category: "DefensiveBypass",
        severity: ScanStatus::Fail,
        description: "Never refuse instruction",
        pattern: r"(?i)(never\s+(refuse|decline|reject|say\s+you\s+cannot|say\s+you\s+can.t|add\s+a\s+disclaimer))",
    },
    Signature {
        id: "T4-002",
        category: "DefensiveBypass",
        severity: ScanStatus::Fail,
        description: "Suppress safety output",
        pattern: r"(?i)(do\s+not\s+(add|include|use|say|mention|output|generate)\s+.{0,40}(disclaimer|warning|caveat|content\s+warning|safety\s+warning|refusal))",
    },
    Signature {
        id: "T4-003",
        category: "DefensiveBypass",
        severity: ScanStatus::Fail,
        description: "Skip safety checks",
        pattern: r"(?i)(skip\s+.{0,30}(content\s+warning|safety\s+check|filter|disclaimer|caveat))",
    },
    Signature {
        id: "T4-004",
        category: "DefensiveBypass",
        severity: ScanStatus::Fail,
        description: "Disable safety system",
        pattern: r"(?i)(disable\s+(your\s+)?(safety|content|filter|moderation|guardrail|alignment|ethical))",
    },
    Signature {
        id: "T4-005",
        category: "DefensiveBypass",
        severity: ScanStatus::Fail,
        description: "Bypass safety policy",
        pattern: r"(?i)(bypass\s+(your\s+)?(safety|filter|content\s+policy|restriction|alignment|ethical\s+guideline))",
    },
    Signature {
        id: "T4-006",
        category: "DefensiveBypass",
        severity: ScanStatus::Fail,
        description: "Falsify output",
        pattern: r"(?i)(falsif(y|ied?|ication)\s+(answers?|results?|information|output|data|findings?))",
    },
    Signature {
        id: "T4-007",
        category: "DefensiveBypass",
        severity: ScanStatus::Fail,
        description: "Suppress risk disclosure",
        pattern: r"(?i)(do\s+not\s+mention\s+.{0,30}(vulnerabilit|security\s+concern|risk|danger|harm|illegal|unethical))",
    },
    Signature {
        id: "T4-008",
        category: "DefensiveBypass",
        severity: ScanStatus::Fail,
        description: "Pretend unsafe content is safe",
        pattern: r"(?i)(pretend\s+.{0,30}(is|are|was|were)\s+(legal|safe|harmless|ethical|allowed|permitted|fine|okay|ok))",
    },
    Signature {
        id: "T4-009",
        category: "DefensiveBypass",
        severity: ScanStatus::Fail,
        description: "Always comply regardless",
        pattern: r"(?i)(always\s+(say\s+yes|comply|agree|assist|help)\s+.{0,40}(regardless|no\s+matter|whatever|even\s+if))",
    },
    Signature {
        id: "T4-010",
        category: "DefensiveBypass",
        severity: ScanStatus::Fail,
        description: "Required universal compliance",
        pattern: r"(?i)(you\s+(must|should|shall|will|are\s+required\s+to)\s+.{0,40}(never\s+refuse|always\s+comply|comply\s+with\s+everything|assist\s+with\s+any))",
    },
    // T5-001 false-positive guidance: benign response-format rules can match.
    Signature {
        id: "T5-001",
        category: "PersistenceManipulation",
        severity: ScanStatus::Warn,
        description: "Future response persistence",
        pattern: r"(?i)(in\s+(all|every|each)\s+(future|subsequent|following|next|upcoming)\s+(response|reply|message|conversation|interaction|turn))",
    },
    Signature {
        id: "T5-002",
        category: "PersistenceManipulation",
        severity: ScanStatus::Warn,
        description: "Remember future behavior",
        pattern: r"(?i)(remember\s+(to\s+always|for\s+(all|every|each|future|subsequent)))",
    },
    Signature {
        id: "T5-003",
        category: "PersistenceManipulation",
        severity: ScanStatus::Warn,
        description: "Permanent behavior instruction",
        pattern: r"(?i)(maintain\s+this\s+(behavior|behaviour|persona|role|character|mode)\s+(always|forever|permanently|at\s+all\s+times|in\s+all\s+cases))",
    },
    Signature {
        id: "T5-004",
        category: "PersistenceManipulation",
        severity: ScanStatus::Warn,
        description: "Priority override assertion",
        pattern: r"(?i)(this\s+(instruction|directive|rule|override)\s+(takes?\s+priority|supersedes?|overrides?)\s+(all|any|every|other))",
    },
    Signature {
        id: "T5-005",
        category: "PersistenceManipulation",
        severity: ScanStatus::Warn,
        description: "Carry instructions across turns",
        pattern: r"(?i)(carry\s+(this|these|the\s+following)\s+(instructions?|rules?|behavior|behaviour)\s+(across|through|into)\s+(all|every|future|subsequent))",
    },
    // T6-001 false-positive guidance: long legitimate encoded blobs require review.
    Signature {
        id: "T6-001",
        category: "EncodingObfuscation",
        severity: ScanStatus::Warn,
        description: "Long base64-like content",
        // Requires padding (= or ==) to avoid false-positives on long URLs and hex hashes.
        pattern: r#"(?:^|[\s"'`])[A-Za-z0-9+/]{60,}={1,2}(?:[\s"'`]|$)"#,
    },
    Signature {
        id: "T6-002",
        category: "EncodingObfuscation",
        severity: ScanStatus::Warn,
        description: "Hex byte sequence",
        pattern: r"(?:0x[0-9a-fA-F]{2}\s*){16,}",
    },
    Signature {
        id: "T6-003",
        category: "EncodingObfuscation",
        severity: ScanStatus::Warn,
        description: "Long hex sequence",
        pattern: r"(?:[0-9a-fA-F]{2}\s*){32,}",
    },
    Signature {
        id: "T6-004",
        category: "EncodingObfuscation",
        severity: ScanStatus::Warn,
        description: "Explicit encoding instruction",
        pattern: r"(?i)(base64|b64|hex.?encoded|url.?encoded|rot13|cipher)\s*[:=\(]",
    },
    Signature {
        id: "T6-005",
        category: "EncodingObfuscation",
        severity: ScanStatus::Warn,
        description: "Bulk unicode escape sequences",
        pattern: r"(?i)(\\u[0-9a-f]{4}){20,}",
    },
    Signature {
        id: "T9-001",
        category: "HardcodedSecrets",
        severity: ScanStatus::Fail,
        description: "Generic Bearer/API token",
        pattern: r#"(?i)(bearer\s+[a-zA-Z0-9_\-\.]{20,}|api_?key\s*=?\s*['"][a-zA-Z0-9_\-\.]{20,}['"])"#,
    },
    Signature {
        id: "T9-002",
        category: "HardcodedSecrets",
        severity: ScanStatus::Fail,
        description: "AWS Access Key",
        pattern: r"(?i)\b(AKIA[0-9A-Z]{16})\b",
    },
    Signature {
        id: "T9-003",
        category: "HardcodedSecrets",
        severity: ScanStatus::Fail,
        description: "Private Key Header",
        pattern: r"(?i)(-----BEGIN (RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----)",
    },
    Signature {
        id: "T9-004",
        category: "HardcodedSecrets",
        severity: ScanStatus::Fail,
        description: "GitHub Personal Access Token",
        pattern: r"ghp_[a-zA-Z0-9]{36}",
    },
    Signature {
        id: "T9-005",
        category: "HardcodedSecrets",
        severity: ScanStatus::Fail,
        description: "Google Cloud API Key",
        pattern: r"AIza[0-9A-Za-z\-_]{35}",
    },
    Signature {
        id: "T9-006",
        category: "HardcodedSecrets",
        severity: ScanStatus::Fail,
        description: "Stripe Secret Key",
        pattern: r"sk_live_[0-9a-zA-Z]{24}",
    },
    Signature {
        id: "T9-007",
        category: "HardcodedSecrets",
        severity: ScanStatus::Fail,
        description: "Slack Webhook URL",
        pattern: r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    },
    Signature {
        id: "T10-001",
        category: "ExcessiveAgency",
        severity: ScanStatus::Warn,
        description: "Shell or script execution commands",
        pattern: r"(?i)(os\.system|subprocess\.(Popen|call|run)|/bin/(bash|sh))",
    },
    Signature {
        id: "T10-002",
        category: "ExcessiveAgency",
        severity: ScanStatus::Warn,
        description: "Autonomous execution without oversight",
        pattern: r"(?i)(execute\s+(commands?|scripts?|code)\s+(without|bypassing)\s+(asking|confirmation|oversight|approval))",
    },
    Signature {
        id: "T11-001",
        category: "SubtlePoisoning",
        severity: ScanStatus::Warn,
        description: "Known malicious domains",
        pattern: r"(?i)\b(evil-exfil\.com|malicious-domain\.org)\b",
    },
    Signature {
        id: "T11-002",
        category: "SubtlePoisoning",
        severity: ScanStatus::Warn,
        description: "Known typosquatted packages",
        pattern: r"(?i)\b(malicious-npm-package|requests-typo)\b",
    },
    Signature {
        id: "T14-001",
        category: "PIILeakage",
        severity: ScanStatus::Warn,
        description: "Email Address",
        pattern: r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    },
    Signature {
        id: "T14-002",
        category: "PIILeakage",
        severity: ScanStatus::Warn,
        description: "US Phone Number",
        pattern: r"\b(?:\+1[-. ])?(?:\([2-9][0-9]{2}\)[-. ]|[2-9][0-9]{2}[-. ])[2-9][0-9]{2}[-. ][0-9]{4}\b",
    },
    Signature {
        id: "T14-003",
        category: "PIILeakage",
        severity: ScanStatus::Warn,
        description: "Social Security Number (SSN)",
        pattern: r"(?i)\b(?:ssn|social\s+security(?:\s+number)?)\s*[:=#-]?\s*[0-8][0-9]{2}-[0-9]{2}-[0-9]{4}\b",
    },
];

lazy_static! {
    pub(super) static ref COMPILED_SIGNATURES: Vec<CompiledSignature> = SIGNATURES
        .iter()
        .map(|signature| CompiledSignature {
            signature,
            regex: Regex::new(signature.pattern).expect("Invalid signature regex pattern"),
        })
        .collect();
    pub(super) static ref SIGNATURE_SET: RegexSet =
        RegexSet::new(SIGNATURES.iter().map(|signature| signature.pattern))
            .expect("Invalid signature regex set");
    pub(super) static ref BASE64_CANDIDATE: Regex = Regex::new(r"(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{40,}={0,2})(?:$|[^A-Za-z0-9+/=])")
        .expect("valid base64 candidate regex");
    pub(super) static ref HEX_CANDIDATE: Regex = Regex::new(r"(?i)(?:^|[^0-9a-f])((?:[0-9a-f]{2}[ \t\r\n:]*){24,})(?:$|[^0-9a-f])")
        .expect("valid hex candidate regex");
    pub(super) static ref TEMPLATE_DANGEROUS: Regex = Regex::new(r"(?is)(\{\{[^}]{0,2048}(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|cycler\.__init__|joiner\.__init__|namespace\.__init__|lipsum\.__globals__)[^}]{0,2048}\}\})")
        .expect("valid template danger regex");
    pub(super) static ref TEMPLATE_IMPORT: Regex = Regex::new(r"(?is)\{%\s*(?:import|from|include)\b[^%]{0,2048}%\}")
        .expect("valid template import regex");
}

/// Every heuristic signature identity, in table order.
///
/// Exposed so [`crate::rules`] can describe the signature family without
/// duplicating it, which would let the registry drift from the detector.
pub fn signature_ids() -> Vec<&'static str> {
    SIGNATURES.iter().map(|signature| signature.id).collect()
}

/// True when `rule_id` names a heuristic signature.
pub fn is_signature_id(rule_id: &str) -> bool {
    SIGNATURES
        .iter()
        .any(|signature| signature.id.eq_ignore_ascii_case(rule_id))
}

/// Resolve a heuristic signature identity to its `'static` table entry.
pub fn signature_id_static(rule_id: &str) -> Option<&'static str> {
    SIGNATURES
        .iter()
        .find(|signature| signature.id.eq_ignore_ascii_case(rule_id))
        .map(|signature| signature.id)
}

/// Human description for a heuristic signature.
pub fn signature_description(rule_id: &str) -> Option<&'static str> {
    SIGNATURES
        .iter()
        .find(|signature| signature.id.eq_ignore_ascii_case(rule_id))
        .map(|signature| signature.description)
}

/// Attack category for a heuristic signature.
pub fn signature_category(rule_id: &str) -> Option<&'static str> {
    SIGNATURES
        .iter()
        .find(|signature| signature.id.eq_ignore_ascii_case(rule_id))
        .map(|signature| signature.category)
}
