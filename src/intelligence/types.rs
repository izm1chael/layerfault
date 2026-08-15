use crate::advisory::RuntimeAdvisory;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntelligencePack {
    pub version: u32,
    pub sequence: u64,
    pub generated_unix: u64,
    #[serde(default)]
    pub expires_unix: Option<u64>,
    #[serde(default)]
    pub channel: IntelligenceChannel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default)]
    pub runtime_advisories: Vec<RuntimeAdvisory>,
    #[serde(default)]
    pub pickle_gadgets: Vec<PickleGadgetRecord>,
    #[serde(default)]
    pub declarative_edges: Vec<DeclarativeEdgeRecord>,
    #[serde(default)]
    pub known_identities: Vec<KnownIdentityRecord>,
    #[serde(default)]
    pub threat_mappings: Vec<ThreatMappingRecord>,
    #[serde(default)]
    pub revocations: Vec<RevocationRecord>,
    #[serde(default)]
    pub adapter_indicators: Vec<AdapterIndicatorRecord>,
    #[serde(default)]
    pub builders: Vec<BuilderRecord>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelligenceChannel {
    #[default]
    Stable,
    Rapid,
    Preview,
    Offline,
    Enterprise,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationTarget {
    Signer,
    Model,
    Passport,
    RuntimeRelease,
    Advisory,
    Builder,
    Adapter,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RevocationRecord {
    pub id: String,
    pub target: RevocationTarget,
    pub value: String,
    pub effective_unix: u64,
    pub reason: String,
    pub reference: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelligenceDisposition {
    Trusted,
    Suspicious,
    Malicious,
    Revoked,
    Compromised,
    Unknown,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdapterIndicatorRecord {
    pub id: String,
    pub sha256: String,
    pub disposition: IntelligenceDisposition,
    #[serde(default)]
    pub declared_base: Option<String>,
    pub reference: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BuilderRecord {
    pub id: String,
    pub identity: String,
    pub disposition: IntelligenceDisposition,
    pub reference: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PickleGadgetRecord {
    pub id: String,
    pub module: String,
    pub callable: String,
    pub severity: crate::advisory::Severity,
    pub capability: PickleGadgetCapability,
    pub reference: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PickleGadgetCapability {
    ProcessExecution,
    DynamicImport,
    FilesystemMutation,
    NetworkAccess,
    NativeLoading,
    Deserialization,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeclarativeEdgeRecord {
    pub id: String,
    pub framework: String,
    pub source_path: String,
    pub field_path: String,
    pub sink_kind: DeclarativeSinkKind,
    #[serde(default)]
    pub allowed_prefixes: Vec<String>,
    #[serde(default)]
    pub affected_runtime: Option<String>,
    pub reference: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclarativeSinkKind {
    DynamicImport,
    CustomClass,
    CustomOperator,
    NativeLibrary,
    TemplateExecution,
    ProcessorModule,
    TokenizerModule,
    ActivationFunction,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KnownIdentityRecord {
    pub id: String,
    pub identity_kind: String,
    pub value: String,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ThreatMapping {
    pub rule_id: String,
    #[serde(default)]
    pub cwe: Vec<String>,
    #[serde(default)]
    pub cve: Vec<String>,
    #[serde(default)]
    pub ghsa: Vec<String>,
    #[serde(default, alias = "atlas")]
    pub mitre_atlas: Vec<String>,
    #[serde(default, alias = "owasp")]
    pub owasp_genai: Vec<String>,
    #[serde(default)]
    pub nist: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

impl ThreatMapping {
    pub(crate) fn canonicalize(&mut self) {
        for values in [
            &mut self.cwe,
            &mut self.cve,
            &mut self.ghsa,
            &mut self.mitre_atlas,
            &mut self.owasp_genai,
            &mut self.nist,
            &mut self.references,
        ] {
            values.sort();
            values.dedup();
        }
    }
}

/// Compatibility name retained for intelligence-pack callers added in Stage 02.
pub type ThreatMappingRecord = ThreatMapping;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelligenceFreshness {
    Current,
    Stale,
    Expired,
}
