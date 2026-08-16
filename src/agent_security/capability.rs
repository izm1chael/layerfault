use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    FilesystemRead,
    FilesystemWrite,
    FilesystemDelete,
    FilesystemOutsideWorkspace,
    ProcessSpawn,
    ProcessShell,
    ProcessSignal,
    NetworkConnect,
    NetworkListen,
    NetworkRaw,
    NetworkInternetEgress,
    SecretRead,
    CredentialUse,
    CredentialExport,
    GitRead,
    GitWrite,
    GitPush,
    GitAdmin,
    DatabaseRead,
    DatabaseWrite,
    DatabaseAdmin,
    CloudRead,
    CloudWrite,
    CloudAdmin,
    CloudIdentity,
    BrowserNavigate,
    BrowserDownload,
    BrowserUpload,
    BrowserCredentials,
    EmailRead,
    EmailSend,
    IdentityImpersonate,
    IdentityDelegate,
    ContainerRead,
    ContainerExec,
    ContainerAdmin,
    KubernetesRead,
    KubernetesWrite,
    KubernetesAdmin,
}

impl CapabilityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FilesystemRead => "filesystem.read",
            Self::FilesystemWrite => "filesystem.write",
            Self::FilesystemDelete => "filesystem.delete",
            Self::FilesystemOutsideWorkspace => "filesystem.outside_workspace",
            Self::ProcessSpawn => "process.spawn",
            Self::ProcessShell => "process.shell",
            Self::ProcessSignal => "process.signal",
            Self::NetworkConnect => "network.connect",
            Self::NetworkListen => "network.listen",
            Self::NetworkRaw => "network.raw",
            Self::NetworkInternetEgress => "network.internet_egress",
            Self::SecretRead => "secret.read",
            Self::CredentialUse => "credential.use",
            Self::CredentialExport => "credential.export",
            Self::GitRead => "git.read",
            Self::GitWrite => "git.write",
            Self::GitPush => "git.push",
            Self::GitAdmin => "git.admin",
            Self::DatabaseRead => "database.read",
            Self::DatabaseWrite => "database.write",
            Self::DatabaseAdmin => "database.admin",
            Self::CloudRead => "cloud.read",
            Self::CloudWrite => "cloud.write",
            Self::CloudAdmin => "cloud.admin",
            Self::CloudIdentity => "cloud.identity",
            Self::BrowserNavigate => "browser.navigate",
            Self::BrowserDownload => "browser.download",
            Self::BrowserUpload => "browser.upload",
            Self::BrowserCredentials => "browser.credentials",
            Self::EmailRead => "email.read",
            Self::EmailSend => "email.send",
            Self::IdentityImpersonate => "identity.impersonate",
            Self::IdentityDelegate => "identity.delegate",
            Self::ContainerRead => "container.read",
            Self::ContainerExec => "container.exec",
            Self::ContainerAdmin => "container.admin",
            Self::KubernetesRead => "kubernetes.read",
            Self::KubernetesWrite => "kubernetes.write",
            Self::KubernetesAdmin => "kubernetes.admin",
        }
    }

    pub fn high_impact(self) -> bool {
        matches!(
            self,
            Self::FilesystemDelete
                | Self::FilesystemOutsideWorkspace
                | Self::ProcessShell
                | Self::NetworkRaw
                | Self::SecretRead
                | Self::CredentialExport
                | Self::GitPush
                | Self::GitAdmin
                | Self::DatabaseAdmin
                | Self::CloudAdmin
                | Self::CloudIdentity
                | Self::BrowserCredentials
                | Self::IdentityImpersonate
                | Self::IdentityDelegate
                | Self::ContainerAdmin
                | Self::KubernetesAdmin
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityScope {
    None,
    Workspace,
    Project,
    User,
    Host,
    Container,
    Cluster,
    Organisation,
    Tenant,
    Internet,
    Unknown,
}

impl CapabilityScope {
    pub fn broad(self) -> bool {
        matches!(
            self,
            Self::User
                | Self::Host
                | Self::Cluster
                | Self::Organisation
                | Self::Tenant
                | Self::Internet
                | Self::Unknown
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub capability: CapabilityKind,
    pub scope: CapabilityScope,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation_required: Option<bool>,
    /// How this grant was discovered. Orthogonal to `confidence`: a
    /// `Declared` claim (the server says so) can still be low-confidence
    /// (unverified self-report), just as a `LexicallyInferred` one can be
    /// medium-confidence. Provenance and certainty are different questions.
    #[serde(default)]
    pub evidence_kind: CapabilityEvidenceKind,
    #[serde(default)]
    pub confidence: CapabilityConfidence,
    /// A known isolation barrier that prevents this capability's result
    /// from reaching the model, or the capability from being invoked in
    /// this execution context. `None` today: static MCP configuration
    /// parsing does not yet produce this signal — it is a hook for later
    /// discovery/posture evidence (sandboxed sub-agents, fixed non-model
    /// data flow) to populate, consulted by the reachability graph in
    /// `crate::agent_security::graph`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolation_barrier: Option<String>,
}

/// How a capability grant was discovered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityEvidenceKind {
    /// The server or tool metadata explicitly declares this capability
    /// (e.g. an annotation), without independent verification.
    Declared,
    /// Derived from JSON Schema structure (branches, combinators,
    /// constraints) rather than keyword matching.
    StructurallyInferred,
    /// Derived from keyword/token matching against tool names,
    /// descriptions and schema text.
    #[default]
    LexicallyInferred,
    /// Observed directly from live MCP protocol discovery.
    ProtocolObserved,
    /// Observed from an actual behavioural run.
    BehaviourallyObserved,
}

/// How certain Layerfault is that a grant is accurate, independent of how
/// it was discovered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityConfidence {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
}
