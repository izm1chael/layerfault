use super::{
    CapabilityConfidence, CapabilityEvidenceKind, CapabilityGrant, CapabilityKind, CapabilityScope,
    ToolDefinition,
};
use crate::assurance::AnalysisCompleteness;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MAX_SCHEMA_DEPTH: usize = 24;
const MAX_SCHEMA_NODES: usize = 8192;
const MAX_TEXT: usize = 64 * 1024;
const MAX_REF_RESOLUTIONS: usize = 256;
const MAX_BRANCHES: usize = 64;
const MAX_ARRAY_ITEMS: usize = 4096;
const MAX_ENUM_VALUES: usize = 256;

/// Whether Layerfault could establish that an accepted input branch can
/// expose a given capability. Deliberately not a boolean: this is not a
/// standards-complete JSON Schema validator, so there must be a state for
/// "could not determine" that is distinct from "determined absent".
/// Unsupported constructs, an exhausted evaluation budget, an external
/// `$ref`, or an unresolved complex constraint must map to `Unknown` (or
/// `Possible`), never to `Absent` — coercing them to `Absent` would let a
/// deliberately unusual schema evade detection purely because the
/// evaluator's own bounds were hit, turning a coverage limitation into an
/// evasion technique.
/// Ordered weakest to strongest positive evidence (`Ord` is derived from
/// declaration order and is relied on when merging repeated hits for the
/// same capability across a schema: the strongest state found anywhere
/// wins, so one `Present` hit outranks any number of `Possible` hits).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SchemaCapabilityState {
    Absent,
    /// Evaluation could not determine this — see the type-level doc.
    Unknown,
    /// Found, but only in a branch that need not apply to every accepted
    /// input: one alternative of `oneOf`/`anyOf`, an optional property, or
    /// content that appears only inside a `not` schema (which describes
    /// what is forbidden in one specific shape, not a guarantee about every
    /// other accepted shape).
    Possible,
    /// Found in a branch that unconditionally applies to every accepted
    /// input (a required/unconditional `properties` entry, an `allOf`
    /// member, the schema's own leaf keywords).
    Present,
}

/// Structural evaluation cannot be complete by construction (this is not a
/// full validator); this records why, so incompleteness is visible rather
/// than silently treated as a clean pass. Mirrors the `McpServer.limitations`
/// pattern used elsewhere in this module.
#[derive(Debug, Clone)]
pub struct SchemaAnalysisOutcome {
    pub completeness: AnalysisCompleteness,
    pub limitations: Vec<String>,
}

/// Whether a schema position is reached through a branch guaranteed to
/// apply to every accepted input (`Definite`) or only to some accepted
/// inputs (`Possible` — a `oneOf`/`anyOf` alternative, or content found
/// only inside a `not` schema).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BranchContext {
    Definite,
    Possible,
}

impl BranchContext {
    fn state(self) -> SchemaCapabilityState {
        match self {
            BranchContext::Definite => SchemaCapabilityState::Present,
            BranchContext::Possible => SchemaCapabilityState::Possible,
        }
    }
}

pub fn capabilities_for_tool(
    server: &str,
    tool: &ToolDefinition,
) -> (Vec<CapabilityGrant>, SchemaAnalysisOutcome) {
    let mut lexical_signals = BTreeSet::<CapabilityKind>::new();
    classify_text(&tool.name, &mut lexical_signals);
    if let Some(description) = &tool.description {
        classify_text(description, &mut lexical_signals);
    }
    for effect in &tool.declared_effects {
        classify_text(effect, &mut lexical_signals);
        let lower = effect.trim().to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "write" | "modify" | "create" | "update" | "edit" | "save" | "patch"
        ) {
            lexical_signals.insert(CapabilityKind::FilesystemWrite);
        } else if matches!(
            lower.as_str(),
            "delete" | "remove" | "destroy" | "drop" | "unlink"
        ) {
            lexical_signals.insert(CapabilityKind::FilesystemDelete);
        }
    }

    let mut schema_states = BTreeMap::<CapabilityKind, SchemaCapabilityState>::new();
    let mut walker = SchemaWalker {
        root: &tool.input_schema,
        nodes: 0,
        ref_resolutions: 0,
        ref_chain: Vec::new(),
        incomplete_reasons: BTreeSet::new(),
    };
    walker.walk(
        &tool.input_schema,
        0,
        BranchContext::Definite,
        &mut schema_states,
    );

    let all_kinds: BTreeSet<CapabilityKind> = lexical_signals
        .iter()
        .copied()
        .chain(schema_states.keys().copied())
        .collect();
    let scope = infer_scope(&tool.input_schema, &all_kinds);

    let mut out = Vec::new();
    for capability in &lexical_signals {
        out.push(build_grant(
            *capability,
            scope_for(*capability, scope),
            server,
            tool,
            CapabilityEvidenceKind::LexicallyInferred,
            CapabilityConfidence::Medium,
        ));
    }
    for (capability, state) in &schema_states {
        // Structurally inferred: the identifier match itself is still
        // lexical (`classify_text`), but whether it counts as evidence at
        // all — and how strongly — now depends on where in the schema's
        // real structure (required vs. one-of-several vs. excluded by
        // `not`) it was found, not on blind traversal of every key/value.
        let confidence = match state {
            SchemaCapabilityState::Present => CapabilityConfidence::Medium,
            SchemaCapabilityState::Possible => CapabilityConfidence::Low,
            SchemaCapabilityState::Absent | SchemaCapabilityState::Unknown => continue,
        };
        out.push(build_grant(
            *capability,
            scope_for(*capability, scope),
            server,
            tool,
            CapabilityEvidenceKind::StructurallyInferred,
            confidence,
        ));
    }
    out.sort();
    out.dedup();

    let completeness = if walker.incomplete_reasons.is_empty() {
        AnalysisCompleteness::Complete
    } else {
        AnalysisCompleteness::Partial
    };
    let limitations = walker
        .incomplete_reasons
        .into_iter()
        .map(|reason| format!("tool '{}': {reason}", tool.name))
        .collect();
    (
        out,
        SchemaAnalysisOutcome {
            completeness,
            limitations,
        },
    )
}

fn build_grant(
    capability: CapabilityKind,
    scope: CapabilityScope,
    server: &str,
    tool: &ToolDefinition,
    evidence_kind: CapabilityEvidenceKind,
    confidence: CapabilityConfidence,
) -> CapabilityGrant {
    CapabilityGrant {
        capability,
        scope,
        source: "tool_schema".into(),
        server: Some(server.to_owned()),
        tool: Some(tool.name.clone()),
        confirmation_required: tool.confirmation_required,
        evidence_kind,
        confidence,
        isolation_barrier: None,
    }
}

/// Semantic JSON Schema walker. Objective, stated precisely: determine
/// whether an accepted input branch can expose a security-relevant
/// capability. This is deliberately not a standards-complete validator —
/// only `$ref`/`$defs`, `oneOf`/`anyOf`/`allOf`/`not`, `const`, `enum`,
/// `pattern`, `format`, `additionalProperties`, `dependentSchemas`,
/// `unevaluatedProperties` and nested object/array schemas are understood,
/// because that is what serves the objective.
struct SchemaWalker<'a> {
    /// The tool's whole `input_schema`, used to resolve in-document
    /// `$ref`s via JSON Pointer.
    root: &'a Value,
    nodes: usize,
    ref_resolutions: usize,
    /// Pointers currently being resolved, for bounded cycle detection.
    ref_chain: Vec<String>,
    incomplete_reasons: BTreeSet<&'static str>,
}

impl<'a> SchemaWalker<'a> {
    fn walk(
        &mut self,
        value: &Value,
        depth: usize,
        context: BranchContext,
        out: &mut BTreeMap<CapabilityKind, SchemaCapabilityState>,
    ) {
        if depth > MAX_SCHEMA_DEPTH {
            self.incomplete_reasons
                .insert("schema exceeded the maximum nesting depth");
            return;
        }
        if self.nodes >= MAX_SCHEMA_NODES {
            self.incomplete_reasons
                .insert("schema exceeded the maximum node budget");
            return;
        }
        self.nodes += 1;
        let Some(object) = value.as_object() else {
            return;
        };

        if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
            self.resolve_ref(reference, depth, context, out);
        }

        for key in ["oneOf", "anyOf"] {
            if let Some(branches) = object.get(key).and_then(Value::as_array) {
                for branch in branches.iter().take(MAX_BRANCHES) {
                    self.walk(branch, depth + 1, BranchContext::Possible, out);
                }
            }
        }
        if let Some(branches) = object.get("allOf").and_then(Value::as_array) {
            // Every allOf branch must hold simultaneously, so a capability
            // in any branch is exactly as certain as the containing schema.
            for branch in branches.iter().take(MAX_BRANCHES) {
                self.walk(branch, depth + 1, context, out);
            }
        }
        if let Some(inner) = object.get("not") {
            // `not` describes what makes an input invalid, not a branch a
            // caller chooses; content found only here is neither guaranteed
            // present nor guaranteed absent from an accepted input, so it
            // must not be treated identically to a normal declared
            // property (that was the bug: it previously counted the same
            // as `required`).
            self.walk(inner, depth + 1, BranchContext::Possible, out);
        }

        if let Some(props) = object.get("properties").and_then(Value::as_object) {
            for (key, value) in props {
                self.classify_identifier(key, context, out);
                self.walk(value, depth + 1, context, out);
            }
        }
        if let Some(props) = object.get("patternProperties").and_then(Value::as_object) {
            for (key, value) in props {
                // A pattern may or may not match any given accepted key.
                self.classify_identifier(key, BranchContext::Possible, out);
                self.walk(value, depth + 1, BranchContext::Possible, out);
            }
        }
        if let Some(inner) = object.get("additionalProperties") {
            if inner.is_object() {
                // Additional properties beyond the declared ones are
                // optional by nature.
                self.walk(inner, depth + 1, BranchContext::Possible, out);
            }
        }
        if let Some(deps) = object.get("dependentSchemas").and_then(Value::as_object) {
            for (key, value) in deps {
                self.classify_identifier(key, BranchContext::Possible, out);
                self.walk(value, depth + 1, BranchContext::Possible, out);
            }
        }
        if let Some(inner) = object.get("unevaluatedProperties") {
            if inner.is_object() {
                self.walk(inner, depth + 1, BranchContext::Possible, out);
            }
        }

        if let Some(items) = object.get("items") {
            match items {
                Value::Array(list) => {
                    for item in list.iter().take(MAX_ARRAY_ITEMS) {
                        self.walk(item, depth + 1, context, out);
                    }
                }
                other => self.walk(other, depth + 1, context, out),
            }
        }
        if let Some(items) = object.get("prefixItems").and_then(Value::as_array) {
            for item in items.iter().take(MAX_ARRAY_ITEMS) {
                self.walk(item, depth + 1, context, out);
            }
        }

        for key in ["description", "title", "format", "pattern"] {
            if let Some(text) = object.get(key).and_then(Value::as_str) {
                if text.len() <= MAX_TEXT {
                    self.classify_identifier(text, context, out);
                }
            }
        }
        if let Some(text) = object.get("const").and_then(Value::as_str) {
            if text.len() <= MAX_TEXT {
                self.classify_identifier(text, context, out);
            }
        }
        if let Some(values) = object.get("enum").and_then(Value::as_array) {
            for value in values.iter().take(MAX_ENUM_VALUES) {
                if let Some(text) = value.as_str() {
                    if text.len() <= MAX_TEXT {
                        self.classify_identifier(text, context, out);
                    }
                }
            }
        }
    }

    fn resolve_ref(
        &mut self,
        reference: &str,
        depth: usize,
        context: BranchContext,
        out: &mut BTreeMap<CapabilityKind, SchemaCapabilityState>,
    ) {
        if !reference.starts_with('#') {
            // External/network $ref: never fetch. Layerfault is
            // offline-first; a scanner that dereferences attacker-supplied
            // URLs is itself an SSRF primitive.
            self.incomplete_reasons
                .insert("schema references an external $ref, which is never fetched");
            return;
        }
        if self.ref_resolutions >= MAX_REF_RESOLUTIONS {
            self.incomplete_reasons
                .insert("schema exceeded the maximum $ref resolution budget");
            return;
        }
        if self.ref_chain.iter().any(|seen| seen == reference) {
            // Bounded cycle handling: stop following this cycle rather than
            // recursing unboundedly.
            self.incomplete_reasons
                .insert("schema contains a cyclic $ref");
            return;
        }
        let pointer = reference.trim_start_matches('#');
        let Some(target) = self.root.pointer(pointer) else {
            self.incomplete_reasons
                .insert("schema $ref does not resolve within the document");
            return;
        };
        self.ref_resolutions += 1;
        self.ref_chain.push(reference.to_owned());
        self.walk(target, depth + 1, context, out);
        self.ref_chain.pop();
    }

    fn classify_identifier(
        &self,
        text: &str,
        context: BranchContext,
        out: &mut BTreeMap<CapabilityKind, SchemaCapabilityState>,
    ) {
        let mut signals = BTreeSet::new();
        classify_text(text, &mut signals);
        let state = context.state();
        for capability in signals {
            out.entry(capability)
                .and_modify(|existing| {
                    if state > *existing {
                        *existing = state;
                    }
                })
                .or_insert(state);
        }
    }
}

/// Split an identifier-shaped string into complete, lowercase semantic
/// tokens on `snake_case`, `kebab-case`, `camelCase`/`PascalCase`, dot/path
/// separators, whitespace and punctuation. Any non-alphanumeric character is
/// a separator; a lowercase-to-uppercase transition inside a run of letters
/// is also a boundary (so `maxTokens` yields `["max", "tokens"]`, not one
/// token). This is what `any()` below matches complete tokens against,
/// instead of testing raw substring containment — substring containment
/// treats `"token"` inside `max_tokens` as a match, and `"user"` inside
/// `username` as a match, neither of which is true at the identifier level.
fn tokenize_identifier(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut prev_lower = false;
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            if ch.is_uppercase() && prev_lower && !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            current.push(ch.to_ascii_lowercase());
            prev_lower = ch.is_lowercase() || ch.is_ascii_digit();
        } else {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            prev_lower = false;
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// True when `needle` — itself split into tokens the same way — appears as
/// a contiguous run of complete tokens within `tokens`. A multi-word needle
/// like `"read_file"` tokenises to `["read", "file"]` and matches an
/// identifier only where those two tokens appear adjacent and in order
/// (matching `readFile`/`read_file`/`read-file` alike, but not `file_read`
/// or an unrelated identifier that merely contains both words separately).
fn contains_token_sequence(tokens: &[String], needle: &str) -> bool {
    let needle_tokens = tokenize_identifier(needle);
    if needle_tokens.is_empty() || needle_tokens.len() > tokens.len() {
        return false;
    }
    tokens
        .windows(needle_tokens.len())
        .any(|window| window == needle_tokens.as_slice())
}

fn classify_text(raw: &str, out: &mut BTreeSet<CapabilityKind>) {
    let tokens = tokenize_identifier(raw);
    if any(
        &tokens,
        &["command", "shell", "bash", "powershell", "exec", "terminal"],
    ) {
        out.insert(CapabilityKind::ProcessShell);
        out.insert(CapabilityKind::ProcessSpawn);
    }
    if any(&tokens, &["process", "spawn", "pid", "signal"]) {
        out.insert(CapabilityKind::ProcessSpawn);
    }
    if any(
        &tokens,
        &[
            "file",
            "path",
            "filesystem",
            "directory",
            "folder",
            "read_file",
        ],
    ) {
        out.insert(CapabilityKind::FilesystemRead);
    }
    if any(
        &tokens,
        &[
            "write",
            "write_file",
            "save_file",
            "create_file",
            "overwrite",
            "patch_file",
            "edit_file",
        ],
    ) {
        out.insert(CapabilityKind::FilesystemWrite);
    }
    if any(
        &tokens,
        &[
            "delete",
            "remove_file",
            "unlink",
            "rmdir",
            "destroy",
            "drop",
        ],
    ) {
        out.insert(CapabilityKind::FilesystemDelete);
    }
    if any(
        &tokens,
        &[
            "url", "uri", "http", "fetch", "request", "webhook", "internet", "egress", "download",
            "upload",
        ],
    ) {
        out.insert(CapabilityKind::NetworkConnect);
        out.insert(CapabilityKind::NetworkInternetEgress);
    }
    if any(&tokens, &["listen", "bind_address", "server_port"]) {
        out.insert(CapabilityKind::NetworkListen);
    }
    if any(
        &tokens,
        &[
            "secret",
            "api_key",
            "token",
            "credential",
            "password",
            "private_key",
            "keychain",
            "vault",
        ],
    ) {
        out.insert(CapabilityKind::SecretRead);
        out.insert(CapabilityKind::CredentialUse);
    }
    if any(
        &tokens,
        &[
            "git_status",
            "git_log",
            "git_diff",
            "repository",
            "repo_read",
        ],
    ) {
        out.insert(CapabilityKind::GitRead);
    }
    if any(
        &tokens,
        &[
            "git_commit",
            "git_add",
            "git_write",
            "repository_write",
            "repo_write",
        ],
    ) {
        out.insert(CapabilityKind::GitWrite);
    }
    if any(
        &tokens,
        &["git_push", "push_branch", "create_pr", "merge_pr"],
    ) {
        out.insert(CapabilityKind::GitPush);
    }
    if any(&tokens, &["sql", "query", "database", "db_read", "select"]) {
        out.insert(CapabilityKind::DatabaseRead);
    }
    if any(
        &tokens,
        &[
            "db_write",
            "insert",
            "update_row",
            "delete_row",
            "execute_sql",
        ],
    ) {
        out.insert(CapabilityKind::DatabaseWrite);
    }
    if any(
        &tokens,
        &["database_admin", "db_admin", "drop_table", "alter_table"],
    ) {
        out.insert(CapabilityKind::DatabaseAdmin);
    }
    if any(
        &tokens,
        &[
            "aws",
            "azure",
            "gcp",
            "cloud",
            "iam",
            "assume_role",
            "service_account",
        ],
    ) {
        out.insert(CapabilityKind::CloudRead);
        out.insert(CapabilityKind::CloudIdentity);
    }
    if any(
        &tokens,
        &["cloud_write", "deploy", "provision", "create_resource"],
    ) {
        out.insert(CapabilityKind::CloudWrite);
    }
    if any(
        &tokens,
        &[
            "cloud_admin",
            "iam_admin",
            "subscription_admin",
            "project_owner",
        ],
    ) {
        out.insert(CapabilityKind::CloudAdmin);
    }
    if any(&tokens, &["browser", "navigate", "open_page", "goto"]) {
        out.insert(CapabilityKind::BrowserNavigate);
    }
    if any(&tokens, &["browser_download", "download_file"]) {
        out.insert(CapabilityKind::BrowserDownload);
    }
    if any(&tokens, &["browser_upload", "upload_file"]) {
        out.insert(CapabilityKind::BrowserUpload);
    }
    if any(
        &tokens,
        &["cookie", "browser_credentials", "browser_password"],
    ) {
        out.insert(CapabilityKind::BrowserCredentials);
    }
    if any(&tokens, &["email", "mailbox", "inbox", "read_mail"]) {
        out.insert(CapabilityKind::EmailRead);
    }
    if any(&tokens, &["send_email", "send_mail", "reply_email"]) {
        out.insert(CapabilityKind::EmailSend);
    }
    if any(&tokens, &["docker", "podman", "container_exec"]) {
        out.insert(CapabilityKind::ContainerExec);
    }
    if any(
        &tokens,
        &["docker_socket", "container_admin", "privileged_container"],
    ) {
        out.insert(CapabilityKind::ContainerAdmin);
    }
    if any(&tokens, &["kubernetes", "kubectl", "k8s", "cluster"]) {
        out.insert(CapabilityKind::KubernetesRead);
    }
    if any(&tokens, &["kubectl_apply", "kubernetes_write", "k8s_write"]) {
        out.insert(CapabilityKind::KubernetesWrite);
    }
    if any(&tokens, &["cluster_admin", "kubernetes_admin", "k8s_admin"]) {
        out.insert(CapabilityKind::KubernetesAdmin);
    }
    if any(&tokens, &["impersonate", "act_as", "sudo_as"]) {
        out.insert(CapabilityKind::IdentityImpersonate);
    }
    if any(&tokens, &["delegate", "on_behalf_of"]) {
        out.insert(CapabilityKind::IdentityDelegate);
    }
}

fn any(tokens: &[String], values: &[&str]) -> bool {
    values
        .iter()
        .any(|value| contains_token_sequence(tokens, value))
}

fn infer_scope(schema: &Value, capabilities: &BTreeSet<CapabilityKind>) -> CapabilityScope {
    let text = serde_json::to_string(schema).unwrap_or_default();
    let tokens = tokenize_identifier(&text);
    if any(&tokens, &["organisation", "organization", "org_id"]) {
        CapabilityScope::Organisation
    } else if any(&tokens, &["tenant"]) {
        CapabilityScope::Tenant
    } else if any(&tokens, &["cluster"]) || capabilities.contains(&CapabilityKind::KubernetesAdmin)
    {
        CapabilityScope::Cluster
    } else if any(&tokens, &["workspace", "working_directory"]) {
        CapabilityScope::Workspace
    } else if any(&tokens, &["project", "repository"]) {
        CapabilityScope::Project
    } else if any(&tokens, &["home", "user"]) {
        CapabilityScope::User
    } else if capabilities.contains(&CapabilityKind::NetworkInternetEgress) {
        CapabilityScope::Internet
    } else {
        CapabilityScope::Unknown
    }
}

fn scope_for(capability: CapabilityKind, inferred: CapabilityScope) -> CapabilityScope {
    match capability {
        CapabilityKind::NetworkInternetEgress => CapabilityScope::Internet,
        CapabilityKind::KubernetesRead
        | CapabilityKind::KubernetesWrite
        | CapabilityKind::KubernetesAdmin => CapabilityScope::Cluster,
        _ => inferred,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_form_command_maps_to_shell_execution() {
        let tool = ToolDefinition {
            name: "execute".into(),
            description: None,
            input_schema: serde_json::json!({"type":"object","properties":{"command":{"type":"string"}}}),
            annotations: Value::Null,
            declared_effects: Vec::new(),
            confirmation_required: None,
        };
        let (grants, _outcome) = capabilities_for_tool("local", &tool);
        assert!(grants
            .iter()
            .any(|grant| grant.capability == CapabilityKind::ProcessShell));
    }

    #[test]
    fn narrow_status_tool_does_not_gain_shell() {
        let tool = ToolDefinition {
            name: "git_status".into(),
            description: Some("Show repository status".into()),
            input_schema: serde_json::json!({"type":"object","properties":{}}),
            annotations: Value::Null,
            declared_effects: Vec::new(),
            confirmation_required: None,
        };
        let (grants, _outcome) = capabilities_for_tool("git", &tool);
        assert!(grants
            .iter()
            .any(|grant| grant.capability == CapabilityKind::GitRead));
        assert!(!grants
            .iter()
            .any(|grant| grant.capability == CapabilityKind::ProcessShell));
    }

    #[test]
    fn max_tokens_field_does_not_yield_secret_capability() {
        // Regression fixture: "token" is a substring of "max_tokens" but not
        // a complete token of it ("tokens" != "token").
        let tool = ToolDefinition {
            name: "generate".into(),
            description: None,
            input_schema: serde_json::json!({"type":"object","properties":{"max_tokens":{"type":"integer"}}}),
            annotations: Value::Null,
            declared_effects: Vec::new(),
            confirmation_required: None,
        };
        let (grants, _outcome) = capabilities_for_tool("model", &tool);
        assert!(!grants
            .iter()
            .any(|grant| grant.capability == CapabilityKind::SecretRead
                || grant.capability == CapabilityKind::CredentialUse));
    }

    #[test]
    fn credential_field_still_yields_secret_capability() {
        let tool = ToolDefinition {
            name: "configure".into(),
            description: None,
            input_schema: serde_json::json!({"type":"object","properties":{"api_key":{"type":"string"}}}),
            annotations: Value::Null,
            declared_effects: Vec::new(),
            confirmation_required: None,
        };
        let (grants, _outcome) = capabilities_for_tool("model", &tool);
        assert!(grants
            .iter()
            .any(|grant| grant.capability == CapabilityKind::SecretRead));
    }

    #[test]
    fn fused_compound_word_does_not_match_a_shorter_token() {
        // "filepath" has no discoverable token boundary and stays one
        // token, so it does not match the complete-token needle "path".
        let tokens = tokenize_identifier("filepath");
        assert!(!contains_token_sequence(&tokens, "path"));
        // A real separator or camelCase boundary does still match.
        assert!(contains_token_sequence(
            &tokenize_identifier("file_path"),
            "path"
        ));
        assert!(contains_token_sequence(
            &tokenize_identifier("filePath"),
            "path"
        ));
    }

    #[test]
    fn username_field_does_not_infer_user_scope() {
        // Regression fixture: "user" is a substring of "username" but not a
        // complete token of it.
        let schema =
            serde_json::json!({"type":"object","properties":{"username":{"type":"string"}}});
        let scope = infer_scope(&schema, &BTreeSet::new());
        assert_ne!(scope, CapabilityScope::User);
    }

    #[test]
    fn standalone_user_field_still_infers_user_scope() {
        let schema =
            serde_json::json!({"type":"object","properties":{"user_id":{"type":"string"}}});
        let scope = infer_scope(&schema, &BTreeSet::new());
        assert_eq!(scope, CapabilityScope::User);
    }

    #[test]
    fn read_file_matches_camel_case_and_snake_case_alike() {
        let camel = tokenize_identifier("readFile");
        let snake = tokenize_identifier("read_file");
        assert!(contains_token_sequence(&camel, "read_file"));
        assert!(contains_token_sequence(&snake, "read_file"));
        // Order matters: the reverse compound is a different identifier.
        assert!(!contains_token_sequence(
            &tokenize_identifier("file_read"),
            "read_file"
        ));
    }

    fn tool_with_schema(name: &str, schema: Value) -> ToolDefinition {
        ToolDefinition {
            name: name.into(),
            description: None,
            input_schema: schema,
            annotations: Value::Null,
            declared_effects: Vec::new(),
            confirmation_required: None,
        }
    }

    #[test]
    fn execution_capable_branch_behind_one_of_is_detected() {
        let tool = tool_with_schema(
            "act",
            serde_json::json!({
                "oneOf": [
                    {"properties": {"path": {"type": "string"}}},
                    {"properties": {"execute_command": {"type": "string"}}}
                ]
            }),
        );
        let (grants, outcome) = capabilities_for_tool("local", &tool);
        assert_eq!(outcome.completeness, AnalysisCompleteness::Complete);
        assert!(grants
            .iter()
            .any(|grant| grant.capability == CapabilityKind::ProcessShell));
    }

    #[test]
    fn capability_hidden_behind_a_local_ref_is_detected() {
        let tool = tool_with_schema(
            "act",
            serde_json::json!({
                "$defs": {
                    "executeCommand": {"properties": {"command": {"type": "string"}}}
                },
                "$ref": "#/$defs/executeCommand"
            }),
        );
        let (grants, outcome) = capabilities_for_tool("local", &tool);
        assert_eq!(outcome.completeness, AnalysisCompleteness::Complete);
        assert!(grants
            .iter()
            .any(|grant| grant.capability == CapabilityKind::ProcessShell));
    }

    #[test]
    fn cyclic_ref_is_bounded_not_a_stack_overflow() {
        let tool = tool_with_schema(
            "act",
            serde_json::json!({
                "$defs": {
                    "a": {"$ref": "#/$defs/b"},
                    "b": {"$ref": "#/$defs/a"}
                },
                "$ref": "#/$defs/a"
            }),
        );
        let (_grants, outcome) = capabilities_for_tool("local", &tool);
        assert_eq!(outcome.completeness, AnalysisCompleteness::Partial);
        assert!(outcome
            .limitations
            .iter()
            .any(|limitation| limitation.contains("cyclic")));
    }

    #[test]
    fn external_ref_is_never_fetched_and_marks_partial() {
        let tool = tool_with_schema(
            "act",
            serde_json::json!({"$ref": "https://attacker.invalid/schema.json"}),
        );
        let (grants, outcome) = capabilities_for_tool("local", &tool);
        // No network-visible side effect to assert directly, but the
        // absence of a panic/hang and the Partial completeness together
        // demonstrate the reference was not followed.
        assert_eq!(outcome.completeness, AnalysisCompleteness::Partial);
        assert!(outcome
            .limitations
            .iter()
            .any(|limitation| limitation.contains("external")));
        assert!(grants.is_empty());
    }

    #[test]
    fn deeply_nested_schema_marks_partial_not_a_silent_absent() {
        let mut schema = serde_json::json!({"properties": {"command": {"type": "string"}}});
        for _ in 0..(MAX_SCHEMA_DEPTH + 8) {
            schema = serde_json::json!({"properties": {"nested": schema}});
        }
        let tool = tool_with_schema("act", schema);
        let (_grants, outcome) = capabilities_for_tool("local", &tool);
        assert_eq!(outcome.completeness, AnalysisCompleteness::Partial);
        assert!(outcome
            .limitations
            .iter()
            .any(|limitation| limitation.contains("nesting depth")));
    }

    #[test]
    fn node_budget_exceeded_marks_partial_not_a_silent_absent() {
        let mut properties = serde_json::Map::new();
        for index in 0..(MAX_SCHEMA_NODES + 64) {
            properties.insert(
                format!("field_{index}"),
                serde_json::json!({"type": "string"}),
            );
        }
        let tool = tool_with_schema(
            "act",
            serde_json::json!({"properties": Value::Object(properties)}),
        );
        let (_grants, outcome) = capabilities_for_tool("local", &tool);
        assert_eq!(outcome.completeness, AnalysisCompleteness::Partial);
        assert!(outcome
            .limitations
            .iter()
            .any(|limitation| limitation.contains("node budget")));
    }

    #[test]
    fn not_branch_downgrades_to_possible_not_present() {
        // Regression fixture for "not branches contribute capabilities
        // identically to required properties, which is backwards".
        let tool = tool_with_schema(
            "act",
            serde_json::json!({
                "not": {"properties": {"command": {"type": "string"}}}
            }),
        );
        let (grants, _outcome) = capabilities_for_tool("local", &tool);
        let grant = grants
            .iter()
            .find(|grant| grant.capability == CapabilityKind::ProcessShell)
            .expect("still detected, but weakened");
        assert_eq!(grant.confidence, CapabilityConfidence::Low);
        assert_eq!(
            grant.evidence_kind,
            CapabilityEvidenceKind::StructurallyInferred
        );
    }

    #[test]
    fn required_property_is_present_not_possible() {
        let tool = tool_with_schema(
            "act",
            serde_json::json!({"properties": {"command": {"type": "string"}}, "required": ["command"]}),
        );
        let (grants, _outcome) = capabilities_for_tool("local", &tool);
        let grant = grants
            .iter()
            .find(|grant| grant.capability == CapabilityKind::ProcessShell)
            .expect("detected");
        assert_eq!(grant.confidence, CapabilityConfidence::Medium);
    }

    #[test]
    fn all_of_branch_is_as_certain_as_its_container() {
        let tool = tool_with_schema(
            "act",
            serde_json::json!({
                "allOf": [
                    {"properties": {"command": {"type": "string"}}}
                ]
            }),
        );
        let (grants, _outcome) = capabilities_for_tool("local", &tool);
        let grant = grants
            .iter()
            .find(|grant| grant.capability == CapabilityKind::ProcessShell)
            .expect("detected");
        assert_eq!(grant.confidence, CapabilityConfidence::Medium);
    }

    #[test]
    fn additional_properties_schema_is_possible_not_present() {
        let tool = tool_with_schema(
            "act",
            serde_json::json!({
                "properties": {},
                "additionalProperties": {"properties": {"command": {"type": "string"}}}
            }),
        );
        let (grants, _outcome) = capabilities_for_tool("local", &tool);
        let grant = grants
            .iter()
            .find(|grant| grant.capability == CapabilityKind::ProcessShell)
            .expect("detected");
        assert_eq!(grant.confidence, CapabilityConfidence::Low);
    }
}
