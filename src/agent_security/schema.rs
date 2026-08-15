use super::{
    CapabilityConfidence, CapabilityGrant, CapabilityKind, CapabilityScope, ToolDefinition,
};
use serde_json::Value;
use std::collections::BTreeSet;

const MAX_SCHEMA_DEPTH: usize = 24;
const MAX_SCHEMA_NODES: usize = 8192;
const MAX_TEXT: usize = 64 * 1024;

pub fn capabilities_for_tool(server: &str, tool: &ToolDefinition) -> Vec<CapabilityGrant> {
    let mut signals = BTreeSet::<CapabilityKind>::new();
    classify_text(&tool.name, &mut signals);
    if let Some(description) = &tool.description {
        classify_text(description, &mut signals);
    }
    let mut nodes = 0usize;
    walk_schema(&tool.input_schema, 0, &mut nodes, &mut signals);
    let scope = infer_scope(&tool.input_schema, &signals);
    let mut out = signals
        .into_iter()
        .map(|capability| CapabilityGrant {
            capability,
            scope: scope_for(capability, scope),
            source: "tool_schema".into(),
            server: Some(server.to_owned()),
            tool: Some(tool.name.clone()),
            confirmation_required: tool.confirmation_required,
            confidence: CapabilityConfidence::Inferred,
        })
        .collect::<Vec<_>>();
    out.sort();
    out.dedup();
    out
}

fn walk_schema(value: &Value, depth: usize, nodes: &mut usize, out: &mut BTreeSet<CapabilityKind>) {
    if depth > MAX_SCHEMA_DEPTH || *nodes >= MAX_SCHEMA_NODES {
        return;
    }
    *nodes = nodes.saturating_add(1);
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                classify_text(key, out);
                if matches!(
                    key.as_str(),
                    "description" | "title" | "format" | "const" | "pattern"
                ) {
                    if let Some(text) = value.as_str() {
                        classify_text(text, out);
                    }
                }
                walk_schema(value, depth + 1, nodes, out);
            }
        }
        Value::Array(values) => {
            for value in values.iter().take(4096) {
                walk_schema(value, depth + 1, nodes, out);
            }
        }
        Value::String(text) if text.len() <= MAX_TEXT => classify_text(text, out),
        _ => {}
    }
}

fn classify_text(raw: &str, out: &mut BTreeSet<CapabilityKind>) {
    let text = raw.to_ascii_lowercase();
    let tokens = text.replace(['-', '.', '/', ':'], "_");
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
    if any(&tokens, &["delete", "remove_file", "unlink", "rmdir"]) {
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

fn any(text: &str, values: &[&str]) -> bool {
    values.iter().any(|value| text.contains(value))
}

fn infer_scope(schema: &Value, capabilities: &BTreeSet<CapabilityKind>) -> CapabilityScope {
    let text = serde_json::to_string(schema)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if text.contains("organisation") || text.contains("organization") || text.contains("org_id") {
        CapabilityScope::Organisation
    } else if text.contains("tenant") {
        CapabilityScope::Tenant
    } else if text.contains("cluster") || capabilities.contains(&CapabilityKind::KubernetesAdmin) {
        CapabilityScope::Cluster
    } else if text.contains("workspace") || text.contains("working_directory") {
        CapabilityScope::Workspace
    } else if text.contains("project") || text.contains("repository") {
        CapabilityScope::Project
    } else if text.contains("home") || text.contains("user") {
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
            confirmation_required: None,
        };
        let grants = capabilities_for_tool("local", &tool);
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
            confirmation_required: None,
        };
        let grants = capabilities_for_tool("git", &tool);
        assert!(grants
            .iter()
            .any(|grant| grant.capability == CapabilityKind::GitRead));
        assert!(!grants
            .iter()
            .any(|grant| grant.capability == CapabilityKind::ProcessShell));
    }
}
