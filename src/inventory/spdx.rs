use super::ModelSecurityPassport;
/// SPDX 3.0.1 Core+AI JSON-LD shaped export. Detection never consumes this metadata.
pub fn spdx_ai_3_0_1(p: &ModelSecurityPassport) -> serde_json::Value {
    let id = p
        .identity
        .package
        .as_ref()
        .or(p.identity.byte.as_ref())
        .or(p.identity.structural.as_ref())
        .map(|v| v.value.clone())
        .unwrap_or_else(|| p.subject.name.clone());
    serde_json::json!({"@context":["https://spdx.org/rdf/3.0.1/terms/Core/","https://spdx.org/rdf/3.0.1/terms/AI/"],"spdxVersion":"3.0.1","creationInfo":{"created":p.generated_unix,"createdBy":[format!("Tool: layerfault-{}",p.layerfault_version)]},"elements":[{"type":"ai_AIPackage","spdxId":"SPDXRef-Model","name":p.subject.name,"externalIdentifier":[{"externalIdentifierType":"layerfaultModelIdentity","identifier":id}]}]})
}
