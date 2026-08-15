use super::ModelSecurityPassport;
pub fn cyclonedx_security_passport(p: &ModelSecurityPassport) -> serde_json::Value {
    let mut props = vec![
        prop("layerfault:scanner-revision", &p.scanner_revision),
        prop("layerfault:ruleset-sha256", &p.ruleset_sha256),
        prop(
            "layerfault:coverage-complete",
            &p.coverage.complete.to_string(),
        ),
    ];
    for (name, v) in [
        ("byte", p.identity.byte.as_ref()),
        ("package", p.identity.package.as_ref()),
        ("structural", p.identity.structural.as_ref()),
        ("tokenizer", p.identity.tokenizer.as_ref()),
        ("weight-sample", p.identity.weight_sample.as_ref()),
    ] {
        if let Some(v) = v {
            props.push(prop(&format!("layerfault:identity:{name}"), &v.value));
        }
    }
    if let Some(v) = &p.intelligence_sha256 {
        props.push(prop("layerfault:intelligence-sha256", v));
    }
    if let Some(policy) = &p.policy {
        props.push(prop("layerfault:policy-action", &policy.action));
    }
    serde_json::json!({"bomFormat":"CycloneDX","specVersion":"1.7","version":1,"metadata":{"tools":[{"vendor":"Layerfault","name":"layerfault","version":p.layerfault_version}]},"components":[{"type":"machine-learning-model","bom-ref":p.identity.package.as_ref().or(p.identity.byte.as_ref()).map(|v|v.value.clone()).unwrap_or_else(||p.subject.name.clone()),"name":p.subject.name,"properties":props}]})
}
fn prop(name: &str, value: &str) -> serde_json::Value {
    serde_json::json!({"name":name,"value":value})
}
