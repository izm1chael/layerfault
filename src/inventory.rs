use crate::formats::artifact::{self, ArtifactReport, ArtifactScanMode};
use crate::sources::{self, SourceArtifact, SourceKind};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize)]
pub struct InventoryEntry {
    pub source: SourceKind,
    pub identity: String,
    pub path: String,
    pub format: crate::formats::ArtifactFormat,
    pub size: u64,
    pub sha256: Option<String>,
    pub blocking: bool,
    pub findings: usize,
    pub architecture: Option<String>,
    pub quantization: Option<String>,
}

pub fn scan_artifacts(artifacts: &[SourceArtifact], structure_only: bool) -> Vec<InventoryEntry> {
    artifacts
        .iter()
        .map(|item| {
            let mode = if structure_only {
                ArtifactScanMode::StructureOnly
            } else {
                ArtifactScanMode::Full
            };
            match artifact::inspect_with_format(&item.path, item.format, mode) {
                Ok(report) => from_report(item, &report),
                Err(_) => InventoryEntry {
                    source: item.source,
                    identity: item.identity.clone(),
                    path: item.display_path.clone(),
                    format: item.format,
                    size: item.size,
                    sha256: None,
                    blocking: true,
                    findings: 1,
                    architecture: item.architecture.clone(),
                    quantization: item.quantization.clone(),
                },
            }
        })
        .collect()
}

fn from_report(source: &SourceArtifact, report: &ArtifactReport) -> InventoryEntry {
    InventoryEntry {
        source: source.source,
        identity: source.identity.clone(),
        path: source.display_path.clone(),
        format: source.format,
        size: source.size,
        sha256: report.sha256.clone(),
        blocking: report.blocking(),
        findings: report.results.len(),
        architecture: source.architecture.clone(),
        quantization: source.quantization.clone(),
    }
}

pub fn discover_non_ollama(
    lmstudio: bool,
    hf_cache: bool,
    directories: &[std::path::PathBuf],
    hf_root: Option<&Path>,
) -> Vec<SourceArtifact> {
    let mut artifacts = Vec::new();
    if lmstudio {
        if let Ok(mut found) = sources::discover_lmstudio() {
            artifacts.append(&mut found);
        }
    }
    if hf_cache {
        if let Ok(repos) = sources::audit_hf_cache(hf_root) {
            for repo in repos {
                artifacts.extend(repo.artifacts);
            }
        }
    }
    for dir in directories {
        if let Ok(mut found) = sources::discover_directory(dir, SourceKind::Directory) {
            artifacts.append(&mut found);
        }
    }
    artifacts.sort_by(|a, b| a.identity.cmp(&b.identity));
    artifacts
}

pub fn ollama_entries(
    base_dir: &Path,
    reports: &[crate::app::EvaluatedReport],
) -> Vec<InventoryEntry> {
    let mut out = Vec::new();
    for evaluated in reports {
        let name = &evaluated.report.model_name;
        let resolved = crate::manifest::find_model(base_dir, name);
        match resolved {
            Ok(reference) => match crate::manifest::load_model(&reference) {
                Ok(model) => {
                    let size = model
                        .descriptors()
                        .fold(0_u64, |acc, layer| acc.saturating_add(layer.size));
                    out.push(InventoryEntry {
                        source: SourceKind::Ollama,
                        identity: model.name.clone(),
                        path: reference.manifest_path.display().to_string(),
                        format: crate::formats::ArtifactFormat::Gguf,
                        size,
                        sha256: Some(model.digest.clone()),
                        blocking: evaluated
                            .report
                            .results
                            .iter()
                            .any(|result| result.status == crate::scanner::ScanStatus::Fail)
                            || evaluated.policy.action == crate::policy::PolicyAction::Block,
                        findings: evaluated.report.results.len(),
                        architecture: None,
                        quantization: None,
                    });
                }
                Err(_) => out.push(InventoryEntry {
                    source: SourceKind::Ollama,
                    identity: name.clone(),
                    path: reference.manifest_path.display().to_string(),
                    format: crate::formats::ArtifactFormat::Unknown,
                    size: 0,
                    sha256: None,
                    blocking: true,
                    findings: 0,
                    architecture: None,
                    quantization: None,
                }),
            },
            Err(_) => out.push(InventoryEntry {
                source: SourceKind::Ollama,
                identity: name.clone(),
                path: String::new(),
                format: crate::formats::ArtifactFormat::Unknown,
                size: 0,
                sha256: None,
                blocking: true,
                findings: evaluated.report.results.len(),
                architecture: None,
                quantization: None,
            }),
        }
    }
    out
}

pub fn cyclonedx_mlbom(entries: &[InventoryEntry]) -> Value {
    let serial_seed = serde_json::to_vec(entries).unwrap_or_default();
    let serial = hex::encode(Sha256::digest(serial_seed));
    let components = entries
        .iter()
        .map(|entry| {
            let mut hashes = Vec::new();
            if let Some(digest) = &entry.sha256 {
                hashes.push(serde_json::json!({"alg":"SHA-256","content":digest.trim_start_matches("sha256:")}));
            }
            let mut properties = vec![
                serde_json::json!({"name":"layerfault:source","value":entry.source.as_str()}),
                serde_json::json!({"name":"layerfault:format","value":entry.format.as_str()}),
                serde_json::json!({"name":"layerfault:path","value":entry.path}),
                serde_json::json!({"name":"layerfault:blocking","value":entry.blocking.to_string()}),
            ];
            if let Some(value) = &entry.architecture {
                properties.push(serde_json::json!({"name":"layerfault:architecture","value":value}));
            }
            if let Some(value) = &entry.quantization {
                properties.push(serde_json::json!({"name":"layerfault:quantization","value":value}));
            }
            serde_json::json!({
                "type": "machine-learning-model",
                "bom-ref": format!("layerfault:{}:{}", entry.source.as_str(), stable_ref(&entry.identity)),
                "name": entry.identity,
                "hashes": hashes,
                "properties": properties
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": format!("urn:uuid:{}-{}-{}-{}-{}", &serial[0..8], &serial[8..12], &serial[12..16], &serial[16..20], &serial[20..32]),
        "version": 1,
        "metadata": {
            "tools": [{"vendor":"Layerfault","name":"layerfault","version":env!("CARGO_PKG_VERSION")}]
        },
        "components": components
    })
}

fn stable_ref(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(&digest[..12])
}
