use crate::sources;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: String,
    pub detail: String,
}

pub fn run() -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    for binary in ["ollama", "lms", "llama-cli", "llama-server", "cosign"] {
        match sources::find_executable(binary) {
            Some(path) => checks.push(DoctorCheck {
                name: binary.to_owned(),
                status: "available".to_owned(),
                detail: path.display().to_string(),
            }),
            None => checks.push(DoctorCheck {
                name: binary.to_owned(),
                status: "not-found".to_owned(),
                detail: "optional integration unavailable".to_owned(),
            }),
        }
    }
    for (name, kind) in [
        ("ollama-security", crate::advisory::RuntimeKind::Ollama),
        ("lmstudio-security", crate::advisory::RuntimeKind::LmStudio),
        ("llama-cpp-security", crate::advisory::RuntimeKind::LlamaCpp),
    ] {
        if crate::advisory::detect_runtime(kind).is_ok() {
            checks.push(match crate::advisory::evaluate(kind, None) {
                Ok(value) => DoctorCheck {
                    name: name.to_owned(),
                    status: if value.blocking {
                        "blocked"
                    } else if value
                        .findings
                        .iter()
                        .any(|f| f.status == crate::scanner::ScanStatus::Warn)
                    {
                        "warning"
                    } else {
                        "pass"
                    }
                    .to_owned(),
                    detail: format!(
                        "version={} advisory-db={}",
                        value
                            .runtime
                            .parsed_version
                            .as_deref()
                            .unwrap_or("unparsed"),
                        value.database_sha256
                    ),
                },
                Err(error) => DoctorCheck {
                    name: name.to_owned(),
                    status: "warning".to_owned(),
                    detail: error.to_string(),
                },
            });
        }
    }
    let ollama = crate::app::resolve_base_dir(None);
    checks.push(match ollama {
        Ok(path) => DoctorCheck {
            name: "ollama-store".to_owned(),
            status: if path.is_dir() {
                "available"
            } else {
                "not-found"
            }
            .to_owned(),
            detail: path.display().to_string(),
        },
        Err(error) => DoctorCheck {
            name: "ollama-store".to_owned(),
            status: "not-found".to_owned(),
            detail: error.to_string(),
        },
    });
    let hf = sources::hf_cache_root(None).unwrap_or_else(|_| PathBuf::from("<unknown>"));
    checks.push(DoctorCheck {
        name: "hf-cache".to_owned(),
        status: if hf.is_dir() {
            "available"
        } else {
            "not-found"
        }
        .to_owned(),
        detail: hf.display().to_string(),
    });
    let config = crate::paths::config_dir().unwrap_or_else(|_| PathBuf::from("<unknown>"));
    checks.push(DoctorCheck {
        name: "config".to_owned(),
        status: "configured".to_owned(),
        detail: config.display().to_string(),
    });
    checks
}
