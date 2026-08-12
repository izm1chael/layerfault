//! Software environment runtime closure identification and drift detection.
//!
//! Provides static zero-import Python distribution metadata discovery, native binary
//! dynamic link inspection, sandbox tool identity recording, and canonical closure hashing.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Component;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum ClosureLevel {
    Minimal,
    #[default]
    Standard,
    Deep,
}

impl ClosureLevel {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "minimal" => Ok(Self::Minimal),
            "standard" => Ok(Self::Standard),
            "deep" => Ok(Self::Deep),
            other => anyhow::bail!(
                "unsupported closure level '{other}'; supported: minimal, standard, deep"
            ),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "MINIMAL",
            Self::Standard => "STANDARD",
            Self::Deep => "DEEP",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComponentStatus {
    DiscoveredDependency,
    ObservedLoadedDependency,
    VerifiedRecord,
    UnverifiedRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeComponent {
    pub category: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    pub source: String,
    pub status: ComponentStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl Ord for RuntimeComponent {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            &self.category,
            &self.name,
            &self.version,
            &self.digest,
            &self.source,
            self.status,
        )
            .cmp(&(
                &other.category,
                &other.name,
                &other.version,
                &other.digest,
                &other.source,
                other.status,
            ))
    }
}

impl PartialOrd for RuntimeComponent {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ClosureCoverage {
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incomplete_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeClosure {
    pub closure_id: String,
    pub level: ClosureLevel,
    pub coverage: ClosureCoverage,
    pub components: Vec<RuntimeComponent>,
}

/// PEP 503 canonical distribution name normalization.
/// Lowercases and replaces any run of `_`, `-`, `.` with a single `-`.
pub fn canonicalize_python_dist_name(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let mut result = String::with_capacity(lower.len());
    let mut in_punct = false;
    for c in lower.chars() {
        if c == '-' || c == '_' || c == '.' {
            if !in_punct {
                result.push('-');
                in_punct = true;
            }
        } else {
            result.push(c);
            in_punct = false;
        }
    }
    result
}

/// Discovered Python distribution metadata parsed statically without code execution.
#[derive(Debug, Clone)]
pub struct PythonPackageMetadata {
    pub raw_name: String,
    pub canonical_name: String,
    pub version: String,
    pub dist_info_dir: PathBuf,
    pub record_verified: Option<bool>,
    pub installed_files_digest: Option<String>,
}

/// Safely inspect controlled Python distribution metadata from site-packages directories.
/// NEVER imports or executes package code.
pub fn discover_python_packages(
    site_packages_dirs: &[PathBuf],
    verify_record: bool,
) -> Vec<PythonPackageMetadata> {
    let mut packages = Vec::new();
    let mut seen_canon = BTreeSet::new();

    for site_packages in site_packages_dirs {
        let Ok(entries) = std::fs::read_dir(site_packages) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();

            if !(name.ends_with(".dist-info") || name.ends_with(".egg-info")) {
                continue;
            }

            let metadata_file = if path.is_dir() {
                if name.ends_with(".dist-info") {
                    path.join("METADATA")
                } else {
                    path.join("PKG-INFO")
                }
            } else {
                continue;
            };

            if !metadata_file.is_file() {
                continue;
            }

            let Ok(file) = crate::safeio::open_readonly_nofollow(&metadata_file) else {
                continue;
            };
            let Ok(bytes) = crate::safeio::read_all_from_file(&file, 512 * 1024) else {
                continue;
            };

            let content = String::from_utf8_lossy(&bytes);
            let mut pkg_name = None;
            let mut pkg_version = None;

            for line in content.lines() {
                if line.trim().is_empty() {
                    // RFC 822 header section ends at first blank line
                    break;
                }
                if let Some((key, val)) = line.split_once(':') {
                    let key = key.trim();
                    let val = val.trim();
                    if key.eq_ignore_ascii_case("Name") && pkg_name.is_none() {
                        pkg_name = Some(val.to_owned());
                    } else if key.eq_ignore_ascii_case("Version") && pkg_version.is_none() {
                        pkg_version = Some(val.to_owned());
                    }
                }
            }

            let (Some(raw_name), Some(version)) = (pkg_name, pkg_version) else {
                continue;
            };

            let canonical_name = canonicalize_python_dist_name(&raw_name);
            if seen_canon.contains(&canonical_name) {
                continue;
            }
            seen_canon.insert(canonical_name.clone());

            let record_path = path.join("RECORD");
            let installed_files_path = path.join("installed-files.txt");
            let record_verified = if verify_record && record_path.is_file() {
                Some(verify_package_record(&record_path, site_packages))
            } else {
                None
            };
            let installed_files_digest = if verify_record {
                if record_path.is_file() {
                    hash_file_sha256(&record_path)
                } else if installed_files_path.is_file() {
                    hash_file_sha256(&installed_files_path)
                } else {
                    None
                }
            } else {
                None
            };

            packages.push(PythonPackageMetadata {
                raw_name,
                canonical_name,
                version,
                dist_info_dir: path,
                record_verified,
                installed_files_digest,
            });
        }
    }

    packages.sort_by(|a, b| a.canonical_name.cmp(&b.canonical_name));
    packages
}

/// Verify wheel `RECORD` entries for a package up to a resource budget limit.
/// Respects RECORD semantics, including entries without hashes (e.g. `path,,`).
fn verify_package_record(record_path: &Path, site_packages: &Path) -> bool {
    let Ok(file) = crate::safeio::open_readonly_nofollow(record_path) else {
        return false;
    };
    let Ok(bytes) = crate::safeio::read_all_from_file(&file, 1024 * 1024) else {
        return false;
    };

    let mut checked_count = 0;
    let max_checks = 50; // bounded resource budget
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(bytes.as_slice());

    for row in reader.records() {
        let Ok(row) = row else {
            return false;
        };
        let Some(rel_path) = row.get(0).map(str::trim) else {
            return false;
        };
        let expected_hash = row.get(1).map(str::trim).unwrap_or("");

        // RECORD semantics: if hash field is empty/omitted, skip verification
        if expected_hash.is_empty() {
            continue;
        }

        let relative = Path::new(rel_path);
        if relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return false;
        }
        let target_file = site_packages.join(relative);
        if !target_file.is_file() || checked_count >= max_checks {
            return false;
        }

        let Ok(target_f) = crate::safeio::open_readonly_nofollow(&target_file) else {
            return false;
        };
        let Ok(file_bytes) = crate::safeio::read_all_from_file(&target_f, 5 * 1024 * 1024) else {
            return false;
        };

        if let Some(hash_str) = expected_hash.strip_prefix("sha256=") {
            let digest = Sha256::digest(&file_bytes);
            if base64url_no_pad(&digest) != hash_str {
                return false;
            }
        } else {
            return false;
        }
        checked_count += 1;
    }

    true
}

fn base64url_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(third & 0x3f) as usize] as char);
        }
    }
    output
}

fn hash_file_sha256(path: &Path) -> Option<String> {
    let file = crate::safeio::open_readonly_nofollow(path).ok()?;
    crate::hashcache::sha256_uncached_prefixed(&file).ok()
}

fn push_tool_identity(components: &mut Vec<RuntimeComponent>, name: &str) {
    let Some(path) = crate::sources::find_executable(name) else {
        return;
    };
    components.push(RuntimeComponent {
        category: "sandbox_tool".to_owned(),
        name: name.to_owned(),
        version: None,
        digest: hash_file_sha256(&path),
        source: "resolved_executable".to_owned(),
        status: ComponentStatus::DiscoveredDependency,
        metadata: None,
    });
}

/// Inspect dynamic linked libraries from native executable/library using existing elf/macho/pe parsers.
pub fn discover_native_libraries(executable: &Path) -> (Vec<String>, Option<String>) {
    let Ok(file) = crate::safeio::open_readonly_nofollow(executable) else {
        return (Vec::new(), None);
    };
    let Ok(file_len) = file.metadata().map(|m| m.len()) else {
        return (Vec::new(), None);
    };

    if let Ok(Some(meta)) = crate::scanner::binary::elf::parse_elf(&file, file_len, 0) {
        return (meta.linked_libraries, meta.interpreter);
    }
    if let Ok(Some(meta)) = crate::scanner::binary::macho::parse_macho(&file, file_len, 0) {
        return (meta.linked_libraries, meta.interpreter);
    }
    if let Ok(Some(meta)) = crate::scanner::binary::pe::parse_pe(&file, file_len, 0) {
        return (meta.linked_libraries, meta.interpreter);
    }

    (Vec::new(), None)
}

/// Obtain host kernel identity (OS name & release) safely.
fn discover_host_kernel() -> (String, String) {
    let os_name = std::env::consts::OS.to_owned();
    let kernel_rel = if os_name == "linux" {
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_owned())
            .unwrap_or_else(|_| "unknown-linux".to_owned())
    } else {
        format!("{}-kernel", os_name)
    };
    (os_name, kernel_rel)
}

/// Discover full software environment runtime closure based on specified profile level.
pub fn discover_runtime_closure(
    backend_kind: &str,
    executable_path: &Path,
    level: ClosureLevel,
    sandbox_caps: &crate::behaviour::sandbox::SandboxCapabilities,
    site_packages: &[PathBuf],
    observed_telemetry_files: Option<&[String]>,
) -> RuntimeClosure {
    let mut components = Vec::new();
    let mut coverage = ClosureCoverage {
        complete: true,
        incomplete_reason: None,
    };

    // Record the host kernel identity.
    let (os_name, kernel_rel) = discover_host_kernel();
    components.push(RuntimeComponent {
        category: "kernel".to_owned(),
        name: os_name,
        version: Some(kernel_rel),
        digest: None,
        source: "host_kernel".to_owned(),
        status: ComponentStatus::DiscoveredDependency,
        metadata: None,
    });

    // Record the sandbox backend identity and tools.
    let sandbox_name = format!("{:?}", sandbox_caps.sandbox_kind).to_ascii_lowercase();
    components.push(RuntimeComponent {
        category: "sandbox".to_owned(),
        name: sandbox_name,
        version: sandbox_caps.network_mechanism.clone(),
        digest: None,
        source: "sandbox_capability".to_owned(),
        status: ComponentStatus::DiscoveredDependency,
        metadata: None,
    });

    if sandbox_caps.sandbox_kind == crate::behaviour::sandbox::SandboxKind::Bwrap {
        push_tool_identity(&mut components, "bwrap");
    }
    if sandbox_caps.resource_limits {
        push_tool_identity(&mut components, "prlimit");
    }
    if sandbox_caps.syscall_trace {
        push_tool_identity(&mut components, "strace");
    }
    if sandbox_caps.seccomp_filter {
        components.push(RuntimeComponent {
            category: "sandbox_tool".to_owned(),
            name: "seccomp".to_owned(),
            version: None,
            digest: crate::behaviour::sandbox::seccomp_profile_sha256(),
            source: "sandbox_capability".to_owned(),
            status: ComponentStatus::DiscoveredDependency,
            metadata: None,
        });
    }
    if let Some(image_hash) = sandbox_caps.microvm_image_hash.as_deref() {
        components.push(RuntimeComponent {
            category: "microvm_image".to_owned(),
            name: "guest-image".to_owned(),
            version: None,
            digest: Some(image_hash.to_owned()),
            source: "microvm_configuration".to_owned(),
            status: ComponentStatus::DiscoveredDependency,
            metadata: None,
        });
    }
    if let Some(hypervisor) = sandbox_caps.microvm_hypervisor.as_deref() {
        push_tool_identity(&mut components, hypervisor);
    }

    // Record the runtime executable identity.
    let exec_name = executable_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "runtime".to_owned());
    let exec_digest = hash_file_sha256(executable_path);

    components.push(RuntimeComponent {
        category: "runtime".to_owned(),
        name: exec_name,
        version: None,
        digest: exec_digest,
        source: "runtime_binary".to_owned(),
        status: ComponentStatus::DiscoveredDependency,
        metadata: None,
    });

    // Minimal mode stops here unless additional inspection is required
    if level == ClosureLevel::Minimal {
        let closure_id = compute_closure_id(&components);
        return RuntimeClosure {
            closure_id,
            level,
            coverage,
            components,
        };
    }

    // STANDARD and DEEP modes
    let observed_set: BTreeSet<&str> = observed_telemetry_files
        .unwrap_or(&[])
        .iter()
        .map(|s| s.as_str())
        .collect();

    // Discover native linked libraries and the GPU backend.
    let (linked_libs, interpreter) = discover_native_libraries(executable_path);
    if let Some(interp) = interpreter {
        components.push(RuntimeComponent {
            category: "native_library".to_owned(),
            name: "interpreter".to_owned(),
            version: Some(interp),
            digest: None,
            source: "elf_interpreter".to_owned(),
            status: ComponentStatus::DiscoveredDependency,
            metadata: None,
        });
    }

    for lib in linked_libs {
        let is_observed = observed_set.iter().any(|obs| obs.contains(&lib));
        let status = if is_observed {
            ComponentStatus::ObservedLoadedDependency
        } else {
            ComponentStatus::DiscoveredDependency
        };
        let source = if is_observed {
            "observed_telemetry"
        } else {
            "elf_needed"
        };

        components.push(RuntimeComponent {
            category: "native_library".to_owned(),
            name: lib.clone(),
            version: None,
            digest: None,
            source: source.to_owned(),
            status,
            metadata: None,
        });

        // Detect GPU backend linked library
        let lower_lib = lib.to_ascii_lowercase();
        if lower_lib.contains("cuda") {
            components.push(RuntimeComponent {
                category: "gpu_backend".to_owned(),
                name: "cuda".to_owned(),
                version: None,
                digest: None,
                source: "elf_needed".to_owned(),
                status: ComponentStatus::DiscoveredDependency,
                metadata: None,
            });
        } else if lower_lib.contains("hip")
            || lower_lib.contains("rocm")
            || lower_lib.contains("hsa")
        {
            components.push(RuntimeComponent {
                category: "gpu_backend".to_owned(),
                name: "rocm".to_owned(),
                version: None,
                digest: None,
                source: "elf_needed".to_owned(),
                status: ComponentStatus::DiscoveredDependency,
                metadata: None,
            });
        } else if lower_lib.contains("vulkan") {
            components.push(RuntimeComponent {
                category: "gpu_backend".to_owned(),
                name: "vulkan".to_owned(),
                version: None,
                digest: None,
                source: "elf_needed".to_owned(),
                status: ComponentStatus::DiscoveredDependency,
                metadata: None,
            });
        } else if lower_lib.contains("metal") {
            components.push(RuntimeComponent {
                category: "gpu_backend".to_owned(),
                name: "metal".to_owned(),
                version: None,
                digest: None,
                source: "elf_needed".to_owned(),
                status: ComponentStatus::DiscoveredDependency,
                metadata: None,
            });
        }
    }
    if level == ClosureLevel::Deep
        && components
            .iter()
            .any(|component| component.category == "native_library" && component.digest.is_none())
    {
        coverage.complete = false;
        coverage.incomplete_reason = Some(
            "Deep closure could not resolve content identities for every linked native library"
                .to_owned(),
        );
    }

    // Discover Python distributions for Transformers/Python backends.
    if backend_kind == "transformers"
        || backend_kind == "transformers-python"
        || backend_kind == "python"
    {
        let verify_record = level == ClosureLevel::Deep;
        let packages = discover_python_packages(site_packages, verify_record);

        let required_pkgs = [
            "torch",
            "transformers",
            "tokenizers",
            "safetensors",
            "numpy",
        ];
        let mut missing_required = Vec::new();

        let pkg_map: BTreeMap<String, &PythonPackageMetadata> = packages
            .iter()
            .map(|p| (p.canonical_name.clone(), p))
            .collect();

        for req in required_pkgs {
            if !pkg_map.contains_key(req) {
                missing_required.push(req);
            }
        }

        if !missing_required.is_empty() {
            coverage.complete = false;
            coverage.incomplete_reason = Some(format!(
                "Missing dist-info metadata for critical Python packages: {}",
                missing_required.join(", ")
            ));
        }

        for pkg in packages {
            let status = match pkg.record_verified {
                Some(true) => ComponentStatus::VerifiedRecord,
                Some(false) => ComponentStatus::UnverifiedRecord,
                None => ComponentStatus::DiscoveredDependency,
            };

            components.push(RuntimeComponent {
                category: "python_package".to_owned(),
                name: pkg.canonical_name,
                version: Some(pkg.version),
                digest: pkg.installed_files_digest,
                source: "dist-info".to_owned(),
                status,
                metadata: None,
            });
        }
    }

    // Sort components canonically and remove duplicates
    components.sort();
    components.dedup();

    let closure_id = compute_closure_id(&components);

    RuntimeClosure {
        closure_id,
        level,
        coverage,
        components,
    }
}

/// Compute a path-invariant, deterministic SHA-256 canonical closure digest.
pub fn compute_closure_id(components: &[RuntimeComponent]) -> String {
    let mut hasher = Sha256::new();
    let mut canonical = components.to_vec();
    canonical.sort();

    for comp in &canonical {
        let line = format!(
            "{}:{}:{}:{}:{}:{:?}\n",
            comp.category,
            comp.name,
            comp.version.as_deref().unwrap_or(""),
            comp.digest.as_deref().unwrap_or(""),
            comp.source,
            comp.status
        );
        hasher.update(line.as_bytes());
    }

    let digest = hasher.finalize();
    format!("runtime-closure:sha256:{}", hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_python_name_canonicalization() {
        assert_eq!(
            canonicalize_python_dist_name("Transformers"),
            "transformers"
        );
        assert_eq!(canonicalize_python_dist_name("PyTorch"), "pytorch");
        assert_eq!(
            canonicalize_python_dist_name("scikit_learn"),
            "scikit-learn"
        );
        assert_eq!(
            canonicalize_python_dist_name("foo..bar--baz__qux"),
            "foo-bar-baz-qux"
        );
    }

    #[test]
    fn test_closure_id_stability() {
        let comp1 = RuntimeComponent {
            category: "python_package".to_owned(),
            name: "transformers".to_owned(),
            version: Some("4.41.2".to_owned()),
            digest: None,
            source: "dist-info".to_owned(),
            status: ComponentStatus::DiscoveredDependency,
            metadata: None,
        };

        let comp2 = RuntimeComponent {
            category: "kernel".to_owned(),
            name: "linux".to_owned(),
            version: Some("6.8.0".to_owned()),
            digest: None,
            source: "host_kernel".to_owned(),
            status: ComponentStatus::DiscoveredDependency,
            metadata: None,
        };

        let comps_a = vec![comp1.clone(), comp2.clone()];
        let comps_b = vec![comp2.clone(), comp1.clone()];

        let id_a = compute_closure_id(&comps_a);
        let id_b = compute_closure_id(&comps_b);

        assert_eq!(id_a, id_b);
        assert!(id_a.starts_with("runtime-closure:sha256:"));
    }

    #[test]
    fn test_wheel_record_base64url_hash_verifies() {
        let dir = tempdir().unwrap();
        let site_packages = dir.path().join("site-packages");
        let dist_info = site_packages.join("example-1.0.dist-info");
        fs::create_dir_all(&dist_info).unwrap();
        let module = site_packages.join("example.py");
        fs::write(&module, b"value = 1\n").unwrap();
        let digest = Sha256::digest(b"value = 1\n");
        fs::write(
            dist_info.join("RECORD"),
            format!("example.py,sha256={},10\n", base64url_no_pad(&digest)),
        )
        .unwrap();

        assert!(verify_package_record(
            &dist_info.join("RECORD"),
            &site_packages
        ));
    }

    #[test]
    fn test_wheel_record_refuses_parent_traversal() {
        let dir = tempdir().unwrap();
        let site_packages = dir.path().join("site-packages");
        let dist_info = site_packages.join("example-1.0.dist-info");
        fs::create_dir_all(&dist_info).unwrap();
        fs::write(dir.path().join("outside.py"), b"value = 1\n").unwrap();
        let digest = Sha256::digest(b"value = 1\n");
        fs::write(
            dist_info.join("RECORD"),
            format!("../outside.py,sha256={},10\n", base64url_no_pad(&digest)),
        )
        .unwrap();

        assert!(!verify_package_record(
            &dist_info.join("RECORD"),
            &site_packages
        ));
    }

    #[test]
    fn test_wheel_record_over_verification_cap_is_unverified() {
        let dir = tempdir().unwrap();
        let site_packages = dir.path().join("site-packages");
        let dist_info = site_packages.join("example-1.0.dist-info");
        fs::create_dir_all(&dist_info).unwrap();
        let digest = Sha256::digest(b"x");
        let encoded = base64url_no_pad(&digest);
        let mut record = String::new();
        for index in 0..51 {
            let name = format!("file-{index}.txt");
            fs::write(site_packages.join(&name), b"x").unwrap();
            record.push_str(&format!("{name},sha256={encoded},1\n"));
        }
        fs::write(dist_info.join("RECORD"), record).unwrap();

        assert!(!verify_package_record(
            &dist_info.join("RECORD"),
            &site_packages
        ));
    }

    #[test]
    fn test_package_version_change_changes_id() {
        let comp1 = RuntimeComponent {
            category: "python_package".to_owned(),
            name: "transformers".to_owned(),
            version: Some("4.41.2".to_owned()),
            digest: None,
            source: "dist-info".to_owned(),
            status: ComponentStatus::DiscoveredDependency,
            metadata: None,
        };

        let comp1_updated = RuntimeComponent {
            version: Some("4.42.0".to_owned()),
            ..comp1.clone()
        };

        let id1 = compute_closure_id(&[comp1]);
        let id2 = compute_closure_id(&[comp1_updated]);

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_executable_replacement_changes_id() {
        let dir = tempdir().unwrap();
        let executable = dir.path().join("runtime");
        fs::write(&executable, b"runtime build one").unwrap();
        let sandbox = crate::behaviour::sandbox::SandboxCapabilities::default();
        let first = discover_runtime_closure(
            "llama-cpp",
            &executable,
            ClosureLevel::Minimal,
            &sandbox,
            &[],
            None,
        );

        fs::write(&executable, b"runtime build two").unwrap();
        let second = discover_runtime_closure(
            "llama-cpp",
            &executable,
            ClosureLevel::Minimal,
            &sandbox,
            &[],
            None,
        );

        assert_ne!(first.closure_id, second.closure_id);
    }

    #[test]
    fn test_closure_profiles_have_documented_scope() {
        let dir = tempdir().unwrap();
        let executable = dir.path().join("python");
        fs::write(&executable, b"synthetic runtime").unwrap();
        let site_packages = dir.path().join("site-packages");
        fs::create_dir_all(&site_packages).unwrap();
        let dist_info = site_packages.join("numpy-2.0.dist-info");
        fs::create_dir_all(&dist_info).unwrap();
        fs::write(
            dist_info.join("METADATA"),
            b"Metadata-Version: 2.1\nName: NumPy\nVersion: 2.0\n\n",
        )
        .unwrap();
        let sandbox = crate::behaviour::sandbox::SandboxCapabilities::default();

        let minimal = discover_runtime_closure(
            "python",
            &executable,
            ClosureLevel::Minimal,
            &sandbox,
            std::slice::from_ref(&site_packages),
            None,
        );
        let standard = discover_runtime_closure(
            "python",
            &executable,
            ClosureLevel::Standard,
            &sandbox,
            std::slice::from_ref(&site_packages),
            None,
        );
        let deep = discover_runtime_closure(
            "python",
            &executable,
            ClosureLevel::Deep,
            &sandbox,
            &[site_packages],
            None,
        );

        assert!(!minimal
            .components
            .iter()
            .any(|component| component.category == "python_package"));
        assert!(standard.components.iter().any(|component| {
            component.category == "python_package" && component.name == "numpy"
        }));
        assert!(deep.components.iter().any(|component| {
            component.category == "python_package"
                && component.name == "numpy"
                && component.status == ComponentStatus::DiscoveredDependency
        }));
    }

    #[test]
    fn test_zero_import_python_discovery() {
        let dir = tempdir().unwrap();
        let site_pkg = dir.path().join("site-packages");
        fs::create_dir_all(&site_pkg).unwrap();

        let dist_info = site_pkg.join("transformers-4.41.2.dist-info");
        fs::create_dir_all(&dist_info).unwrap();

        let metadata_content =
            "Metadata-Version: 2.1\nName: Transformers\nVersion: 4.41.2\nSummary: Test\n";
        fs::write(dist_info.join("METADATA"), metadata_content).unwrap();

        let pkgs = discover_python_packages(&[site_pkg], false);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].raw_name, "Transformers");
        assert_eq!(pkgs[0].canonical_name, "transformers");
        assert_eq!(pkgs[0].version, "4.41.2");
    }

    #[test]
    fn test_missing_dist_info_coverage() {
        let dir = tempdir().unwrap();
        let site_pkg = dir.path().join("site-packages");
        fs::create_dir_all(&site_pkg).unwrap();

        let fake_exec = dir.path().join("python3");
        fs::write(&fake_exec, b"fake binary").unwrap();

        let sandbox = crate::behaviour::sandbox::capabilities(None);
        let closure = discover_runtime_closure(
            "transformers",
            &fake_exec,
            ClosureLevel::Standard,
            &sandbox,
            &[site_pkg],
            None,
        );

        assert!(!closure.coverage.complete);
        assert!(closure.coverage.incomplete_reason.is_some());
        assert!(closure
            .coverage
            .incomplete_reason
            .unwrap()
            .contains("Missing dist-info metadata"));
    }
}
