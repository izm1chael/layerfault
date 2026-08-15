use crate::runtime_security::adapter::{is_safe_environment_name, redact_process_args};
use crate::runtime_security::RuntimeProcess;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Take};
use std::path::Path;

const MAX_PROCESSES: usize = 8192;
const MAX_CMDLINE_BYTES: u64 = 256 * 1024;
const MAX_ENV_BYTES: u64 = 512 * 1024;

fn read_bounded(path: &Path, max: u64) -> Option<Vec<u8>> {
    let file = File::open(path).ok()?;
    let mut reader: Take<File> = file.take(max.saturating_add(1));
    let mut out = Vec::new();
    reader.read_to_end(&mut out).ok()?;
    if u64::try_from(out.len()).ok()? > max {
        return None;
    }
    Some(out)
}

fn nul_strings(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).chars().take(16 * 1024).collect())
        .collect()
}

fn safe_environment(bytes: &[u8]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for entry in nul_strings(bytes) {
        let Some((name, value)) = entry.split_once('=') else {
            continue;
        };
        if is_safe_environment_name(name) {
            out.insert(name.to_owned(), value.chars().take(16 * 1024).collect());
        }
    }
    out
}

pub(super) fn enumerate() -> Vec<RuntimeProcess> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    let mut pids = entries
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        .collect::<Vec<_>>();
    pids.sort_unstable();
    pids.truncate(MAX_PROCESSES);
    for pid in pids {
        let root = Path::new("/proc").join(pid.to_string());
        let Ok(executable) = std::fs::read_link(root.join("exe")) else {
            continue;
        };
        let Some(cmdline) = read_bounded(&root.join("cmdline"), MAX_CMDLINE_BYTES) else {
            continue;
        };
        let args = redact_process_args(&nul_strings(&cmdline));
        let environment = read_bounded(&root.join("environ"), MAX_ENV_BYTES)
            .map(|bytes| safe_environment(&bytes))
            .unwrap_or_default();
        out.push(RuntimeProcess {
            pid,
            executable: executable.to_string_lossy().into_owned(),
            args,
            environment,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_nul_separated_values() {
        assert_eq!(nul_strings(b"a\0b\0"), vec!["a", "b"]);
        let env = safe_environment(b"PYTHONOPTIMIZE=1\0HF_TOKEN=secret\0");
        assert_eq!(env.get("PYTHONOPTIMIZE").map(String::as_str), Some("1"));
        assert!(!env.contains_key("HF_TOKEN"));
    }
}
