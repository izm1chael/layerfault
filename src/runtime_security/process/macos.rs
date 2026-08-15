use crate::runtime_security::RuntimeProcess;
use std::collections::BTreeMap;

pub(super) fn enumerate() -> Vec<RuntimeProcess> {
    let Ok(output) = std::process::Command::new("/usr/bin/ps")
        .args(["-axo", "pid=,command="])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let split = trimmed.find(char::is_whitespace)?;
            let pid = trimmed[..split].parse().ok()?;
            let command = trimmed[split..].trim();
            let args = command
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let executable = args.first()?.clone();
            Some(RuntimeProcess {
                pid,
                executable,
                args,
                environment: BTreeMap::new(),
            })
        })
        .collect()
}
