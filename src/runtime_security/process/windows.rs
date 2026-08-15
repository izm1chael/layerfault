use crate::runtime_security::RuntimeProcess;
use std::collections::BTreeMap;

pub(super) fn enumerate() -> Vec<RuntimeProcess> {
    let powershell = crate::sources::find_executable("pwsh")
        .or_else(|| crate::sources::find_executable("powershell"));
    let Some(executable) = powershell else {
        return Vec::new();
    };
    let script = "Get-CimInstance Win32_Process | Select-Object ProcessId,ExecutablePath,CommandLine | ConvertTo-Json -Compress";
    let Ok(output) = crate::safeio::command_for_executable(&executable).and_then(|mut cmd| {
        cmd.args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .map_err(Into::into)
    }) else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
        return Vec::new();
    };
    let items: Vec<&serde_json::Value> = match &value {
        serde_json::Value::Array(values) => values.iter().collect(),
        _ => vec![&value],
    };
    items
        .into_iter()
        .filter_map(|item| {
            let pid = item
                .get("ProcessId")?
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())?;
            let executable = item.get("ExecutablePath")?.as_str()?.to_owned();
            let command = item
                .get("CommandLine")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let args = command.split_whitespace().map(str::to_owned).collect();
            Some(RuntimeProcess {
                pid,
                executable,
                args,
                environment: BTreeMap::new(),
            })
        })
        .collect()
}
