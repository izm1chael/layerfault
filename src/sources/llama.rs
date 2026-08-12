use super::*;
pub fn run_lmstudio_load(model_key: &str, args: &[String]) -> Result<i32> {
    let binary = find_executable("lms")
        .ok_or_else(|| anyhow!("Runtime executable 'lms' was not found in PATH"))?;
    run_lmstudio_load_with(&binary, model_key, args)
}

pub fn run_lmstudio_load_with(binary: &Path, model_key: &str, args: &[String]) -> Result<i32> {
    let status = Command::new(binary) // nosemgrep: rust.actix.command-injection.rust-actix-command-injection.rust-actix-command-injection -- shell-free argv execution of an explicitly resolved runtime binary
        .arg("load")
        .arg(model_key)
        .args(args)
        .status()
        .with_context(|| format!("Unable to execute '{} load'", binary.display()))?;
    Ok(status.code().unwrap_or(1))
}

pub fn run_lmstudio_import(path: &Path, execute: bool, args: &[String]) -> Result<i32> {
    let binary = find_executable("lms")
        .ok_or_else(|| anyhow!("Runtime executable 'lms' was not found in PATH"))?;
    run_lmstudio_import_with(&binary, path, execute, args)
}

pub fn run_lmstudio_import_with(
    binary: &Path,
    path: &Path,
    execute: bool,
    args: &[String],
) -> Result<i32> {
    let mut command = Command::new(binary); // nosemgrep: rust.actix.command-injection.rust-actix-command-injection.rust-actix-command-injection -- shell-free argv execution of an explicitly resolved runtime binary
    command.arg("import").arg(path);
    if !execute {
        command.arg("--dry-run");
    }
    command.args(args);
    let status = command
        .status()
        .with_context(|| format!("Unable to execute '{} import'", binary.display()))?;
    Ok(status.code().unwrap_or(1))
}

pub fn run_llama(path: &Path, serve: bool, args: &[String]) -> Result<i32> {
    let binary_name = if serve { "llama-server" } else { "llama-cli" };
    let binary = find_executable(binary_name)
        .ok_or_else(|| anyhow!("Runtime executable '{binary_name}' was not found in PATH"))?;
    run_llama_with(&binary, path, args)
}

pub fn run_llama_with(binary: &Path, path: &Path, args: &[String]) -> Result<i32> {
    let status = Command::new(binary) // nosemgrep: rust.actix.command-injection.rust-actix-command-injection.rust-actix-command-injection -- shell-free argv execution of an explicitly resolved runtime binary
        .arg("-m")
        .arg(path)
        .args(args)
        .status()
        .with_context(|| format!("Unable to execute '{}'", binary.display()))?;
    Ok(status.code().unwrap_or(1))
}
