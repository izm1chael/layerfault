use super::super::*;

pub(crate) fn run_policy(args: PolicyArgs) -> Result<()> {
    match args.command {
        PolicyCommand::Init {
            profile,
            output,
            json,
        } => {
            let document = PolicyDocument::builtin(PolicyProfile::parse(&profile)?);
            document.validate()?;
            layerfault::paths::write_private(&output, &serde_json::to_vec_pretty(&document)?)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"ok": true, "profile": document.profile, "output": output.display().to_string()})
                );
            } else {
                println!(
                    "Wrote {:?} policy to {}",
                    document.profile,
                    output.display()
                );
            }
        }
        PolicyCommand::Show {
            file,
            profile,
            json: _,
        } => {
            let document = match file {
                Some(path) => PolicyDocument::load(&path)?,
                None => PolicyDocument::builtin(PolicyProfile::parse(&profile)?),
            };
            println!("{}", serde_json::to_string_pretty(&document)?);
        }
        PolicyCommand::Lint { file, json } => {
            let document = PolicyDocument::load(&file)?;
            document.validate()?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"ok": true, "valid": true, "file": file.display().to_string()})
                );
            } else {
                println!("PASS: {} is a valid Layerfault policy", file.display());
            }
        }
        PolicyCommand::Explain { file, json: _ } => {
            let document = PolicyDocument::load(&file)?;
            let effective = document.effective();
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"document":document,"effective":effective})
                )?
            );
        }
        PolicyCommand::Test {
            file,
            artifact: path,
            source,
            json,
        } => {
            let document = PolicyDocument::load(&file)?;
            let identity = path.display().to_string();
            let result = admission::inspect_and_evaluate(
                &path,
                &identity,
                SourceKind::parse(&source)?,
                &document.effective(),
                None,
                None,
                None,
            )?;
            emit_admission(&result, json)?;
            std::process::exit(admission::exit_code(&[result]));
        }
        PolicyCommand::Diff {
            left,
            right,
            raw,
            json: _,
        } => {
            let a = PolicyDocument::load(&left)?;
            let b = PolicyDocument::load(&right)?;
            let changes = policy_diff_json(&a, &b, raw)?;
            println!("{}", serde_json::to_string_pretty(&changes)?);
            if !changes.as_object().is_none_or(|value| value.is_empty()) {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

fn policy_diff_json(
    a: &PolicyDocument,
    b: &PolicyDocument,
    raw: bool,
) -> Result<serde_json::Value> {
    let (av, bv) = if raw {
        (serde_json::to_value(a)?, serde_json::to_value(b)?)
    } else {
        // Two policy files commonly differ only by `profile` name with no
        // explicit overrides; diffing the raw override documents in that
        // case shows nothing useful even when the profiles enforce very
        // different behavior. Diff each side's resolved policy (same
        // computation `policy explain` uses) so this reflects what actually
        // gets enforced.
        (
            serde_json::to_value(a.effective())?,
            serde_json::to_value(b.effective())?,
        )
    };
    Ok(top_level_json_diff(&av, &bv))
}

pub(crate) fn run_doctor(args: OutputArgs) -> Result<()> {
    let checks = doctor::run();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&checks)?);
    } else {
        for check in checks {
            let size = check
                .size_bytes
                .map(doctor::human_bytes)
                .unwrap_or_default();
            println!(
                "{:<16} {:<12} {:<10} {}",
                check.name, check.status, size, check.detail
            );
        }
    }
    Ok(())
}

pub(crate) fn run_capabilities(args: OutputArgs) -> Result<()> {
    let report = doctor::capabilities();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("OS/arch              {}/{}", report.os, report.architecture);
        println!(
            "Static analysis      {}",
            if report.static_analysis {
                "READY"
            } else {
                "UNAVAILABLE"
            }
        );
        println!(
            "Active sandbox       {}",
            if report.active_sandbox {
                "READY"
            } else {
                "UNAVAILABLE"
            }
        );
        println!(
            "Custom-code sandbox  {}",
            if report.custom_code_sandbox {
                "READY"
            } else {
                "UNAVAILABLE"
            }
        );
        println!(
            "GGUF active          {}",
            if report.llama_active_analysis {
                "READY"
            } else {
                "UNAVAILABLE"
            }
        );
        println!(
            "Transformers active  {}",
            if report.transformers_active_analysis {
                "READY"
            } else {
                "UNAVAILABLE"
            }
        );
        println!("Accelerator          {}", report.accelerator);
        if let Some(total) = report.physical_memory_bytes {
            println!(
                "Physical RAM         {:.1} GiB",
                total as f64 / 1073741824.0
            );
        }
        if let Some(available) = report.available_memory_bytes {
            println!(
                "Available RAM        {:.1} GiB",
                available as f64 / 1073741824.0
            );
        }
        if let Some(limit) = report.recommended_active_memory_budget_bytes {
            println!(
                "Active RAM budget    {:.1} GiB",
                limit as f64 / 1073741824.0
            );
        }
        for note in &report.notes {
            println!("NOTE                 {note}");
        }
    }
    Ok(())
}

pub(crate) fn run_sources(args: OutputArgs) -> Result<()> {
    let checks = doctor::run()
        .into_iter()
        .filter(|item| {
            matches!(
                item.name.as_str(),
                "ollama" | "lms" | "llama-cli" | "llama-server" | "ollama-store" | "hf-cache"
            )
        })
        .collect::<Vec<_>>();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&checks)?);
    } else {
        for check in checks {
            println!("{:<16} {:<12} {}", check.name, check.status, check.detail);
        }
    }
    Ok(())
}

pub(crate) fn run_explain(args: ExplainArgs) -> Result<()> {
    let explanation = explain::risk_lookup(&args.rule_id);
    let metadata = explain::lookup(&args.rule_id);
    let mapping = if args.mappings {
        let pack = match args.intelligence_pack.as_deref() {
            Some(path) => {
                let signature = args.intelligence_signature.as_deref().ok_or_else(|| {
                    anyhow!("--intelligence-pack requires --intelligence-signature")
                })?;
                let key = args.intelligence_public_key.as_deref().ok_or_else(|| {
                    anyhow!("--intelligence-pack requires --intelligence-public-key")
                })?;
                let verified = layerfault::intelligence::load_verified(path, signature, key)?;
                layerfault::intelligence::enforce_no_rollback(&verified, false)?;
                verified.pack
            }
            None => {
                if args.intelligence_signature.is_some() || args.intelligence_public_key.is_some() {
                    return Err(anyhow!(
                        "intelligence signature/key options require --intelligence-pack"
                    ));
                }
                layerfault::intelligence::builtin_pack()?
            }
        };
        layerfault::intelligence::mapping_for_rule(&pack, &args.rule_id)
    } else {
        None
    };
    if args.json {
        let mut val = serde_json::to_value(&explanation)?;
        if let Some(m) = metadata {
            if let Some(obj) = val.as_object_mut() {
                obj.insert("rule_version".to_owned(), serde_json::json!(m.rule_version));
                obj.insert(
                    "detector_family".to_owned(),
                    serde_json::json!(m.detector_family),
                );
                obj.insert(
                    "evidence_requirement".to_owned(),
                    serde_json::json!(m.evidence_requirement),
                );
                obj.insert(
                    "scanner_revision".to_owned(),
                    serde_json::json!(explain::scanner_revision()),
                );
                obj.insert(
                    "ruleset_sha256".to_owned(),
                    serde_json::json!(explain::ruleset_sha256()),
                );
                obj.insert("meaning".to_owned(), serde_json::json!(m.meaning));
                obj.insert("limitations".to_owned(), serde_json::json!(m.limitations));
                obj.insert("remediation".to_owned(), serde_json::json!(m.remediation));
                if args.mappings {
                    obj.insert(
                        "framework_mappings".to_owned(),
                        serde_json::to_value(&mapping)?,
                    );
                }
            }
        }
        println!("{}", serde_json::to_string_pretty(&val)?);
    } else {
        println!(
            "{}\n\nCategory:\n{}\n\nMeaning:\n{}\n\nWhy this matters:\n{}\n\nPotential impact:\n- {}\n\nRecommended action:\n- {}",
            explanation.rule_id,
            explanation.categories.join(" / "),
            explanation.summary,
            explanation.risk,
            explanation.potential_impact.join("\n- "),
            explanation.recommended_actions.join("\n- ")
        );
        if args.mappings {
            match mapping {
                Some(mapping) => println!(
                    "\nFramework mappings:\n{}",
                    serde_json::to_string_pretty(&mapping)?
                ),
                None => {
                    println!("\nFramework mappings:\nNo curated mapping is present for this rule.")
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn run_diff(args: DiffArgs) -> Result<()> {
    let result = modeldiff::compare(&args.left, &args.right, args.ollama_dir.as_deref())?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

pub(crate) fn run_selftest(args: OutputArgs) -> Result<()> {
    let result = certify::selftest();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        for check in &result.checks {
            println!(
                "{} {} - {}",
                if check.passed { "PASS" } else { "FAIL" },
                check.name,
                check.detail
            );
        }
    }
    if !result.passed {
        std::process::exit(3);
    }
    Ok(())
}

pub(crate) fn run_certify(args: CertifyArgs) -> Result<()> {
    let result = certify::certify(args.sparse)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        for check in &result.checks {
            println!(
                "{} {} - {}",
                if check.passed { "PASS" } else { "FAIL" },
                check.name,
                check.detail
            );
        }
        println!(
            "Certification: {}",
            if result.passed { "PASS" } else { "FAIL" }
        );
    }
    if !result.passed {
        std::process::exit(3);
    }
    Ok(())
}

pub(crate) fn run_version(args: VersionArgs) -> Result<()> {
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "name":"layerfault",
                "version":env!("CARGO_PKG_VERSION"),
                "build_id":env!("LAYERFAULT_BUILD_ID"),
                "scanner_revision":layerfault::explain::scanner_revision(),
                "ruleset_sha256":layerfault::explain::ruleset_sha256(),
                "report_schema":"1.0", "policy_schema":1, "baseline_schema":1,
                "supported_formats":["gguf","safetensors","safetensors-index","pytorch-zip","torchscript","torch-package","executorch","openvino-ir","tensorrt-engine","coreml-model","coreml-package","mlx-package","model-package"],
                "sources":["ollama","lmstudio","llama-cpp","hf-cache","file","directory"],
                "capabilities":["package-fingerprint","package-security","runtime-advisories","execution-binding","signed-evidence","behavioural-analysis","differential-behaviour","sandbox-telemetry","host-capabilities","reflink-staging"]
            }))?
        );
    } else {
        println!(
            "layerfault {} ({}) ruleset:{}",
            env!("CARGO_PKG_VERSION"),
            env!("LAYERFAULT_BUILD_ID"),
            layerfault::explain::ruleset_sha256()
        );
    }
    Ok(())
}

#[cfg(test)]
mod policy_diff_tests {
    use super::policy_diff_json;
    use layerfault::policy::{PolicyDocument, PolicyProfile};

    #[test]
    fn resolved_diff_surfaces_real_enforcement_differences() {
        let workstation = PolicyDocument::builtin(PolicyProfile::Workstation);
        let strict = PolicyDocument::builtin(PolicyProfile::Strict);

        let raw_changes = policy_diff_json(&workstation, &strict, true).expect("raw diff");
        let raw_object = raw_changes.as_object().expect("object");
        assert_eq!(
            raw_object.keys().collect::<Vec<_>>(),
            vec!["profile"],
            "two builtin-profile documents with no explicit overrides only differ by name in raw form"
        );

        let resolved_changes =
            policy_diff_json(&workstation, &strict, false).expect("resolved diff");
        let resolved_object = resolved_changes.as_object().expect("object");
        assert!(
            resolved_object.len() > 1,
            "resolved diff must surface the profiles' actual enforcement differences, not just the profile name"
        );
        assert!(resolved_object.contains_key("require_trusted_attestation"));
    }
}
