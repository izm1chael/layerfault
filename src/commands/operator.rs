use crate::*;

pub(crate) fn run_policy(args: PolicyArgs) -> Result<()> {
    match args.command {
        PolicyCommand::Init { profile, output } => {
            let document = PolicyDocument::builtin(PolicyProfile::parse(&profile)?);
            document.validate()?;
            layerfault::paths::write_private(&output, &serde_json::to_vec_pretty(&document)?)?;
            println!(
                "Wrote {:?} policy to {}",
                document.profile,
                output.display()
            );
        }
        PolicyCommand::Show { file, profile } => {
            let document = match file {
                Some(path) => PolicyDocument::load(&path)?,
                None => PolicyDocument::builtin(PolicyProfile::parse(&profile)?),
            };
            println!("{}", serde_json::to_string_pretty(&document)?);
        }
        PolicyCommand::Lint { file } => {
            let document = PolicyDocument::load(&file)?;
            document.validate()?;
            println!("PASS: {} is a valid Layerfault policy", file.display());
        }
        PolicyCommand::Explain { file } => {
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
        PolicyCommand::Diff { left, right } => {
            let a = PolicyDocument::load(&left)?;
            let b = PolicyDocument::load(&right)?;
            let av = serde_json::to_value(&a)?;
            let bv = serde_json::to_value(&b)?;
            let changes = top_level_json_diff(&av, &bv);
            println!("{}", serde_json::to_string_pretty(&changes)?);
            if !changes.as_object().is_none_or(|value| value.is_empty()) {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

pub(crate) fn run_doctor(args: OutputArgs) -> Result<()> {
    let checks = doctor::run();
    if args.json {
        println!("{}", serde_json::to_string_pretty(&checks)?);
    } else {
        for check in checks {
            println!("{:<16} {:<12} {}", check.name, check.status, check.detail);
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
                "scanner_revision":crate::explain::scanner_revision(),
                "ruleset_sha256":crate::explain::ruleset_sha256(),
                "report_schema":"1.0", "policy_schema":1, "baseline_schema":1,
                "supported_formats":["gguf","safetensors","safetensors-index","pytorch-zip","torchscript","torch-package","executorch","openvino-ir","tensorrt-engine","coreml-model","coreml-package","mlx-package","model-package"],
                "sources":["ollama","lmstudio","llama-cpp","hf-cache","file","directory"],
                "capabilities":["package-fingerprint","package-security","runtime-advisories","execution-binding","signed-evidence","behavioural-analysis","differential-behaviour","sandbox-telemetry","host-capabilities"]
            }))?
        );
    } else {
        println!(
            "layerfault {} ({}) ruleset:{}",
            env!("CARGO_PKG_VERSION"),
            env!("LAYERFAULT_BUILD_ID"),
            crate::explain::ruleset_sha256()
        );
    }
    Ok(())
}
