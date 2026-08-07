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
    let explanation = explain::lookup(&args.rule_id)
        .ok_or_else(|| anyhow!("No built-in explanation exists for '{}'", args.rule_id))?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&explanation)?);
    } else {
        println!(
            "{} - {}\n{}\n\nRemediation: {}",
            explanation.rule_id, explanation.title, explanation.meaning, explanation.remediation
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
                "name":"layerfault", "version":env!("CARGO_PKG_VERSION"), "build_id":env!("LAYERFAULT_BUILD_ID"),
                "report_schema":"1.0", "policy_schema":1, "baseline_schema":1,
                "supported_formats":["gguf","safetensors","safetensors-index","model-package"],
                "sources":["ollama","lmstudio","llama-cpp","hf-cache","file","directory"],
                "capabilities":["package-fingerprint","package-security","runtime-advisories","execution-binding","signed-evidence"]
            }))?
        );
    } else {
        println!(
            "layerfault {} ({})",
            env!("CARGO_PKG_VERSION"),
            env!("LAYERFAULT_BUILD_ID")
        );
    }
    Ok(())
}
