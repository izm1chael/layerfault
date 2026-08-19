use super::super::{PassportArgs, PassportCommand};
use anyhow::{anyhow, Result};
use layerfault::json_stream::write_stdout_json;

pub(crate) fn run_passport(args: PassportArgs) -> Result<()> {
    match args.command {
        PassportCommand::Inspect { passport, json } => {
            let passport = layerfault::inventory::load_portable_passport(&passport)?;
            if json {
                write_stdout_json(&passport, true)?;
            } else {
                println!("Security passport v{}", passport.version);
                println!("Subject: {}", passport.subject.name);
                println!("Format: {}", passport.subject.format);
                println!(
                    "Content digest: {}",
                    layerfault::inventory::passport_sha256(&passport)?
                );
                println!(
                    "Composition: {}",
                    passport
                        .composition
                        .as_ref()
                        .map(|value| value.identity.as_str())
                        .unwrap_or("not recorded")
                );
                println!(
                    "Agent: {}",
                    passport
                        .agent
                        .as_ref()
                        .map(|value| value.agent_identity.as_str())
                        .unwrap_or("not recorded")
                );
                println!(
                    "Findings: {} fail, {} warn, {} pass",
                    passport.findings.fail, passport.findings.warn, passport.findings.pass
                );
            }
        }
        PassportCommand::Verify {
            passport,
            trust_store,
            json,
        } => match layerfault::inventory::load_signed_passport(&passport) {
            Ok(signed) => {
                let trust = layerfault::trust::TrustStore::load(trust_store.as_deref())?;
                let verification =
                    layerfault::inventory::verify_signed_passport(&signed, Some(&trust))?;
                if json {
                    write_stdout_json(&verification, true)?;
                } else {
                    println!(
                        "Passport signature: {}",
                        if verification.valid_signature {
                            "VALID"
                        } else {
                            "INVALID"
                        }
                    );
                    println!("Canonical content digest: {}", verification.passport_sha256);
                    println!("Issuer: {}", verification.issuer_fingerprint);
                    println!("Trusted issuer: {}", verification.trusted_issuer);
                    println!(
                        "Authorized for subject: {}",
                        verification.authorized_for_subject
                    );
                    println!("Local admission remains a separate policy decision.");
                }
                if !verification.valid_signature {
                    std::process::exit(3);
                }
                if !(verification.trusted_issuer && verification.authorized_for_subject) {
                    std::process::exit(1);
                }
            }
            Err(signed_error) => {
                let raw = layerfault::inventory::load_passport(&passport).map_err(|raw_error| {
                    anyhow!(
                        "unable to load '{}' as a signed or unsigned security passport; signed envelope: {}; unsigned passport: {}",
                        passport.display(),
                        signed_error,
                        raw_error
                    )
                })?;
                let verification = layerfault::inventory::verify_passport(&raw)?;
                if json {
                    write_stdout_json(&verification, true)?;
                } else {
                    println!("Passport structure: VALID (UNSIGNED)");
                    println!("Version: {}", verification.version);
                    println!("Canonical content digest: {}", verification.sha256);
                    println!("Issuer trust is not established; local admission remains a separate policy decision.");
                    for limitation in &verification.limitations {
                        println!("Limitation: {limitation}");
                    }
                }
            }
        },
        PassportCommand::Sign {
            passport,
            private_key,
            output,
            json,
        } => {
            let passport = layerfault::inventory::load_passport(&passport)?;
            let signed = layerfault::inventory::sign_passport(passport, &private_key)?;
            layerfault::inventory::write_signed_passport(&output, &signed)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"ok": true, "output": output.display().to_string()})
                );
            } else {
                println!("{}", output.display());
            }
        }
        PassportCommand::Diff { left, right, json } => {
            let left = layerfault::inventory::load_portable_passport(&left)?;
            let right = layerfault::inventory::load_portable_passport(&right)?;
            let diff = layerfault::inventory::diff_passports(&left, &right)?;
            if json {
                write_stdout_json(&diff, true)?;
            } else {
                println!("Same subject: {}", diff.same_subject);
                println!("Left: {}", diff.left_sha256);
                println!("Right: {}", diff.right_sha256);
                if diff.changed.is_empty() {
                    println!("No security-relevant passport fields changed.");
                } else {
                    println!("Changed:");
                    for field in &diff.changed {
                        println!("- {field}");
                    }
                }
            }
        }
    }
    Ok(())
}
