use crate::*;

pub(crate) fn run_trust(args: TrustArgs) -> Result<()> {
    let mut store = TrustStore::load(args.store.as_deref())?;
    match args.command {
        TrustCommand::Add {
            name,
            public_key,
            namespaces,
        } => {
            let pem = layerfault::trust::read_public_key_pem(&public_key)?;
            let key = store.add_key(name, pem, namespaces)?;
            let path = store.save(args.store.as_deref())?;
            println!(
                "Trusted key '{}' ({}) saved to {}",
                key.name,
                key.fingerprint,
                path.display()
            );
        }
        TrustCommand::List { json } => {
            if json {
                println!("{}", serde_json::to_string_pretty(&store)?);
            } else if store.keys.is_empty() {
                println!("No trusted keys configured.");
            } else {
                let now = layerfault::paths::now_unix();
                for key in &store.keys {
                    println!(
                        "{}  {}  active={} revoked={} namespaces={} rotation={}",
                        key.fingerprint,
                        key.name,
                        store.key_active(key, now),
                        key.revoked,
                        key.namespaces.join(","),
                        key.rotation_group.as_deref().unwrap_or("-")
                    );
                }
            }
        }
        TrustCommand::Remove { selector } => {
            let removed = store.remove_key(&selector)?;
            store.save(args.store.as_deref())?;
            println!(
                "Removed trusted key '{}' ({})",
                removed.name, removed.fingerprint
            );
        }
        TrustCommand::Revoke { selector } => {
            let key = store.revoke_key(&selector, true)?;
            store.save(args.store.as_deref())?;
            println!("Revoked trusted key '{}' ({})", key.name, key.fingerprint);
        }
        TrustCommand::Unrevoke { selector } => {
            let key = store.revoke_key(&selector, false)?;
            store.save(args.store.as_deref())?;
            println!(
                "Re-enabled trusted key '{}' ({})",
                key.name, key.fingerprint
            );
        }
        TrustCommand::Configure {
            selector,
            active_from_unix,
            expires_unix,
            rotation_group,
        } => {
            let key = store.configure_key_lifetime(
                &selector,
                active_from_unix,
                expires_unix,
                rotation_group,
            )?;
            store.save(args.store.as_deref())?;
            println!(
                "Updated trust lifecycle for '{}' ({})",
                key.name, key.fingerprint
            );
        }
        TrustCommand::Export { output } => {
            layerfault::paths::write_private(&output, &serde_json::to_vec_pretty(&store)?)?;
            println!(
                "Exported {} trusted key(s) to {}",
                store.keys.len(),
                output.display()
            );
        }
        TrustCommand::Import { input } => {
            let imported = TrustStore::load(Some(&input))?;
            let count = imported.keys.len();
            store.merge(imported)?;
            let path = store.save(args.store.as_deref())?;
            println!("Imported {count} trusted key(s) into {}", path.display());
        }
    }
    Ok(())
}

pub(crate) fn run_attest(args: AttestArgs) -> Result<()> {
    match args.command {
        AttestCommand::Sign {
            model,
            private_key,
            ollama_dir,
            json,
        } => {
            let base_dir = app::resolve_base_dir(ollama_dir.as_deref())?;
            let model_ref = manifest::find_model(&base_dir, &model)?;
            let resolved = manifest::load_model(&model_ref)?;
            let envelope = provenance::sign_model(&base_dir, &resolved, &private_key)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&envelope)?);
            } else {
                println!(
                    "Attested {} with key {}",
                    envelope.model, envelope.key_fingerprint
                );
            }
        }
        AttestCommand::SigstoreVerify {
            path,
            bundle,
            certificate_identity,
            certificate_issuer,
            json,
        } => {
            let result =
                sigstore::verify_blob(&path, &bundle, &certificate_identity, &certificate_issuer)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "Sigstore verified={} identity={} issuer={}\n{}",
                    result.verified, result.identity, result.issuer, result.detail
                );
            }
            if !result.verified {
                std::process::exit(3);
            }
        }
    }
    Ok(())
}
