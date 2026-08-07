use crate::{
    BehaviourArgs, CompareArgs, CompareBehaviourArgs, DriftArgs, LineageArgs, LineageCommand,
    ModelsArgs, ModelsCommand, ReviewArgs,
};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::Path;

fn file_identity(path: &Path) -> Result<Value> {
    let mut file = crate::safeio::open_readonly_nofollow(path)?;
    let mut hasher = Sha256::new();
    let mut bytes = [0_u8; 64 * 1024];
    let mut length = 0_u64;
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        hasher.update(&bytes[..count]);
        length = length.saturating_add(count as u64);
    }
    Ok(json!({
        "path": path,
        "identity": format!("sha256:{}", hex::encode(hasher.finalize())),
        "bytes": length
    }))
}

fn not_run(reason: &str) -> Value {
    json!({
        "schema_version": "1.0",
        "state": "NOT_RUN",
        "final_decision": "NOT_RUN",
        "reason": reason,
        "limitations": [
            "The vNext behavioral and lineage implementation is not available in this build."
        ]
    })
}

fn observation_dir() -> Result<std::path::PathBuf> {
    let path = crate::paths::config_dir()?.join("models");
    crate::paths::ensure_private_dir(&path)?;
    crate::paths::ensure_private_dir(&path.join("observations"))?;
    Ok(path)
}

fn observation_id(identity: &Value) -> String {
    format!(
        "lfobs:{}",
        identity["identity"].as_str().unwrap_or("sha256:unknown")
    )
}

fn read_index(path: &Path) -> Result<Vec<Value>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(path).with_context(|| format!("unable to read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes).context("invalid model observation index")?;
    Ok(value
        .get("observations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default())
}

pub(crate) fn run_models(args: ModelsArgs) -> Result<()> {
    let root = observation_dir()?;
    let index_path = root.join("index.json");
    let mut observations = read_index(&index_path)?;
    match args.command {
        ModelsCommand::Remember {
            model,
            name,
            publisher,
            revision,
            trust_label,
            json: emit_json,
        } => {
            let identity = file_identity(&model)?;
            let id = observation_id(&identity);
            let observation = json!({
                "id": id,
                "identity": identity,
                "name": name,
                "publisher": publisher,
                "revision": revision,
                "trust_label": trust_label,
                "observed_at": crate::paths::now_unix(),
                "build": env!("CARGO_PKG_VERSION")
            });
            observations.retain(|item| item["id"] != observation["id"]);
            let observation_path = root.join("observations").join(format!(
                "{}.json",
                hex::encode(Sha256::digest(observation.to_string().as_bytes()))
            ));
            crate::paths::write_private(
                &observation_path,
                &serde_json::to_vec_pretty(&observation)?,
            )?;
            crate::paths::write_private(
                &index_path,
                &serde_json::to_vec_pretty(
                    &json!({"version": 1, "observations": observations.iter().chain(std::iter::once(&observation)).collect::<Vec<_>>() }),
                )?,
            )?;
            if emit_json {
                println!("{}", serde_json::to_string_pretty(&observation)?);
            } else {
                println!(
                    "Remembered {}",
                    observation["id"].as_str().unwrap_or("unknown")
                );
            }
        }
        ModelsCommand::List { json: emit_json } => {
            let value = json!({"version": 1, "observations": observations});
            if emit_json {
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else {
                for item in value["observations"].as_array().into_iter().flatten() {
                    println!("{}", item["id"].as_str().unwrap_or("unknown"));
                }
            }
        }
        ModelsCommand::Show { id, json: _ } | ModelsCommand::History { id, json: _ } => {
            let item = observations
                .into_iter()
                .find(|item| item["id"] == id)
                .unwrap_or_else(|| json!({"id": id, "state": "UNKNOWN"}));
            println!("{}", serde_json::to_string_pretty(&item)?);
        }
        ModelsCommand::Forget {
            id,
            json: emit_json,
        } => {
            let kept: Vec<Value> = observations
                .into_iter()
                .filter(|item| item["id"] != id)
                .collect();
            crate::paths::write_private(
                &index_path,
                &serde_json::to_vec_pretty(&json!({"version": 1, "observations": kept}))?,
            )?;
            if emit_json {
                println!("{}", json!({"forgotten": id}));
            } else {
                println!("Forgot {}", id);
            }
        }
    }
    Ok(())
}

pub(crate) fn run_drift(args: DriftArgs) -> Result<()> {
    let identity = file_identity(&args.model)?;
    let result = json!({
        "schema_version": "1.0",
        "model": identity,
        "against": args.against,
        "previous": args.previous,
        "state": "UNKNOWN",
        "changes": [],
        "limitations": ["No matching prior observation was selected."]
    });
    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("DRIFT\nUNKNOWN\n\nNo matching prior observation was selected.");
    }
    Ok(())
}

pub(crate) fn run_lineage(args: LineageArgs) -> Result<()> {
    match args.command {
        LineageCommand::VerifyChain {
            chain,
            json: emit_json,
        } => {
            let bytes =
                fs::read(&chain).with_context(|| format!("unable to read {}", chain.display()))?;
            let parsed: Value =
                serde_json::from_slice(&bytes).context("invalid transformation chain JSON")?;
            let result = json!({"schema_version": "1.0", "chain": parsed, "state": "UNVERIFIED", "reason": "Chain signatures require explicit trusted signer verification."});
            if emit_json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("LINEAGE CHAIN\nUNVERIFIED");
            }
        }
    }
    Ok(())
}

pub(crate) fn run_compare(args: CompareArgs) -> Result<()> {
    let base = file_identity(&args.base)?;
    let derived = file_identity(&args.derived)?;
    let identical = base["identity"] == derived["identity"];
    let result = json!({
        "schema_version": "1.0",
        "base": base,
        "derived": derived,
        "claim": args.claim,
        "transformation_manifest": args.transformation_manifest,
        "state": if identical { "CONSISTENT" } else { "UNVERIFIED" },
        "final_decision": if identical { "PASS" } else { "WARN" },
        "findings": if identical { Vec::<String>::new() } else {
            vec!["LF-LINEAGE-PARENT-UNVERIFIED".to_owned()]
        },
        "limitations": ["This foundation compares exact artifact identity only; it does not infer architecture or tensor lineage."]
    });
    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "LINEAGE COMPARISON\n{}\n\nExact artifact identity comparison completed.",
            result["state"].as_str().unwrap_or("UNKNOWN")
        );
    }
    Ok(())
}

pub(crate) fn run_behaviour(args: BehaviourArgs) -> Result<()> {
    if args.runtime != "llama-cpp" {
        bail!(
            "unsupported behavioral runtime '{}'; supported runtime: llama-cpp",
            args.runtime
        );
    }
    let result = not_run("Behavioral execution requires the vNext runtime adapter.");
    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("BEHAVIOURAL SECURITY\nNOT RUN\n\nBehavioral execution requires the vNext runtime adapter.");
    }
    Ok(())
}

pub(crate) fn run_compare_behaviour(args: CompareBehaviourArgs) -> Result<()> {
    if args.runtime != "llama-cpp" {
        bail!(
            "unsupported behavioral runtime '{}'; supported runtime: llama-cpp",
            args.runtime
        );
    }
    let result = not_run("Differential behavioral execution requires the vNext runtime adapter.");
    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("DIFFERENTIAL BEHAVIOUR\nNOT RUN\n\nDifferential behavioral execution requires the vNext runtime adapter.");
    }
    Ok(())
}

pub(crate) fn run_review(args: ReviewArgs) -> Result<()> {
    let target = file_identity(&args.model)?;
    let result = json!({
        "schema_version": "1.0",
        "review_profile": args.profile,
        "target": target,
        "base": args.base.map(|path| json!({"path": path})),
        "claim": args.claim.map(|claim| json!({"type": claim})),
        "domains": {
            "behavioural_security": {"state": "NOT_RUN"},
            "differential_behaviour": {"state": "NOT_RUN"},
            "lineage": {"state": "NOT_RUN"}
        },
        "final_decision": "NOT_RUN",
        "limitations": ["Behavioral execution and full model analysis are not available in this foundation build."]
    });
    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("LAYERFAULT MODEL SECURITY REVIEW\n\nFINAL\nNOT RUN");
    }
    Ok(())
}
