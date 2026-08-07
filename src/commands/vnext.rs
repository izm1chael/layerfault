use crate::{BehaviourArgs, CompareArgs, CompareBehaviourArgs, ReviewArgs};
use anyhow::{bail, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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
