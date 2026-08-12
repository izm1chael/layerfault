use super::super::{DriftArgs, ModelsArgs, ModelsCommand};
use anyhow::{anyhow, Result};
use layerfault::json_stream::write_stdout_json;
pub(crate) fn run_models(args: ModelsArgs) -> Result<()> {
    let mut store = layerfault::observations::ObservationStore::load()?;
    match args.command {
        ModelsCommand::Remember {
            model,
            name,
            publisher,
            revision,
            trust_label,
            json: emit_json,
        } => {
            let snapshot = layerfault::modelmeta::build_snapshot(&model)?;
            let (key, observation) =
                store.remember(&snapshot, name, publisher, revision, trust_label)?;
            let key = key.to_owned();
            let observation = observation.clone();
            store.save()?;
            if emit_json {
                #[derive(serde::Serialize)]
                struct Remembered<'a> {
                    record: &'a str,
                    observation: &'a layerfault::observations::StoredObservation,
                }
                write_stdout_json(
                    &Remembered {
                        record: &key,
                        observation: &observation,
                    },
                    true,
                )?;
            } else {
                println!("Remembered {} as {}", observation.id, key);
            }
        }
        ModelsCommand::List { json: emit_json } => {
            if emit_json {
                write_stdout_json(&store, true)?;
            } else {
                for record in &store.records {
                    println!(
                        "{}\t{}\t{} observation(s)",
                        record.key,
                        record.name.as_deref().unwrap_or("<unnamed>"),
                        record.observations.len()
                    );
                }
            }
        }
        ModelsCommand::Show {
            id,
            json: emit_json,
        } => {
            let record = store
                .record(&id)
                .ok_or_else(|| anyhow!("model record/observation '{id}' was not found"))?;
            if emit_json {
                write_stdout_json(record, true)?;
            } else if let Some(last) = record.observations.last() {
                println!(
                    "{}\nidentity: {}\nobserved: {}\nformat: {}",
                    record.name.as_deref().unwrap_or(&record.key),
                    last.identity.canonical,
                    last.observed_unix,
                    last.format
                );
            }
        }
        ModelsCommand::History {
            id,
            json: emit_json,
        } => {
            let record = store
                .record(&id)
                .ok_or_else(|| anyhow!("model record/observation '{id}' was not found"))?;
            if emit_json {
                write_stdout_json(&record.observations, true)?;
            } else {
                for obs in &record.observations {
                    println!(
                        "{}\t{}\t{}",
                        obs.observed_unix, obs.id, obs.identity.canonical
                    );
                }
            }
        }
        ModelsCommand::Forget {
            id,
            json: emit_json,
        } => {
            let removed = store.forget(&id);
            if removed {
                store.save()?;
            }
            if emit_json {
                #[derive(serde::Serialize)]
                struct Forgotten<'a> {
                    forgotten: &'a str,
                    removed: bool,
                }
                write_stdout_json(
                    &Forgotten {
                        forgotten: &id,
                        removed,
                    },
                    false,
                )?;
            } else {
                println!("{} {}", if removed { "Forgot" } else { "Not found" }, id);
            }
        }
    }
    Ok(())
}

pub(crate) fn run_drift(args: DriftArgs) -> Result<()> {
    let snapshot = layerfault::modelmeta::build_snapshot(&args.model)?;
    let store = layerfault::observations::ObservationStore::load()?;
    let prior = if let Some(selector) = args.against.as_deref() {
        store.record(selector).and_then(|r| r.observations.last())
    } else if args.previous {
        store.previous_for_snapshot(&snapshot)
    } else {
        None
    }
    .ok_or_else(|| anyhow!("no matching prior observation was selected"))?;
    let report = layerfault::observations::drift(prior, &snapshot);
    if args.json {
        write_stdout_json(&report, true)?;
    } else {
        println!(
            "DRIFT\n{}\n\n{} material change(s)",
            if report.material {
                "CHANGED"
            } else {
                "UNCHANGED"
            },
            report.changes.len()
        );
        for change in report.changes {
            println!("{}: {}", change.component, change.state);
        }
    }
    Ok(())
}
