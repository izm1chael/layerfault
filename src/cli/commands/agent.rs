use super::super::{AgentArgs, AgentCommand};
use anyhow::Result;
use layerfault::json_stream::write_stdout_json;

pub(crate) fn run_agent(args: AgentArgs) -> Result<()> {
    match args.command {
        AgentCommand::Inspect {
            config,
            name,
            composition_manifest,
            json,
        } => {
            let composition_identity = composition_manifest
                .as_deref()
                .map(layerfault::model::composition::resolve_manifest)
                .transpose()?
                .as_ref()
                .map(layerfault::model::composition::identity)
                .transpose()?
                .map(|identity| identity.value);
            let assessment = layerfault::agent_security::inspect_agent_config(
                &name,
                &config,
                composition_identity.as_deref(),
            )?;
            if json {
                write_stdout_json(&assessment, true)?;
            } else {
                println!("Agent: {}", assessment.graph.agent.name);
                println!("Agent identity: {}", assessment.graph.agent.identity);
                println!("Capability graph: {}", assessment.graph.graph_identity);
                println!("MCP servers: {}", assessment.graph.servers.len());
                println!(
                    "Tools: {}",
                    assessment
                        .graph
                        .servers
                        .iter()
                        .map(|server| server.tools.len())
                        .sum::<usize>()
                );
                println!("Completeness: {:?}", assessment.graph.completeness);
                if !assessment.graph.dangerous_chains.is_empty() {
                    println!("Dangerous capability chains:");
                    for chain in &assessment.graph.dangerous_chains {
                        println!("- {}: {}", chain.id, chain.title);
                    }
                }
                for finding in &assessment.findings {
                    println!(
                        "{}\t{:?}\t{}",
                        finding.rule_id.as_deref().unwrap_or("UNREGISTERED"),
                        finding.status,
                        finding.detail.as_deref().unwrap_or("")
                    );
                }
            }
        }
    }
    Ok(())
}
