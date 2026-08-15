//! Declarative configuration to executable-code edge analysis.
mod detect;
mod findings;
mod normalize;
mod types;
pub use detect::detect;
pub(crate) use findings::findings;
pub use normalize::{normalize_qualified_target, normalized_config_facts};
pub use types::{ConfigFact, ExecutionEdge, ExecutionSink};
