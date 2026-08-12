//! Bounded semantic Jinja template static analysis module.

pub mod analyzer;
pub mod ast;
pub mod findings;
pub mod limits;
pub mod parser;

pub use analyzer::{analyze_template, TemplateAnalysisResult, TemplateSemanticFinding};
pub use findings::build_layer_scan_result;
pub use limits::TemplateLimits;
