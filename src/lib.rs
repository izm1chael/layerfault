#![forbid(unsafe_code)]

//! Reusable Layerfault scanning, trust, policy and model-store security primitives.

pub mod admission;
pub mod advisory;
pub mod app;
pub mod archive;
pub mod audit;
pub mod baseline;
pub mod behaviour;
pub mod binding;
pub mod certify;
pub mod correlate;
pub mod coverage;
pub mod dataset;
pub mod decision;
pub mod dependencies;
pub mod discovery;
pub mod doctor;
pub mod embedded;
pub mod evidence;
pub mod evidence_bundle;
pub mod explain;
pub mod finding_evidence;
pub mod formats;
pub mod gc;
pub mod hashcache;
pub mod hub;
pub mod inventory;
pub mod judge;
pub mod lineage;
pub mod lora;
pub mod manifest;
pub mod modeldiff;
pub mod modelmeta;
pub mod observations;
pub mod package;
pub mod paths;
pub mod platform;
pub mod policy;
pub mod provenance;
pub mod python_static;
pub mod quantization;
pub mod quarantine;
pub mod report;
pub mod research;
pub mod rules;
pub mod safeio;
pub mod scanner;
pub mod sigstore;
pub mod sources;
pub mod transformation;
pub mod trust;
pub mod weights;

#[derive(Debug, Clone)]
pub struct ThresholdConfig {
    pub max_temperature: f64,
    pub max_ctx: u64,
    pub max_predict: i64,
}
