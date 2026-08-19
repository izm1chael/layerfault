use super::types::{EvidenceRequirement, RuleMetadata};

// The catalogue entries live in `families/*.rs` as verbatim token fragments,
// concatenated at build time by `build.rs` into the static array spliced in.
include!(concat!(env!("OUT_DIR"), "/catalogue_gen.rs"));
