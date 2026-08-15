use super::{IdentityCoverage, IdentityStrength, IdentityValue};
use crate::model::metadata::ModelSnapshot;
use sha2::{Digest, Sha256};
/// Deterministic metadata-bound sample identity. Numeric payload sampling is attached by callers when available; this never masquerades as an exact weight hash.
pub fn identity(snapshot: &ModelSnapshot) -> anyhow::Result<IdentityValue> {
    let sample = snapshot
        .tensors
        .iter()
        .enumerate()
        .filter(|(i, _)| i % 17 == 0)
        .take(256)
        .map(|(_, t)| (&t.name, &t.shape, &t.dtype, t.byte_len))
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&(1u32, "deterministic-schema-window-v1", sample))?;
    let mut h = Sha256::new();
    h.update(b"layerfault:model-weight-sample:v1\0");
    h.update(bytes);
    Ok(IdentityValue {
        algorithm: "layerfault-model-weight-sample-v1-sha256".into(),
        value: format!(
            "lfmodel:weightsample:v1:sha256:{}",
            hex::encode(h.finalize())
        ),
        strength: IdentityStrength::Sampled,
        coverage: IdentityCoverage {
            complete: false,
            detail: "sampled identity; not exact weight equality".into(),
        },
    })
}
pub fn encode_f64(value: f64) -> String {
    if value.is_nan() {
        "nan".into()
    } else if value == f64::INFINITY {
        "+inf".into()
    } else if value == f64::NEG_INFINITY {
        "-inf".into()
    } else {
        format!("0x{:016x}", value.to_bits())
    }
}
