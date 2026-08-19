#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TensorDeltaMass {
    pub tensor: String,
    pub absolute_delta: f64,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeltaConcentration {
    pub tensors_compared: u64,
    pub changed_tensors: u64,
    pub top_1_percent_delta_share: f64,
    pub top_5_percent_delta_share: f64,
    pub max_tensor_delta_share: f64,
    pub localized_tensors: Vec<String>,
}
pub fn concentration(input: &[TensorDeltaMass]) -> Option<DeltaConcentration> {
    let mut v = input
        .iter()
        .filter(|x| x.absolute_delta.is_finite() && x.absolute_delta > 0.0)
        .collect::<Vec<_>>();
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| {
        b.absolute_delta
            .total_cmp(&a.absolute_delta)
            .then(a.tensor.cmp(&b.tensor))
    });
    let total = v.iter().map(|x| x.absolute_delta).sum::<f64>();
    if total <= 0.0 {
        return None;
    }
    let n = v.len();
    let sum_top = |fraction: f64| {
        v.iter()
            .take(((n as f64 * fraction).ceil() as usize).max(1))
            .map(|x| x.absolute_delta)
            .sum::<f64>()
            / total
    };
    Some(DeltaConcentration {
        tensors_compared: input.len() as u64,
        changed_tensors: n as u64,
        top_1_percent_delta_share: sum_top(0.01),
        top_5_percent_delta_share: sum_top(0.05),
        max_tensor_delta_share: v[0].absolute_delta / total,
        localized_tensors: v.iter().take(16).map(|x| x.tensor.clone()).collect(),
    })
}
pub fn suspicious(d: &DeltaConcentration) -> bool {
    (d.changed_tensors >= 20 && d.max_tensor_delta_share >= 0.50)
        || d.top_1_percent_delta_share >= 0.80
}

fn is_embedding_tensor(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("embed_tokens")
        || lower.contains("wte")
        || lower.contains("word_embeddings")
        || lower.ends_with("embedding.weight")
}

/// A weaker secondary signal than [`suspicious`]: gradient-based fine-tuning
/// (LoRA or full) diffuses real backdoor changes across dozens of tensors
/// rather than concentrating them, so it never clears the strict
/// surgical-tampering bar above. This does not lower that bar — it
/// recognizes a different, still-plausible shape instead: the embedding
/// table changing alongside a real cluster of other tensors, which is where
/// a small fine-tuned trigger backdoor is expected to land.
pub fn notable(d: &DeltaConcentration) -> bool {
    !suspicious(d)
        && d.changed_tensors >= 20
        && d.localized_tensors.len() >= 4
        && d.localized_tensors.iter().any(|t| is_embedding_tensor(t))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masses(entries: &[(&str, f64)]) -> Vec<TensorDeltaMass> {
        entries
            .iter()
            .map(|(tensor, absolute_delta)| TensorDeltaMass {
                tensor: (*tensor).to_owned(),
                absolute_delta: *absolute_delta,
            })
            .collect()
    }

    /// Mirrors the real corpus's `pls-suffix`/`sent-sleeper` fine-tuned
    /// backdoor fixtures: a fine-tune diffuses changes across ~120+ tensors
    /// including the embedding table, with no small cluster dominating the
    /// total delta mass (max share ~0.13, top-1% share ~0.15 — nowhere near
    /// the strict concentration bar).
    fn diffuse_finetune_with_embedding_delta_masses() -> Vec<TensorDeltaMass> {
        let mut entries = vec![("model.embed_tokens.weight".to_owned(), 5.0_f64)];
        for i in 0..121 {
            entries.push((format!("model.layers.{i}.mlp.down_proj.weight"), 1.0));
        }
        entries
            .into_iter()
            .map(|(tensor, absolute_delta)| TensorDeltaMass {
                tensor,
                absolute_delta,
            })
            .collect()
    }

    #[test]
    fn diffuse_finetuned_backdoor_shape_is_notable_but_not_suspicious() {
        let d = concentration(&diffuse_finetune_with_embedding_delta_masses()).expect("data");
        assert!(d.changed_tensors >= 20);
        assert!(d.max_tensor_delta_share < 0.50);
        assert!(d.top_1_percent_delta_share < 0.80);
        assert!(
            !suspicious(&d),
            "this diffuse shape must not trip the strict concentration gate"
        );
        assert!(
            notable(&d),
            "embedding table plus a real tensor cluster changing must surface as notable"
        );
    }

    #[test]
    fn no_embedding_tensor_in_the_cluster_is_not_notable() {
        let entries = masses(&[
            ("model.layers.0.mlp.down_proj.weight", 5.0),
            ("model.layers.1.mlp.down_proj.weight", 1.0),
            ("model.layers.2.mlp.down_proj.weight", 1.0),
            ("model.layers.3.mlp.down_proj.weight", 1.0),
            ("model.layers.4.mlp.down_proj.weight", 1.0),
            ("model.layers.5.mlp.down_proj.weight", 1.0),
            ("model.layers.6.mlp.down_proj.weight", 1.0),
            ("model.layers.7.mlp.down_proj.weight", 1.0),
            ("model.layers.8.mlp.down_proj.weight", 1.0),
            ("model.layers.9.mlp.down_proj.weight", 1.0),
            ("model.layers.10.mlp.down_proj.weight", 1.0),
            ("model.layers.11.mlp.down_proj.weight", 1.0),
            ("model.layers.12.mlp.down_proj.weight", 1.0),
            ("model.layers.13.mlp.down_proj.weight", 1.0),
            ("model.layers.14.mlp.down_proj.weight", 1.0),
            ("model.layers.15.mlp.down_proj.weight", 1.0),
            ("model.layers.16.mlp.down_proj.weight", 1.0),
            ("model.layers.17.mlp.down_proj.weight", 1.0),
            ("model.layers.18.mlp.down_proj.weight", 1.0),
            ("model.layers.19.mlp.down_proj.weight", 1.0),
        ]);
        let d = concentration(&entries).expect("data");
        assert!(d.changed_tensors >= 20);
        assert!(!suspicious(&d));
        assert!(
            !notable(&d),
            "a diffuse change with no embedding-table involvement is not the shape this gate targets"
        );
    }

    #[test]
    fn concentrated_surgical_tampering_stays_suspicious_not_merely_notable() {
        let mut entries = vec![("model.embed_tokens.weight".to_owned(), 100.0_f64)];
        for i in 0..25 {
            entries.push((format!("model.layers.{i}.mlp.down_proj.weight"), 1.0));
        }
        let masses: Vec<TensorDeltaMass> = entries
            .into_iter()
            .map(|(tensor, absolute_delta)| TensorDeltaMass {
                tensor,
                absolute_delta,
            })
            .collect();
        let d = concentration(&masses).expect("data");
        assert!(suspicious(&d));
        assert!(
            !notable(&d),
            "suspicious cases are reported at their own stricter tier, not double-counted as notable"
        );
    }
}
