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
