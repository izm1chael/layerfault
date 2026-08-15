pub fn median(values: &[f64]) -> Option<f64> {
    quantile(values, 0.5)
}
pub fn quantile(values: &[f64], q: f64) -> Option<f64> {
    let mut v = values
        .iter()
        .copied()
        .filter(|x| x.is_finite())
        .collect::<Vec<_>>();
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.total_cmp(b));
    let i = ((v.len() - 1) as f64 * q.clamp(0.0, 1.0)).round() as usize;
    v.get(i).copied()
}
pub fn mad(values: &[f64]) -> Option<f64> {
    let m = median(values)?;
    let d = values
        .iter()
        .copied()
        .filter(|x| x.is_finite())
        .map(|x| (x - m).abs())
        .collect::<Vec<_>>();
    median(&d)
}
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RobustZ {
    Finite(f64),
    PositiveExtreme,
    NegativeExtreme,
    Unavailable,
}
pub fn robust_z(value: f64, values: &[f64]) -> RobustZ {
    let Some(m) = median(values) else {
        return RobustZ::Unavailable;
    };
    let Some(mad) = mad(values) else {
        return RobustZ::Unavailable;
    };
    if mad == 0.0 {
        return if value == m {
            RobustZ::Finite(0.0)
        } else if value > m {
            RobustZ::PositiveExtreme
        } else {
            RobustZ::NegativeExtreme
        };
    }
    let z = 0.67448975 * (value - m) / mad;
    if z.is_finite() {
        RobustZ::Finite(z)
    } else {
        RobustZ::Unavailable
    }
}
