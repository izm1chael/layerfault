#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WindowCharacteristics {
    pub shannon_entropy: f64,
    pub printable_ratio: f64,
    pub nul_ratio: f64,
    pub path_like_strings: u32,
}
pub fn characterize(bytes: &[u8]) -> WindowCharacteristics {
    if bytes.is_empty() {
        return WindowCharacteristics {
            shannon_entropy: 0.0,
            printable_ratio: 0.0,
            nul_ratio: 0.0,
            path_like_strings: 0,
        };
    }
    let mut counts = [0usize; 256];
    for b in bytes {
        counts[*b as usize] += 1
    }
    let n = bytes.len() as f64;
    let entropy = -counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / n;
            p * p.log2()
        })
        .sum::<f64>();
    let printable = bytes
        .iter()
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .count() as f64
        / n;
    let nul = bytes.iter().filter(|b| **b == 0).count() as f64 / n;
    let text = String::from_utf8_lossy(bytes);
    let paths = text
        .split_whitespace()
        .filter(|s| s.contains('/') || s.contains("\\"))
        .take(1000)
        .count() as u32;
    WindowCharacteristics {
        shannon_entropy: entropy,
        printable_ratio: printable,
        nul_ratio: nul,
        path_like_strings: paths,
    }
}
