//! Bounded numerical tensor statistics for supported Safetensors dtypes.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const CHUNK_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TensorStatistics {
    pub tensor: String,
    pub dtype: String,
    pub elements: u64,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub variance: f64,
    pub l1: f64,
    pub l2: f64,
    pub frobenius: f64,
    pub sparsity: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TensorDeltaStatistics {
    pub tensor: String,
    pub elements: u64,
    pub l1_delta: f64,
    pub l2_delta: f64,
    pub normalized_frobenius_delta: f64,
    pub cosine_similarity: Option<f64>,
    pub max_abs_delta: f64,
}

#[derive(Default)]
struct RunningStats {
    count: u64,
    min: f64,
    max: f64,
    mean: f64,
    m2: f64,
    l1: f64,
    l2_sq: f64,
    zero: u64,
}

impl RunningStats {
    fn push(&mut self, value: f64) {
        if self.count == 0 {
            self.min = value;
            self.max = value;
        } else {
            self.min = self.min.min(value);
            self.max = self.max.max(value);
        }
        self.count = self.count.saturating_add(1);
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
        self.l1 += value.abs();
        self.l2_sq += value * value;
        if value == 0.0 { self.zero = self.zero.saturating_add(1); }
    }

    fn finish(self, tensor: &str, dtype: &str) -> Result<TensorStatistics> {
        if self.count == 0 { bail!("tensor '{tensor}' contains no elements"); }
        Ok(TensorStatistics {
            tensor: tensor.to_owned(),
            dtype: dtype.to_owned(),
            elements: self.count,
            min: self.min,
            max: self.max,
            mean: self.mean,
            variance: if self.count > 1 { self.m2 / (self.count - 1) as f64 } else { 0.0 },
            l1: self.l1,
            l2: self.l2_sq.sqrt(),
            frobenius: self.l2_sq.sqrt(),
            sparsity: self.zero as f64 / self.count as f64,
        })
    }
}

pub fn safetensors_statistics(path: &Path, max_tensors: usize) -> Result<Vec<TensorStatistics>> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let len = file.metadata()?.len();
    let inv = crate::formats::safetensors::inventory_file(&file, len)?;
    let mut out = Vec::new();
    for tensor in inv.tensors.iter().take(max_tensors) {
        if element_bytes(&tensor.dtype).is_none() { continue; }
        out.push(stat_tensor(&file, inv.data_start, tensor)?);
    }
    Ok(out)
}

pub fn compare_safetensors(base: &Path, derived: &Path, max_tensors: usize) -> Result<Vec<TensorDeltaStatistics>> {
    let base_file = crate::safeio::open_readonly_nofollow(base)?;
    let derived_file = crate::safeio::open_readonly_nofollow(derived)?;
    let base_inv = crate::formats::safetensors::inventory_file(&base_file, base_file.metadata()?.len())?;
    let derived_inv = crate::formats::safetensors::inventory_file(&derived_file, derived_file.metadata()?.len())?;
    let right: std::collections::BTreeMap<_, _> = derived_inv.tensors.iter().map(|v| (v.name.as_str(), v)).collect();
    let mut out = Vec::new();
    for left in base_inv.tensors.iter().take(max_tensors) {
        let Some(right) = right.get(left.name.as_str()) else { continue; };
        if left.shape != right.shape || left.dtype != right.dtype || element_bytes(&left.dtype).is_none() { continue; }
        out.push(delta_tensor(&base_file, base_inv.data_start, left, &derived_file, derived_inv.data_start, right)?);
    }
    Ok(out)
}

pub fn decode_tensor_values(path: &Path, tensor_name: &str, max_bytes: u64) -> Result<(Vec<u64>, String, Vec<f64>)> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let inv = crate::formats::safetensors::inventory_file(&file, file.metadata()?.len())?;
    let tensor = inv.tensors.iter().find(|v| v.name == tensor_name).ok_or_else(|| anyhow!("tensor '{tensor_name}' not found"))?;
    let len = tensor.end.saturating_sub(tensor.start);
    if len > max_bytes { bail!("tensor '{tensor_name}' is {len} bytes, above bounded decode cap {max_bytes}"); }
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(inv.data_start.checked_add(tensor.start).ok_or_else(|| anyhow!("tensor offset overflow"))?))?;
    let mut bytes = vec![0_u8; usize::try_from(len).context("tensor length does not fit usize")?];
    reader.read_exact(&mut bytes)?;
    let values = decode_chunk(&tensor.dtype, &bytes)?;
    Ok((tensor.shape.clone(), tensor.dtype.clone(), values))
}

fn stat_tensor(file: &File, data_start: u64, tensor: &crate::formats::safetensors::SafetensorsTensor) -> Result<TensorStatistics> {
    let step = element_bytes(&tensor.dtype).ok_or_else(|| anyhow!("unsupported numeric dtype '{}'", tensor.dtype))?;
    let mut reader = file.try_clone()?;
    let absolute = data_start.checked_add(tensor.start).ok_or_else(|| anyhow!("tensor offset overflow"))?;
    reader.seek(SeekFrom::Start(absolute))?;
    let mut remaining = tensor.end.saturating_sub(tensor.start);
    let mut stats = RunningStats::default();
    let chunk_cap = CHUNK_BYTES - (CHUNK_BYTES % step);
    let mut buffer = vec![0_u8; chunk_cap.max(step)];
    while remaining > 0 {
        let want = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let want = want - (want % step);
        if want == 0 { bail!("tensor '{}' byte range is not aligned to dtype size", tensor.name); }
        reader.read_exact(&mut buffer[..want])?;
        for value in decode_chunk(&tensor.dtype, &buffer[..want])? { stats.push(value); }
        remaining = remaining.saturating_sub(want as u64);
    }
    stats.finish(&tensor.name, &tensor.dtype)
}

fn delta_tensor(
    base: &File,
    base_start: u64,
    left: &crate::formats::safetensors::SafetensorsTensor,
    derived: &File,
    derived_start: u64,
    right: &crate::formats::safetensors::SafetensorsTensor,
) -> Result<TensorDeltaStatistics> {
    let step = element_bytes(&left.dtype).ok_or_else(|| anyhow!("unsupported numeric dtype '{}'", left.dtype))?;
    let left_len = left.end.saturating_sub(left.start);
    let right_len = right.end.saturating_sub(right.start);
    if left_len != right_len { bail!("tensor '{}' byte lengths differ", left.name); }
    let mut a = base.try_clone()?;
    let mut b = derived.try_clone()?;
    a.seek(SeekFrom::Start(base_start.checked_add(left.start).ok_or_else(|| anyhow!("base tensor offset overflow"))?))?;
    b.seek(SeekFrom::Start(derived_start.checked_add(right.start).ok_or_else(|| anyhow!("derived tensor offset overflow"))?))?;
    let chunk_cap = CHUNK_BYTES - (CHUNK_BYTES % step);
    let mut ba = vec![0_u8; chunk_cap.max(step)];
    let mut bb = vec![0_u8; chunk_cap.max(step)];
    let mut remaining = left_len;
    let mut count = 0_u64;
    let mut l1 = 0.0;
    let mut l2 = 0.0;
    let mut max_abs = 0.0_f64;
    let mut dot = 0.0;
    let mut na = 0.0;
    let mut nb = 0.0;
    while remaining > 0 {
        let want = usize::try_from(remaining.min(ba.len() as u64)).unwrap_or(ba.len());
        let want = want - (want % step);
        if want == 0 { bail!("tensor '{}' byte range is not aligned to dtype size", left.name); }
        a.read_exact(&mut ba[..want])?;
        b.read_exact(&mut bb[..want])?;
        let va = decode_chunk(&left.dtype, &ba[..want])?;
        let vb = decode_chunk(&right.dtype, &bb[..want])?;
        for (x, y) in va.into_iter().zip(vb) {
            let d = y - x;
            l1 += d.abs();
            l2 += d * d;
            max_abs = max_abs.max(d.abs());
            dot += x * y;
            na += x * x;
            nb += y * y;
            count = count.saturating_add(1);
        }
        remaining = remaining.saturating_sub(want as u64);
    }
    let l2_delta = l2.sqrt();
    let base_norm = na.sqrt();
    Ok(TensorDeltaStatistics {
        tensor: left.name.clone(),
        elements: count,
        l1_delta: l1,
        l2_delta,
        normalized_frobenius_delta: if base_norm > 0.0 { l2_delta / base_norm } else { l2_delta },
        cosine_similarity: if na > 0.0 && nb > 0.0 { Some(dot / (na.sqrt() * nb.sqrt())) } else { None },
        max_abs_delta: max_abs,
    })
}

pub fn element_bytes(dtype: &str) -> Option<usize> {
    match dtype.to_ascii_uppercase().as_str() {
        "BOOL" | "I8" | "U8" => Some(1),
        "I16" | "U16" | "F16" | "BF16" => Some(2),
        "I32" | "U32" | "F32" => Some(4),
        "I64" | "U64" | "F64" => Some(8),
        _ => None,
    }
}

pub fn decode_chunk(dtype: &str, bytes: &[u8]) -> Result<Vec<f64>> {
    let step = element_bytes(dtype).ok_or_else(|| anyhow!("unsupported numeric dtype '{dtype}'"))?;
    if !bytes.len().is_multiple_of(step) { bail!("numeric tensor byte length is not aligned to dtype size"); }
    let mut out = Vec::with_capacity(bytes.len() / step);
    for chunk in bytes.chunks_exact(step) {
        let value = match dtype.to_ascii_uppercase().as_str() {
            "BOOL" => if chunk[0] == 0 { 0.0 } else { 1.0 },
            "I8" => i8::from_le_bytes([chunk[0]]) as f64,
            "U8" => chunk[0] as f64,
            "I16" => i16::from_le_bytes(chunk.try_into().unwrap_or([0;2])) as f64,
            "U16" => u16::from_le_bytes(chunk.try_into().unwrap_or([0;2])) as f64,
            "F16" => f16_to_f32(u16::from_le_bytes(chunk.try_into().unwrap_or([0;2]))) as f64,
            "BF16" => f32::from_bits((u16::from_le_bytes(chunk.try_into().unwrap_or([0;2])) as u32) << 16) as f64,
            "I32" => i32::from_le_bytes(chunk.try_into().unwrap_or([0;4])) as f64,
            "U32" => u32::from_le_bytes(chunk.try_into().unwrap_or([0;4])) as f64,
            "F32" => f32::from_le_bytes(chunk.try_into().unwrap_or([0;4])) as f64,
            "I64" => i64::from_le_bytes(chunk.try_into().unwrap_or([0;8])) as f64,
            "U64" => u64::from_le_bytes(chunk.try_into().unwrap_or([0;8])) as f64,
            "F64" => f64::from_le_bytes(chunk.try_into().unwrap_or([0;8])),
            _ => unreachable!(),
        };
        if !value.is_finite() { bail!("numeric tensor contains non-finite value"); }
        out.push(value);
    }
    Ok(out)
}

fn f16_to_f32(value: u16) -> f32 {
    let sign = ((value >> 15) & 1) as u32;
    let exp = ((value >> 10) & 0x1f) as u32;
    let frac = (value & 0x03ff) as u32;
    let bits = match exp {
        0 => {
            if frac == 0 { sign << 31 } else {
                let mut f = frac;
                let mut e = -14_i32;
                while (f & 0x400) == 0 { f <<= 1; e -= 1; }
                f &= 0x3ff;
                (sign << 31) | (((e + 127) as u32) << 23) | (f << 13)
            }
        }
        0x1f => (sign << 31) | 0x7f80_0000 | (frac << 13),
        _ => (sign << 31) | ((exp + 112) << 23) | (frac << 13),
    };
    f32::from_bits(bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decodes_basic_f16() {
        assert_eq!(f16_to_f32(0x3c00), 1.0);
        assert_eq!(f16_to_f32(0xc000), -2.0);
    }
}
