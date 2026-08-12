use anyhow::{anyhow, bail, Result};

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
    let step =
        element_bytes(dtype).ok_or_else(|| anyhow!("unsupported numeric dtype '{dtype}'"))?;
    if !bytes.len().is_multiple_of(step) {
        bail!("numeric tensor byte length is not aligned to dtype size");
    }
    let mut out = Vec::with_capacity(bytes.len() / step);
    for chunk in bytes.chunks_exact(step) {
        let value = match dtype.to_ascii_uppercase().as_str() {
            "BOOL" => {
                if chunk[0] == 0 {
                    0.0
                } else {
                    1.0
                }
            }
            "I8" => i8::from_le_bytes([chunk[0]]) as f64,
            "U8" => chunk[0] as f64,
            "I16" => i16::from_le_bytes(chunk.try_into().unwrap_or([0; 2])) as f64,
            "U16" => u16::from_le_bytes(chunk.try_into().unwrap_or([0; 2])) as f64,
            "F16" => f16_to_f32(u16::from_le_bytes(chunk.try_into().unwrap_or([0; 2]))) as f64,
            "BF16" => f32::from_bits(
                (u16::from_le_bytes(chunk.try_into().unwrap_or([0; 2])) as u32) << 16,
            ) as f64,
            "I32" => i32::from_le_bytes(chunk.try_into().unwrap_or([0; 4])) as f64,
            "U32" => u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4])) as f64,
            "F32" => f32::from_le_bytes(chunk.try_into().unwrap_or([0; 4])) as f64,
            "I64" => i64::from_le_bytes(chunk.try_into().unwrap_or([0; 8])) as f64,
            "U64" => u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8])) as f64,
            "F64" => f64::from_le_bytes(chunk.try_into().unwrap_or([0; 8])),
            _ => unreachable!(),
        };
        if !value.is_finite() {
            bail!("numeric tensor contains non-finite value");
        }
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
            if frac == 0 {
                sign << 31
            } else {
                let mut f = frac;
                let mut e = -14_i32;
                while (f & 0x400) == 0 {
                    f <<= 1;
                    e -= 1;
                }
                f &= 0x3ff;
                (sign << 31) | (((e + 127) as u32) << 23) | (f << 13)
            }
        }
        0x1f => (sign << 31) | 0x7f80_0000 | (frac << 13),
        _ => (sign << 31) | ((exp + 112) << 23) | (frac << 13),
    };
    f32::from_bits(bits)
}

pub(super) fn tensor_elements(
    tensor: &crate::formats::safetensors::SafetensorsTensor,
) -> Result<u64> {
    let step = element_bytes(&tensor.dtype)
        .ok_or_else(|| anyhow!("unsupported numeric dtype '{}'", tensor.dtype))?
        as u64;
    let bytes = tensor.end.saturating_sub(tensor.start);
    if !bytes.is_multiple_of(step) {
        bail!(
            "tensor '{}' byte range is not aligned to dtype size",
            tensor.name
        );
    }
    Ok(bytes / step)
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
