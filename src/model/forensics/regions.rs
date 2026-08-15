use super::{FileRegion, RegionKind};
use crate::formats::ArtifactFormat;
use anyhow::{bail, Result};
use std::path::Path;
pub trait RegionProvider {
    fn regions(&self, path: &Path, file_size: u64) -> Result<Vec<FileRegion>>;
}
pub fn regions(path: &Path, format: ArtifactFormat, file_size: u64) -> Result<Vec<FileRegion>> {
    match format {
        ArtifactFormat::Safetensors => safetensors(path, file_size),
        ArtifactFormat::Gguf => gguf(path, file_size),
        _ => Ok(vec![FileRegion {
            offset: 0,
            length: file_size,
            kind: RegionKind::Unknown,
            owner: None,
        }]),
    }
}
fn safetensors(path: &Path, size: u64) -> Result<Vec<FileRegion>> {
    let f = crate::safeio::open_readonly_nofollow(path)?;
    let inv = crate::formats::safetensors::inventory_file(&f, size)?;
    let mut r = vec![
        FileRegion {
            offset: 0,
            length: 8,
            kind: RegionKind::Header,
            owner: None,
        },
        FileRegion {
            offset: 8,
            length: inv.data_start.saturating_sub(8),
            kind: RegionKind::Metadata,
            owner: None,
        },
    ];
    for t in &inv.tensors {
        let off = inv
            .data_start
            .checked_add(t.start)
            .ok_or_else(|| anyhow::anyhow!("tensor region overflow"))?;
        r.push(FileRegion {
            offset: off,
            length: t.end.saturating_sub(t.start),
            kind: RegionKind::TensorData,
            owner: Some(t.name.clone()),
        })
    }
    let extent = inv.logical_extent(size).logical_end;
    if extent < size {
        r.push(FileRegion {
            offset: extent,
            length: size - extent,
            kind: RegionKind::Trailing,
            owner: None,
        })
    }
    normalize(r, size)
}
fn gguf(path: &Path, size: u64) -> Result<Vec<FileRegion>> {
    let f = crate::safeio::open_readonly_nofollow(path)?;
    let inv = crate::formats::gguf::parse_file(&f, size)?;
    let mut r = vec![FileRegion {
        offset: 0,
        length: inv.tensor_data_start,
        kind: RegionKind::Metadata,
        owner: None,
    }];
    for t in &inv.tensors {
        let Some(len) = t.byte_len else { continue };
        let off = inv
            .tensor_data_start
            .checked_add(t.offset)
            .ok_or_else(|| anyhow::anyhow!("gguf tensor overflow"))?;
        r.push(FileRegion {
            offset: off,
            length: len,
            kind: RegionKind::TensorData,
            owner: Some(t.name.clone()),
        })
    }
    let extent = inv.logical_extent(size).logical_end;
    if extent < size {
        r.push(FileRegion {
            offset: extent,
            length: size - extent,
            kind: RegionKind::Trailing,
            owner: None,
        })
    }
    normalize(r, size)
}
fn normalize(mut r: Vec<FileRegion>, size: u64) -> Result<Vec<FileRegion>> {
    r.sort_by_key(|x| x.offset);
    let mut end = 0;
    for x in &r {
        let e = x
            .offset
            .checked_add(x.length)
            .ok_or_else(|| anyhow::anyhow!("region overflow"))?;
        if e > size {
            bail!("region outside file")
        }
        if x.offset < end {
            bail!("overlapping region plan")
        }
        end = e;
    }
    Ok(r)
}
