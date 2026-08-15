use super::{magic, regions, CarvedObject, ForensicsProfile, RegionKind, TensorForensicsReport};
use crate::formats::ArtifactFormat;
use crate::scanner::Confidence;
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
const MAX_REGION: u64 = 64 * 1024 * 1024;
const MAX_STANDARD: u64 = 256 * 1024 * 1024;
const WINDOW: usize = 1024 * 1024;
pub fn inspect(
    path: &Path,
    format: ArtifactFormat,
    profile: ForensicsProfile,
) -> Result<TensorForensicsReport> {
    let f = crate::safeio::open_readonly_nofollow(path)?;
    let size = f.metadata()?.len();
    let identity = crate::hashcache::sha256_hex(path, &f)?.sha256;
    let regions = regions::regions(path, format, size)?;
    let mut carved = Vec::new();
    let mut read_total = 0u64;
    for r in &regions {
        let scan = matches!(
            r.kind,
            RegionKind::Gap | RegionKind::Trailing | RegionKind::Alignment
        ) || matches!(profile, ForensicsProfile::Research)
            && r.kind == RegionKind::TensorData;
        if !scan {
            continue;
        }
        let take = r
            .length
            .min(MAX_REGION)
            .min(MAX_STANDARD.saturating_sub(read_total));
        if take == 0 {
            break;
        }
        let mut reader = f.try_clone()?;
        reader.seek(SeekFrom::Start(r.offset))?;
        let mut buf = vec![0u8; usize::try_from(take).unwrap_or(0)];
        reader.read_exact(&mut buf)?;
        read_total += take;
        for i in 0..buf.len().saturating_sub(4) {
            if let Some(m) = magic::detect(&buf[i..]) {
                let w = &buf[i..(i + WINDOW).min(buf.len())];
                let chars = super::entropy::characterize(w);
                let corroborated = r.kind != RegionKind::TensorData
                    || w.len() > 32
                        && (chars.printable_ratio > 0.25 || m.executable && w.len() >= 64);
                carved.push(CarvedObject {
                    object_type: m.name.into(),
                    offset: r.offset + i as u64,
                    observed_length: w.len() as u64,
                    region_kind: r.kind,
                    owner: r.owner.clone(),
                    sha256_prefix_window: format!("sha256:{}", hex::encode(Sha256::digest(w))),
                    confidence: if corroborated {
                        Confidence::High
                    } else {
                        Confidence::Medium
                    },
                    evidence_only: !corroborated,
                });
                if carved.len() >= 128 {
                    break;
                }
            }
        }
        if carved.len() >= 128 {
            break;
        }
    }
    let incomplete = regions.iter().any(|r| r.kind == RegionKind::Unknown)
        || regions
            .iter()
            .filter(|r| {
                matches!(
                    r.kind,
                    RegionKind::Gap | RegionKind::Trailing | RegionKind::Alignment
                )
            })
            .map(|r| r.length.min(MAX_REGION))
            .sum::<u64>()
            > read_total;
    let findings = super::findings::build(&identity, &carved, incomplete);
    let mut coverage = crate::coverage::Coverage::complete(1, read_total);
    if incomplete {
        coverage.omit(
            0,
            "forensic byte budget or region provider left unexamined bytes",
            &[],
        )
    }
    Ok(TensorForensicsReport {
        artifact_sha256: identity,
        regions,
        carved,
        findings,
        coverage,
    })
}
