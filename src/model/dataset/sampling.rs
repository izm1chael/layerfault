use super::types::CountedFile;

pub(super) const MAX_RECORDS: usize = 250_000;
pub(super) const MAX_TOKEN_KEYS: usize = 200_000;

/// Deterministically allocate the global record budget across every parseable
/// member. Every non-empty member receives at least one record when the budget
/// permits (MAX_FILES < MAX_RECORDS), then the remaining budget is distributed
/// proportionally by record population.
pub(super) fn analysis_quotas(files: &[CountedFile]) -> Vec<usize> {
    let total: usize = files
        .iter()
        .map(|file| file.records_available)
        .fold(0_usize, |acc, value| acc.saturating_add(value));
    if total <= MAX_RECORDS {
        return files.iter().map(|file| file.records_available).collect();
    }

    let mut quotas = vec![0_usize; files.len()];
    let active: Vec<usize> = files
        .iter()
        .enumerate()
        .filter_map(|(index, file)| (file.records_available > 0).then_some(index))
        .collect();
    let mut remaining = MAX_RECORDS;
    for &index in &active {
        if remaining == 0 {
            break;
        }
        quotas[index] = 1;
        remaining -= 1;
    }
    if remaining == 0 {
        return quotas;
    }

    let extra_total: usize = active
        .iter()
        .map(|&index| files[index].records_available.saturating_sub(1))
        .sum();
    if extra_total == 0 {
        return quotas;
    }
    let mut remainders = Vec::with_capacity(active.len());
    let mut allocated = 0_usize;
    for &index in &active {
        let capacity = files[index].records_available.saturating_sub(1);
        let numerator = (remaining as u128).saturating_mul(capacity as u128);
        let share = (numerator / extra_total as u128) as usize;
        let share = share.min(capacity);
        quotas[index] = quotas[index].saturating_add(share);
        allocated = allocated.saturating_add(share);
        remainders.push((numerator % extra_total as u128, index));
    }
    let mut leftover = remaining.saturating_sub(allocated);
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    for (_, index) in remainders {
        if leftover == 0 {
            break;
        }
        if quotas[index] < files[index].records_available {
            quotas[index] += 1;
            leftover -= 1;
        }
    }
    quotas
}

pub(super) fn selected_indices(total: usize, quota: usize) -> Vec<usize> {
    if quota == 0 || total == 0 {
        return Vec::new();
    }
    if quota >= total {
        return (0..total).collect();
    }
    if quota == 1 {
        return vec![total / 2];
    }
    let last = total - 1;
    (0..quota)
        .map(|position| position.saturating_mul(last) / (quota - 1))
        .collect()
}

pub(super) fn token_key_quotas(record_quotas: &[usize]) -> Vec<usize> {
    let active: Vec<usize> = record_quotas
        .iter()
        .enumerate()
        .filter_map(|(index, quota)| (*quota > 0).then_some(index))
        .collect();
    let mut out = vec![0_usize; record_quotas.len()];
    if active.is_empty() {
        return out;
    }
    let mut remaining = MAX_TOKEN_KEYS;
    for &index in &active {
        if remaining == 0 {
            break;
        }
        out[index] = 1;
        remaining -= 1;
    }
    if remaining == 0 {
        return out;
    }
    let total_records: usize = active
        .iter()
        .map(|&index| record_quotas[index])
        .fold(0_usize, |acc, value| acc.saturating_add(value));
    if total_records == 0 {
        return out;
    }
    let mut allocated = 0_usize;
    let mut remainders = Vec::with_capacity(active.len());
    for &index in &active {
        let numerator = (remaining as u128).saturating_mul(record_quotas[index] as u128);
        let share = usize::try_from(numerator / total_records as u128).unwrap_or(usize::MAX);
        out[index] = out[index].saturating_add(share);
        allocated = allocated.saturating_add(share);
        remainders.push((numerator % total_records as u128, index));
    }
    let mut leftover = remaining.saturating_sub(allocated);
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    for (_, index) in remainders {
        if leftover == 0 {
            break;
        }
        out[index] = out[index].saturating_add(1);
        leftover -= 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::types::DatasetPlan;
    use super::*;
    use crate::model::dataset::types::DatasetFormat;
    use std::path::PathBuf;

    #[test]
    fn quotas_are_bounded_and_cover_every_nonempty_file() {
        let root = PathBuf::from("/tmp");
        let files: Vec<_> = [400_000_usize, 200_000, 10]
            .into_iter()
            .enumerate()
            .map(|(index, count)| CountedFile {
                plan: DatasetPlan {
                    path: root.join(format!("{index}.jsonl")),
                    relative: format!("{index}.jsonl"),
                    format: DatasetFormat::Jsonl,
                    bytes: 1,
                },
                sha256: "00".repeat(32),
                records_available: count,
                parse_warning: None,
            })
            .collect();
        let quotas = analysis_quotas(&files);
        assert_eq!(quotas.iter().sum::<usize>(), MAX_RECORDS);
        assert!(quotas.iter().all(|quota| *quota > 0));
        assert!(quotas[0] > quotas[1]);
    }

    #[test]
    fn parallel_token_key_budgets_remain_globally_bounded() {
        let record_quotas = vec![100_000, 75_000, 50_000, 25_000];
        let quotas = token_key_quotas(&record_quotas);
        assert_eq!(quotas.len(), record_quotas.len());
        assert_eq!(quotas.iter().sum::<usize>(), MAX_TOKEN_KEYS);
        assert!(quotas.iter().all(|quota| *quota > 0));
    }

    #[test]
    fn stratified_selection_includes_head_middle_and_tail() {
        let selected = selected_indices(1_000_000, 5);
        assert_eq!(selected.first().copied(), Some(0));
        assert_eq!(selected.last().copied(), Some(999_999));
        assert!(selected
            .iter()
            .any(|index| *index > 400_000 && *index < 600_000));
    }

    #[test]
    fn tail_records_are_selected_when_budget_is_bounded() {
        let selected = selected_indices(MAX_RECORDS + 50_000, MAX_RECORDS);
        assert_eq!(selected[0], 0);
        assert_eq!(*selected.last().expect("tail index"), MAX_RECORDS + 49_999);
    }
}
