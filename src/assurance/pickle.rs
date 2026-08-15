use crate::intelligence::IntelligencePack;

/// Match a normalized dotted callable against signed, data-only gadget intelligence.
/// No pattern is executed and no regex/script content is accepted here.
pub fn gadget_match(callable: &str, pack: &IntelligencePack) -> Option<String> {
    let normalized = normalize_callable(callable)?;
    pack.pickle_gadgets.iter().find_map(|gadget| {
        let candidate = normalize_callable(&gadget.callable)?;
        (candidate == normalized).then(|| gadget.id.clone())
    })
}

pub fn normalize_callable(value: &str) -> Option<String> {
    let value = value.trim().replace("::", ".");
    if value.is_empty() || value.len() > 4096 {
        return None;
    }
    if value
        .split('.')
        .any(|part| part.is_empty() || !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
    {
        return None;
    }
    Some(value)
}
