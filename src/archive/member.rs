use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedMemberPath {
    pub virtual_path: String,
    pub components: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizationError {
    EmptyName,
    ControlCharacter(char),
    ExceedsPathLimit { bytes: usize, limit: usize },
    AbsolutePath(String),
    ParentTraversal(String),
    DotAmbiguity(String),
    BackslashTraversal(String),
    DrivePrefix(String),
    UncPrefix(String),
    ExcessiveDepth { depth: usize, limit: usize },
}

impl fmt::Display for NormalizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName => write!(f, "Archive member path is empty"),
            Self::ControlCharacter(c) => write!(
                f,
                "Archive member path contains illegal control character (code {})",
                *c as u32
            ),
            Self::ExceedsPathLimit { bytes, limit } => write!(
                f,
                "Archive member path length ({} bytes) exceeds safety limit ({} bytes)",
                bytes, limit
            ),
            Self::AbsolutePath(p) => write!(f, "Archive member path '{}' is absolute", p),
            Self::ParentTraversal(p) => {
                write!(
                    f,
                    "Archive member path '{}' contains parent '..' component",
                    p
                )
            }
            Self::DotAmbiguity(p) => {
                write!(
                    f,
                    "Archive member path '{}' contains ambiguous '.' component",
                    p
                )
            }
            Self::BackslashTraversal(p) => write!(
                f,
                "Archive member path '{}' contains backslash component separator/traversal",
                p
            ),
            Self::DrivePrefix(p) => {
                write!(
                    f,
                    "Archive member path '{}' contains Windows drive prefix",
                    p
                )
            }
            Self::UncPrefix(p) => write!(
                f,
                "Archive member path '{}' contains UNC network path prefix",
                p
            ),
            Self::ExcessiveDepth { depth, limit } => write!(
                f,
                "Archive member path component depth ({}) exceeds safety limit ({})",
                depth, limit
            ),
        }
    }
}

impl std::error::Error for NormalizationError {}

pub fn normalize_member_path(
    raw_name: &str,
    max_path_bytes: usize,
) -> Result<NormalizedMemberPath, NormalizationError> {
    if raw_name.is_empty() {
        return Err(NormalizationError::EmptyName);
    }

    if raw_name.len() > max_path_bytes {
        return Err(NormalizationError::ExceedsPathLimit {
            bytes: raw_name.len(),
            limit: max_path_bytes,
        });
    }

    for c in raw_name.chars() {
        if c.is_control() || c == '\0' {
            return Err(NormalizationError::ControlCharacter(c));
        }
    }

    // Check UNC prefix
    if raw_name.starts_with("\\\\") || raw_name.starts_with("//") {
        return Err(NormalizationError::UncPrefix(raw_name.to_owned()));
    }

    // Check Windows drive prefix (e.g. C: or C:\ or c:/)
    let bytes = raw_name.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(NormalizationError::DrivePrefix(raw_name.to_owned()));
    }

    // Check backslash traversal
    if raw_name.contains('\\') {
        return Err(NormalizationError::BackslashTraversal(raw_name.to_owned()));
    }

    // Check absolute path
    if raw_name.starts_with('/') {
        return Err(NormalizationError::AbsolutePath(raw_name.to_owned()));
    }

    let mut components = Vec::new();
    for segment in raw_name.split('/') {
        if segment.is_empty() {
            // Trailing slash for directories is fine if at end of path and components non-empty,
            // but multiple slashes // inside path are ambiguous/invalid.
            continue;
        }
        if segment == ".." {
            return Err(NormalizationError::ParentTraversal(raw_name.to_owned()));
        }
        if segment == "." {
            return Err(NormalizationError::DotAmbiguity(raw_name.to_owned()));
        }
        components.push(segment.to_owned());
    }

    if components.is_empty() {
        return Err(NormalizationError::EmptyName);
    }

    const MAX_COMPONENT_DEPTH: usize = 64;
    if components.len() > MAX_COMPONENT_DEPTH {
        return Err(NormalizationError::ExcessiveDepth {
            depth: components.len(),
            limit: MAX_COMPONENT_DEPTH,
        });
    }

    let virtual_path = components.join("/");
    Ok(NormalizedMemberPath {
        virtual_path,
        components,
    })
}

/// Helper to format a virtual subject path for evidence reporting.
/// Outer: `outer.zip!/path/in/archive/model.pkl`
/// Nested: `outer.zip!/inner.tar!/x/modeling.py`
pub fn format_virtual_subject(outer_identity: &str, member_relative_path: &str) -> String {
    let clean_member = member_relative_path.trim_start_matches('/');
    format!("{outer_identity}!/{clean_member}")
}

#[derive(Debug, Default)]
pub struct ArchiveMemberTracker {
    pub seen_normalized: BTreeMap<String, usize>,
    pub seen_case_folded: BTreeMap<String, String>,
}

impl ArchiveMemberTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a normalized path. Returns (is_duplicate, Option<case_collision_original>).
    pub fn record(&mut self, path: &str) -> (bool, Option<String>) {
        let count = self.seen_normalized.entry(path.to_owned()).or_insert(0);
        *count += 1;
        let is_duplicate = *count > 1;

        let lower = path.to_ascii_lowercase();
        let mut case_collision = None;
        if let Some(existing) = self.seen_case_folded.get(&lower) {
            if existing != path {
                case_collision = Some(existing.clone());
            }
        } else {
            self.seen_case_folded.insert(lower, path.to_owned());
        }

        (is_duplicate, case_collision)
    }
}
