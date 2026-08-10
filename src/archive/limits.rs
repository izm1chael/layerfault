use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveLimits {
    pub max_depth: usize,
    pub max_members_per_archive: usize,
    pub max_members_total: usize,
    pub max_compressed_bytes: u64,
    pub max_uncompressed_member_bytes: u64,
    pub max_uncompressed_total_bytes: u64,
    pub max_compression_ratio: f64,
    pub max_path_bytes: usize,
    pub max_retained_findings: usize,
    pub max_nested_archives: usize,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_depth: 8,
            max_members_per_archive: 10_000,
            max_members_total: 50_000,
            max_compressed_bytes: 512 * 1024 * 1024,
            max_uncompressed_member_bytes: 256 * 1024 * 1024,
            max_uncompressed_total_bytes: 2 * 1024 * 1024 * 1024,
            max_compression_ratio: 100.0,
            max_path_bytes: 4096,
            max_retained_findings: 1000,
            max_nested_archives: 16,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArchiveBudgetTracker {
    pub limits: ArchiveLimits,
    pub current_depth: usize,
    pub total_members_seen: usize,
    pub total_uncompressed_bytes_seen: u64,
    pub total_nested_archives_seen: usize,
}

impl ArchiveBudgetTracker {
    pub fn new(limits: ArchiveLimits, initial_depth: usize) -> Self {
        Self {
            limits,
            current_depth: initial_depth,
            total_members_seen: 0,
            total_uncompressed_bytes_seen: 0,
            total_nested_archives_seen: 0,
        }
    }

    pub fn enter_nested(&mut self) -> Result<(), String> {
        self.current_depth += 1;
        self.total_nested_archives_seen += 1;
        self.check_depth()?;
        self.check_nested_archives()?;
        Ok(())
    }

    pub fn leave_nested(&mut self) {
        self.current_depth = self.current_depth.saturating_sub(1);
    }

    pub fn check_depth(&self) -> Result<(), String> {
        if self.current_depth > self.limits.max_depth {
            return Err(format!(
                "Archive nesting depth {} exceeds maximum limit {}",
                self.current_depth, self.limits.max_depth
            ));
        }
        Ok(())
    }

    pub fn check_nested_archives(&self) -> Result<(), String> {
        if self.total_nested_archives_seen > self.limits.max_nested_archives {
            return Err(format!(
                "Total nested archive count {} exceeds limit {}",
                self.total_nested_archives_seen, self.limits.max_nested_archives
            ));
        }
        Ok(())
    }

    pub fn add_member(&mut self) -> Result<(), String> {
        self.total_members_seen = self.total_members_seen.saturating_add(1);
        if self.total_members_seen > self.limits.max_members_total {
            return Err(format!(
                "Total archive member count {} exceeds cumulative limit {}",
                self.total_members_seen, self.limits.max_members_total
            ));
        }
        Ok(())
    }

    pub fn add_uncompressed_bytes(&mut self, bytes: u64) -> Result<(), String> {
        self.total_uncompressed_bytes_seen = self
            .total_uncompressed_bytes_seen
            .checked_add(bytes)
            .ok_or_else(|| "Cumulative uncompressed bytes overflow".to_string())?;
        if self.total_uncompressed_bytes_seen > self.limits.max_uncompressed_total_bytes {
            return Err(format!(
                "Total uncompressed bytes {} exceeds cumulative budget limit {}",
                self.total_uncompressed_bytes_seen, self.limits.max_uncompressed_total_bytes
            ));
        }
        Ok(())
    }
}
