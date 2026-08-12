//! Host-side scope-identity helpers. Pure safe Rust (no BPF/unsafe
//! involved) — reads `/proc` to derive the same scope tokens the main
//! crate's `ScopeToken` (in `src/behaviour/ebpf_telemetry.rs`) validates
//! frames against, so both sides agree on what "in scope for this run"
//! means without trusting each other's arithmetic.

use std::fs;
use std::os::unix::fs::MetadataExt as _;

/// (pid, start_time) uniquely identifies a process even across PID reuse,
/// per `man proc(5)`'s description of field 22 in `/proc/<pid>/stat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_time_ticks: u64,
}

/// Read the root sandboxed process's (pid, start_time) fallback scope
/// identity. Returns `None` if `/proc/<pid>/stat` is unreadable or
/// unparseable (process already exited, or a non-Linux/odd `/proc` layout);
/// callers should treat that as "fall back further down the scope chain",
/// not as a fatal error.
pub fn process_identity(pid: u32) -> Option<ProcessIdentity> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name field is parenthesized and may itself contain
    // spaces/parens, so locate fields by the last ')' rather than naive
    // whitespace splitting.
    let close = stat.rfind(')')?;
    let mut fields = stat[close + 1..].split_whitespace();
    // Field 3 (state) is fields.next() == index 0 here; start_time is field
    // 22 overall, i.e. the 20th field after the command name.
    let start_time_ticks = fields.nth(19)?.parse::<u64>().ok()?;
    Some(ProcessIdentity {
        pid,
        start_time_ticks,
    })
}

/// PID namespace identity for `pid`, read from the inode number of
/// `/proc/<pid>/ns/pid`. Any two processes in the same PID namespace report
/// the same inode.
pub fn pid_namespace_inode(pid: u32) -> Option<u64> {
    let metadata = fs::metadata(format!("/proc/{pid}/ns/pid")).ok()?;
    Some(metadata.ino())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_identity_of_self_is_readable_and_stable() {
        let pid = std::process::id();
        let first = process_identity(pid).expect("own /proc/self/stat must be readable");
        let second = process_identity(pid).expect("re-read must succeed");
        assert_eq!(first, second);
        assert_eq!(first.pid, pid);
    }

    #[test]
    fn pid_namespace_inode_of_self_is_readable_and_stable() {
        let pid = std::process::id();
        let first = pid_namespace_inode(pid).expect("own PID namespace inode must be readable");
        let second = pid_namespace_inode(pid).expect("re-read must succeed");
        assert_eq!(first, second);
    }

    #[test]
    fn nonexistent_pid_returns_none_not_a_panic() {
        assert!(process_identity(u32::MAX).is_none());
        assert!(pid_namespace_inode(u32::MAX).is_none());
    }
}
