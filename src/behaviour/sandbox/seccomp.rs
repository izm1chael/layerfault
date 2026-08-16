use anyhow::{Context, Result};
use std::fs::File;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(super) fn seccomp_filter_supported() -> bool {
    true
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
pub(super) fn seccomp_filter_supported() -> bool {
    false
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) fn seccomp_filter_file() -> Result<File> {
    use std::io::{Seek, SeekFrom, Write};

    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_JMP_JGE_K: u16 = 0x35;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc000_00b7;

    // Keep the broad, version-dependent ML runtime syscall surface available,
    // but deny primitives commonly used to attack the shared host kernel or
    // reconfigure the namespace boundary.
    let denied = [
        libc::SYS_add_key,
        libc::SYS_bpf,
        libc::SYS_delete_module,
        libc::SYS_finit_module,
        libc::SYS_init_module,
        libc::SYS_kexec_load,
        libc::SYS_keyctl,
        libc::SYS_mount,
        libc::SYS_open_by_handle_at,
        libc::SYS_perf_event_open,
        libc::SYS_pivot_root,
        libc::SYS_process_vm_writev,
        libc::SYS_ptrace,
        libc::SYS_reboot,
        libc::SYS_request_key,
        libc::SYS_setns,
        libc::SYS_umount2,
        libc::SYS_unshare,
        libc::SYS_userfaultfd,
    ];
    // struct seccomp_data starts with syscall number at offset 0 and audit
    // architecture at offset 4. Kill rather than evaluate a foreign ABI.
    let mut instructions = vec![
        (BPF_LD_W_ABS, 0, 0, 4),
        (BPF_JMP_JEQ_K, 1, 0, AUDIT_ARCH),
        (BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        (BPF_LD_W_ABS, 0, 0, 0),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        // Prevent x32 syscall-number aliases from bypassing the deny rules.
        instructions.push((BPF_JMP_JGE_K, 0, 1, 0x4000_0000));
        instructions.push((BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS));
    }
    for syscall in denied {
        instructions.push((BPF_JMP_JEQ_K, 0, 1, syscall as u32));
        instructions.push((BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));
    }
    instructions.push((BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW));

    // Bubblewrap accepts the same raw cBPF instruction stream produced by
    // seccomp_export_bpf. Keep the descriptor alive across prlimit/strace execs.
    let mut filter = tempfile::tempfile().context("unable to create seccomp filter file")?;
    for (code, jt, jf, k) in instructions {
        filter.write_all(&code.to_ne_bytes())?;
        filter.write_all(&[jt, jf])?;
        filter.write_all(&k.to_ne_bytes())?;
    }
    filter.seek(SeekFrom::Start(0))?;
    let mut flags = rustix::io::fcntl_getfd(&filter)?;
    flags.remove(rustix::io::FdFlags::CLOEXEC);
    rustix::io::fcntl_setfd(&filter, flags).context("unable to make seccomp filter inheritable")?;
    Ok(filter)
}

pub(crate) fn seccomp_profile_sha256() -> Option<String> {
    let filter = seccomp_filter_file().ok()?;
    crate::hashcache::sha256_uncached_prefixed(&filter).ok()
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
pub(crate) fn seccomp_filter_file() -> Result<File> {
    anyhow::bail!("the behavioural seccomp filter is unsupported on this platform")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn seccomp_filter_is_nonempty_pinned_cbpf() -> Result<()> {
        use std::io::Read as _;

        let mut filter = seccomp_filter_file()?;
        assert!(!rustix::io::fcntl_getfd(&filter)?.contains(rustix::io::FdFlags::CLOEXEC));
        let mut bytes = Vec::new();
        filter.read_to_end(&mut bytes)?;
        assert!(bytes.len() >= 8 * 40);
        assert_eq!(bytes.len() % 8, 0);
        Ok(())
    }
}
