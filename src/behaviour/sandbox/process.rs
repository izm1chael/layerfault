use anyhow::Result;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use std::collections::{BTreeMap, BTreeSet};

/// Put a spawned behavioural command in its own host-side process group where
/// the platform supports it. Bubblewrap creates additional namespaces/sessions
/// internally, so teardown also enumerates descendants instead of relying on
/// the process group alone.
pub fn configure_process_group(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
}

/// Terminate and reap the complete behavioural process tree without using
/// unsafe signal syscalls in Layerfault itself. On Linux, descendants are
/// enumerated from /proc and signalled explicitly; elsewhere Child::kill is the
/// conservative fallback. This is used for timeout, cancellation and failed
/// session startup.
pub fn terminate_process_tree(child: &mut Child, grace: Duration) -> Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let root = child.id();
        signal_linux_tree(root, "-TERM");
        let started = Instant::now();
        while started.elapsed() < grace {
            if child.try_wait()?.is_some() {
                // A dead parent can still leave descendants if an inner
                // namespace/session escaped group signalling. Recheck /proc.
                if linux_descendants(root).is_empty() {
                    return Ok(());
                }
            }
            if linux_descendants(root).is_empty() {
                let _ = child.try_wait()?;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        signal_linux_tree(root, "-KILL");
        let kill_started = Instant::now();
        while kill_started.elapsed() < Duration::from_secs(2) {
            if child.try_wait()?.is_some() && linux_descendants(root).is_empty() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = child.kill();
        let _ = child.wait();
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = child.kill();
        let _ = child.wait();
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn signal_linux_tree(root: u32, signal: &str) {
    let mut pids = linux_descendants(root);
    pids.push(root);
    // Descendants first so a parent cannot immediately respawn a child after
    // its child was terminated but before the parent receives the signal.
    pids.sort_unstable_by(|a, b| b.cmp(a));
    pids.dedup();
    let Some(kill) = crate::sources::find_executable("kill") else {
        return;
    };
    for pid in pids {
        if let Ok(mut command) = crate::safeio::command_for_executable(&kill) {
            let _ = command
                .arg(signal)
                .arg("--")
                .arg(pid.to_string())
                .env_clear()
                .status();
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_descendants(root: u32) -> Vec<u32> {
    let mut parent_by_pid = BTreeMap::<u32, u32>::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some(close) = stat.rfind(')') else {
            continue;
        };
        let mut fields = stat[close + 1..].split_whitespace();
        let _state = fields.next();
        let Some(ppid) = fields.next().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        parent_by_pid.insert(pid, ppid);
    }
    let mut found = BTreeSet::new();
    let mut frontier = vec![root];
    while let Some(parent) = frontier.pop() {
        for (&pid, &ppid) in &parent_by_pid {
            if ppid == parent && found.insert(pid) {
                frontier.push(pid);
            }
        }
    }
    found.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn timeout_teardown_kills_sigterm_ignoring_descendant() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("layerfault-process-tree-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root)?;
        let pidfile = root.join("child.pid");
        let mut command = Command::new("sh");
        command.arg("-c").arg(format!(
            "trap '' TERM; (trap '' TERM; while :; do sleep 1; done) & echo $! > '{}'; while :; do sleep 1; done",
            pidfile.display()
        ));
        configure_process_group(&mut command);
        let mut child = command.spawn()?;
        let started = Instant::now();
        while !pidfile.is_file() && started.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(20));
        }
        let descendant: u32 = std::fs::read_to_string(&pidfile)?.trim().parse()?;
        terminate_process_tree(&mut child, Duration::from_millis(100))?;
        assert!(child.try_wait()?.is_some());
        let proc_stat = std::fs::read_to_string(format!("/proc/{descendant}/stat")).ok();
        if let Some(stat) = proc_stat {
            let state = stat
                .rsplit_once(')')
                .and_then(|(_, tail)| tail.split_whitespace().next());
            assert_eq!(
                state,
                Some("Z"),
                "descendant remained live after teardown: {stat}"
            );
        }
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }
}
