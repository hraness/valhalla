//! Linux-only test diagnostics for the supervisor lock; never read capabilities.

use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader},
    os::unix::fs::MetadataExt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug)]
pub(super) struct Snapshot {
    pub(super) dev: u64,
    pub(super) ino: u64,
    pub(super) fds: Vec<u32>,
    pub(super) holders: Vec<String>,
}

fn lock_id(value: &str) -> Option<(u64, u64, u64)> {
    let mut parts = value.split(':');
    let major = u64::from_str_radix(parts.next()?, 16).ok()?;
    let minor = u64::from_str_radix(parts.next()?, 16).ok()?;
    let inode = parts.next()?.parse().ok()?;
    parts.next().is_none().then_some((major, minor, inode))
}

fn holder(line: &str, id: (u64, u64, u64)) -> Option<String> {
    let fields: Vec<_> = line.split_whitespace().collect();
    // /proc/locks inserts "->" before the lock type for a queued request.
    // A waiter is not a holder, even if it targets the same inode.
    if fields.get(1) == Some(&"->") {
        return None;
    }
    let (kind, pid, file_id) = (fields.get(1)?, fields.get(4)?, fields.get(5)?);
    (lock_id(file_id) == Some(id)).then(|| format!("{kind} pid={pid}"))
}

pub(super) fn held_by(state: &Snapshot, pid: u32) -> bool {
    let expected = format!("pid={pid}");
    state
        .holders
        .iter()
        .any(|entry| entry.split_whitespace().any(|part| part == expected))
}

fn matching_fds(pid: &str, dev: u64, ino: u64) -> io::Result<Vec<u32>> {
    // Inspect only the observer or the explicitly task-owned test child.
    // The iterator's own directory descriptor can disappear mid-scan; it is
    // unrelated to this regular-file inode and need not be kept open.
    let mut fds = Vec::new();
    for (index, entry) in fs::read_dir(format!("/proc/{pid}/fd"))?.enumerate() {
        if index == 4_096 {
            return Err(io::Error::other("/proc/fd scan exceeded 4096 entries"));
        }
        let entry = entry?;
        if let Ok(fd) = entry.file_name().to_string_lossy().parse::<u32>() {
            if fs::metadata(entry.path())
                .is_ok_and(|fd_meta| fd_meta.dev() == dev && fd_meta.ino() == ino)
            {
                fds.push(fd);
            }
        }
    }
    fds.sort_unstable();
    Ok(fds)
}

pub(super) fn child_fds(state: &Snapshot, pid: u32) -> io::Result<Vec<u32>> {
    matching_fds(&pid.to_string(), state.dev, state.ino)
}

pub(super) fn snapshot(home: &Path) -> io::Result<Snapshot> {
    let metadata = fs::metadata(home.join("control/supervisor.lock"))?;
    let dev = metadata.dev();
    let ino = metadata.ino();
    // Linux's dev_t layout, used by /proc/locks as hexadecimal major:minor.
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000);
    let minor = (dev & 0xff) | ((dev >> 12) & 0xffffff00);
    let mut holders = Vec::new();
    for (index, line) in BufReader::new(File::open("/proc/locks")?)
        .lines()
        .enumerate()
    {
        if index == 16_384 {
            return Err(io::Error::other("/proc/locks scan exceeded 16384 entries"));
        }
        if let Some(entry) = holder(&line?, (major, minor, ino)) {
            holders.push(entry);
        }
    }
    let fds = matching_fds("self", dev, ino)?;
    Ok(Snapshot {
        dev,
        ino,
        fds,
        holders,
    })
}

fn millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis())
}

/// A bounded snapshot, not a global proof that an absent lock cannot exist in
/// another PID namespace. The refusal snapshot is taken just after try_lock.
pub(super) fn record(home: &Path, phase: &str) -> Option<Snapshot> {
    match snapshot(home) {
        Ok(state) => {
            eprintln!(
                "supervisor-lock phase={phase} ms={} observer_pid={} dev={} ino={} holders={:?} self_fds={:?}",
                millis(),
                std::process::id(),
                state.dev,
                state.ino,
                state.holders,
                state.fds
            );
            Some(state)
        }
        Err(error) => {
            eprintln!(
                "supervisor-lock phase={phase} ms={} observer_pid={} trace_unavailable={error}",
                millis(),
                std::process::id()
            );
            None
        }
    }
}

/// Positive control only: the named child is synthetic and owned by this test.
pub(super) fn record_child(home: &Path, phase: &str, pid: u32) -> io::Result<(Snapshot, Vec<u32>)> {
    let state = snapshot(home)?;
    let child = child_fds(&state, pid)?;
    eprintln!(
        "supervisor-lock phase={phase} ms={} observer_pid={} dev={} ino={} holders={:?} self_fds={:?} synthetic_child_pid={pid} child_fds={child:?}",
        millis(),
        std::process::id(),
        state.dev,
        state.ino,
        state.holders,
        state.fds
    );
    Ok((state, child))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headless::{commands, local, service::ServiceBackend};
    use hraness_control_kit::{ErrorBody, ErrorCode};
    use std::{
        io::Read,
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };

    #[test]
    fn proc_lock_id_uses_hex_device_and_decimal_inode() {
        assert_eq!(lock_id("00:1a:12345"), Some((0, 26, 12345)));
        assert_eq!(lock_id("00:1a:bad"), None);
        assert_eq!(lock_id("00:1a:123:other"), None);
    }

    #[test]
    fn queued_lock_request_is_not_a_holder() {
        let id = (0, 26, 12345);
        assert_eq!(
            holder("1: FLOCK ADVISORY WRITE 4242 00:1a:12345 0 EOF", id),
            Some("FLOCK pid=4242".to_owned())
        );
        assert_eq!(
            holder("1: -> FLOCK ADVISORY WRITE 5252 00:1a:12345 0 EOF", id),
            None
        );
        assert_eq!(
            holder("2: FLOCK ADVISORY WRITE 4242 00:1a:12346 0 EOF", id),
            None
        );
        assert!(held_by(
            &Snapshot {
                dev: 0,
                ino: 12345,
                fds: vec![],
                holders: vec!["FLOCK pid=4242".into()],
            },
            4242
        ));
    }

    // A failed assertion must never strand a child holding the synthetic home.
    struct OwnedChild(Option<Child>);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    // This *controlled* refusal tests the observation path, not the cause of
    // the two spontaneous CI refusals (which have no matching inode trace).
    #[tokio::test]
    async fn synthetic_child_owner_fds_release_before_restart() {
        const CHILD_HOME: &str = "VHALLA_TEST_SYNTHETIC_LOCK_HOME";
        if let Some(path) = std::env::var_os(CHILD_HOME) {
            let home = Path::new(&path);
            let before = record(home, "synthetic-child-before-open").unwrap();
            assert!(before.fds.is_empty(), "inherited lock FD: {before:?}");
            assert!(
                before.holders.is_empty(),
                "lock held before child open: {before:?}"
            );
            let lock = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(home.join("control/supervisor.lock"))
                .unwrap();
            lock.lock().unwrap();
            let held = record(home, "synthetic-child-held").unwrap();
            assert_eq!((held.dev, held.ino), (before.dev, before.ino));
            assert!(held_by(&held, std::process::id()) && !held.fds.is_empty());
            // The parent closes our pipe only after observing its refusal.
            assert_eq!(std::io::stdin().read(&mut [0u8; 1]).unwrap(), 0);
            drop(lock);
            let released = record(home, "synthetic-child-released").unwrap();
            assert!(released.fds.is_empty() && released.holders.is_empty());
            return;
        }

        let root = tempfile::Builder::new()
            .prefix("vh-lock-")
            .tempdir_in("/tmp")
            .unwrap();
        let home = root.path().join("home");
        commands::execute(&["init".into(), "--home".into(), home.as_os_str().into()])
            .await
            .unwrap();
        let identity = fs::read(home.join("account/identity")).unwrap();
        let after_init = record(&home, "synthetic-after-init").unwrap();
        assert!(after_init.fds.is_empty() && after_init.holders.is_empty());
        assert!(!home.join("control/admin.cap").exists());

        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "headless::lock_trace::tests::synthetic_child_owner_fds_release_before_restart",
                "--nocapture",
            ])
            .env(CHILD_HOME, &home)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut child = OwnedChild(Some(child));
        let pid = child.0.as_ref().unwrap().id();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(Instant::now() < deadline, "child did not acquire lock");
            assert_eq!(child.0.as_mut().unwrap().try_wait().unwrap(), None);
            let state = snapshot(&home).unwrap();
            if held_by(&state, pid) && !child_fds(&state, pid).unwrap().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let (held, held_fds) = record_child(&home, "synthetic-child-confirmed", pid).unwrap();
        assert!(held_by(&held, pid) && !held_fds.is_empty() && held.fds.is_empty());
        assert_eq!((held.dev, held.ino), (after_init.dev, after_init.ino));

        let called = std::sync::atomic::AtomicBool::new(false);
        let refusal = local::serve_factory(
            &home,
            |_| async {
                called.store(true, std::sync::atomic::Ordering::SeqCst);
                Err::<local::Launch<ServiceBackend>, _>(ErrorBody::new(
                    ErrorCode::Internal,
                    "Factory entered despite a competing lock holder.",
                ))
            },
            async {},
        )
        .await
        .unwrap_err();
        let (refused, refused_fds) = record_child(&home, "synthetic-refused", pid).unwrap();
        assert_eq!(refusal.code, ErrorCode::ControlAlreadyRunning);
        assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!((refused.dev, refused.ino), (held.dev, held.ino));
        assert!(held_by(&refused, pid) && !refused_fds.is_empty());
        assert!(refused.fds.is_empty());
        assert_eq!(fs::read(home.join("account/identity")).unwrap(), identity);
        assert!(!home.join("control/admin.cap").exists());
        assert!(!home.join("control/admin.sock").exists());

        // EOF releases exactly this child; never signal another holder.
        drop(child.0.as_mut().unwrap().stdin.take());
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            assert!(Instant::now() < deadline, "child did not release lock");
            if let Some(status) = child.0.as_mut().unwrap().try_wait().unwrap() {
                break status;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(status.success(), "synthetic child failed: {status}");
        drop(child.0.take());
        let after_child = record(&home, "synthetic-child-exited").unwrap();
        assert_eq!((after_child.dev, after_child.ino), (held.dev, held.ino));
        assert!(after_child.fds.is_empty() && after_child.holders.is_empty());

        let restart_home = home.as_path();
        tokio::time::timeout(
            Duration::from_secs(20),
            local::serve_factory(
                &home,
                |generation| async move {
                    Ok(local::Launch {
                        backend: ServiceBackend::open(restart_home, generation).await?,
                        endpoint: None,
                    })
                },
                async {},
            ),
        )
        .await
        .unwrap()
        .unwrap();
        let restarted = record(&home, "synthetic-after-restart").unwrap();
        assert_eq!((restarted.dev, restarted.ino), (held.dev, held.ino));
        assert!(restarted.fds.is_empty() && restarted.holders.is_empty());
        assert_eq!(fs::read(home.join("account/identity")).unwrap(), identity);
        assert!(!home.join("control/admin.cap").exists());
    }
}
