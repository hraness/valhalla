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

fn fd_matches(metadata: io::Result<fs::Metadata>, dev: u64, ino: u64) -> io::Result<bool> {
    match metadata {
        Ok(fd_meta) => Ok(fd_meta.dev() == dev && fd_meta.ino() == ino),
        // An FD may close between read_dir and metadata. Other errors are
        // missing evidence, not proof that no matching FD exists.
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
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
            if fd_matches(fs::metadata(entry.path()), dev, ino)? {
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

// This observer only runs in the missing-state test. The old refusals were at
// the first init -> run boundary; a post-refusal snapshot can miss a short-lived
// holder. Sample the exact home concurrently, without acquiring the lock or
// reading any capability. Procfs reads are not atomic: this is a timeline to
// investigate, never proof that an absent holder could not have existed.
#[derive(Default)]
struct Timeline {
    previous: Option<String>,
    changes: std::collections::VecDeque<String>,
    discarded: usize,
    samples: usize,
    first_run_samples: usize,
    exhausted: bool,
}

impl Timeline {
    const MAX_CHANGES: usize = 32;
    const MAX_SAMPLES: usize = 2_048;
    fn push(&mut self, state: String, first_run: bool) {
        self.samples += 1;
        self.first_run_samples += usize::from(first_run);
        // Deduplicate within a phase, not across its boundary. A first-run
        // sample needs its own timestamp even if the lock state never changed.
        // The phase is read before the non-atomic procfs snapshot begins.
        let phase = if first_run { "first-run" } else { "pre-run" };
        let observation = format!("phase={phase} {state}");
        if self.previous.as_deref() == Some(&observation) {
            return;
        }
        self.previous = Some(observation.clone());
        if self.changes.len() == Self::MAX_CHANGES {
            self.changes.pop_front();
            self.discarded += 1;
        }
        self.changes
            .push_back(format!("ms={} {observation}", millis()));
    }
}

pub(super) struct FirstRunObserver {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    first_run: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<Timeline>>,
}

impl FirstRunObserver {
    pub(super) fn start(home: &Path) -> io::Result<Self> {
        Self::start_with_budget(home, Timeline::MAX_SAMPLES)
    }

    fn start_with_budget(home: &Path, max_samples: usize) -> io::Result<Self> {
        assert!((1..=Timeline::MAX_SAMPLES).contains(&max_samples));
        use std::{
            sync::{atomic::Ordering, mpsc, Arc},
            thread,
            time::Duration,
        };
        let home = home.to_path_buf();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let first_run = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (started, ready) = mpsc::sync_channel(1);
        let observer_stop = Arc::clone(&stop);
        let observer_first_run = Arc::clone(&first_run);
        let worker = thread::Builder::new()
            .name("supervisor-lock-observer".into())
            .spawn(move || {
                let mut timeline = Timeline::default();
                // Even if the caller stalls, bound all sampling and history.
                for _ in 0..max_samples {
                    if observer_stop.load(Ordering::Acquire) {
                        break;
                    }
                    // A sample before the caller enters the first run does
                    // not cover its lock attempt, even if it saw an owner.
                    let during_first_run = observer_first_run.load(Ordering::Acquire);
                    let state = match snapshot(&home) {
                        Ok(state) => format!(
                            "dev={} ino={} holders={:?} self_fds={:?}",
                            state.dev, state.ino, state.holders, state.fds
                        ),
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {
                            "lock_missing".to_owned()
                        }
                        Err(error) => format!("trace_unavailable={error}"),
                    };
                    timeline.push(state, during_first_run);
                    if timeline.samples == 1 {
                        let _ = started.send(());
                    }
                    if timeline.samples == max_samples {
                        timeline.exhausted = true;
                        break;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                timeline
            })?;
        let observer = Self {
            stop,
            first_run,
            thread: Some(worker),
        };
        if ready.recv_timeout(Duration::from_secs(10)).is_err() {
            // Drop joins the exact observer before reporting a startup error.
            drop(observer);
            return Err(io::Error::other("lock observer did not start"));
        }
        Ok(observer)
    }

    pub(super) fn mark_first_run_started(&self) {
        use std::sync::atomic::Ordering;
        self.first_run.store(true, Ordering::Release);
    }

    fn stop_and_report(&mut self, report: bool) -> Option<Timeline> {
        use std::sync::atomic::Ordering;
        self.stop.store(true, Ordering::Release);
        let worker = self.thread.take()?;
        match worker.join() {
            Ok(timeline) => {
                // A green run with no first-run samples, or an exhausted
                // sampling budget, cannot be read as an absence of holders.
                if report || timeline.exhausted || timeline.first_run_samples == 0 {
                    eprintln!(
                        "supervisor-lock phase=first-run-timeline observer_pid={} samples={} first_run_samples={} sampling_exhausted={} no_first_run_sample={} discarded={} (non-atomic procfs samples)",
                        std::process::id(),
                        timeline.samples,
                        timeline.first_run_samples,
                        timeline.exhausted,
                        timeline.first_run_samples == 0,
                        timeline.discarded
                    );
                    for entry in &timeline.changes {
                        eprintln!("supervisor-lock phase=first-run-sample {entry}");
                    }
                }
                Some(timeline)
            }
            Err(_) => {
                eprintln!(
                    "supervisor-lock phase=first-run-timeline trace_unavailable=observer-panicked"
                );
                None
            }
        }
    }

    pub(super) fn finish(mut self, refusal: bool) {
        let _ = self.stop_and_report(refusal);
    }
}

impl Drop for FirstRunObserver {
    fn drop(&mut self) {
        let _ = self.stop_and_report(std::thread::panicking());
    }
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

    #[test]
    fn unreadable_fd_is_not_an_empty_observation() {
        assert!(!fd_matches(Err(io::Error::from(io::ErrorKind::NotFound)), 0, 0).unwrap());
        assert_eq!(
            fd_matches(Err(io::Error::from(io::ErrorKind::PermissionDenied)), 0, 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn first_run_timeline_is_bounded_and_keeps_only_distinct_recent_states() {
        let mut timeline = Timeline::default();
        timeline.push("lock_missing".into(), false);
        timeline.push("lock_missing".into(), false);
        for ino in 0..Timeline::MAX_CHANGES {
            timeline.push(format!("dev=2049 ino={ino} holders=[] self_fds=[]"), true);
        }
        assert_eq!(timeline.samples, Timeline::MAX_CHANGES + 2);
        assert_eq!(timeline.first_run_samples, Timeline::MAX_CHANGES);
        assert_eq!(timeline.discarded, 1);
        assert_eq!(timeline.changes.len(), Timeline::MAX_CHANGES);
        assert!(!timeline.changes.front().unwrap().contains("lock_missing"));
        assert!(timeline.changes.back().unwrap().contains("ino=31 "));
    }

    #[test]
    fn first_run_timeline_marks_phase_even_when_lock_state_is_unchanged() {
        let mut timeline = Timeline::default();
        let state = "dev=2049 ino=42 holders=[] self_fds=[]";
        timeline.push(state.into(), false);
        timeline.push(state.into(), false);
        timeline.push(state.into(), true);
        timeline.push(state.into(), true);
        assert_eq!(timeline.samples, 4);
        assert_eq!(timeline.first_run_samples, 2);
        assert_eq!(timeline.changes.len(), 2);
        assert!(timeline.changes[0].starts_with("ms="));
        assert!(timeline.changes[0].contains(&format!(" phase=pre-run {state}")));
        assert!(timeline.changes[1].starts_with("ms="));
        assert!(timeline.changes[1].contains(&format!(" phase=first-run {state}")));
    }

    // A small test budget reproduces an init -> run gap that outlives the
    // observer, without waiting through the full 2,048-sample cap. The run
    // still uses the real lock path; this is not a spontaneous refusal.
    #[tokio::test]
    async fn post_init_observer_reports_exhaustion_before_first_run() {
        let root = tempfile::Builder::new()
            .prefix("vh-lock-")
            .tempdir_in("/tmp")
            .unwrap();
        let home = root.path().join("home");
        commands::execute(&["init".into(), "--home".into(), home.as_os_str().into()])
            .await
            .unwrap();
        let after_init = record(&home, "exhaustion-after-init").unwrap();
        assert!(after_init.fds.is_empty() && after_init.holders.is_empty());

        let mut observer = FirstRunObserver::start_with_budget(&home, 1).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !observer.thread.as_ref().unwrap().is_finished() {
            assert!(
                Instant::now() < deadline,
                "observer did not exhaust its budget"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        observer.mark_first_run_started();
        let run_home = home.as_path();
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            local::serve_factory(
                &home,
                |generation| async move {
                    Ok(local::Launch {
                        backend: ServiceBackend::open(run_home, generation).await?,
                        endpoint: None,
                    })
                },
                async {},
            ),
        )
        .await
        .expect("first run timed out");
        if result.is_err() {
            let _ = record(&home, "exhaustion-run-refused");
        }
        let timeline = observer.stop_and_report(result.is_err()).unwrap();
        assert_eq!(timeline.samples, 1);
        assert_eq!(timeline.first_run_samples, 0);
        assert!(timeline.exhausted);
        result.unwrap();
        let after_run = record(&home, "exhaustion-after-run").unwrap();
        assert_eq!(
            (after_run.dev, after_run.ino),
            (after_init.dev, after_init.ino)
        );
        assert!(after_run.fds.is_empty() && after_run.holders.is_empty());
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
