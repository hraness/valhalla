//! Bounded local generator used only by the explicit history command.
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use valhalla_clankdar_attest_prototype::GeneratedInstance;

const OUTPUT_LIMIT: usize = 1024 * 1024;
const MAX_ORACLE_CALLS: usize = 1024;
const CACHE_LIMIT: usize = 8 * 1024 * 1024;
type InstanceKey = (String, String, u32, u64);

pub(super) struct LocalOracle {
    executable: PathBuf,
    directory: PathBuf,
    deadline: Instant,
    cache: RefCell<BTreeMap<InstanceKey, GeneratedInstance>>,
    cache_bytes: Cell<usize>,
    attempts: Cell<usize>,
}

impl LocalOracle {
    pub(super) fn new(executable: &Path, directory: &Path) -> Result<Self, String> {
        if !executable.is_absolute() || !executable.is_file() {
            return Err("--bun must name an installed absolute executable path".into());
        }
        let directory = directory
            .canonicalize()
            .map_err(|_| "cannot open selected Clankdar checkout")?;
        if !directory.join("bench/instance.ts").is_file() {
            return Err(
                "--clankdar must contain the locally trusted bench/instance.ts generator".into(),
            );
        }
        Ok(Self {
            executable: executable.into(),
            directory,
            deadline: Instant::now() + Duration::from_secs(120),
            cache: RefCell::new(BTreeMap::new()),
            cache_bytes: Cell::new(0),
            attempts: Cell::new(0),
        })
    }

    pub(super) fn instance(
        &self,
        suite: &str,
        family: &str,
        tier: u32,
        seed: u64,
    ) -> Result<GeneratedInstance, String> {
        // Time is checked before cache use: a caller cannot keep a job alive by
        // issuing repeated cached requests after its total replay budget.
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("history replay deadline exceeded".into());
        }
        let key = (suite.to_owned(), family.to_owned(), tier, seed);
        if let Some(instance) = self.cache.borrow().get(&key) {
            return Ok(instance.clone());
        }
        if self.attempts.get() >= MAX_ORACLE_CALLS {
            return Err("history replay instance budget exceeded".into());
        }
        self.attempts.set(self.attempts.get() + 1);
        let mut command = Command::new(&self.executable);
        command
            .env_clear()
            .current_dir(&self.directory)
            .args([
                "bench/instance.ts",
                "--suite-version",
                suite,
                "--family",
                family,
                "--tier",
                &tier.to_string(),
                "--seed",
                &seed.to_string(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let bytes = collect(command, remaining.min(Duration::from_secs(30)))?;
        let instance: GeneratedInstance = serde_json::from_slice(&bytes)
            .map_err(|_| "local generator returned malformed bounded JSON")?;
        if instance.suite_version != suite
            || instance.family != family
            || instance.tier != tier
            || instance.seed != seed
        {
            return Err("local generator returned a different puzzle instance".into());
        }
        let retained = self
            .cache_bytes
            .get()
            .checked_add(bytes.len())
            .filter(|size| *size <= CACHE_LIMIT)
            .ok_or("history replay cache exceeded 8 MiB")?;
        self.cache_bytes.set(retained);
        self.cache.borrow_mut().insert(key, instance.clone());
        Ok(instance)
    }
}

// Retain the child until group cleanup so its process ID cannot be reused.
#[cfg(unix)]
struct ChildGroup(Option<std::process::Child>);
#[cfg(unix)]
impl ChildGroup {
    fn exited(&self) -> Result<bool, String> {
        let child = self.0.as_ref().ok_or("local generator already reaped")?;
        // SAFETY: waitid initializes this siginfo_t and selects only our child.
        // WNOWAIT observes exit without releasing the retained process ID.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                child.id() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err("local generator process check failed".into());
        }
        // SAFETY: si_pid is valid for the initialized child-status siginfo_t.
        Ok(unsafe { info.si_pid() } != 0)
    }
    fn finish(&mut self) -> Result<std::process::ExitStatus, String> {
        let mut child = self.0.take().ok_or("local generator already reaped")?;
        let group = i32::try_from(child.id()).map_err(|_| "invalid generator process group")?;
        // SAFETY: process_group(0) made this child's own group. We have not
        // reaped the child, so its group ID cannot have been reused.
        unsafe { libc::kill(-group, libc::SIGKILL) };
        child
            .wait()
            .map_err(|_| "could not reap local generator".into())
    }
}
#[cfg(unix)]
impl Drop for ChildGroup {
    fn drop(&mut self) {
        if self.0.is_some() {
            let _ = self.finish();
        }
    }
}

#[cfg(unix)]
fn collect(mut command: Command, remaining: Duration) -> Result<Vec<u8>, String> {
    use std::os::{fd::AsRawFd, unix::process::CommandExt};
    let deadline = Instant::now() + remaining;
    command.process_group(0);
    let child = command
        .spawn()
        .map_err(|_| "could not start selected local generator")?;
    let mut owner = ChildGroup(Some(child));
    let mut stdout = owner
        .0
        .as_mut()
        .and_then(|child| child.stdout.take())
        .ok_or("local generator output pipe missing")?;
    let fd = stdout.as_raw_fd();
    // SAFETY: stdout owns this live pipe descriptor throughout the read loop.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err("could not bound local generator output reads".into());
    }
    let mut bytes = Vec::new();
    let mut eof = false;
    let result = 'poll: loop {
        if Instant::now() >= deadline {
            break Err("local generator deadline exceeded".to_owned());
        }
        if !eof {
            let mut buffer = [0; 8192];
            loop {
                match stdout.read(&mut buffer) {
                    Ok(0) => {
                        eof = true;
                        break;
                    }
                    Ok(count) => {
                        if bytes.len() + count > OUTPUT_LIMIT {
                            break 'poll Err("local generator output exceeded 1 MiB".into());
                        }
                        bytes.extend_from_slice(&buffer[..count]);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => break,
                    Err(_) => break 'poll Err("local generator output failed".into()),
                }
            }
        }
        match owner.exited() {
            Ok(true) if eof => break Ok(()),
            Ok(_) => {}
            Err(error) => break Err(error),
        }
        std::thread::sleep(
            Duration::from_millis(5).min(deadline.saturating_duration_since(Instant::now())),
        );
    };
    // No reader thread or blocking join survives a timeout. Group cleanup is
    // not a sandbox for the explicitly selected, trusted local program.
    let status = owner.finish();
    result?;
    if !status?.success() {
        return Err("local generator refused this puzzle or was unavailable".into());
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn collect(_command: Command, _remaining: Duration) -> Result<Vec<u8>, String> {
    Err("bounded history generator execution currently requires Unix".into())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    fn shell(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        command
    }
    #[test]
    fn deadline_kills_and_reaps_generator_before_returning() {
        let start = Instant::now();
        assert!(collect(shell("exec sleep 30"), Duration::from_millis(50))
            .unwrap_err()
            .contains("deadline"));
        assert!(start.elapsed() < Duration::from_secs(5));
    }
    #[test]
    fn inherited_stdout_cannot_outlive_the_deadline() {
        let start = Instant::now();
        assert!(
            collect(shell("sleep 30 & exit 0"), Duration::from_millis(50))
                .unwrap_err()
                .contains("deadline")
        );
        assert!(start.elapsed() < Duration::from_secs(5));
    }
    #[test]
    fn closed_stdout_does_not_hide_a_live_generator() {
        let start = Instant::now();
        assert!(
            collect(shell("exec 1>&-; exec sleep 30"), Duration::from_millis(50))
                .unwrap_err()
                .contains("deadline")
        );
        assert!(start.elapsed() < Duration::from_secs(5));
    }
    #[test]
    fn output_is_bounded_even_when_child_exits_successfully() {
        assert!(
            collect(shell("exec /usr/bin/yes x"), Duration::from_secs(3))
                .unwrap_err()
                .contains("exceeded")
        );
        assert_eq!(
            collect(shell("printf 'bounded'"), Duration::from_secs(3)).unwrap(),
            b"bounded"
        );
    }
}
