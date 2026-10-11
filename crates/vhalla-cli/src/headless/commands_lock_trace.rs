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

fn snapshot(home: &Path) -> io::Result<Snapshot> {
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
    // Inspect only our own descriptors and compare fstat identities, not names.
    // The iterator's own directory descriptor can disappear mid-scan; it is
    // unrelated to this regular-file inode and need not be kept open.
    let mut fds = Vec::new();
    for (index, entry) in fs::read_dir("/proc/self/fd")?.enumerate() {
        if index == 4_096 {
            return Err(io::Error::other("/proc/self/fd scan exceeded 4096 entries"));
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
    Ok(Snapshot {
        dev,
        ino,
        fds,
        holders,
    })
}

/// A bounded snapshot, not a global proof that an absent lock cannot exist in
/// another PID namespace. The refusal snapshot is taken just after try_lock.
pub(super) fn record(home: &Path, phase: &str) -> Option<Snapshot> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());
    match snapshot(home) {
        Ok(state) => {
            eprintln!(
                "supervisor-lock phase={phase} ms={millis} observer_pid={} dev={} ino={} holders={:?} self_fds={:?}",
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
                "supervisor-lock phase={phase} ms={millis} observer_pid={} trace_unavailable={error}",
                std::process::id()
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
