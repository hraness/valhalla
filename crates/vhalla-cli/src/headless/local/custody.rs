//! Exclusive local endpoint custody. No process is signalled from disk metadata.
//! Linux requires procfs at `/proc` to restrict a pinned socket inode safely.

use super::{Channel, AGENT_PROTOCOL};
use hraness_control_kit::{
    control::{OwnerInfo, OwnerPaths, CONTROL_PROTOCOL},
    ErrorBody, ErrorCode,
};
use rustix::fs::{self as rfs, AtFlags, FileType, Mode, OFlags, Stat};
use std::{
    fs::{File, TryLockError},
    io::Write,
    os::unix::{fs::FileExt, net::UnixListener as StdListener},
    path::Path,
};
use tokio::net::UnixListener;
use vhalla_custody::{self as local, Owner};

const MAX_FILES: usize = 64;
const MAX_METADATA_BYTES: usize = 16 * 1024;
const CAP_BYTES: usize = 64;
const SOCKET_NAMES: [&str; 2] = ["admin.sock", "agent.sock"];
const REQUIRED_NAMES: [&str; 4] = ["supervisor.lock", "admin.cap", "admin.sock", "agent.sock"];
const OPEN_FLAGS: OFlags = OFlags::NOFOLLOW
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);

fn refused() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::PermissionDenied,
        "The service home is unsafe or has changed.",
    )
}

fn failed() -> ErrorBody {
    ErrorBody::new(
        ErrorCode::Internal,
        "Could not initialize the service endpoints.",
    )
}

fn same(first: &Stat, second: &Stat) -> bool {
    first.st_dev == second.st_dev && first.st_ino == second.st_ino
}

fn stat(directory: &File, name: &str) -> Result<Stat, ErrorBody> {
    rfs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| refused())
}

fn private_stat(metadata: &Stat, kind: FileType, mode: rfs::RawMode) -> Result<(), ErrorBody> {
    if FileType::from_raw_mode(metadata.st_mode) != kind
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode & 0o7777 != mode
        || (kind != FileType::Directory && metadata.st_nlink != 1)
    {
        return Err(refused());
    }
    Ok(())
}

fn named(directory: &File, name: &str, file: &File) -> Result<(), ErrorBody> {
    if !same(
        &stat(directory, name)?,
        &rfs::fstat(file).map_err(|_| refused())?,
    ) {
        return Err(refused());
    }
    Ok(())
}

fn directory_at(parent: &File, name: &str) -> Result<File, ErrorBody> {
    let file = File::from(
        rfs::openat(
            parent,
            name,
            OPEN_FLAGS | OFlags::DIRECTORY | OFlags::RDONLY,
            Mode::empty(),
        )
        .map_err(|_| refused())?,
    );
    private_stat(
        &rfs::fstat(&file).map_err(|_| refused())?,
        FileType::Directory,
        0o700,
    )?;
    named(parent, name, &file)?;
    Ok(file)
}

fn regular_at(
    directory: &File,
    name: &str,
    owner: Owner,
    max_bytes: usize,
    create: bool,
) -> Result<File, ErrorBody> {
    let flags = OPEN_FLAGS | if create { OFlags::RDWR } else { OFlags::RDONLY };
    let opened = rfs::openat(directory, name, flags, Mode::empty());
    let descriptor = match opened {
        Ok(file) => file,
        Err(rustix::io::Errno::NOENT) if create => {
            match rfs::openat(
                directory,
                name,
                flags | OFlags::CREATE | OFlags::EXCL,
                Mode::from_raw_mode(0o600),
            ) {
                Ok(file) => file,
                // A concurrent starter may have installed the same empty lock.
                Err(rustix::io::Errno::EXIST) => {
                    rfs::openat(directory, name, flags, Mode::empty()).map_err(|_| refused())?
                }
                Err(_) => return Err(failed()),
            }
        }
        Err(_) => return Err(refused()),
    };
    let file = File::from(descriptor);
    local::check_regular_file(
        Path::new(name),
        &file.metadata().map_err(|_| refused())?,
        owner,
        max_bytes,
    )
    .map_err(|_| refused())?;
    named(directory, name, &file)?;
    Ok(file)
}

fn legacy_temporary(name: &str) -> bool {
    ["admin.tmp-", "owner.tmp-"].iter().any(|prefix| {
        name.strip_prefix(prefix).is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
    })
}

fn scan(directory: &File, owner: Owner) -> Result<(), ErrorBody> {
    let entries = rfs::Dir::read_from(directory).map_err(|_| refused())?;
    let mut count = 0;
    let mut present = [false; REQUIRED_NAMES.len()];
    for entry in entries {
        let entry = entry.map_err(|_| refused())?;
        let name = entry.file_name().to_str().map_err(|_| refused())?;
        if matches!(name, "." | "..") {
            continue;
        }
        count += 1;
        if count > MAX_FILES {
            return Err(refused());
        }
        if let Some(index) = REQUIRED_NAMES.iter().position(|required| *required == name) {
            present[index] = true;
        }
        match name {
            "supervisor.lock" => {
                regular_at(directory, name, owner, 0, false)?;
            }
            "admin.cap" | "owner.json" => {
                regular_at(directory, name, owner, MAX_METADATA_BYTES, false)?;
            }
            "admin.sock" | "agent.sock" => {
                private_stat(&stat(directory, name)?, FileType::Socket, 0o600)?
            }
            _ if legacy_temporary(name) => {
                regular_at(directory, name, owner, MAX_METADATA_BYTES, false)?;
            }
            _ => return Err(refused()),
        }
    }
    // Startup must fit its own files as well as every preserved legacy file.
    // Count existing endpoints once so a fully occupied valid home can reopen.
    if count + present.iter().filter(|exists| !**exists).count() > MAX_FILES {
        return Err(refused());
    }
    Ok(())
}

fn home_matches(paths: &OwnerPaths, home: &File, owner: Owner) -> Result<(), ErrorBody> {
    let (current, found) =
        local::open_private_directory(&paths.state_home).map_err(|_| refused())?;
    if found != owner
        || Owner::current().map_err(|_| refused())? != owner
        || !local::same_open_file(&current, home).map_err(|_| refused())?
    {
        return Err(refused());
    }
    Ok(())
}

fn control_matches(
    paths: &OwnerPaths,
    home: &File,
    directory: &File,
    owner: Owner,
) -> Result<(), ErrorBody> {
    home_matches(paths, home, owner)?;
    private_stat(
        &rfs::fstat(directory).map_err(|_| refused())?,
        FileType::Directory,
        0o700,
    )?;
    named(home, "control", directory)?;
    Ok(())
}

/// Read-only bounded inspection; old control-kit temporaries remain untouched.
pub(super) fn preflight(home: &Path) -> Result<OwnerPaths, ErrorBody> {
    let paths = OwnerPaths::in_state_home(local::absolute(home).map_err(|_| refused())?);
    let (home, owner) = local::open_private_directory(&paths.state_home).map_err(|_| refused())?;
    home_matches(&paths, &home, owner)?;
    match rfs::statat(&home, "control", AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => return Ok(paths),
        Err(_) => return Err(refused()),
        Ok(_) => {}
    }
    let directory = directory_at(&home, "control")?;
    scan(&directory, owner)?;
    control_matches(&paths, &home, &directory, owner)?;
    Ok(paths)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}

/// The runtime retains this guard until its backend and transport work end.
pub(super) struct Guard {
    paths: OwnerPaths,
    info: OwnerInfo,
    owner: Owner,
    cap_text: String,
    home: File,
    directory: File,
    cap: File,
    sockets: [Option<Stat>; 2],
    // The exclusive lock is released last, after conditional cleanup and FDs.
    lock: File,
}

impl Guard {
    pub(super) fn acquire(home: &Path) -> Result<Self, ErrorBody> {
        let paths = preflight(home)?;
        let (home, owner) =
            local::open_private_directory(&paths.state_home).map_err(|_| refused())?;
        match rfs::mkdirat(&home, "control", Mode::from_raw_mode(0o700)) {
            Ok(()) => home.sync_all().map_err(|_| failed())?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err(failed()),
        }
        let directory = directory_at(&home, "control")?;
        control_matches(&paths, &home, &directory, owner)?;
        scan(&directory, owner)?;
        let lock = regular_at(&directory, "supervisor.lock", owner, 0, true)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(ErrorBody::new(
                    ErrorCode::ControlAlreadyRunning,
                    "Another service owns this home.",
                ))
            }
            Err(TryLockError::Error(_)) => return Err(failed()),
        }
        control_matches(&paths, &home, &directory, owner)?;
        named(&directory, "supervisor.lock", &lock)?;
        scan(&directory, owner)?;
        let mut cap = regular_at(&directory, "admin.cap", owner, MAX_METADATA_BYTES, true)?;
        let mut random = [0; 64];
        getrandom::fill(&mut random).map_err(|_| failed())?;
        if random[32..] == [0; 32] {
            return Err(failed());
        }
        let cap_text = hex(&random[..32]);
        let generation = hex(&random[32..]);
        control_matches(&paths, &home, &directory, owner)?;
        named(&directory, "supervisor.lock", &lock)?;
        named(&directory, "admin.cap", &cap)?;
        // Updating the exact held inode permits recovery after an interrupted
        // write. There is no rename temporary and no write through a new path.
        cap.set_len(0).map_err(|_| failed())?;
        cap.write_all(cap_text.as_bytes()).map_err(|_| failed())?;
        cap.sync_all().map_err(|_| failed())?;
        directory.sync_all().map_err(|_| failed())?;
        let mut protocols = vec![AGENT_PROTOCOL.to_owned(), CONTROL_PROTOCOL.to_owned()];
        protocols.sort();
        let guard = Self {
            paths,
            owner,
            cap_text,
            home,
            directory,
            cap,
            lock,
            info: OwnerInfo {
                product: "valhalla".to_owned(),
                pid: std::process::id(),
                generation,
                protocols,
            },
            sockets: [None, None],
        };
        guard.check()?;
        Ok(guard)
    }

    fn namespace(&self) -> Result<(), ErrorBody> {
        control_matches(&self.paths, &self.home, &self.directory, self.owner)?;
        local::check_regular_file(
            &self.paths.lock,
            &self.lock.metadata().map_err(|_| refused())?,
            self.owner,
            0,
        )
        .map_err(|_| refused())?;
        named(&self.directory, "supervisor.lock", &self.lock)
    }

    pub(super) fn check(&self) -> Result<(), ErrorBody> {
        self.namespace()?;
        local::check_regular_file(
            &self.paths.cap,
            &self.cap.metadata().map_err(|_| refused())?,
            self.owner,
            CAP_BYTES,
        )
        .map_err(|_| refused())?;
        named(&self.directory, "admin.cap", &self.cap)?;
        let mut cap = [0; CAP_BYTES];
        self.cap.read_exact_at(&mut cap, 0).map_err(|_| refused())?;
        if cap.as_slice() != self.cap_text.as_bytes() {
            return Err(refused());
        }
        for (index, expected) in self.sockets.iter().enumerate() {
            if let Some(expected) = expected {
                let current = stat(&self.directory, SOCKET_NAMES[index])?;
                private_stat(&current, FileType::Socket, 0o600)?;
                if !same(&current, expected) {
                    return Err(refused());
                }
            }
        }
        self.namespace()
    }

    #[cfg(test)]
    pub(super) fn paths(&self) -> &OwnerPaths {
        &self.paths
    }
    pub(super) fn info(&self) -> &OwnerInfo {
        &self.info
    }

    pub(super) fn accepts_cap(&self, cap: &str) -> bool {
        cap.len() == self.cap_text.len()
            && cap
                .bytes()
                .zip(self.cap_text.bytes())
                .fold(0u8, |difference, (a, b)| difference | (a ^ b))
                == 0
    }

    pub(super) fn bind(&mut self, channel: Channel) -> Result<UnixListener, ErrorBody> {
        self.check()?;
        scan(&self.directory, self.owner)?;
        let index = match channel {
            Channel::Admin => 0,
            Channel::Agent => 1,
        };
        let name = SOCKET_NAMES[index];
        if self.sockets[index].is_some() {
            return Err(failed());
        }
        match rfs::statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            Err(_) => return Err(refused()),
            Ok(old) => {
                private_stat(&old, FileType::Socket, 0o600)?;
                self.namespace()?;
                if !same(&stat(&self.directory, name)?, &old) {
                    return Err(refused());
                }
                rfs::unlinkat(&self.directory, name, AtFlags::empty()).map_err(|_| failed())?;
            }
        }
        self.check()?;
        let path = self.paths.dir.join(name);
        let listener = StdListener::bind(&path).map_err(|_| failed())?;
        self.namespace()?;
        let created = stat(&self.directory, name)?;
        if FileType::from_raw_mode(created.st_mode) != FileType::Socket
            || created.st_uid != rustix::process::geteuid().as_raw()
            || created.st_nlink != 1
        {
            return Err(refused());
        }
        self.sockets[index] = Some(created);
        socket_mode(&self.directory, name, &created)?;
        self.check()?;
        listener.set_nonblocking(true).map_err(|_| failed())?;
        UnixListener::from_std(listener).map_err(|_| failed())
    }
}

#[cfg(not(target_os = "linux"))]
fn socket_mode(directory: &File, name: &str, expected: &Stat) -> Result<(), ErrorBody> {
    if !same(&stat(directory, name)?, expected) {
        return Err(refused());
    }
    rfs::chmodat(
        directory,
        name,
        Mode::from_raw_mode(0o600),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|_| failed())?;
    if !same(&stat(directory, name)?, expected) {
        return Err(refused());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn socket_mode(directory: &File, name: &str, expected: &Stat) -> Result<(), ErrorBody> {
    use std::os::fd::AsRawFd;
    // Linux fchmod does not accept O_PATH, and rustix's fchmodat has no safe
    // no-follow implementation there. Pin the socket inode and use the kernel's
    // procfs FD link, never a possibly replaced socket pathname.
    let socket = File::from(
        rfs::openat(
            directory,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| refused())?,
    );
    if !same(&rfs::fstat(&socket).map_err(|_| refused())?, expected) {
        return Err(refused());
    }
    let proc = File::open("/proc/self/fd").map_err(|_| failed())?;
    if rfs::fstatfs(&proc).map_err(|_| failed())?.f_type != rfs::PROC_SUPER_MAGIC {
        return Err(refused());
    }
    let name_in_proc = socket.as_raw_fd().to_string();
    let pinned =
        rfs::statat(&proc, name_in_proc.as_str(), AtFlags::empty()).map_err(|_| refused())?;
    if !same(&pinned, expected) {
        return Err(refused());
    }
    rfs::chmodat(
        &proc,
        name_in_proc.as_str(),
        Mode::from_raw_mode(0o600),
        AtFlags::empty(),
    )
    .map_err(|_| failed())?;
    if !same(&stat(directory, name)?, expected) {
        return Err(refused());
    }
    Ok(())
}

impl Drop for Guard {
    fn drop(&mut self) {
        // Never traverse a replacement home/control directory or lock. Unknown
        // files, legacy temporaries, old owner.json and the lock are preserved.
        if self.namespace().is_err() {
            return;
        }
        for (index, expected) in self.sockets.iter().enumerate() {
            if let Some(expected) = expected {
                let name = SOCKET_NAMES[index];
                if self.namespace().is_ok()
                    && stat(&self.directory, name).is_ok_and(|current| {
                        same(&current, expected)
                            && FileType::from_raw_mode(current.st_mode) == FileType::Socket
                            && current.st_uid == rustix::process::geteuid().as_raw()
                            && current.st_nlink == 1
                    })
                {
                    let _ = rfs::unlinkat(&self.directory, name, AtFlags::empty());
                }
            }
        }
        if self.namespace().is_ok()
            && named(&self.directory, "admin.cap", &self.cap).is_ok()
            && self.cap.metadata().is_ok_and(|metadata| {
                local::check_regular_file(&self.paths.cap, &metadata, self.owner, CAP_BYTES).is_ok()
            })
        {
            let _ = rfs::unlinkat(&self.directory, "admin.cap", AtFlags::empty());
        }
        let _ = self.directory.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, MetadataExt, PermissionsExt},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            // Keep even nested test socket paths below macOS's address bound.
            let path = PathBuf::from("/tmp").join(format!(
                "vhic-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            drop(local::create_private_directory(&path).unwrap());
            drop(local::create_private_directory(&path.join("home")).unwrap());
            Self(path)
        }
        fn home(&self) -> PathBuf {
            self.0.join("home")
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn private_file(path: &Path, bytes: &[u8]) {
        local::create_private_file(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

    #[test]
    fn competing_owner_cannot_rotate_cap_and_last_drop_releases_custody() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<Guard>();
        let temp = Temp::new();
        let guard = Guard::acquire(&temp.home()).unwrap();
        let cap = fs::read_to_string(&guard.paths().cap).unwrap();
        assert!(guard.accepts_cap(&cap));
        assert!(!guard.accepts_cap(&cap[..63]));
        let mut changed = cap.clone();
        changed.replace_range(..1, if cap.starts_with('0') { "1" } else { "0" });
        assert!(!guard.accepts_cap(&changed));
        assert_eq!(guard.info().pid, std::process::id());
        assert_eq!(
            guard.info().protocols,
            vec![CONTROL_PROTOCOL, AGENT_PROTOCOL]
        );
        assert!(
            matches!(Guard::acquire(&temp.home()), Err(error) if error.code == ErrorCode::ControlAlreadyRunning)
        );
        assert!(fs::read_to_string(&guard.paths().cap).unwrap() == cap);
        guard.check().unwrap();
        let paths = guard.paths().clone();
        let generation = guard.info().generation.clone();
        let hold = std::sync::Arc::new(guard);
        let survivor = hold.clone();
        drop(hold);
        assert!(Guard::acquire(&temp.home()).is_err());
        drop(survivor);
        assert!(!paths.cap.exists());
        assert!(paths.lock.exists());
        let reopened = Guard::acquire(&temp.home()).unwrap();
        assert_ne!(reopened.info().generation, generation);
        assert!(!reopened.accepts_cap(&cap));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sockets_are_private_and_replaced_socket_is_never_removed() {
        let temp = Temp::new();
        let mut guard = Guard::acquire(&temp.home()).unwrap();
        let admin = guard.bind(Channel::Admin).unwrap();
        let agent = guard.bind(Channel::Agent).unwrap();
        let paths = guard.paths().clone();
        for path in [&paths.admin_sock, &paths.agent_sock] {
            let metadata = fs::symlink_metadata(path).unwrap();
            assert_eq!(metadata.mode() & 0o7777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
        assert!(guard.bind(Channel::Agent).is_err());
        guard.check().unwrap();
        fs::rename(&paths.agent_sock, temp.0.join("moved.sock")).unwrap();
        let replacement = StdListener::bind(&paths.agent_sock).unwrap();
        fs::set_permissions(&paths.agent_sock, fs::Permissions::from_mode(0o600)).unwrap();
        let replacement_inode = fs::symlink_metadata(&paths.agent_sock).unwrap().ino();
        assert!(guard.check().is_err());
        drop(admin);
        drop(agent);
        drop(guard);
        assert!(!paths.admin_sock.exists());
        assert!(!paths.cap.exists());
        assert_eq!(
            fs::symlink_metadata(&paths.agent_sock).unwrap().ino(),
            replacement_inode
        );
        assert!(temp.0.join("moved.sock").exists());
        drop(replacement);
    }

    #[test]
    fn replacement_cap_is_preserved_and_in_place_changes_refuse() {
        let temp = Temp::new();
        let guard = Guard::acquire(&temp.home()).unwrap();
        let cap = guard.paths().cap.clone();
        fs::write(&cap, b"partial overwrite").unwrap();
        assert!(guard.check().is_err());
        fs::rename(&cap, temp.0.join("old-cap")).unwrap();
        private_file(&cap, b"replacement must remain");
        drop(guard);
        assert_eq!(fs::read(&cap).unwrap(), b"replacement must remain");
        assert_eq!(
            fs::read(temp.0.join("old-cap")).unwrap(),
            b"partial overwrite"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn replacement_home_control_or_lock_disables_all_cleanup() {
        for changed in ["home", "control", "lock"] {
            let temp = Temp::new();
            let mut guard = Guard::acquire(&temp.home()).unwrap();
            let listener = guard.bind(Channel::Agent).unwrap();
            let paths = guard.paths().clone();
            let old_control = match changed {
                "home" => {
                    let moved = temp.0.join("old-home");
                    fs::rename(temp.home(), &moved).unwrap();
                    drop(local::create_private_directory(&temp.home()).unwrap());
                    drop(local::create_private_directory(&paths.dir).unwrap());
                    moved.join("control")
                }
                "control" => {
                    let moved = temp.0.join("old-control");
                    fs::rename(&paths.dir, &moved).unwrap();
                    drop(local::create_private_directory(&paths.dir).unwrap());
                    moved
                }
                "lock" => {
                    fs::rename(&paths.lock, temp.0.join("old-lock")).unwrap();
                    private_file(&paths.lock, b"");
                    paths.dir.clone()
                }
                _ => unreachable!(),
            };
            if changed != "lock" {
                private_file(&paths.lock, b"");
                private_file(&paths.cap, b"replacement cap");
            }
            assert!(guard.check().is_err());
            drop(listener);
            drop(guard);
            assert!(old_control.join("agent.sock").exists());
            assert!(old_control.join("admin.cap").exists());
            assert!(paths.lock.exists());
            if changed != "lock" {
                assert_eq!(fs::read(&paths.cap).unwrap(), b"replacement cap");
            }
        }
    }

    #[test]
    fn legacy_temporaries_and_partial_cap_recover_without_removal() {
        let temp = Temp::new();
        let paths = OwnerPaths::in_state_home(temp.home());
        drop(local::create_private_directory(&paths.dir).unwrap());
        private_file(&paths.cap, b"part");
        private_file(&paths.owner_json, b"old owner metadata is never authority");
        let maximum = vec![b'x'; MAX_METADATA_BYTES];
        private_file(&paths.dir.join("admin.tmp-123"), &maximum);
        private_file(&paths.dir.join("owner.tmp-456"), b"");
        preflight(&temp.home()).unwrap();
        let guard = Guard::acquire(&temp.home()).unwrap();
        guard.check().unwrap();
        assert_eq!(fs::metadata(&paths.cap).unwrap().len(), CAP_BYTES as u64);
        assert_eq!(fs::read(paths.dir.join("admin.tmp-123")).unwrap(), maximum);
        drop(guard);
        assert_eq!(
            fs::read(&paths.owner_json).unwrap(),
            b"old owner metadata is never authority"
        );
        assert!(paths.dir.join("owner.tmp-456").exists());
        assert!(paths.dir.join("admin.tmp-123").exists());
        assert!(!paths.cap.exists());
    }

    #[test]
    fn unsafe_modes_links_unknown_files_and_oversized_metadata_are_preserved() {
        for case in [
            "home-mode",
            "home-link",
            "control-link",
            "cap-link",
            "cap-hardlink",
            "unknown",
            "bad-temp",
            "oversized",
        ] {
            let temp = Temp::new();
            let home = temp.home();
            let paths = OwnerPaths::in_state_home(&home);
            let target = temp.0.join("target");
            private_file(&target, b"preserved");
            match case {
                "home-mode" => {
                    fs::set_permissions(&home, fs::Permissions::from_mode(0o755)).unwrap()
                }
                "home-link" => {
                    fs::rename(&home, temp.0.join("actual-home")).unwrap();
                    symlink(temp.0.join("actual-home"), &home).unwrap();
                }
                "control-link" => symlink(&home, &paths.dir).unwrap(),
                _ => {
                    drop(local::create_private_directory(&paths.dir).unwrap());
                    match case {
                        "cap-link" => symlink(&target, &paths.cap).unwrap(),
                        "cap-hardlink" => fs::hard_link(&target, &paths.cap).unwrap(),
                        "unknown" => private_file(&paths.dir.join("user-data"), b"untouched"),
                        "bad-temp" => {
                            private_file(&paths.dir.join("admin.tmp-not-a-pid"), b"untouched")
                        }
                        "oversized" => private_file(
                            &paths.dir.join("owner.tmp-123"),
                            &vec![0; MAX_METADATA_BYTES + 1],
                        ),
                        _ => unreachable!(),
                    }
                }
            }
            assert!(preflight(&home).is_err(), "{case}");
            assert!(Guard::acquire(&home).is_err(), "{case}");
            assert_eq!(fs::read(&target).unwrap(), b"preserved");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inventory_reserves_missing_endpoints_and_accepts_a_full_valid_home() {
        let temp = Temp::new();
        let paths = OwnerPaths::in_state_home(temp.home());
        drop(local::create_private_directory(&paths.dir).unwrap());
        for index in 0..MAX_FILES - REQUIRED_NAMES.len() {
            private_file(&paths.dir.join(format!("owner.tmp-{index}")), b"");
        }
        preflight(&temp.home()).unwrap();
        let extra = paths.dir.join("admin.tmp-999");
        private_file(&extra, b"");
        assert!(preflight(&temp.home()).is_err());
        assert!(Guard::acquire(&temp.home()).is_err());
        assert!(!paths.lock.exists());
        assert!(!paths.cap.exists());
        assert!(extra.exists());
        fs::remove_file(&extra).unwrap();

        let mut guard = Guard::acquire(&temp.home()).unwrap();
        let admin = guard.bind(Channel::Admin).unwrap();
        let agent = guard.bind(Channel::Agent).unwrap();
        assert_eq!(fs::read_dir(&paths.dir).unwrap().count(), MAX_FILES);
        preflight(&temp.home()).unwrap();
        guard.check().unwrap();
        private_file(&extra, b"");
        assert!(preflight(&temp.home()).is_err());
        assert_eq!(fs::read_dir(&paths.dir).unwrap().count(), MAX_FILES + 1);
        drop(admin);
        drop(agent);
        drop(guard);
        assert!(extra.exists());
        fs::remove_file(&extra).unwrap();
        let mut restarted = Guard::acquire(&temp.home()).unwrap();
        let _admin = restarted.bind(Channel::Admin).unwrap();
        let _agent = restarted.bind(Channel::Agent).unwrap();
        preflight(&temp.home()).unwrap();
        assert_eq!(fs::read_dir(&paths.dir).unwrap().count(), MAX_FILES);
    }
}
