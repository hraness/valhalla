//! One immutable daemon selection over the existing per-user supervisor helpers.
//!
//! Install's caller first opens retained native state under service custody and
//! releases it. This module then checks only bounded read-only namespace shapes
//! and immutable commitments; it never opens a native writer or holds a daemon
//! lock while the supervisor starts. Status/removal need no healthy native data.

use super::{
    catalog::{Hash, Hex},
    network::Listen,
};
use crate::private_host::{launchd, systemd};
use hraness_control_kit::{ErrorBody, ErrorCode};
use rustix::fs::{self as rfs, Mode, OFlags};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};
use vhalla_custody::{self as custody, Owner};
use vhalla_direct_store::Store;
use zeroize::Zeroizing;

const CONFIG_NAME: &str = "managed-service.json";
const MAX_CONFIG: usize = 16 * 1024;
const MAX_PATH: usize = 4096;
type Result<T> = std::result::Result<T, ErrorBody>;

fn usage(message: &str) -> ErrorBody {
    ErrorBody::new(ErrorCode::Usage, message)
}
fn refused() -> ErrorBody {
    ErrorBody::new(ErrorCode::Conflict, "Managed service selection is missing, changed, or unsafe. Preserve the daemon home, configuration, service files, and logs.")
}
fn supervisor_error() -> ErrorBody {
    ErrorBody::new(ErrorCode::Conflict, "The supervisor operation was refused or could not be verified. Preserve the managed selection and inspect daemon managed status before retrying.")
}
fn digest(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hash = Sha256::new();
    hash.update(b"valhalla/headless/managed/v1\0");
    hash.update((domain.len() as u64).to_be_bytes());
    hash.update(domain);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    Hex(hash.finalize().into())
}
fn path_text(path: &Path) -> Result<&str> {
    let text = path.to_str().ok_or_else(refused)?;
    if !path.is_absolute()
        || text.len() > MAX_PATH
        || text.bytes().any(|v| v < 32 || v == 127)
        || path
            .components()
            .any(|v| matches!(v, Component::CurDir | Component::ParentDir))
        || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
    {
        return Err(refused());
    }
    Ok(text)
}
fn label(home: &Path) -> Result<String> {
    Ok(format!(
        "me.vhalla.daemon.{}",
        digest(b"label", path_text(home)?.as_bytes())
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Stamp {
    device: u64,
    inode: u64,
}
impl Stamp {
    fn of(file: &File) -> Result<Self> {
        let meta = file.metadata().map_err(|_| refused())?;
        Ok(Self {
            device: meta.dev(),
            inode: meta.ino(),
        })
    }
}
struct Directory {
    path: PathBuf,
    file: File,
    owner: Owner,
}
impl Directory {
    fn open(path: &Path) -> Result<Self> {
        path_text(path)?;
        if path.canonicalize().map_err(|_| refused())?.as_os_str() != path.as_os_str() {
            return Err(refused());
        }
        let (file, owner) = custody::open_private_directory(path).map_err(|_| refused())?;
        if owner != Owner::current().map_err(|_| refused())? {
            return Err(refused());
        }
        Ok(Self {
            path: path.to_owned(),
            file,
            owner,
        })
    }
    fn check(&self) -> Result<()> {
        let current = Self::open(&self.path)?;
        if current.owner != self.owner
            || !custody::same_open_file(&self.file, &current.file).map_err(|_| refused())?
        {
            return Err(refused());
        }
        Ok(())
    }
}
struct HeldFile {
    path: PathBuf,
    file: File,
    owner: Owner,
    max: usize,
    hash: Option<Hash>,
}
impl HeldFile {
    fn open(path: &Path, owner: Owner, max: usize, immutable: bool) -> Result<Self> {
        let file = custody::open_private_file(path, owner, max).map_err(|_| refused())?;
        let mut held = Self {
            path: path.to_owned(),
            file,
            owner,
            max,
            hash: None,
        };
        if immutable {
            held.hash = Some(digest(b"file", &held.read()?));
        }
        held.check()?;
        Ok(held)
    }
    fn read(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut file =
            custody::open_private_file(&self.path, self.owner, self.max).map_err(|_| refused())?;
        if !custody::same_open_file(&file, &self.file).map_err(|_| refused())? {
            return Err(refused());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut file)
            .take(self.max.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| refused())?;
        if bytes.len() > self.max {
            return Err(refused());
        }
        Ok(bytes)
    }
    fn check(&self) -> Result<()> {
        let current =
            custody::open_private_file(&self.path, self.owner, self.max).map_err(|_| refused())?;
        if !custody::same_open_file(&current, &self.file).map_err(|_| refused())?
            || self.hash.is_some_and(|hash| {
                self.read()
                    .map(|v| digest(b"file", &v) != hash)
                    .unwrap_or(true)
            })
        {
            return Err(refused());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativePins {
    account: Hash,
    peer: Hash,
    catalog: Hash,
    public_sync: Hash,
    private_delivery: Hash,
}
struct NativeGuard {
    directories: Vec<Directory>,
    files: Vec<HeldFile>,
    pins: NativePins,
}
impl NativeGuard {
    fn open(home: &Directory) -> Result<Self> {
        let mut directories = Vec::new();
        for name in [
            "account",
            "rooms",
            "rooms/public",
            "rooms/private",
            "catalog",
            "public-sync",
            "public-sync/rooms",
            "public-sync/metadata",
            "private-delivery",
        ] {
            directories.push(Directory::open(&home.path.join(name))?);
        }
        let mut files = Vec::new();
        let mut pin = |name: &str, size: usize| -> Result<Hash> {
            let file = HeldFile::open(&home.path.join(name), home.owner, size, true)?;
            if file.file.metadata().map_err(|_| refused())?.len() != size as u64 {
                return Err(refused());
            }
            let hash = file.hash.ok_or_else(refused)?;
            files.push(file);
            Ok(hash)
        };
        let account = pin("account/identity", 72)?;
        let peer = pin("peer.key", 40)?;
        let catalog = pin("catalog/FORMAT", 104)?;
        let public_sync = pin("public-sync/metadata/FORMAT", 104)?;
        let private_delivery = pin("private-delivery/FORMAT", 104)?;
        files.push(HeldFile::open(
            &home.path.join("account/lock"),
            home.owner,
            0,
            false,
        )?);
        for name in ["catalog", "public-sync/metadata", "private-delivery"] {
            // This supported reader checks only the immutable bounded marker;
            // opening a Store would enter writer recovery and is inappropriate.
            Store::locate_context(home.path.join(name)).map_err(|_| refused())?;
            files.push(HeldFile::open(
                &home.path.join(name).join("lock"),
                home.owner,
                0,
                false,
            )?);
            let database = HeldFile::open(
                &home.path.join(name).join("direct.sqlite"),
                home.owner,
                usize::MAX,
                false,
            )?;
            if database.file.metadata().map_err(|_| refused())?.len() < 100 {
                return Err(refused());
            }
            files.push(database);
        }
        let guard = Self {
            directories,
            files,
            pins: NativePins {
                account,
                peer,
                catalog,
                public_sync,
                private_delivery,
            },
        };
        guard.check()?;
        Ok(guard)
    }
    fn check(&self) -> Result<()> {
        for directory in &self.directories {
            directory.check()?;
        }
        for file in &self.files {
            file.check()?;
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    version: u32,
    home: PathBuf,
    home_stamp: Stamp,
    label: String,
    executable: PathBuf,
    listen: Listen,
    native: NativePins,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    selection: Selection,
    commitment: Hash,
}
impl Config {
    fn new(
        home: &Directory,
        executable: &Path,
        listen: &Listen,
        native: NativePins,
    ) -> Result<Self> {
        let selection = Selection {
            version: 1,
            home: home.path.clone(),
            home_stamp: Stamp::of(&home.file)?,
            label: label(&home.path)?,
            executable: executable.to_owned(),
            listen: listen.clone(),
            native,
        };
        let commitment = digest(
            b"selection",
            &serde_json::to_vec(&selection).map_err(|_| refused())?,
        );
        Ok(Self {
            selection,
            commitment,
        })
    }
    fn encode(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).map_err(|_| refused())?;
        if bytes.len() > MAX_CONFIG {
            return Err(refused());
        }
        Ok(bytes)
    }
    fn check(&self, home: &Directory) -> Result<()> {
        if self.selection.version != 1
            || self.selection.home != home.path
            || self.selection.home_stamp != Stamp::of(&home.file)?
            || self.selection.label != label(&home.path)?
            || self.commitment
                != digest(
                    b"selection",
                    &serde_json::to_vec(&self.selection).map_err(|_| refused())?,
                )
        {
            return Err(refused());
        }
        path_text(&self.selection.executable)?;
        self.selection.listen.validate()?;
        Ok(())
    }
}
struct ConfigGuard {
    home: Directory,
    file: HeldFile,
    config: Config,
}
impl ConfigGuard {
    fn open(home: Directory) -> Result<Self> {
        let file = HeldFile::open(&home.path.join(CONFIG_NAME), home.owner, MAX_CONFIG, true)?;
        let bytes = file.read()?;
        let config: Config = serde_json::from_slice(&bytes).map_err(|_| refused())?;
        config.check(&home)?;
        if config.encode()?.as_slice() != bytes.as_slice() {
            return Err(refused());
        }
        let guard = Self { home, file, config };
        guard.check()?;
        Ok(guard)
    }
    fn select(home: Directory, desired: Config) -> Result<Self> {
        home.check()?;
        desired.check(&home)?;
        let bytes = desired.encode()?;
        let path = home.path.join(CONFIG_NAME);
        let created = match path.symlink_metadata() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // An interrupted write remains visible; no repair, replacement,
                // truncation, or retry write is ever made to this selection.
                let mut file = custody::create_private_file(&path).map_err(|_| refused())?;
                home.file.sync_all().map_err(|_| refused())?;
                file.write_all(&bytes)
                    .and_then(|()| file.sync_all())
                    .map_err(|_| refused())?;
                home.file.sync_all().map_err(|_| refused())?;
                Some(file)
            }
            Ok(_) => None,
            Err(_) => return Err(refused()),
        };
        let guard = Self::open(home)?;
        if let Some(created) = created {
            if !custody::same_open_file(&created, &guard.file.file).map_err(|_| refused())? {
                return Err(refused());
            }
        }
        if guard.config.encode()? != bytes {
            return Err(refused());
        }
        Ok(guard)
    }
    fn check(&self) -> Result<()> {
        self.home.check()?;
        self.file.check()?;
        self.config.check(&self.home)
    }
}

struct Executable {
    path: PathBuf,
    file: File,
}
impl Executable {
    fn open(path: &Path) -> Result<Self> {
        path_text(path)?;
        if path.canonicalize().map_err(|_| refused())?.as_os_str() != path.as_os_str() {
            return Err(refused());
        }
        let file = Self::read(path)?;
        let value = Self {
            path: path.to_owned(),
            file,
        };
        value.check()?;
        Ok(value)
    }
    fn check(&self) -> Result<()> {
        if self.path.canonicalize().map_err(|_| refused())?.as_os_str() != self.path.as_os_str() {
            return Err(refused());
        }
        let meta = fs::symlink_metadata(&self.path).map_err(|_| refused())?;
        if !meta.is_file() || meta.mode() & 0o111 == 0 || meta.mode() & 0o6022 != 0 {
            return Err(refused());
        }
        let current = Self::read(&self.path)?;
        if !custody::same_open_file(&current, &self.file).map_err(|_| refused())?
            || !custody::same_file(&self.path, &current).map_err(|_| refused())?
        {
            return Err(refused());
        }
        Ok(())
    }
    fn read(path: &Path) -> Result<File> {
        // A substituted FIFO must fail promptly, and a final symlink must
        // never turn a retained executable choice into another object.
        rfs::open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|_| refused())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Platform {
    Mac,
    Linux,
    Unsupported,
}
impl Platform {
    fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::Mac
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else {
            Self::Unsupported
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Mac => "launchd",
            Self::Linux => "systemd",
            Self::Unsupported => "unsupported",
        }
    }
}
enum Spec {
    #[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
    Mac(launchd::AgentSpec),
    #[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
    Linux(systemd::UnitSpec),
}
impl Spec {
    fn new(config: &Config, platform: Platform) -> Result<Self> {
        let selection = &config.selection;
        let executable = path_text(&selection.executable)?;
        let mut arguments = vec![
            "daemon".to_owned(),
            "run".to_owned(),
            "--home".to_owned(),
            path_text(&selection.home)?.to_owned(),
            "--bind".to_owned(),
            selection.listen.bind.to_string(),
        ];
        if let Some(relay) = &selection.listen.relay_url {
            arguments.extend(["--relay-url".to_owned(), relay.clone()]);
        }
        if selection.listen.relay_only {
            arguments.push("--relay-only".to_owned());
        }
        let log_path = selection.home.join(launchd::SUPERVISOR_LOG_NAME);
        match platform {
            Platform::Mac => {
                let throttle = launchd::THROTTLE_INTERVAL_SECONDS;
                let arguments = std::iter::once(executable)
                    .chain(arguments.iter().map(String::as_str))
                    .map(|arg| launchd::xml(arg).map(|arg| format!("<string>{arg}</string>")))
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|_| refused())?
                    .join("");
                let label = launchd::xml(&selection.label).map_err(|_| refused())?;
                let log = launchd::xml(path_text(&log_path)?).map_err(|_| refused())?;
                Ok(Self::Mac(launchd::AgentSpec { label: selection.label.clone(), alternates: Vec::new(), plist: format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{label}</string>\n<key>ProgramArguments</key><array>{arguments}</array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n<key>ThrottleInterval</key><integer>{throttle}</integer>\n<key>ExitTimeOut</key><integer>15</integer>\n<key>Umask</key><integer>63</integer>\n<key>ProcessType</key><string>Background</string>\n<key>AbandonProcessGroup</key><false/>\n<key>StandardOutPath</key><string>{log}</string>\n<key>StandardErrorPath</key><string>{log}</string>\n</dict></plist>\n") }))
            }
            Platform::Linux => {
                let args: Vec<_> = arguments.iter().map(String::as_str).collect();
                let unit = systemd::unit_text("Valhalla headless daemon", executable, &args, path_text(&log_path)?)
                    .map_err(|_| usage("systemd requires paths and relay URLs without whitespace, quotes, backslashes, or expansion characters."))?;
                Ok(Self::Linux(systemd::UnitSpec {
                    label: selection.label.clone(),
                    unit,
                    alternates: Vec::new(),
                }))
            }
            Platform::Unsupported => Err(usage(
                "Managed daemon services require macOS launchd or a Linux systemd user manager.",
            )),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    Install,
    Status,
    Uninstall,
}
fn supervise(action: Action, spec: &Spec) -> std::result::Result<Value, String> {
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = action;
    match spec {
        #[cfg(target_os = "macos")]
        Spec::Mac(spec) => match action {
            Action::Status => launchd::agent_status(spec),
            Action::Install => launchd::agent_install_quiet(spec).map(|()| Value::Null),
            Action::Uninstall => launchd::agent_uninstall_quiet(spec).map(|()| Value::Null),
        },
        #[cfg(target_os = "linux")]
        Spec::Linux(spec) => match action {
            Action::Status => systemd::linux::agent_status(spec),
            Action::Install => systemd::linux::agent_install_quiet(spec).map(|()| Value::Null),
            Action::Uninstall => systemd::linux::agent_uninstall_quiet(spec).map(|()| Value::Null),
        },
        _ => Err("This supervisor is unsupported on the current platform.".into()),
    }
}
fn report(
    guard: &ConfigGuard,
    platform: Platform,
    observed: std::result::Result<Value, String>,
) -> Value {
    let service = observed.unwrap_or_else(|_| json!({"state":"unknown","installed":null,"loaded":null,"manager":"unavailable_or_unverified"}));
    json!({"managed":true,"supported":platform != Platform::Unsupported,"supervisor":platform.name(),
        "label":guard.config.selection.label,"home":guard.config.selection.home,
        "executable":guard.config.selection.executable,"listen":guard.config.selection.listen,
        "supervisor_log":guard.home.path.join(launchd::SUPERVISOR_LOG_NAME),"service":service})
}

pub(super) fn install(home: &Path, executable: &Path, listen: &Listen) -> Result<Value> {
    install_with(home, executable, listen, Platform::current(), supervise)
}
fn install_with(
    home: &Path,
    executable: &Path,
    listen: &Listen,
    platform: Platform,
    mut run: impl FnMut(Action, &Spec) -> std::result::Result<Value, String>,
) -> Result<Value> {
    listen.validate()?;
    let home = Directory::open(home)?;
    let executable = Executable::open(executable)?;
    let native = NativeGuard::open(&home)?;
    let desired = Config::new(&home, &executable.path, listen, native.pins.clone())?;
    // Prove the exact platform arguments before publishing any selection.
    let spec = Spec::new(&desired, platform)?;
    let guard = ConfigGuard::select(home, desired)?;
    native.check()?;
    executable.check()?;
    guard.check()?;
    run(Action::Install, &spec).map_err(|_| supervisor_error())?;
    native.check()?;
    executable.check()?;
    guard.check()?;
    let observed = run(Action::Status, &spec);
    guard.check()?;
    let mut result = report(&guard, platform, observed);
    result["operation"] = json!("install");
    Ok(result)
}
pub(super) fn status(home: &Path) -> Result<Value> {
    inspect_with(home, Platform::current(), false, supervise)
}
pub(super) fn uninstall(home: &Path) -> Result<Value> {
    inspect_with(home, Platform::current(), true, supervise)
}
fn inspect_with(
    home: &Path,
    platform: Platform,
    remove: bool,
    mut run: impl FnMut(Action, &Spec) -> std::result::Result<Value, String>,
) -> Result<Value> {
    let guard = ConfigGuard::open(Directory::open(home)?)?;
    if platform == Platform::Unsupported {
        if remove {
            return Err(usage(
                "Managed daemon removal requires macOS launchd or a Linux systemd user manager.",
            ));
        }
        return Ok(report(&guard, platform, Err("unsupported".into())));
    }
    let spec = Spec::new(&guard.config, platform)?;
    guard.check()?;
    if remove {
        run(Action::Uninstall, &spec).map_err(|_| supervisor_error())?;
        guard.check()?;
    }
    let observed = run(Action::Status, &spec);
    guard.check()?;
    let mut result = report(&guard, platform, observed);
    if remove {
        result["operation"] = json!("uninstall");
        result["home_preserved"] = json!(true);
        result["configuration_preserved"] = json!(true);
        result["logs_preserved"] = json!(true);
    }
    Ok(result)
}

#[cfg(test)]
#[path = "managed_tests.rs"]
mod tests;
