//! Per-user, exact-identity systemd user unit ownership for Linux hosts.
//!
//! This mirrors the LaunchAgent custody path: one label, the exact unit bytes
//! it must contain, refusal of foreign content at that label, and no
//! management of unrelated services. The install, status and removal flows
//! take the `systemctl` runner and the unit path as parameters so they are
//! platform-independent and tested everywhere; only the real command and the
//! per-user unit directory are Linux-specific.
#[cfg(target_os = "linux")]
use super::config::Loaded;
use super::{config::Config, launchd::SUPERVISOR_LOG_NAME, REFUSED};
use std::{collections::BTreeMap, ffi::OsString, path::Path};
use vhalla_custody as custody;

/// A fully resolved per-user unit: the exact label plus the exact unit file
/// bytes it must contain. `alternates` names earlier emitted shapes that stay
/// admissible for the same label so an upgrade never wedges an installation.
pub(crate) struct UnitSpec {
    pub label: String,
    pub unit: String,
    pub alternates: Vec<String>,
}

/// One systemctl reply; only the exit status and bounded output are kept.
pub(crate) struct Reply {
    pub success: bool,
    pub stdout: String,
}

/// systemd expands `%` specifiers, splits `ExecStart=` on whitespace and reads
/// quotes and backslashes as escapes. A path with any of those characters is
/// refused rather than escaped, so the unit says exactly what runs.
pub(crate) fn argument(value: &str) -> Result<&str, String> {
    if value.is_empty()
        || value
            .chars()
            .any(|c| c <= ' ' || c == '\u{7f}' || matches!(c, '%' | '"' | '\'' | '\\' | ';' | '$'))
    {
        return Err(REFUSED.into());
    }
    Ok(value)
}

/// The exact unit text: restart only after an unsuccessful exit with the same
/// 30-second throttle and 15-second stop grace as the LaunchAgent, an owner-only
/// umask, and supervisor output appended to the bounded `supervisor.log`.
pub(crate) fn unit_text(
    description: &str,
    executable: &str,
    args: &[&str],
    log: &str,
) -> Result<String, String> {
    if description.is_empty() || description.chars().any(|c| c < ' ' || c == '\u{7f}') {
        return Err(REFUSED.into());
    }
    let mut exec = String::from(argument(executable)?);
    for arg in args {
        exec.push(' ');
        exec.push_str(argument(arg)?);
    }
    let log = argument(log)?;
    Ok(format!(
        "[Unit]\nDescription={description}\n\n[Service]\nType=simple\nExecStart={exec}\nRestart=on-failure\nRestartSec=30\nTimeoutStopSec=15\nUMask=0077\nStandardOutput=append:{log}\nStandardError=append:{log}\n\n[Install]\nWantedBy=default.target\n"
    ))
}

/// Resolve the host's unit, embedding its exact executable, home and log.
pub(super) fn spec(home: &Path, c: &Config) -> Result<UnitSpec, String> {
    let executable = c.executable.to_str().ok_or(REFUSED)?;
    let home_text = home.to_str().ok_or(REFUSED)?;
    let log = home.join(SUPERVISOR_LOG_NAME);
    Ok(UnitSpec {
        label: c.label.clone(),
        unit: unit_text(
            &format!("Valhalla private host {}", c.label),
            executable,
            &["private-host", "serve", home_text],
            log.to_str().ok_or(REFUSED)?,
        )?,
        alternates: Vec::new(),
    })
}

pub(crate) fn unit_name(spec: &UnitSpec) -> String {
    format!("{}.service", spec.label)
}

fn ours(spec: &UnitSpec, bytes: &[u8]) -> bool {
    spec.unit.as_bytes() == bytes
        || spec
            .alternates
            .iter()
            .any(|shape| shape.as_bytes() == bytes)
}

/// One read of the installed unit: `None` when absent, `Some(true)` for the
/// exact current shape, `Some(false)` for an admissible earlier shape. Foreign
/// content refuses. Decisions derive from these bytes, never a second read.
fn installed_shape(spec: &UnitSpec, path: &Path) -> Result<Option<bool>, String> {
    let uid = rustix::process::geteuid().as_raw();
    if !custody::private_file_present(path, uid, 65536).map_err(|_| REFUSED)? {
        return Ok(None);
    }
    let bytes = custody::read_private_file(path, uid, 65536).map_err(|_| REFUSED)?;
    if !ours(spec, &bytes) {
        return Err("refusing a foreign or changed unit file at the selected label".into());
    }
    Ok(Some(bytes == spec.unit.as_bytes()))
}

fn args(parts: &[&str]) -> Vec<OsString> {
    parts.iter().map(OsString::from).collect()
}

const PROPERTIES: &str =
    "--property=LoadState,ActiveState,SubState,MainPID,ExecMainStatus,NRestarts,FragmentPath";

/// `systemctl show` succeeds for an absent unit (`LoadState=not-found`), so a
/// failed command never proves absence: it preserves custody and refuses.
fn show(
    spec: &UnitSpec,
    run: &mut impl FnMut(&[OsString]) -> Result<Reply, String>,
) -> Result<BTreeMap<String, String>, String> {
    let reply = run(&args(&["--user", "show", PROPERTIES, &unit_name(spec)]))?;
    if !reply.success {
        return Err(
            "systemctl could not prove the selected unit state; preserve the unit file and exact home"
                .into(),
        );
    }
    let mut fields = BTreeMap::new();
    for line in reply.stdout.lines() {
        if let Some((key, value)) = line.split_once('=') {
            fields.insert(key.trim().to_owned(), value.trim().to_owned());
        }
    }
    if !fields.contains_key("LoadState") || !fields.contains_key("ActiveState") {
        return Err("systemctl returned an unrecognized unit description; preserve custody".into());
    }
    Ok(fields)
}

fn active(fields: &BTreeMap<String, String>) -> bool {
    matches!(
        fields.get("ActiveState").map(String::as_str),
        Some("active" | "activating" | "reloading")
    )
}
/// Only `inactive` and `failed` prove the unit is not running; `deactivating`
/// still has a process and `activating` is starting one.
fn stopped(fields: &BTreeMap<String, String>) -> bool {
    matches!(
        fields.get("ActiveState").map(String::as_str),
        Some("inactive" | "failed")
    )
}
fn loaded(fields: &BTreeMap<String, String>) -> bool {
    fields.get("LoadState").map(String::as_str) == Some("loaded")
}
fn fragment_is(fields: &BTreeMap<String, String>, path: &Path) -> bool {
    fields.get("FragmentPath").map(String::as_str) == path.to_str()
}
fn number(fields: &BTreeMap<String, String>, key: &str) -> Option<u64> {
    fields.get(key).and_then(|v| v.parse().ok())
}

pub(crate) fn status_with(
    spec: &UnitSpec,
    path: &Path,
    mut run: impl FnMut(&[OsString]) -> Result<Reply, String>,
) -> Result<serde_json::Value, String> {
    let installed = installed_shape(spec, path)?;
    // `status` is the operator's view: a manager that does not answer (no user
    // session, a container, CI) is reported as unknown state, never as absence
    // and never as a failed command. Install and removal still fail closed.
    let fields = match show(spec, &mut run) {
        Ok(fields) => fields,
        Err(reason) => {
            return Ok(serde_json::json!({
                "supported": true,
                "supervisor": "systemd",
                "installed": installed.is_some(),
                "unit_current": installed == Some(true),
                "unit": path,
                "manager": "unavailable",
                "manager_error": reason,
                "loaded": serde_json::Value::Null,
                "state": "unknown",
                "pid": serde_json::Value::Null,
                "restart_loop_suspected": false,
            }));
        }
    };
    let pid = number(&fields, "MainPID").filter(|pid| *pid != 0);
    let last_exit = number(&fields, "ExecMainStatus");
    let restarts = number(&fields, "NRestarts").unwrap_or(0);
    let is_loaded = loaded(&fields);
    // Restart=on-failure with no live pid and a nonzero last exit is systemd
    // rescheduling a failing service — suspicion only.
    let restart_loop_suspected =
        is_loaded && pid.is_none() && restarts > 0 && last_exit.is_some_and(|code| code != 0);
    Ok(serde_json::json!({
        "supported": true,
        "supervisor": "systemd",
        "installed": installed.is_some(),
        "unit_current": installed == Some(true),
        "unit": path,
        "manager": "answered",
        "loaded": is_loaded,
        "unit_matches": is_loaded && fragment_is(&fields, path),
        "state": format!("{}/{}", fields.get("ActiveState").cloned().unwrap_or_default(), fields.get("SubState").cloned().unwrap_or_default()),
        "pid": pid,
        "last_exit_code": last_exit,
        "restarts": restarts,
        "restart_loop_suspected": restart_loop_suspected,
    }))
}

pub(crate) fn install_with(
    spec: &UnitSpec,
    destination: impl FnOnce() -> Result<std::path::PathBuf, String>,
    mut run: impl FnMut(&[OsString]) -> Result<Reply, String>,
) -> Result<(), String> {
    // The exact unit probe also proves that the user manager answers. Never
    // list every unit: a user's unrelated services are outside this selection.
    let before = show(spec, &mut run)?;
    if !stopped(&before) {
        return Err("this exact unit is already active; inspect status before changing it".into());
    }
    let path = destination()?;
    if loaded(&before) && !fragment_is(&before, &path) {
        return Err(
            "a unit with this label is loaded from another path; refusing to replace a foreign unit"
                .into(),
        );
    }
    // An installed earlier emitted shape is ours but outdated. The unit is
    // proven inactive, so replace it with the exact current shape; the file
    // that starts is always the one this software emits now.
    let installed = installed_shape(spec, &path)?;
    if installed == Some(false) {
        std::fs::remove_file(&path).map_err(|_| REFUSED)?;
    }
    if installed != Some(true) {
        use std::io::Write;
        let mut file = custody::create_private_file(&path).map_err(|_| REFUSED)?;
        file.write_all(spec.unit.as_bytes())
            .and_then(|()| file.sync_all())
            .and_then(|()| {
                std::fs::File::open(
                    path.parent()
                        .ok_or_else(|| std::io::Error::other("parent"))?,
                )?
                .sync_all()
            })
            .map_err(|_| REFUSED)?;
    }
    if installed_shape(spec, &path)? != Some(true) {
        return Err(REFUSED.into());
    }
    if !run(&args(&["--user", "daemon-reload"]))?.success {
        return Err(
            "systemd user manager refused to reload; exact unit and home were preserved".into(),
        );
    }
    if !run(&args(&["--user", "enable", "--now", &unit_name(spec)]))?.success {
        return Err(
            "unit enable refused; exact unit file and home were preserved for inspection".into(),
        );
    }
    let after = show(spec, &mut run)?;
    if !active(&after) || !fragment_is(&after, &path) {
        return Err(
            "enable returned without a verifiable active service from the owned unit file; preserve exact home and unit"
                .into(),
        );
    }
    println!(
        "{}",
        serde_json::json!({"status":"installed","supervisor":"systemd","label":spec.label,"health":"not yet qualified; check TLS and durable retention separately"})
    );
    Ok(())
}

pub(crate) fn uninstall_with(
    spec: &UnitSpec,
    path: &Path,
    run: impl FnMut(&[OsString]) -> Result<Reply, String>,
) -> Result<(), String> {
    uninstall_bounded(spec, path, run, std::time::Duration::from_secs(20))
}

fn uninstall_bounded(
    spec: &UnitSpec,
    path: &Path,
    mut run: impl FnMut(&[OsString]) -> Result<Reply, String>,
    stop_bound: std::time::Duration,
) -> Result<(), String> {
    let installed = installed_shape(spec, path)?.is_some();
    let fields = show(spec, &mut run)?;
    if loaded(&fields) {
        if !installed || !fragment_is(&fields, path) {
            return Err(
                "loaded unit does not identify the exact owned unit file; refusing to stop it"
                    .into(),
            );
        }
        if !run(&args(&["--user", "disable", "--now", &unit_name(spec)]))?.success {
            return Err("unit stop refused; preserve the installed unit file and host home".into());
        }
        let deadline = std::time::Instant::now() + stop_bound;
        while !stopped(&show(spec, &mut run)?) {
            if std::time::Instant::now() >= deadline {
                return Err("unit has not stopped; preserve its file and exact custody".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    if installed {
        if installed_shape(spec, path)?.is_none() {
            return Err(REFUSED.into());
        }
        std::fs::remove_file(path).map_err(|_| REFUSED)?;
        std::fs::File::open(path.parent().ok_or(REFUSED)?)
            .and_then(|f| f.sync_all())
            .map_err(|_| REFUSED)?;
        if !run(&args(&["--user", "daemon-reload"]))?.success {
            return Err(
                "unit file removed but the systemd user manager refused to reload; run systemctl --user daemon-reload"
                    .into(),
            );
        }
    }
    println!(
        "{}",
        serde_json::json!({"status":"uninstalled","supervisor":"systemd","label":spec.label,"home_preserved":true})
    );
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn status(loaded: &Loaded) -> Result<serde_json::Value, String> {
    match spec(&loaded.home, &loaded.config) {
        Ok(unit) => linux::agent_status(&unit),
        Err(reason) => Ok(serde_json::json!({
            "supported": true,
            "supervisor": "systemd",
            "installed": false,
            "unit": serde_json::Value::Null,
            "unsupervisable": reason,
            "loaded": serde_json::Value::Null,
            "state": "unknown",
            "pid": serde_json::Value::Null,
            "restart_loop_suspected": false,
        })),
    }
}
#[cfg(target_os = "linux")]
pub(super) fn install(loaded: &Loaded) -> Result<(), String> {
    if time::OffsetDateTime::now_utc().unix_timestamp() >= loaded.config.certificate_expires_at {
        return Err("refusing to install an expired TLS host".into());
    }
    linux::agent_install(&spec(&loaded.home, &loaded.config)?)
}
#[cfg(target_os = "linux")]
pub(super) fn uninstall(loaded: &Loaded) -> Result<(), String> {
    linux::agent_uninstall(&spec(&loaded.home, &loaded.config)?)
}

/// The real per-user manager: `systemctl --user` with bounded output and a
/// fixed deadline, and the unit directory under the user's configuration home.
#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use super::*;
    use std::{
        fs,
        io::Read,
        os::unix::fs::{DirBuilderExt, MetadataExt},
        path::PathBuf,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    const MAX_OUTPUT: u64 = 65536;

    fn systemctl() -> Result<PathBuf, String> {
        ["/usr/bin/systemctl", "/bin/systemctl"]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
            .ok_or_else(|| "systemctl unavailable; use foreground serve on this machine".into())
    }
    pub(crate) fn command(arguments: &[OsString]) -> Result<Reply, String> {
        let mut child = Command::new(systemctl()?)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "systemctl unavailable")?;
        let stdout = child.stdout.take().ok_or(REFUSED)?;
        let stderr = child.stderr.take().ok_or(REFUSED)?;
        let read = |stream: Box<dyn Read + Send>| {
            thread::spawn(move || {
                let mut bytes = Vec::new();
                stream
                    .take(MAX_OUTPUT + 1)
                    .read_to_end(&mut bytes)
                    .map(|_| bytes)
            })
        };
        let out = read(Box::new(stdout));
        let err = read(Box::new(stderr));
        let deadline = Instant::now() + Duration::from_secs(10);
        let result = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err("systemctl did not complete within its fixed deadline");
                }
            }
        };
        let stdout = out.join().map_err(|_| REFUSED)?.map_err(|_| REFUSED)?;
        let stderr = err.join().map_err(|_| REFUSED)?.map_err(|_| REFUSED)?;
        if stdout.len() > MAX_OUTPUT as usize || stderr.len() > MAX_OUTPUT as usize {
            return Err("systemctl output exceeded its fixed bound".into());
        }
        let status = result?;
        Ok(Reply {
            success: status.success(),
            stdout: String::from_utf8(stdout).map_err(|_| REFUSED)?,
        })
    }
    /// `$XDG_CONFIG_HOME/systemd/user` or `~/.config/systemd/user`, with owned,
    /// non-group/world-writable, non-linked ancestry. An absent directory means
    /// no unit is installed; it is created owner-only just for `install`.
    fn directory(create: bool) -> Result<PathBuf, String> {
        let uid = rustix::process::geteuid().as_raw();
        let base = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            Some(config) => PathBuf::from(config),
            None => PathBuf::from(std::env::var_os("HOME").ok_or("user home unavailable")?)
                .join(".config"),
        };
        let mut path = match fs::symlink_metadata(&base) {
            Ok(meta) => {
                if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o022 != 0 {
                    return Err(REFUSED.into());
                }
                base.canonicalize().map_err(|_| REFUSED)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&base)
                    .map_err(|_| REFUSED)?;
                fs::File::open(base.parent().ok_or(REFUSED)?)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| REFUSED)?;
                base.canonicalize().map_err(|_| REFUSED)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(base.join("systemd").join("user"));
            }
            Err(_) => return Err(REFUSED.into()),
        };
        for part in ["systemd", "user"] {
            path.push(part);
            match fs::symlink_metadata(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => {
                    fs::DirBuilder::new()
                        .mode(0o700)
                        .create(&path)
                        .map_err(|_| REFUSED)?;
                    fs::File::open(path.parent().ok_or(REFUSED)?)
                        .and_then(|f| f.sync_all())
                        .map_err(|_| REFUSED)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(path.join(if part == "systemd" { "user" } else { "" }));
                }
                Err(_) => return Err(REFUSED.into()),
                Ok(_) => (),
            }
            let metadata = fs::symlink_metadata(&path).map_err(|_| REFUSED)?;
            if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
                return Err("systemd user directory ancestry must be owned directories without group/world write or symlinks".into());
            }
        }
        Ok(path)
    }
    fn destination(spec: &UnitSpec, create: bool) -> Result<PathBuf, String> {
        Ok(directory(create)?.join(unit_name(spec)))
    }
    pub(crate) fn agent_status(spec: &UnitSpec) -> Result<serde_json::Value, String> {
        match destination(spec, false) {
            Ok(path) => status_with(spec, &path, command),
            Err(reason) => Ok(serde_json::json!({
                "supported": true,
                "supervisor": "systemd",
                "installed": false,
                "unit": serde_json::Value::Null,
                "unit_directory": "unusable",
                "unit_directory_error": reason,
                "loaded": serde_json::Value::Null,
                "state": "unknown",
                "pid": serde_json::Value::Null,
                "restart_loop_suspected": false,
            })),
        }
    }
    pub(crate) fn agent_install(spec: &UnitSpec) -> Result<(), String> {
        install_with(spec, || destination(spec, true), command)
    }
    pub(crate) fn agent_uninstall(spec: &UnitSpec) -> Result<(), String> {
        uninstall_with(spec, &destination(spec, false)?, command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    fn reply(success: bool, stdout: &str) -> Result<Reply, String> {
        Ok(Reply {
            success,
            stdout: stdout.into(),
        })
    }
    fn shown(
        load: &str,
        active: &str,
        sub: &str,
        pid: u64,
        exit: u64,
        restarts: u64,
        fragment: &str,
    ) -> String {
        format!("LoadState={load}\nActiveState={active}\nSubState={sub}\nMainPID={pid}\nExecMainStatus={exit}\nNRestarts={restarts}\nFragmentPath={fragment}\n")
    }
    fn home(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "valhalla-systemd-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        dir
    }
    fn test_spec(home: &Path) -> UnitSpec {
        let config = crate::private_host::launchd::test_config("me.vhalla.private-host.unit-test");
        spec(home, &config).unwrap()
    }

    #[test]
    fn unit_text_is_exact_and_refuses_characters_systemd_would_reinterpret() {
        let text = unit_text(
            "Valhalla private host x",
            "/opt/vhalla",
            &["private-host", "serve", "/home/op/host"],
            "/home/op/host/supervisor.log",
        )
        .unwrap();
        assert!(text.contains("ExecStart=/opt/vhalla private-host serve /home/op/host\n"));
        assert!(text.contains("StandardOutput=append:/home/op/host/supervisor.log\n"));
        assert!(text.contains("StandardError=append:/home/op/host/supervisor.log\n"));
        assert!(text.contains("Restart=on-failure\nRestartSec=30\nTimeoutStopSec=15\nUMask=0077\n"));
        assert!(text.contains("WantedBy=default.target\n"));
        for bad in [
            "/home/op/my host",
            "/home/op/%h",
            "/home/op/\"q\"",
            "/home/op/a;b",
            "/home/op/$x",
            "/home/op/back\\slash",
            "",
        ] {
            assert!(
                unit_text("d", "/opt/vhalla", &["serve", bad], "/log").is_err(),
                "{bad:?}"
            );
        }
        assert!(unit_text("multi\nline", "/opt/vhalla", &[], "/log").is_err());
        let home = Path::new("/srv/valhalla-host");
        let unit = test_spec(home);
        assert_eq!(unit_name(&unit), "me.vhalla.private-host.unit-test.service");
        assert!(unit
            .unit
            .contains("ExecStart=/private/binary private-host serve /srv/valhalla-host\n"));
        assert!(unit
            .unit
            .contains("append:/srv/valhalla-host/supervisor.log\n"));
    }

    #[test]
    fn install_probes_the_exact_unit_writes_it_owner_only_and_requires_active_readback() {
        let dir = home("install");
        let unit = test_spec(&dir);
        let path = dir.join(unit_name(&unit));
        let name = unit_name(&unit);
        let path_text = path.to_str().unwrap().to_owned();
        // An active unit refuses before any file is written; a loaded unit from
        // another path is foreign and refuses too.
        for (load, active, fragment) in [
            ("loaded", "active", path_text.as_str()),
            ("loaded", "inactive", "/etc/systemd/user/other.service"),
        ] {
            let result = install_with(
                &unit,
                || Ok(path.clone()),
                |a| {
                    assert_eq!(a[1], "show");
                    reply(true, &shown(load, active, "running", 7, 0, 0, fragment))
                },
            );
            assert!(result.is_err());
            assert!(!path.exists());
        }
        let mut calls = Vec::new();
        install_with(
            &unit,
            || Ok(path.clone()),
            |a| {
                let argv: Vec<String> =
                    a.iter().map(|s| s.to_string_lossy().into_owned()).collect();
                calls.push(argv.clone());
                match calls.len() {
                    1 => reply(true, &shown("not-found", "inactive", "dead", 0, 0, 0, "")),
                    2 => {
                        assert_eq!(argv, ["--user", "daemon-reload"]);
                        reply(true, "")
                    }
                    3 => {
                        assert_eq!(argv, ["--user", "enable", "--now", &name]);
                        let meta = std::fs::metadata(&path).unwrap();
                        assert_eq!(
                            meta.mode() & 0o7777,
                            0o600,
                            "unit is owner-only before enable"
                        );
                        assert_eq!(std::fs::read(&path).unwrap(), unit.unit.as_bytes());
                        reply(true, "")
                    }
                    4 => reply(
                        true,
                        &shown("loaded", "active", "running", 4242, 0, 0, &path_text),
                    ),
                    _ => panic!("unexpected systemctl call"),
                }
            },
        )
        .unwrap();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0], ["--user", "show", PROPERTIES, &name]);
        // Enable that returns without an active service from our file refuses
        // but keeps the exact unit for inspection.
        assert!(install_with(
            &unit,
            || Ok(path.clone()),
            |a| match a[1].to_str().unwrap() {
                "show" => reply(
                    true,
                    &shown("loaded", "inactive", "dead", 0, 0, 0, &path_text)
                ),
                _ => reply(true, ""),
            }
        )
        .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), unit.unit.as_bytes());
        // A foreign unit file at the label is never replaced or removed.
        std::fs::write(&path, b"[Unit]\nDescription=foreign\n").unwrap();
        assert!(install_with(
            &unit,
            || Ok(path.clone()),
            |_| reply(true, &shown("not-found", "inactive", "dead", 0, 0, 0, ""))
        )
        .is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"[Unit]\nDescription=foreign\n"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn uninstall_requires_exact_unit_identity_and_preserves_the_file_on_uncertainty() {
        let dir = home("uninstall");
        let unit = test_spec(&dir);
        let path = dir.join(unit_name(&unit));
        let path_text = path.to_str().unwrap().to_owned();
        std::fs::write(&path, &unit.unit).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        // A failed probe, an unrecognized reply, and a loaded unit from another
        // file all refuse and keep the installed unit.
        for (success, stdout) in [
            (false, ""),
            (true, "garbage"),
            (
                true,
                shown(
                    "loaded",
                    "active",
                    "running",
                    9,
                    0,
                    0,
                    "/etc/systemd/user/foreign.service",
                )
                .as_str(),
            ),
        ] {
            let mut calls = 0;
            assert!(uninstall_with(&unit, &path, |_| {
                calls += 1;
                reply(success, stdout)
            })
            .is_err());
            assert_eq!(calls, 1);
            assert_eq!(std::fs::read(&path).unwrap(), unit.unit.as_bytes());
        }
        // A stop that never becomes inactive refuses after its bound without
        // removing the file.
        let mut calls = 0;
        assert!(uninstall_bounded(
            &unit,
            &path,
            |a| {
                calls += 1;
                if a[1] == "disable" {
                    return reply(true, "");
                }
                reply(
                    true,
                    &shown(
                        "loaded",
                        "deactivating",
                        "stop-sigterm",
                        9,
                        0,
                        0,
                        &path_text,
                    ),
                )
            },
            std::time::Duration::from_millis(300)
        )
        .is_err());
        assert!(calls > 3);
        assert!(path.exists());
        // The exact loaded unit stops, becomes inactive, and only then is its
        // file removed and the manager reloaded.
        let mut calls = Vec::new();
        uninstall_with(&unit, &path, |a| {
            let argv: Vec<String> = a.iter().map(|s| s.to_string_lossy().into_owned()).collect();
            calls.push(argv.clone());
            match calls.len() {
                1 => reply(
                    true,
                    &shown("loaded", "active", "running", 9, 0, 0, &path_text),
                ),
                2 => {
                    assert_eq!(argv[1], "disable");
                    assert_eq!(argv[2], "--now");
                    reply(true, "")
                }
                3 => reply(
                    true,
                    &shown("loaded", "inactive", "dead", 0, 0, 0, &path_text),
                ),
                4 => {
                    assert_eq!(argv, ["--user", "daemon-reload"]);
                    reply(true, "")
                }
                _ => panic!("unexpected systemctl call"),
            }
        })
        .unwrap();
        assert!(!path.exists());
        assert!(dir.is_dir());
        // An absent unit and an absent file is a clean no-op.
        uninstall_with(&unit, &path, |_| {
            reply(true, &shown("not-found", "inactive", "dead", 0, 0, 0, ""))
        })
        .unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn status_reports_custody_and_manager_state_separately() {
        let dir = home("status");
        let unit = test_spec(&dir);
        let path = dir.join(unit_name(&unit));
        let path_text = path.to_str().unwrap().to_owned();
        let absent = status_with(&unit, &path, |_| {
            reply(true, &shown("not-found", "inactive", "dead", 0, 0, 0, ""))
        })
        .unwrap();
        assert_eq!(absent["supported"], true);
        assert_eq!(absent["supervisor"], "systemd");
        assert_eq!(absent["installed"], false);
        assert_eq!(absent["loaded"], false);
        assert_eq!(absent["state"], "inactive/dead");
        std::fs::write(&path, &unit.unit).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let running = status_with(&unit, &path, |_| {
            reply(
                true,
                &shown("loaded", "active", "running", 515, 0, 0, &path_text),
            )
        })
        .unwrap();
        assert_eq!(running["installed"], true);
        assert_eq!(running["unit_current"], true);
        assert_eq!(running["unit_matches"], true);
        assert_eq!(running["pid"], 515);
        assert_eq!(running["restart_loop_suspected"], false);
        let failing = status_with(&unit, &path, |_| {
            reply(
                true,
                &shown("loaded", "activating", "auto-restart", 0, 1, 3, &path_text),
            )
        })
        .unwrap();
        assert_eq!(failing["pid"], serde_json::Value::Null);
        assert_eq!(failing["restarts"], 3);
        assert_eq!(failing["restart_loop_suspected"], true);
        let unknown = status_with(&unit, &path, |_| reply(false, "")).unwrap();
        assert_eq!(unknown["manager"], "unavailable");
        assert_eq!(unknown["loaded"], serde_json::Value::Null);
        assert_eq!(unknown["state"], "unknown");
        assert_eq!(unknown["installed"], true, "custody is still reported");
        assert_eq!(running["manager"], "answered");
        std::fs::write(&path, b"foreign").unwrap();
        assert!(status_with(&unit, &path, |_| reply(
            true,
            &shown("not-found", "inactive", "dead", 0, 0, 0, "")
        ))
        .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"foreign");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
