//! Per-user, exact-identity LaunchAgent ownership. Never manages unrelated services.
#[cfg(not(target_os = "linux"))]
use super::config;
use super::{
    config::{Config, Loaded},
    REFUSED,
};
use std::path::Path;

/// A fully resolved per-user LaunchAgent: the exact label plus the exact plist
/// bytes it must contain. `alternates` names earlier emitted shapes that
/// remain admissible for the same label so an upgrade never wedges a sealed
/// home's installed agent. The host and the gateway install through this one
/// custody path, which refuses foreign content at the selected label.
pub(crate) struct AgentSpec {
    // Only the macOS backend reads the label: other platforms cannot load
    // launchd services, so the field is inert there.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub label: String,
    pub plist: String,
    pub alternates: Vec<String>,
}
/// Resolve the host's selected agent, embedding its exact home and logs. Both
/// earlier emitted shapes stay admissible so an existing installation is still
/// ours; `install` replaces an outdated shape only while its label is unloaded.
pub(super) fn spec(home: &Path, c: &Config) -> Result<AgentSpec, String> {
    Ok(AgentSpec {
        label: c.label.clone(),
        plist: plist(home, c)?,
        alternates: vec![plist_v2(home, c)?, plist_v1(home, c)?],
    })
}

pub(crate) fn xml(value: &str) -> Result<String, String> {
    if value.chars().any(|c| c < ' ' || c == '\u{7f}') {
        return Err(REFUSED.into());
    }
    Ok(value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;"))
}
/// The bounded lifecycle event log inside the owner-private home. Only the
/// service's own event writer appends structured lines here.
pub(crate) const LOG_NAME: &str = "events.log";
/// Where launchd redirects the service's stdout and stderr: startup lines,
/// panics and coarse errors that are not structured events. The service
/// rotates it at startup once it exceeds its bound, keeping one generation, so
/// arbitrary supervisor output can never fill the event log or wedge startup.
pub(crate) const SUPERVISOR_LOG_NAME: &str = "supervisor.log";
pub(crate) const THROTTLE_INTERVAL_SECONDS: u64 = 30;
fn plist_v1(home: &Path, c: &Config) -> Result<String, String> {
    plist_shape(home, c, "/dev/null")
}
/// The second emitted shape sent launchd output into the event log itself.
fn plist_v2(home: &Path, c: &Config) -> Result<String, String> {
    let log = xml(home.join(LOG_NAME).to_str().ok_or(REFUSED)?)?;
    plist_shape(home, c, &log)
}
pub(super) fn plist(home: &Path, c: &Config) -> Result<String, String> {
    let log = xml(home.join(SUPERVISOR_LOG_NAME).to_str().ok_or(REFUSED)?)?;
    plist_shape(home, c, &log)
}
fn plist_shape(home: &Path, c: &Config, out: &str) -> Result<String, String> {
    let executable = xml(c.executable.to_str().ok_or(REFUSED)?)?;
    let home = xml(home.to_str().ok_or(REFUSED)?)?;
    let label = xml(&c.label)?;
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{label}</string>
<key>ProgramArguments</key><array><string>{executable}</string><string>private-host</string><string>serve</string><string>{home}</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ThrottleInterval</key><integer>{throttle}</integer>
<key>ExitTimeOut</key><integer>15</integer>
<key>Umask</key><integer>63</integer>
<key>ProcessType</key><string>Background</string>
<key>AbandonProcessGroup</key><false/>
<key>StandardOutPath</key><string>{out}</string>
<key>StandardErrorPath</key><string>{out}</string>
</dict></plist>
"#,
        throttle = THROTTLE_INTERVAL_SECONDS,
    ))
}
/// Earlier homes were sealed with launchd output discarded or sent into the
/// event log; those exact shapes remain admissible evidence so an upgrade never
/// invalidates a sealed home.
fn ours(spec: &AgentSpec, bytes: &[u8]) -> bool {
    spec.plist.as_bytes() == bytes
        || spec
            .alternates
            .iter()
            .any(|shape| shape.as_bytes() == bytes)
}
/// The sealed template is ours only if it matches a plist shape this software
/// can emit; legacy /dev/null output stays acceptable for existing homes.
pub(super) fn template_ours(loaded: &Loaded, template: &[u8]) -> Result<bool, String> {
    Ok(ours(&spec(&loaded.home, &loaded.config)?, template))
}

/// Generate only an exact one-port overlay template. This neither creates a key
/// nor installs or executes Tailcat, and never publishes its capability address.
/// Linux takes the systemd unit in `systemd::tailcat_unit` instead.
#[cfg(not(target_os = "linux"))]
pub(super) fn tailcat_plist(
    loaded: &Loaded,
    binary: &Path,
    key: &Path,
    output: &Path,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let port = tailcat_port(&loaded.config)?;
    let binary = binary
        .canonicalize()
        .map_err(|_| "selected Tailcat executable unavailable")?;
    let metadata = std::fs::metadata(&binary).map_err(|_| REFUSED)?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 || metadata.mode() & 0o6022 != 0 {
        return Err("Tailcat must be an explicit regular executable without set-ID or group/world write bits".into());
    }
    let key = config::resolve(key)?;
    // Custody validation only: the selected Tailcat binary authenticates its own
    // saved-key format at activation. Do not print or reinterpret key material.
    let retained_key = config::read(
        key.parent().ok_or(REFUSED)?,
        key.file_name().and_then(|n| n.to_str()).ok_or(REFUSED)?,
        65536,
    )?;
    if retained_key.is_empty() {
        return Err("saved Tailcat key must already exist; never use an ephemeral key".into());
    }
    let output = config::resolve(output)?;
    let label = format!("{}.tailcat", loaded.config.label);
    let argv = [
        binary.to_str().ok_or(REFUSED)?.to_owned(),
        format!("--key={}", key.to_str().ok_or(REFUSED)?),
        "serve".to_owned(),
        port,
    ];
    let arguments = argv
        .iter()
        .map(|arg| xml(arg).map(|v| format!("<string>{v}</string>")))
        .collect::<Result<Vec<_>, _>>()?
        .join("");
    let template = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{label}</string>
<key>ProgramArguments</key><array>{arguments}</array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ThrottleInterval</key><integer>30</integer>
<key>ExitTimeOut</key><integer>5</integer>
<key>Umask</key><integer>63</integer>
<key>ProcessType</key><string>Background</string>
<key>AbandonProcessGroup</key><false/>
<key>StandardOutPath</key><string>/dev/null</string>
<key>StandardErrorPath</key><string>/dev/null</string>
</dict></plist>
"#
    );
    config::write(
        output.parent().ok_or(REFUSED)?,
        output.file_name().and_then(|n| n.to_str()).ok_or(REFUSED)?,
        template.as_bytes(),
    )?;
    println!(
        "{}",
        serde_json::json!({"status":"template-created","launch_agent":output,"label":label,"installed":false})
    );
    Ok(())
}

// Pinned Tailcat v0.7.0 `serve` accepts bare ports and proxies them to
// localhost; it does not support the later upstream PORT:TARGET syntax.
pub(super) fn tailcat_port(config: &Config) -> Result<String, String> {
    super::require_tls(config)?;
    if config.listen.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        || config.listen.port() == 0
    {
        return Err(
            "Tailcat v0.7.0 template requires the host to bind exactly 127.0.0.1 on a nonzero port"
                .into(),
        );
    }
    Ok(config.listen.port().to_string())
}

#[cfg(test)]
pub(super) fn test_config(label: &str) -> Config {
    Config {
        version: 1,
        iroh: None,
        retained_generations: Vec::new(),
        advertise: Vec::new(),
        label: label.into(),
        listen: "127.0.0.1:9473".parse().unwrap(),
        tls_name: "relay.invalid".into(),
        executable: "/private/binary".into(),
        namespace: "a".repeat(64),
        credential_ids: vec!["b".repeat(32), "c".repeat(32)],
        credential_generations: Vec::new(),
        revoked_credential_ids: Default::default(),
        leaf_lifetime_seconds: None,
        mailbox: "mailbox".into(),
        created_at: 1,
        certificate_expires_at: 2,
        authority_expires_at: 3,
        files: Default::default(),
    }
}
#[cfg(test)]
mod shape_tests {
    use super::*;
    #[test]
    fn current_shape_redirects_supervisor_output_and_earlier_shapes_stay_ours() {
        let home = Path::new("/private/host-home");
        let config = test_config("me.vhalla.private-host.shape-test");
        let agent = spec(home, &config).unwrap();
        for key in ["StandardOutPath", "StandardErrorPath"] {
            assert!(agent.plist.contains(&format!(
                "<key>{key}</key><string>/private/host-home/supervisor.log</string>"
            )));
        }
        assert!(!agent.plist.contains("events.log"));
        let v2 = plist_v2(home, &config).unwrap();
        let v1 = plist_v1(home, &config).unwrap();
        assert!(
            v2.contains("<key>StandardOutPath</key><string>/private/host-home/events.log</string>")
        );
        assert!(v1.contains("<key>StandardOutPath</key><string>/dev/null</string>"));
        assert_eq!(v2.replace("events.log", "supervisor.log"), agent.plist);
        assert_eq!(agent.alternates, vec![v2.clone(), v1.clone()]);
        assert!(ours(&agent, agent.plist.as_bytes()));
        assert!(ours(&agent, v2.as_bytes()));
        assert!(ours(&agent, v1.as_bytes()));
        assert!(!ours(&agent, v2.replace("30", "31").as_bytes()));
        assert!(!ours(&agent, b"foreign retained configuration"));
        // A sealed home from either earlier version still validates.
        for template in [&v2, &v1] {
            assert!(template_ours(
                &Loaded {
                    home: home.to_path_buf(),
                    config: config.clone()
                },
                template.as_bytes()
            )
            .unwrap());
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn agent_status(_: &AgentSpec) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({"supported":false,"loaded":false,"installed":false}))
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn agent_install(_: &AgentSpec) -> Result<(), String> {
    Err("LaunchAgent installation requires macOS; use foreground serve on this platform".into())
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn agent_uninstall(_: &AgentSpec) -> Result<(), String> {
    Err("LaunchAgent removal requires macOS".into())
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn agent_install_quiet(spec: &AgentSpec) -> Result<(), String> {
    agent_install(spec)
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn agent_uninstall_quiet(spec: &AgentSpec) -> Result<(), String> {
    agent_uninstall(spec)
}
// Linux hosts are supervised by a per-user systemd unit through the same
// exact-identity custody rules; see `systemd.rs`.
#[cfg(target_os = "linux")]
pub(super) fn status(loaded: &Loaded) -> Result<serde_json::Value, String> {
    super::systemd::status(loaded)
}
#[cfg(target_os = "linux")]
pub(super) fn install(loaded: &Loaded) -> Result<(), String> {
    super::systemd::install(loaded)
}
#[cfg(target_os = "linux")]
pub(super) fn uninstall(loaded: &Loaded) -> Result<(), String> {
    super::systemd::uninstall(loaded)
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(super) fn status(_: &Loaded) -> Result<serde_json::Value, String> {
    agent_status(&AgentSpec {
        label: String::new(),
        plist: String::new(),
        alternates: Vec::new(),
    })
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(super) fn install(_: &Loaded) -> Result<(), String> {
    agent_install(&AgentSpec {
        label: String::new(),
        plist: String::new(),
        alternates: Vec::new(),
    })
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(super) fn uninstall(_: &Loaded) -> Result<(), String> {
    agent_uninstall(&AgentSpec {
        label: String::new(),
        plist: String::new(),
        alternates: Vec::new(),
    })
}

#[cfg(target_os = "macos")]
mod mac {
    use super::*;
    use std::{
        ffi::OsString,
        fs,
        io::Read,
        os::unix::fs::{DirBuilderExt, MetadataExt},
        path::PathBuf,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    use vhalla_custody::{self as custody, Owner};
    const MAX_OUTPUT: u64 = 65536;
    struct Reply {
        success: bool,
        code: Option<i32>,
        stdout: String,
        stderr: String,
    }
    fn command_timeout(args: &[OsString]) -> Duration {
        // Even a clean stopped job can make kickstart wait for its configured
        // throttle. The exact no-flags resume must outlast that interval. Other
        // command shapes retain the shorter probe/mutation deadline.
        match args {
            [verb, _target] if verb == "kickstart" => {
                Duration::from_secs(THROTTLE_INTERVAL_SECONDS + 5)
            }
            _ => Duration::from_secs(10),
        }
    }
    fn command(args: &[OsString]) -> Result<Reply, String> {
        let mut child = Command::new("/bin/launchctl")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "launchctl unavailable")?;
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
        let deadline = Instant::now() + command_timeout(args);
        let result = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err("launchctl did not complete within its fixed deadline");
                }
            }
        };
        let stdout = out.join().map_err(|_| REFUSED)?.map_err(|_| REFUSED)?;
        let stderr = err.join().map_err(|_| REFUSED)?.map_err(|_| REFUSED)?;
        if stdout.len() > MAX_OUTPUT as usize || stderr.len() > MAX_OUTPUT as usize {
            return Err("launchctl output exceeded its fixed bound".into());
        }
        let status = result?;
        Ok(Reply {
            success: status.success(),
            code: status.code(),
            stdout: String::from_utf8(stdout).map_err(|_| REFUSED)?,
            stderr: String::from_utf8(stderr).map_err(|_| REFUSED)?,
        })
    }
    fn domain() -> String {
        format!("gui/{}", rustix::process::geteuid().as_raw())
    }
    fn target(spec: &AgentSpec) -> String {
        format!("{}/{}", domain(), spec.label)
    }
    fn directory(create: bool) -> Result<PathBuf, String> {
        let base = PathBuf::from(std::env::var_os("HOME").ok_or("user home unavailable")?)
            .canonicalize()
            .map_err(|_| REFUSED)?;
        let uid = rustix::process::geteuid().as_raw();
        let base_meta = fs::symlink_metadata(&base).map_err(|_| REFUSED)?;
        if !base_meta.is_dir() || base_meta.uid() != uid || base_meta.mode() & 0o022 != 0 {
            return Err(REFUSED.into());
        }
        let mut path = base;
        for part in ["Library", "LaunchAgents"] {
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
                    return Ok(path.join(if part == "Library" {
                        "LaunchAgents"
                    } else {
                        ""
                    }));
                }
                Err(_) => return Err(REFUSED.into()),
                Ok(_) => (),
            }
            let metadata = fs::symlink_metadata(&path).map_err(|_| REFUSED)?;
            if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
                return Err("LaunchAgents ancestry must be owned directories without group/world write or symlinks".into());
            }
        }
        Ok(path)
    }
    fn destination(spec: &AgentSpec, create: bool) -> Result<PathBuf, String> {
        Ok(directory(create)?.join(format!("{}.plist", spec.label)))
    }
    fn expected(spec: &AgentSpec, path: &Path) -> Result<bool, String> {
        let owner = Owner::current().map_err(|_| REFUSED)?;
        if !custody::private_file_present(path, owner, 65536).map_err(|_| REFUSED)? {
            return Ok(false);
        }
        if !ours(
            spec,
            &custody::read_private_file(path, owner, 65536).map_err(|_| REFUSED)?,
        ) {
            return Err("refusing a foreign or changed LaunchAgent at the selected label".into());
        }
        Ok(true)
    }
    /// One read of the installed template: `None` when absent, `Some(true)`
    /// for the exact current shape, `Some(false)` for an admissible earlier
    /// shape. Foreign content refuses. Decisions derive from these bytes, never
    /// from a second read.
    fn installed_shape(spec: &AgentSpec, path: &Path) -> Result<Option<bool>, String> {
        let owner = Owner::current().map_err(|_| REFUSED)?;
        if !custody::private_file_present(path, owner, 65536).map_err(|_| REFUSED)? {
            return Ok(None);
        }
        let bytes = custody::read_private_file(path, owner, 65536).map_err(|_| REFUSED)?;
        if !ours(spec, &bytes) {
            return Err("refusing a foreign or changed LaunchAgent at the selected label".into());
        }
        Ok(Some(bytes == spec.plist.as_bytes()))
    }
    /// Whether the installed template is the exact current shape rather than
    /// an admissible earlier one. Absent or foreign files are not exact.
    fn exact(spec: &AgentSpec, path: &Path) -> Result<bool, String> {
        Ok(installed_shape(spec, path)? == Some(true))
    }
    // Only the exact service-not-found response proves absence. IPC errors,
    // unavailable domains, permissions failures and signals preserve custody.
    fn classify_service(spec: &AgentSpec, reply: Reply) -> Result<Reply, String> {
        let absent = format!(
            "Bad request.\nCould not find service \"{}\" in domain for user gui: {}\n",
            spec.label,
            rustix::process::geteuid().as_raw(),
        );
        if reply.success
            || (reply.code == Some(113) && reply.stdout.is_empty() && reply.stderr == absent)
        {
            Ok(reply)
        } else {
            Err("launchctl could not prove the selected service state; preserve its plist and exact home".into())
        }
    }
    fn loaded(spec: &AgentSpec) -> Result<Reply, String> {
        classify_service(spec, command(&["print".into(), target(spec).into()])?)
    }
    fn field<'a>(stdout: &'a str, name: &str) -> Option<&'a str> {
        stdout
            .lines()
            .map(str::trim)
            .find_map(|line| line.strip_prefix(name).and_then(|v| v.strip_prefix(" = ")))
    }
    pub(crate) fn agent_status(spec: &AgentSpec) -> Result<serde_json::Value, String> {
        let path = destination(spec, false)?;
        let installed = expected(spec, &path)?;
        // An earlier emitted shape is still ours, but launchd is then using its
        // older output redirection: `uninstall` and `install` refresh it.
        let current = installed && exact(spec, &path)?;
        let reply = loaded(spec)?;
        let state = field(&reply.stdout, "state").unwrap_or("unavailable");
        let pid = field(&reply.stdout, "pid").and_then(|v| v.parse::<u64>().ok());
        let last_exit = field(&reply.stdout, "last exit code").and_then(|v| v.parse::<i64>().ok());
        // KeepAlive{SuccessfulExit:false} means a nonzero exit with no live
        // pid is launchd rescheduling a failing service — suspicion only.
        let restart_loop_suspected =
            reply.success && pid.is_none() && last_exit.is_some_and(|code| code != 0);
        Ok(
            serde_json::json!({"supported":true,"installed":installed,"launch_agent_current":current,"loaded":reply.success,"launch_agent":path,"state":state,"pid":pid,"last_exit_code":last_exit,"restart_loop_suspected":restart_loop_suspected}),
        )
    }
    pub(crate) fn agent_install(spec: &AgentSpec) -> Result<(), String> {
        install_selected(spec, || destination(spec, true), command)?;
        println!(
            "{}",
            serde_json::json!({"status":"installed","label":spec.label,"health":"not yet qualified; check TLS and durable retention separately"})
        );
        Ok(())
    }
    #[cfg(feature = "headless")]
    pub(crate) fn agent_install_quiet(spec: &AgentSpec) -> Result<(), String> {
        install_or_resume_selected(spec, || destination(spec, true), command, true)
    }
    fn install_selected(
        spec: &AgentSpec,
        destination: impl FnOnce() -> Result<PathBuf, String>,
        run: impl FnMut(&[OsString]) -> Result<Reply, String>,
    ) -> Result<(), String> {
        install_or_resume_selected(spec, destination, run, false)
    }
    fn install_or_resume_selected(
        spec: &AgentSpec,
        destination: impl FnOnce() -> Result<PathBuf, String>,
        mut run: impl FnMut(&[OsString]) -> Result<Reply, String>,
        resume: bool,
    ) -> Result<(), String> {
        // The exact service probe also proves that this GUI domain exists.
        // Never list the entire domain: a user's unrelated services can exceed
        // the bounded output and are outside this command's selection.
        let probe = ["print".into(), target(spec).into()];
        let before = classify_service(spec, run(&probe)?)?;
        if before.success {
            if resume {
                return resume_selected(spec, &destination()?, before, run);
            }
            return Err(
                "this exact label is already loaded; inspect status before changing it".into(),
            );
        }
        let path = destination()?;
        // An installed earlier emitted shape is ours but outdated. The label is
        // proven unloaded, so replace it with the exact current shape before
        // bootstrap; the file that bootstraps is always the one this software
        // emits now. Removal and the decision to remove use the same bytes.
        let installed = installed_shape(spec, &path)?;
        if installed == Some(false) {
            fs::remove_file(&path).map_err(|_| REFUSED)?;
        }
        if installed != Some(true) {
            use std::io::Write;
            let mut file = custody::create_private_file(&path).map_err(|_| REFUSED)?;
            file.write_all(spec.plist.as_bytes())
                .and_then(|()| file.sync_all())
                .and_then(|()| {
                    fs::File::open(
                        path.parent()
                            .ok_or_else(|| std::io::Error::other("parent"))?,
                    )?
                    .sync_all()
                })
                .map_err(|_| REFUSED)?;
        }
        if !exact(spec, &path)? {
            return Err(REFUSED.into());
        }
        if !run(&[
            "bootstrap".into(),
            domain().into(),
            path.as_os_str().to_owned(),
        ])?
        .success
        {
            return Err(
                "LaunchAgent bootstrap refused; exact plist and home were preserved for inspection"
                    .into(),
            );
        }
        if !classify_service(spec, run(&probe)?)?.success {
            return Err("bootstrap returned without a verifiable loaded service; preserve exact home and plist".into());
        }
        Ok(())
    }
    fn resume_selected(
        spec: &AgentSpec,
        path: &Path,
        before: Reply,
        mut run: impl FnMut(&[OsString]) -> Result<Reply, String>,
    ) -> Result<(), String> {
        // A clean control.stop leaves the job loaded because this template
        // restarts only failed exits. Resume just that exact successful stop;
        // never kill a live process or interrupt launchd's failure backoff.
        if field(&before.stdout, "path") != path.to_str()
            || field(&before.stdout, "state") != Some("not running")
            || field(&before.stdout, "pid").is_some()
            || field(&before.stdout, "last exit code") != Some("0")
        {
            return Err("the loaded service is not a verified successful stop of this exact LaunchAgent; inspect status before reinstalling".into());
        }
        let owner = Owner::current().map_err(|_| REFUSED)?;
        let selected = custody::open_private_file(path, owner, 65536).map_err(|_| REFUSED)?;
        let check = || -> Result<(), String> {
            if !exact(spec, path)? || !custody::same_file(path, &selected).map_err(|_| REFUSED)? {
                return Err("the selected LaunchAgent changed; preserve its plist and home".into());
            }
            Ok(())
        };
        check()?;
        // No -k: if another actor starts it after the probe, this command
        // cannot terminate that process to force a restart.
        if !run(&["kickstart".into(), target(spec).into()])?.success {
            return Err(
                "LaunchAgent resume refused; exact plist and home were preserved for inspection"
                    .into(),
            );
        }
        check()?;
        let after = classify_service(spec, run(&["print".into(), target(spec).into()])?)?;
        if !after.success || field(&after.stdout, "path") != path.to_str() {
            return Err(
                "resume returned without the exact loaded LaunchAgent; preserve its plist and home"
                    .into(),
            );
        }
        check()
    }
    pub(crate) fn agent_uninstall(spec: &AgentSpec) -> Result<(), String> {
        agent_uninstall_quiet(spec)?;
        println!(
            "{}",
            serde_json::json!({"status":"uninstalled","label":spec.label,"home_preserved":true})
        );
        Ok(())
    }
    pub(crate) fn agent_uninstall_quiet(spec: &AgentSpec) -> Result<(), String> {
        let path = destination(spec, false)?;
        uninstall_at(spec, &path, command)
    }
    fn uninstall_at(
        spec: &AgentSpec,
        path: &Path,
        mut run: impl FnMut(&[OsString]) -> Result<Reply, String>,
    ) -> Result<(), String> {
        let installed = expected(spec, path)?;
        let probe = ["print".into(), target(spec).into()];
        let active = classify_service(spec, run(&probe)?)?;
        if active.success {
            let wanted = format!("path = {}", path.to_str().ok_or(REFUSED)?);
            if !installed || !active.stdout.lines().any(|line| line.trim() == wanted) {
                return Err("loaded service does not identify the exact owned LaunchAgent; refusing to stop it".into());
            }
            if !run(&["bootout".into(), target(spec).into()])?.success {
                return Err(
                    "LaunchAgent stop refused; preserve the installed plist and host home".into(),
                );
            }
            let deadline = Instant::now() + Duration::from_secs(20);
            while classify_service(spec, run(&probe)?)?.success {
                if Instant::now() >= deadline {
                    return Err(
                        "LaunchAgent has not stopped; preserve its plist and exact custody".into(),
                    );
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
        if installed {
            if !expected(spec, path)? {
                return Err(REFUSED.into());
            }
            fs::remove_file(path).map_err(|_| REFUSED)?;
            fs::File::open(path.parent().ok_or(REFUSED)?)
                .and_then(|f| f.sync_all())
                .map_err(|_| REFUSED)?;
        }
        Ok(())
    }
    pub(in crate::private_host) fn status(loaded: &Loaded) -> Result<serde_json::Value, String> {
        agent_status(&spec(&loaded.home, &loaded.config)?)
    }
    pub(in crate::private_host) fn install(loaded: &Loaded) -> Result<(), String> {
        if loaded.config.iroh.is_none()
            && time::OffsetDateTime::now_utc().unix_timestamp()
                >= loaded.config.certificate_expires_at
        {
            return Err("refusing to install an expired TLS host".into());
        }
        agent_install(&spec(&loaded.home, &loaded.config)?)
    }
    pub(in crate::private_host) fn uninstall(loaded: &Loaded) -> Result<(), String> {
        agent_uninstall(&spec(&loaded.home, &loaded.config)?)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn resume_fixture() -> (tempfile::TempDir, AgentSpec, PathBuf) {
            let temp = tempfile::TempDir::new().unwrap();
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let agent = spec(temp.path(), &test_config("me.vhalla.daemon.resume-test")).unwrap();
            let path = temp.path().join("selected.plist");
            fs::write(&path, &agent.plist).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            (temp, agent, path)
        }
        fn stopped_reply(path: &Path) -> Reply {
            Reply {
                success: true,
                code: Some(0),
                stdout: format!(
                    "path = {}\nstate = not running\nlast exit code = 0\n",
                    path.display()
                ),
                stderr: String::new(),
            }
        }

        #[test]
        fn exact_resume_deadline_covers_the_template_throttle_without_widening_other_commands() {
            let (_temp, agent, path) = resume_fixture();
            let throttle: u64 = agent
                .plist
                .split_once("<key>ThrottleInterval</key><integer>")
                .unwrap()
                .1
                .split_once("</integer>")
                .unwrap()
                .0
                .parse()
                .unwrap();
            let resume = [OsString::from("kickstart"), target(&agent).into()];
            assert_eq!(command_timeout(&resume), Duration::from_secs(35));
            assert!(command_timeout(&resume) > Duration::from_secs(throttle));
            for args in [
                vec!["print".into(), target(&agent).into()],
                vec!["bootout".into(), target(&agent).into()],
                vec!["bootstrap".into(), domain().into(), path.into_os_string()],
                vec!["kickstart".into()],
                vec!["kickstart".into(), "-k".into(), target(&agent).into()],
                vec!["kickstart".into(), "-p".into(), target(&agent).into()],
                vec!["kickstart".into(), target(&agent).into(), "extra".into()],
            ] {
                assert_eq!(command_timeout(&args), Duration::from_secs(10), "{args:?}");
            }
        }

        #[test]
        fn managed_install_resumes_an_exact_cleanly_stopped_job_without_replacing_its_plist() {
            let (_temp, agent, path) = resume_fixture();
            let retained =
                custody::open_private_file(&path, Owner::current().unwrap(), 65536).unwrap();
            let mut calls = 0;
            install_or_resume_selected(
                &agent,
                || Ok(path.clone()),
                |args| {
                    calls += 1;
                    match calls {
                        1 => {
                            assert_eq!(args, [OsString::from("print"), target(&agent).into()]);
                            Ok(stopped_reply(&path))
                        }
                        2 => {
                            assert_eq!(args, [OsString::from("kickstart"), target(&agent).into()]);
                            Ok(stopped_reply(&path))
                        }
                        3 => {
                            assert_eq!(args, [OsString::from("print"), target(&agent).into()]);
                            let mut reply = stopped_reply(&path);
                            reply.stdout =
                                format!("path = {}\nstate = running\npid = 123\n", path.display());
                            Ok(reply)
                        }
                        _ => panic!("unexpected supervisor call"),
                    }
                },
                true,
            )
            .unwrap();
            assert_eq!(calls, 3);
            assert!(custody::same_file(&path, &retained).unwrap());
            assert_eq!(fs::read_to_string(&path).unwrap(), agent.plist);
        }

        #[test]
        fn managed_resume_refuses_running_backoff_unknown_and_foreign_jobs() {
            let (_temp, agent, path) = resume_fixture();
            let clean = stopped_reply(&path).stdout;
            for stdout in [
                clean.replace("not running", "running") + "pid = 123\n",
                clean.clone() + "pid = 123\n",
                clean.replace("last exit code = 0", "last exit code = 1"),
                clean.replace("last exit code = 0\n", ""),
                clean.replace("not running", "waiting"),
                clean.replace(path.to_str().unwrap(), "/foreign/selected.plist"),
            ] {
                let mut calls = 0;
                assert!(install_or_resume_selected(
                    &agent,
                    || Ok(path.clone()),
                    |args| {
                        calls += 1;
                        assert_eq!(args[0], "print");
                        let mut reply = stopped_reply(&path);
                        reply.stdout = stdout.clone();
                        Ok(reply)
                    },
                    true,
                )
                .is_err());
                assert_eq!(calls, 1);
                assert_eq!(fs::read_to_string(&path).unwrap(), agent.plist);
            }
            fs::write(&path, b"foreign plist").unwrap();
            let mut calls = 0;
            assert!(install_or_resume_selected(
                &agent,
                || Ok(path.clone()),
                |_| {
                    calls += 1;
                    Ok(stopped_reply(&path))
                },
                true,
            )
            .is_err());
            assert_eq!(calls, 1);
            assert_eq!(fs::read(&path).unwrap(), b"foreign plist");
        }

        #[test]
        fn managed_resume_preserves_evidence_after_refusal_replacement_or_identity_drift() {
            for fault in 0..3 {
                let (temp, agent, path) = resume_fixture();
                let retained = temp.path().join("retained.plist");
                let mut calls = 0;
                assert!(install_or_resume_selected(
                    &agent,
                    || Ok(path.clone()),
                    |args| {
                        calls += 1;
                        let mut reply = stopped_reply(&path);
                        match calls {
                            1 => assert_eq!(args[0], "print"),
                            2 => {
                                assert_eq!(
                                    args,
                                    [OsString::from("kickstart"), target(&agent).into()]
                                );
                                if fault == 0 {
                                    reply.success = false;
                                    reply.code = Some(5);
                                } else if fault == 1 {
                                    fs::rename(&path, &retained).unwrap();
                                    fs::write(&path, &agent.plist).unwrap();
                                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                                        .unwrap();
                                }
                            }
                            3 if fault == 2 => {
                                assert_eq!(args[0], "print");
                                reply.stdout =
                                    "path = /foreign/selected.plist\nstate = running\npid = 123\n"
                                        .to_owned();
                            }
                            _ => panic!("unexpected supervisor call"),
                        }
                        Ok(reply)
                    },
                    true,
                )
                .is_err());
                assert_eq!(calls, if fault == 2 { 3 } else { 2 });
                assert_eq!(fs::read_to_string(&path).unwrap(), agent.plist);
                if fault == 1 {
                    assert_eq!(fs::read_to_string(retained).unwrap(), agent.plist);
                }
            }
        }

        #[test]
        fn managed_install_bootstraps_an_unloaded_job_without_kickstart() {
            let (_temp, agent, path) = resume_fixture();
            let mut calls = 0;
            install_or_resume_selected(
                &agent,
                || Ok(path.clone()),
                |args| {
                    calls += 1;
                    if calls == 1 {
                        assert_eq!(args[0], "print");
                        Ok(Reply {
                            success: false,
                            code: Some(113),
                            stdout: String::new(),
                            stderr: format!("Bad request.\nCould not find service \"{}\" in domain for user gui: {}\n", agent.label, rustix::process::geteuid().as_raw()),
                        })
                    } else {
                        assert_eq!(args[0], if calls == 2 { "bootstrap" } else { "print" });
                        assert!(calls <= 3);
                        Ok(stopped_reply(&path))
                    }
                },
                true,
            )
            .unwrap();
            assert_eq!(calls, 3);
            assert_eq!(fs::read_to_string(path).unwrap(), agent.plist);
        }

        #[test]
        fn install_probes_only_exact_service_and_never_lists_the_gui_domain() {
            let home = std::env::temp_dir().join(format!(
                "valhalla-launch-agent-install-{}",
                std::process::id()
            ));
            fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
            let loaded = Loaded {
                home: home.clone(),
                config: Config {
                    version: 1,
                    iroh: None,
                    retained_generations: Vec::new(),
                    advertise: Vec::new(),
                    label: "me.vhalla.private-host.install-test".into(),
                    listen: "127.0.0.1:9473".parse().unwrap(),
                    tls_name: "relay.invalid".into(),
                    executable: "/private/binary".into(),
                    namespace: "a".repeat(64),
                    credential_ids: vec!["b".repeat(32), "c".repeat(32)],
                    credential_generations: Vec::new(),
                    revoked_credential_ids: Default::default(),
                    leaf_lifetime_seconds: None,
                    mailbox: "mailbox".into(),
                    created_at: 1,
                    certificate_expires_at: 2,
                    authority_expires_at: 3,
                    files: Default::default(),
                },
            };
            let path = home.join("selected.plist");
            let agent = spec(&loaded.home, &loaded.config).unwrap();
            let absent = format!(
                "Bad request.\nCould not find service \"{}\" in domain for user gui: {}\n",
                loaded.config.label,
                rustix::process::geteuid().as_raw()
            );
            for success in [true, false] {
                let result = install_selected(
                    &agent,
                    || panic!("probe refusal must precede destination creation"),
                    |args| {
                        assert_eq!(args, [OsString::from("print"), target(&agent).into()]);
                        Ok(Reply {
                            success,
                            code: Some(if success { 0 } else { 5 }),
                            stdout: String::new(),
                            stderr: String::new(),
                        })
                    },
                );
                assert!(result.is_err());
                assert!(!path.exists());
            }
            let mut calls = 0;
            install_selected(
                &agent,
                || Ok(path.clone()),
                |args| {
                    calls += 1;
                    match calls {
                        1 => {
                            assert_eq!(args, [OsString::from("print"), target(&agent).into()]);
                            Ok(Reply {
                                success: false,
                                code: Some(113),
                                stdout: String::new(),
                                stderr: absent.clone(),
                            })
                        }
                        2 => {
                            assert_eq!(
                                args,
                                [
                                    OsString::from("bootstrap"),
                                    domain().into(),
                                    path.as_os_str().to_owned()
                                ]
                            );
                            assert!(expected(&agent, &path).unwrap());
                            Ok(Reply {
                                success: true,
                                code: Some(0),
                                stdout: String::new(),
                                stderr: String::new(),
                            })
                        }
                        3 => {
                            assert_eq!(args, [OsString::from("print"), target(&agent).into()]);
                            Ok(Reply {
                                success: true,
                                code: Some(0),
                                stdout: format!("path = {}\n", path.display()),
                                stderr: String::new(),
                            })
                        }
                        _ => panic!("unexpected launchctl call"),
                    }
                },
            )
            .unwrap();
            assert_eq!(calls, 3);
            assert!(expected(&agent, &path).unwrap());
            fs::remove_dir_all(home).unwrap();
        }
        #[test]
        fn install_replaces_an_outdated_owned_shape_only_while_its_label_is_unloaded() {
            let home = std::env::temp_dir().join(format!(
                "valhalla-launch-agent-upgrade-{}",
                std::process::id()
            ));
            fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
            let config = test_config("me.vhalla.private-host.upgrade-test");
            let path = home.join("selected.plist");
            let agent = spec(&home, &config).unwrap();
            let outdated = plist_v2(&home, &config).unwrap();
            fs::write(&path, &outdated).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(expected(&agent, &path).unwrap());
            assert!(!exact(&agent, &path).unwrap());
            // A loaded label refuses before touching the installed template.
            assert!(install_selected(
                &agent,
                || Ok(path.clone()),
                |_| Ok(Reply {
                    success: true,
                    code: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                }),
            )
            .is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), outdated);
            let absent = format!(
                "Bad request.\nCould not find service \"{}\" in domain for user gui: {}\n",
                config.label,
                rustix::process::geteuid().as_raw()
            );
            let mut calls = 0;
            install_selected(
                &agent,
                || Ok(path.clone()),
                |args| {
                    calls += 1;
                    match calls {
                        1 => Ok(Reply {
                            success: false,
                            code: Some(113),
                            stdout: String::new(),
                            stderr: absent.clone(),
                        }),
                        2 => {
                            assert_eq!(args[0], "bootstrap");
                            assert!(
                                exact(&agent, &path).unwrap(),
                                "bootstrap sees the current shape"
                            );
                            Ok(Reply {
                                success: true,
                                code: Some(0),
                                stdout: String::new(),
                                stderr: String::new(),
                            })
                        }
                        _ => Ok(Reply {
                            success: true,
                            code: Some(0),
                            stdout: format!("path = {}\n", path.display()),
                            stderr: String::new(),
                        }),
                    }
                },
            )
            .unwrap();
            assert_eq!(calls, 3);
            assert_eq!(fs::read_to_string(&path).unwrap(), agent.plist);
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
            // A foreign template is never replaced, even while unloaded.
            fs::write(&path, b"foreign retained configuration").unwrap();
            assert!(install_selected(
                &agent,
                || Ok(path.clone()),
                |_| Ok(Reply {
                    success: false,
                    code: Some(113),
                    stdout: String::new(),
                    stderr: absent.clone(),
                }),
            )
            .is_err());
            assert_eq!(fs::read(&path).unwrap(), b"foreign retained configuration");
            fs::remove_dir_all(home).unwrap();
        }
        #[test]
        fn uninstall_requires_exact_absence_and_preserves_plist_after_probe_failures() {
            let home = std::env::temp_dir().join(format!(
                "valhalla-launch-agent-probe-{}",
                std::process::id()
            ));
            fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
            let loaded = Loaded {
                home: home.clone(),
                config: Config {
                    version: 1,
                    iroh: None,
                    retained_generations: Vec::new(),
                    advertise: Vec::new(),
                    label: "me.vhalla.private-host.probe-test".into(),
                    listen: "127.0.0.1:9473".parse().unwrap(),
                    tls_name: "relay.invalid".into(),
                    executable: "/private/binary".into(),
                    namespace: "a".repeat(64),
                    credential_ids: vec!["b".repeat(32), "c".repeat(32)],
                    credential_generations: Vec::new(),
                    revoked_credential_ids: Default::default(),
                    leaf_lifetime_seconds: None,
                    mailbox: "mailbox".into(),
                    created_at: 1,
                    certificate_expires_at: 2,
                    authority_expires_at: 3,
                    files: Default::default(),
                },
            };
            let path = home.join("selected.plist");
            let agent = spec(&loaded.home, &loaded.config).unwrap();
            let exact = plist(&home, &loaded.config).unwrap();
            fs::write(&path, &exact).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let absent = format!(
                "Bad request.\nCould not find service \"{}\" in domain for user gui: {}\n",
                loaded.config.label,
                rustix::process::geteuid().as_raw()
            );
            // Include permission/IPC errors, a signal, a different target, an
            // unavailable domain, and plausible but unproven output.
            for (code, stdout, stderr) in [
                (Some(5), "", "Input/output error".to_owned()),
                (Some(1), "", "Operation not permitted".to_owned()),
                (None, "", absent.clone()),
                (
                    Some(113),
                    "",
                    absent.replace(&loaded.config.label, "foreign.service"),
                ),
                (Some(113), "", "Could not find domain for user".to_owned()),
                (Some(113), "unexpected", absent.clone()),
            ] {
                let mut calls = 0;
                let outcome = uninstall_at(&agent, &path, |args| {
                    calls += 1;
                    assert_eq!(args, [OsString::from("print"), target(&agent).into()]);
                    Ok(Reply {
                        success: false,
                        code,
                        stdout: stdout.into(),
                        stderr: stderr.clone(),
                    })
                });
                assert!(outcome.is_err());
                assert_eq!(calls, 1);
                assert_eq!(fs::read_to_string(&path).unwrap(), exact);
            }
            // Even after a successful bootout, an uncertain follow-up must
            // preserve the installed template, allowing an exact later retry.
            let mut calls = 0;
            assert!(uninstall_at(&agent, &path, |args| {
                calls += 1;
                match calls {
                    1 => Ok(Reply {
                        success: true,
                        code: Some(0),
                        stdout: format!("  path = {}\n", path.display()),
                        stderr: String::new(),
                    }),
                    2 => {
                        assert_eq!(args[0], "bootout");
                        Ok(Reply {
                            success: true,
                            code: Some(0),
                            stdout: String::new(),
                            stderr: String::new(),
                        })
                    }
                    _ => Ok(Reply {
                        success: false,
                        code: Some(5),
                        stdout: String::new(),
                        stderr: "Input/output error".into(),
                    }),
                }
            })
            .is_err());
            assert_eq!(calls, 3);
            assert_eq!(fs::read_to_string(&path).unwrap(), exact);
            // The exact observed macOS absence response authorizes removal of
            // only this matching installed template, never the private home.
            uninstall_at(&agent, &path, |_| {
                Ok(Reply {
                    success: false,
                    code: Some(113),
                    stdout: String::new(),
                    stderr: absent.clone(),
                })
            })
            .unwrap();
            assert!(!path.exists());
            assert!(home.is_dir());
            fs::remove_dir_all(home).unwrap();
        }
        #[test]
        fn installed_plist_custody_refuses_foreign_modes_and_links_without_mutation() {
            let home = std::env::temp_dir().join(format!(
                "valhalla-launch-agent-custody-{}",
                std::process::id()
            ));
            fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
            let loaded = Loaded {
                home: home.clone(),
                config: Config {
                    version: 1,
                    iroh: None,
                    retained_generations: Vec::new(),
                    advertise: Vec::new(),
                    label: "me.vhalla.private-host.test".into(),
                    listen: "127.0.0.1:9473".parse().unwrap(),
                    tls_name: "relay.invalid".into(),
                    executable: "/private/binary".into(),
                    namespace: "a".repeat(64),
                    credential_ids: vec!["b".repeat(32), "c".repeat(32)],
                    credential_generations: Vec::new(),
                    revoked_credential_ids: Default::default(),
                    leaf_lifetime_seconds: None,
                    mailbox: "mailbox".into(),
                    created_at: 1,
                    certificate_expires_at: 2,
                    authority_expires_at: 3,
                    files: Default::default(),
                },
            };
            let target = home.join("selected.plist");
            let agent = spec(&loaded.home, &loaded.config).unwrap();
            assert!(!expected(&agent, &target).unwrap());
            fs::write(&target, plist(&home, &loaded.config).unwrap()).unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(expected(&agent, &target).unwrap());
            fs::write(&target, b"foreign retained configuration").unwrap();
            assert!(expected(&agent, &target).is_err());
            assert_eq!(
                fs::read(&target).unwrap(),
                b"foreign retained configuration"
            );
            fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(expected(&agent, &target).is_err());
            let link = home.join("linked.plist");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(expected(&agent, &link).is_err());
            assert!(fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink());
            fs::remove_dir_all(home).unwrap();
        }
    }
}
#[cfg(target_os = "macos")]
pub(crate) use mac::{agent_install, agent_status, agent_uninstall};
#[cfg(all(target_os = "macos", feature = "headless"))]
pub(crate) use mac::{agent_install_quiet, agent_uninstall_quiet};
#[cfg(target_os = "macos")]
pub(super) use mac::{install, status, uninstall};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn launch_agent_escapes_paths_and_has_bounded_nonsecret_supervision() {
        let mut c = Config {
            version: 1,
            iroh: None,
            retained_generations: Vec::new(),
            advertise: Vec::new(),
            label: "me.vhalla.private-host.test".into(),
            listen: "127.0.0.1:9473".parse().unwrap(),
            tls_name: "relay.invalid".into(),
            executable: "/private/binary & tool".into(),
            namespace: "a".repeat(64),
            credential_ids: vec!["b".repeat(32), "c".repeat(32)],
            credential_generations: Vec::new(),
            revoked_credential_ids: Default::default(),
            leaf_lifetime_seconds: None,
            mailbox: "mailbox".into(),
            created_at: 1,
            certificate_expires_at: 2,
            authority_expires_at: 3,
            files: Default::default(),
        };
        let plist = plist(Path::new("/private/home <one>"), &c).unwrap();
        assert!(plist.contains("/private/binary &amp; tool"));
        assert!(plist.contains("/private/home &lt;one&gt;"));
        assert!(plist.contains("<key>ThrottleInterval</key><integer>30</integer>"));
        assert!(plist.contains("<key>ExitTimeOut</key><integer>15</integer>"));
        assert!(plist.contains("<key>SuccessfulExit</key><false/>"));
        assert!(!plist.contains(&c.namespace));
        assert!(!plist.contains("token"));
        assert!(!plist.contains("sh</string>"));
        assert!(xml("bad\npath").is_err());
        assert_eq!(tailcat_port(&c).unwrap(), "9473");
        c.listen = "127.0.0.2:9473".parse().unwrap();
        assert!(tailcat_port(&c).is_err());
        c.listen = "[::1]:9473".parse().unwrap();
        assert!(tailcat_port(&c).is_err());
    }
}
