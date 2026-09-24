//! Per-user gateway LaunchAgent selection through the shared custody path.
use super::{resolve, REFUSED};
use crate::private_host::launchd::{self, AgentSpec, LOG_NAME, SUPERVISOR_LOG_NAME};
use sha2::{Digest, Sha256};
use std::path::Path;

/// The label is bound to the canonical config path, never to file contents:
/// rotating configuration never transfers custody of another service.
pub(super) fn label(config: &Path) -> Result<String, String> {
    let resolved = resolve(config)?;
    let digest = Sha256::digest(resolved.to_str().ok_or(REFUSED)?.as_bytes());
    Ok(format!(
        "me.vhalla.private-gateway.{}",
        digest[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}
/// Exact agent: installed executable plus absolute config path, with launchd
/// output redirected into the bounded supervisor log next to the config. The
/// earlier shape that sent that output into the event log stays admissible.
pub(super) fn spec(config: &Path) -> Result<AgentSpec, String> {
    let resolved = resolve(config)?;
    let executable = std::env::current_exe()
        .map_err(|_| REFUSED)?
        .canonicalize()
        .map_err(|_| "selected executable unavailable")?;
    let executable = launchd::xml(executable.to_str().ok_or(REFUSED)?)?;
    let argument = launchd::xml(resolved.to_str().ok_or(REFUSED)?)?;
    let directory = resolved.parent().ok_or(REFUSED)?;
    let label_xml = launchd::xml(&label(&resolved)?)?;
    let shape = |name: &str| -> Result<String, String> {
        let log = launchd::xml(directory.join(name).to_str().ok_or(REFUSED)?)?;
        Ok(format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{label_xml}</string>
<key>ProgramArguments</key><array><string>{executable}</string><string>private-gateway</string><string>serve</string><string>{argument}</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ThrottleInterval</key><integer>30</integer>
<key>ExitTimeOut</key><integer>15</integer>
<key>Umask</key><integer>63</integer>
<key>ProcessType</key><string>Background</string>
<key>AbandonProcessGroup</key><false/>
<key>StandardOutPath</key><string>{log}</string>
<key>StandardErrorPath</key><string>{log}</string>
</dict></plist>
"#
        ))
    };
    Ok(AgentSpec {
        label: label(config)?,
        plist: shape(SUPERVISOR_LOG_NAME)?,
        alternates: vec![shape(LOG_NAME)?],
    })
}
pub(super) fn status(config: &Path) -> Result<serde_json::Value, String> {
    launchd::agent_status(&spec(config)?)
}
pub(super) fn install(config: &Path) -> Result<(), String> {
    launchd::agent_install(&spec(config)?)
}
pub(super) fn uninstall(config: &Path) -> Result<(), String> {
    launchd::agent_uninstall(&spec(config)?)
}
