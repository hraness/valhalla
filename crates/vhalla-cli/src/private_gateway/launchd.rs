//! Per-user gateway supervisor selection through the shared custody path: a
//! LaunchAgent on macOS, a systemd user unit on Linux.
use super::{resolve, REFUSED};
use crate::private_host::launchd::{self, AgentSpec, LOG_NAME, SUPERVISOR_LOG_NAME};
#[cfg(any(target_os = "linux", test))]
use crate::private_host::systemd::{self, UnitSpec};
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
// On Linux only the tests build this plist shape; the systemd unit is installed.
#[cfg_attr(target_os = "linux", allow(dead_code))]
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
/// Exact systemd user unit: installed executable plus absolute config path,
/// with supervisor output appended to the bounded log next to the config.
#[cfg(any(target_os = "linux", test))]
pub(super) fn unit_spec(config: &Path) -> Result<UnitSpec, String> {
    let resolved = resolve(config)?;
    let executable = std::env::current_exe()
        .map_err(|_| REFUSED)?
        .canonicalize()
        .map_err(|_| "selected executable unavailable")?;
    let label = label(&resolved)?;
    let log = resolved.parent().ok_or(REFUSED)?.join(SUPERVISOR_LOG_NAME);
    Ok(UnitSpec {
        unit: systemd::unit_text(
            &format!("Valhalla private gateway {label}"),
            executable.to_str().ok_or(REFUSED)?,
            &[
                "private-gateway",
                "serve",
                resolved.to_str().ok_or(REFUSED)?,
            ],
            log.to_str().ok_or(REFUSED)?,
        )?,
        label,
        alternates: Vec::new(),
    })
}
#[cfg(target_os = "linux")]
pub(super) fn status(config: &Path) -> Result<serde_json::Value, String> {
    systemd::linux::agent_status(&unit_spec(config)?)
}
#[cfg(target_os = "linux")]
pub(super) fn install(config: &Path) -> Result<(), String> {
    systemd::linux::agent_install(&unit_spec(config)?)
}
#[cfg(target_os = "linux")]
pub(super) fn uninstall(config: &Path) -> Result<(), String> {
    systemd::linux::agent_uninstall(&unit_spec(config)?)
}
#[cfg(not(target_os = "linux"))]
pub(super) fn status(config: &Path) -> Result<serde_json::Value, String> {
    launchd::agent_status(&spec(config)?)
}
#[cfg(not(target_os = "linux"))]
pub(super) fn install(config: &Path) -> Result<(), String> {
    launchd::agent_install(&spec(config)?)
}
#[cfg(not(target_os = "linux"))]
pub(super) fn uninstall(config: &Path) -> Result<(), String> {
    launchd::agent_uninstall(&spec(config)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gateway_unit_runs_the_exact_config_and_logs_beside_it() {
        let dir = std::env::temp_dir().join(format!(
            "vhalla-gateway-unit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let config = dir.join("gateway.json");
        let unit = unit_spec(&config).unwrap();
        let canonical = dir.canonicalize().unwrap();
        assert_eq!(unit.label, label(&config).unwrap());
        assert_eq!(systemd::unit_name(&unit), format!("{}.service", unit.label));
        assert!(unit.unit.contains(&format!(
            " private-gateway serve {}\n",
            canonical.join("gateway.json").display()
        )));
        assert!(unit.unit.contains(&format!(
            "StandardOutput=append:{}\n",
            canonical.join("supervisor.log").display()
        )));
        assert!(unit.alternates.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
