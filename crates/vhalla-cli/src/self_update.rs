//! Executable maintenance before identity, room, transport, or service work.
use anyhow::{bail, Context, Result};
use hraness_cli_update::{
    parse_update_command, ActiveLease, Channel, CurlGithub, Paths, Product, RunningIdentity,
    StartupContext, StartupOutcome, Updater,
};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub(crate) const SCHEMA: &str = "valhalla.update/1";

pub(crate) fn report_error(error: &anyhow::Error) {
    use hraness_control_kit::envelope::{Envelope, ErrorBody, ErrorCode};
    let report = Envelope::<()>::error(ErrorBody::new(
        ErrorCode::Product("valhalla.update-failed".into()),
        format!("{error:#}"),
    ));
    println!(
        "{}",
        serde_json::to_string(&report).expect("serializable error envelope")
    );
}

#[cfg(unix)]
#[path = "self_update/unix.rs"]
mod native;

pub(crate) struct InitialInstall {
    archive: PathBuf,
    checksum: PathBuf,
    prefix: PathBuf,
    pinned: bool,
}

pub(crate) fn product() -> Product {
    Product {
        id: "valhalla".into(), repository: "hraness/valhalla".into(), tag_prefix: "v".into(),
        channel: Channel::Stable,
        running_identity: match option_env!("VHALLA_COMPILED_RELEASE_TAG") {
            Some(tag) if !tag.is_empty() => RunningIdentity::Release { release_tag: tag, build_sha: None },
            _ => RunningIdentity::Source,
        },
        executable_name: if cfg!(windows) { "vhalla.exe" } else { "vhalla" }.into(),
        platform: platform().into(),
        required_assets: if cfg!(windows) {
            vec!["valhalla-{tag}-{platform}.zip".into(), "valhalla-{tag}-{platform}.zip.sha256".into()]
        } else {
            vec!["valhalla-{tag}-{platform}.tar.gz".into(), "valhalla-{tag}-{platform}.tar.gz.sha256".into()]
        },
        require_immutable: true,
        manual_instructions: "Use Valhalla's verified installer for native releases, brew upgrade hraness/tap/vhalla for Homebrew, or the original Cargo/source workflow. Windows updates use install.ps1.".into(),
    }
}

fn platform() -> &'static str {
    env!("VHALLA_COMPILED_TARGET")
}

pub(crate) fn paths(executable: &Path) -> Result<Paths> {
    let bin = executable.parent().context("Executable has no parent")?;
    Ok(Paths {
        receipt: bin.join(".hraness-cli-update-valhalla/install.json"),
        // Saving an opt-out for a source build must not create the managed
        // installation's independent activity-lock authority.
        state_dir: bin.join(".hraness-cli-update-valhalla-preferences"),
    })
}

fn updater() -> Result<Updater> {
    let executable = std::env::current_exe()?.canonicalize()?;
    Ok(Updater::new(product(), paths(&executable)?)?)
}

fn client() -> Result<CurlGithub> {
    Ok(CurlGithub::new(if cfg!(windows) {
        "C:/Windows/System32/curl.exe"
    } else {
        "/usr/bin/curl"
    })?)
}

#[cfg(not(unix))]
struct UnsupportedInstaller;
#[cfg(not(unix))]
impl hraness_cli_update::Installer for UnsupportedInstaller {
    fn install(
        &self,
        _: &hraness_cli_update::InstallRequest<'_>,
    ) -> hraness_cli_update::Result<()> {
        Err(hraness_cli_update::Error::new(
            hraness_cli_update::ErrorCode::Unsupported,
            "Use Valhalla's verified Windows installer.",
        ))
    }
}

fn parse_initial(args: &[OsString]) -> Result<InitialInstall> {
    let mut archive = None;
    let mut checksum = None;
    let mut prefix = None;
    let mut pinned = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let slot = match arg.to_str() {
            Some("--archive") => &mut archive,
            Some("--checksum") => &mut checksum,
            Some("--install-dir") => &mut prefix,
            Some("--pinned") if !pinned => {
                pinned = true;
                continue;
            }
            _ => bail!("Invalid native installer argument"),
        };
        if slot.is_some() {
            bail!("Duplicate native installer argument");
        }
        *slot = Some(PathBuf::from(
            args.next()
                .context("Native installer argument needs a path")?,
        ));
    }
    Ok(InitialInstall {
        archive: archive.context("Native installer needs --archive")?,
        checksum: checksum.context("Native installer needs --checksum")?,
        prefix: prefix.context("Native installer needs --install-dir")?,
        pinned,
    })
}

pub(crate) fn maintenance(args: &[OsString]) -> Option<Result<()>> {
    if args.len() == 1 && args[0] == "__build-identity" {
        let identity = match product().running_identity {
            RunningIdentity::Release { release_tag, .. } => Some(release_tag),
            RunningIdentity::Source => None,
        };
        println!(
            "{}",
            serde_json::json!({"schema":"valhalla.build.v1","version":env!("CARGO_PKG_VERSION"),"releaseTag":identity,"platform":platform()})
        );
        return Some(Ok(()));
    }
    if args.first().is_some_and(|arg| arg == "__install-release") {
        return Some((|| {
            let install = parse_initial(&args[1..])?;
            #[cfg(unix)]
            {
                native::initial_install(&install)
            }
            #[cfg(not(unix))]
            {
                let _ = (
                    install.archive,
                    install.checksum,
                    install.prefix,
                    install.pinned,
                );
                bail!("Use Valhalla's verified Windows installer.");
            }
        })());
    }
    if args.first().is_none_or(|arg| arg != "update") {
        return None;
    }
    Some((|| {
        let request = parse_update_command(args)?.context("Missing update command")?;
        let updater = updater()?;
        let source = client()?;
        #[cfg(unix)]
        let installer = native::NativeInstaller;
        #[cfg(not(unix))]
        let installer = UnsupportedInstaller;
        let report = updater.execute_with_context(
            request.action,
            &StartupContext::from_process(),
            &source,
            &installer,
        )?;
        if request.json {
            println!(
                "{}",
                serde_json::to_string(&hraness_control_kit::envelope::Envelope::ok(
                    SCHEMA, report
                ))?
            );
        } else {
            println!(
                "Valhalla updates: {:?} (automatic policy: {:?})",
                report.status, report.policy
            );
            if let Some(reason) = report.reason {
                println!("{reason}");
            }
            if let Some(instructions) = report.instructions {
                println!("{instructions}");
            }
            if let Some(current) = report.current {
                println!("Installed: {current}");
            }
            if let Some(latest) = report.latest {
                println!("Available: {latest}");
            }
        }
        Ok(())
    })())
}

pub(crate) fn startup(no_update: bool, args: &[OsString]) -> Result<Option<ActiveLease>> {
    let mut context = StartupContext::from_process();
    context.no_update |= no_update;
    // Diagnostics, support and local identity work must not check for updates.
    context.offline = offline_command(args);
    #[cfg(unix)]
    {
        context.no_update |= rustix::process::geteuid().is_root();
    }
    let updater = updater()?;
    let source = client()?;
    #[cfg(unix)]
    let installer = native::NativeInstaller;
    #[cfg(not(unix))]
    let installer = UnsupportedInstaller;
    match updater.startup(&context, &source, &installer)? {
        StartupOutcome::Continue { lease, .. } => Ok(lease),
        StartupOutcome::Reenter(reentry) => reentry.run_and_exit(),
    }
}

fn offline_command(args: &[OsString]) -> bool {
    args.first()
        .and_then(|arg| arg.to_str())
        .is_some_and(|arg| {
            matches!(
                arg,
                "daemon" | "demo" | "identity" | "doctor" | "support" | "commands"
            )
        })
}

#[cfg(unix)]
pub(crate) fn released_tag() -> Result<&'static str> {
    match product().running_identity {
        RunningIdentity::Release { release_tag, .. } => Ok(release_tag),
        RunningIdentity::Source => {
            bail!("This source build cannot enroll as an official release installation.")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_and_local_commands_skip_automatic_network_access() {
        for command in [
            "daemon", "demo", "identity", "doctor", "support", "commands",
        ] {
            assert!(offline_command(&[command.into()]));
        }
        assert!(!offline_command(&["private".into(), "serve".into()]));
    }
}
