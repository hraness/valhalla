#![forbid(unsafe_code)]
#![allow(missing_docs)]

#[cfg(unix)]
mod intro;

#[cfg(all(unix, feature = "experimental-social"))]
mod json;
#[cfg(all(unix, feature = "experimental-social"))]
mod social;

#[cfg(all(unix, feature = "experimental-rooms"))]
mod rooms;
#[cfg(all(unix, feature = "experimental-rooms-node"))]
mod rooms_node;
#[cfg(all(unix, feature = "experimental-rooms-tui"))]
mod rooms_submit;
#[cfg(all(unix, feature = "experimental-rooms-tui"))]
mod rooms_tui;

fn main() {
    #[cfg(unix)]
    if let Err(error) = run() {
        eprintln!("vhalla: {error}");
        std::process::exit(1);
    }
    #[cfg(not(unix))]
    {
        eprintln!("vhalla: native identity custody is currently qualified only on Unix");
        std::process::exit(1);
    }
}

#[cfg(unix)]
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).take(65).collect();
    if args.len() > 64 {
        return Err("too many arguments (maximum 64)".into());
    }
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        use std::io::IsTerminal;
        let term = std::env::var("TERM").ok();
        let columns = std::env::var("COLUMNS")
            .ok()
            .and_then(|value| value.parse().ok());
        print!(
            "{}",
            intro::terminal_intro(std::io::stdout().is_terminal(), term.as_deref(), columns)
        );
        println!("vhalla (valhalla)\n\nvhalla identity init <new-directory>\nvhalla identity show <existing-directory>\nvhalla menubar [run|install|uninstall|status]\nvhalla outputs");
        #[cfg(feature = "experimental-network")]
        println!("\nvhalla experimental [--json] listen <identity-directory> <peer-app-key>\nvhalla experimental [--json] send <identity-directory> <peer-app-key> <route> <expiry> <message>\n\nExperimental loopback chat; fixed test room, 60-second listener lifetime. --json emits bounded versioned JSON lines.");
        #[cfg(feature = "experimental-social")]
        println!("\n{}", social::help());
        #[cfg(feature = "experimental-rooms")]
        println!("\n{}", rooms::HELP);
        return Ok(());
    }
    if args.first().is_some_and(|s| s == "social") {
        #[cfg(feature = "experimental-social")]
        return social::run(args);
        #[cfg(not(feature = "experimental-social"))]
        return Err(
            "social commands require an explicit build with --features experimental-social".into(),
        );
    }
    if args.first().is_some_and(|s| s == "rooms") {
        #[cfg(feature = "experimental-rooms")]
        return rooms::run(args);
        #[cfg(not(feature = "experimental-rooms"))]
        return Err(
            "rooms commands require an explicit build with --features experimental-rooms".into(),
        );
    }
    if args.first().is_some_and(|s| s == "experimental") {
        #[cfg(feature = "experimental-network")]
        return network(args);
        #[cfg(not(feature = "experimental-network"))]
        return Err(
            "network commands require an explicit build with --features experimental-network"
                .into(),
        );
    }
    if args.first().is_some_and(|s| s == "menubar") {
        return menubar(&args);
    }
    if args.first().is_some_and(|s| s == "outputs") {
        return outputs(&args);
    }
    if args.len() != 3 || args[0] != "identity" {
        return Err("usage: vhalla identity <init|show> <directory>".into());
    }
    let identity = if args[1] == "init" {
        vhalla_identity::Identity::create_new(&args[2])
    } else if args[1] == "show" {
        vhalla_identity::Identity::open(&args[2])
    } else {
        return Err("identity command must be init or show".into());
    }
    .map_err(|error| format!("identity operation failed: {error:?}"))?;
    let public = identity
        .public_key()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    println!("application-key {public}");
    Ok(())
}

/// `~/Library/Application Support/Valhalla` on macOS, `$XDG_DATA_HOME/valhalla`
/// or `~/.local/share/valhalla` elsewhere — the one implicit location the CLI
/// owns. Identities and stores stay explicit-path; this root exists only for
/// the menu-bar companion and the agent outputs directory.
#[cfg(unix)]
fn state_directory() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from)?;
    if cfg!(target_os = "macos") {
        Some(home.join("Library/Application Support/Valhalla"))
    } else {
        let data = std::env::var_os("XDG_DATA_HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share"));
        Some(data.join("valhalla"))
    }
}

/// `vhalla outputs` — create and print the agent outputs directory. Agents
/// drop descriptively named files here; the menu bar lists them newest-first.
#[cfg(unix)]
fn outputs(args: &[std::ffi::OsString]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: vhalla outputs".into());
    }
    let directory = state_directory()
        .ok_or_else(|| "could not resolve the state directory (is HOME set?)".to_owned())?
        .join("outputs");
    std::fs::create_dir_all(&directory)
        .map_err(|e| format!("could not create the outputs directory: {e}"))?;
    println!("{}", directory.display());
    Ok(())
}

/// `vhalla menubar [run|install|uninstall|status]` — the menu-bar
/// companion lifecycle. The companion is a disposable unbundled client:
/// `run` launches it once, `install` copies a qualified release binary to
/// the per-user state directory and registers a LaunchAgent so it
/// survives login — no `.app` packaging, signing or notarization is
/// involved anywhere.
#[cfg(unix)]
fn menubar(args: &[std::ffi::OsString]) -> Result<(), String> {
    match args.get(1).and_then(|a| a.to_str()) {
        None if args.len() == 1 => menubar_launch(),
        Some("run") if args.len() == 2 => menubar_launch(),
        Some("install") if args.len() == 2 => menubar_install(),
        Some("uninstall") if args.len() == 2 => menubar_uninstall(),
        Some("status") if args.len() == 2 => menubar_status(),
        _ => Err("usage: vhalla menubar [run|install|uninstall|status]".into()),
    }
}

const MENUBAR_LAUNCH_AGENT: &str = "com.hraness.valhalla.menubar";

/// `state_directory()/bin/vhalla-menubar` — the stable per-user install
/// location a bare `vhalla menubar` resolves before the repository build.
#[cfg(unix)]
fn installed_menubar() -> Option<std::path::PathBuf> {
    state_directory().map(|dir| dir.join("bin").join("vhalla-menubar"))
}

/// A launchable companion is a regular file with an execute bit and no
/// group/other write — anything weaker is not a qualified binary.
#[cfg(unix)]
fn qualified_binary(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|meta| {
            let mode = meta.permissions().mode();
            meta.is_file() && mode & 0o111 != 0 && mode & 0o022 == 0
        })
        .unwrap_or(false)
}

/// Resolution order: the installed copy, a sibling of this executable,
/// then the in-repository release build. Debug builds are deliberately
/// absent — development binaries go through `VHALLA_MENUBAR_PATH`.
/// `install` uses the reverse order (release build first, installed copy
/// last) so a rebuilt binary upgrades the installation rather than
/// reinstalling it onto itself.
#[cfg(unix)]
fn menubar_candidates(for_install: bool) -> Vec<std::path::PathBuf> {
    let mut candidates = Vec::new();
    if !for_install {
        if let Some(installed) = installed_menubar() {
            candidates.push(installed);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("vhalla-menubar"));
        }
    }
    candidates.push(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../desktop/target/release/vhalla-menubar"),
    );
    if for_install {
        if let Some(installed) = installed_menubar() {
            candidates.push(installed);
        }
    }
    candidates
}

#[cfg(unix)]
fn resolve_menubar(for_install: bool) -> Result<std::path::PathBuf, String> {
    if let Some(value) = std::env::var_os("VHALLA_MENUBAR_PATH") {
        if !value.is_empty() {
            let path = std::path::PathBuf::from(value);
            return if qualified_binary(&path) {
                Ok(path)
            } else {
                Err("VHALLA_MENUBAR_PATH names no qualified binary — it is not built, not executable, or group/world-writable".into())
            };
        }
    }
    menubar_candidates(for_install)
        .into_iter()
        .find(|path| qualified_binary(path))
        .ok_or_else(|| {
            "vhalla-menubar is not built; run `cargo build --release --manifest-path desktop/Cargo.toml`"
                .to_owned()
        })
}

#[cfg(unix)]
fn menubar_launch() -> Result<(), String> {
    let binary = resolve_menubar(false)?;
    let mut child = std::process::Command::new(&binary)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("could not start the menu bar: {e}"))?;
    std::thread::sleep(std::time::Duration::from_millis(400));
    match child.try_wait().map_err(|e| e.to_string())? {
        Some(status) if status.success() => println!("valhalla menu bar already running"),
        Some(status) => return Err(format!("the menu bar exited during startup ({status})")),
        None => println!("valhalla menu bar running"),
    }
    Ok(())
}

/// `~/Library/LaunchAgents/<label>.plist`.
#[cfg(unix)]
fn launch_agent_path() -> Result<std::path::PathBuf, String> {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .ok_or("could not resolve HOME")?;
    Ok(home
        .join("Library/LaunchAgents")
        .join(format!("{MENUBAR_LAUNCH_AGENT}.plist")))
}

/// The launchd `gui/<uid>` domain of the logged-in user, resolved through
/// `id -u` — this crate forbids `unsafe`, so `libc::getuid` is not an
/// option.
#[cfg(unix)]
fn user_launch_domain() -> Result<String, String> {
    let output = std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .map_err(|e| format!("could not resolve the user id: {e}"))?;
    let uid =
        String::from_utf8(output.stdout).map_err(|_| "id -u did not print UTF-8".to_owned())?;
    let uid: u64 = uid
        .trim()
        .parse()
        .map_err(|_| "id -u did not print a numeric uid".to_owned())?;
    if uid < 1 {
        return Err("the menu bar requires a logged-in macOS user".into());
    }
    Ok(format!("gui/{uid}"))
}

#[cfg(unix)]
fn launchctl(args: &[&str]) -> Result<(), String> {
    let status = std::process::Command::new("/bin/launchctl")
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("could not run launchctl: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("launchctl {} failed ({status})", args[0]))
    }
}

fn launch_agent_plist(binary: &std::path::Path) -> String {
    let path = binary.to_string_lossy();
    let escaped = path
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>{MENUBAR_LAUNCH_AGENT}</string>\n\
         \x20 <key>ProgramArguments</key>\n  <array>\n    <string>{escaped}</string>\n  </array>\n\
         \x20 <key>RunAtLoad</key>\n  <true/>\n</dict>\n</plist>\n"
    )
}

/// Write `content` to `path` atomically (same-directory temp + rename)
/// with `mode` permissions.
#[cfg(unix)]
fn atomic_write(path: &std::path::Path, content: &str, mode: u32) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let temporary = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        std::process::id()
    ));
    let write = || -> Result<(), String> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(mode)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        file.write_all(content.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| e.to_string())?;
        std::fs::rename(&temporary, path).map_err(|e| e.to_string())
    };
    if let Err(error) = write() {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

#[cfg(unix)]
fn menubar_install() -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("menubar install manages a launchd agent, which exists only on macOS".into());
    }
    let source = resolve_menubar(true)?;
    let installed =
        installed_menubar().ok_or("could not resolve the state directory (is HOME set?)")?;
    if source != installed {
        use std::os::unix::fs::PermissionsExt;
        let bin_dir = installed.parent().unwrap();
        std::fs::create_dir_all(bin_dir).map_err(|e| e.to_string())?;
        std::fs::set_permissions(bin_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        let temporary =
            installed.with_file_name(format!(".vhalla-menubar.tmp-{}", std::process::id()));
        let copy = || -> Result<(), String> {
            std::fs::copy(&source, &temporary).map_err(|e| e.to_string())?;
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| e.to_string())?;
            std::fs::rename(&temporary, &installed).map_err(|e| e.to_string())
        };
        if let Err(error) = copy() {
            let _ = std::fs::remove_file(&temporary);
            return Err(format!("could not install the menu-bar binary: {error}"));
        }
    }
    let plist = launch_agent_path()?;
    if let Some(dir) = plist.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    atomic_write(&plist, &launch_agent_plist(&installed), 0o600)?;
    let domain = user_launch_domain()?;
    // A stale registration is replaced idempotently; a failed bootout just
    // means the label was not loaded. Bootout is asynchronous — bootstrap
    // races the teardown unless the label has actually left the domain.
    let label = format!("{domain}/{MENUBAR_LAUNCH_AGENT}");
    let _ = launchctl(&["bootout", &label]);
    for _ in 0..20 {
        let still_loaded = std::process::Command::new("/bin/launchctl")
            .args(["print", &label])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !still_loaded {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    launchctl(&["bootstrap", &domain, &plist.to_string_lossy()])
        .map_err(|e| format!("the launch agent could not be loaded: {e}"))?;
    println!("installed: {}", installed.display());
    println!("launch agent loaded: {MENUBAR_LAUNCH_AGENT}");
    Ok(())
}

#[cfg(unix)]
fn menubar_uninstall() -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("menubar uninstall manages a launchd agent, which exists only on macOS".into());
    }
    if let Ok(domain) = user_launch_domain() {
        let _ = launchctl(&["bootout", &format!("{domain}/{MENUBAR_LAUNCH_AGENT}")]);
    }
    if let Ok(plist) = launch_agent_path() {
        let _ = std::fs::remove_file(plist);
    }
    if let Some(installed) = installed_menubar() {
        let _ = std::fs::remove_file(installed);
    }
    println!("valhalla menu bar uninstalled");
    Ok(())
}

#[cfg(unix)]
fn menubar_status() -> Result<(), String> {
    match installed_menubar() {
        Some(installed) if qualified_binary(&installed) => {
            println!("installed: {}", installed.display());
        }
        _ => println!("installed: none"),
    }
    if cfg!(target_os = "macos") {
        let plist = launch_agent_path()?;
        if !plist.exists() {
            println!("launch agent: none");
        } else {
            let loaded = user_launch_domain()
                .map(|domain| {
                    std::process::Command::new("/bin/launchctl")
                        .args(["print", &format!("{domain}/{MENUBAR_LAUNCH_AGENT}")])
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            println!(
                "launch agent: {}",
                if loaded { "loaded" } else { "not loaded" }
            );
        }
    }
    match resolve_menubar(false) {
        Ok(binary) => println!("launch resolves to: {}", binary.display()),
        Err(_) => println!("launch resolves to: nothing qualified"),
    }
    Ok(())
}

#[cfg(all(unix, feature = "experimental-network"))]
fn network(args: Vec<std::ffi::OsString>) -> Result<(), String> {
    use std::io::Write;
    const MAX_JSON_LINE_BYTES: usize = 140_000;
    use vhalla_native::{Event, Listener, Route};
    fn hex(raw: &[u8]) -> String {
        raw.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn print_line(line: &str) -> Result<(), String> {
        let mut out = std::io::stdout().lock();
        writeln!(out, "{line}")
            .and_then(|()| out.flush())
            .map_err(|e| e.to_string())
    }
    fn json_quote(value: &str) -> String {
        let mut out = String::with_capacity(value.len() + 2);
        out.push('"');
        for character in value.chars() {
            match character {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                character if character.is_control() => {
                    out.push_str(&format!("\\u{:04x}", character as u32))
                }
                _ => out.push(character),
            }
        }
        out.push('"');
        out
    }
    fn bounded_detail(value: &str) -> String {
        const MAX_DETAIL_BYTES: usize = 1_024;
        if value.len() <= MAX_DETAIL_BYTES {
            return value.to_owned();
        }
        let mut end = MAX_DETAIL_BYTES;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &value[..end])
    }
    fn print_json(kind: &str, fields: &str) -> Result<(), String> {
        let mut line = format!("{{\"v\":1,\"kind\":{}{}}}", json_quote(kind), fields);
        if line.len() + 1 > MAX_JSON_LINE_BYTES {
            return Err("JSON event exceeds bounded line size".into());
        }
        line.push('\n');
        let mut out = std::io::stdout().lock();
        out.write_all(line.as_bytes())
            .and_then(|()| out.flush())
            .map_err(|e| e.to_string())
    }
    fn emit(json: bool, line: &str, kind: &str, fields: &str) -> Result<(), String> {
        if json {
            print_json(kind, fields)
        } else {
            print_line(line)
        }
    }
    let text = |index: usize| -> Result<&str, String> {
        args.get(index)
            .and_then(|a| a.to_str())
            .ok_or_else(|| "missing or non-UTF-8 argument".into())
    };
    let json = args.get(1).is_some_and(|value| value == "--json");
    let offset = usize::from(json);
    let mode = text(1 + offset)?;
    if !((mode == "listen" && args.len() == 4 + offset)
        || (mode == "send" && args.len() == 7 + offset))
    {
        return Err("see vhalla --help for experimental command arguments".into());
    }
    let peer = text(3 + offset)?;
    if peer.len() != 64 || !peer.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected full 64-hex-digit application key".into());
    }
    let mut peer_app = [0; 32];
    for (i, byte) in peer_app.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&peer[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    let identity = vhalla_identity::Identity::open(&args[2 + offset])
        .map_err(|e| format!("identity: {e:?}"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async {
        if mode == "listen" {
            let mut listener = Listener::bind(identity, peer_app)
                .await
                .map_err(|e| e.to_string())?;
            let address = listener.route().address();
            let expires_at = listener.route().expires_at();
            emit(
                json,
                &format!("route {address} {expires_at}"),
                "ready",
                &format!(
                    ",\"route\":{},\"expires_at\":{}",
                    json_quote(&address),
                    expires_at
                ),
            )?;
            loop {
                match listener.next().await {
                    Ok(Event::Joined(session)) => emit(
                        json,
                        &format!("joined session={:032x}", session.0),
                        "joined",
                        &format!(
                            ",\"session\":{}",
                            json_quote(&format!("{:032x}", session.0))
                        ),
                    )?,
                    Ok(Event::Message(message)) => {
                        let peer = hex(message.signer_key());
                        let session = message.context().session.0;
                        let body = hex(message.envelope().body());
                        emit(
                            json,
                            &format!("message peer={peer} session={session:032x} body-hex={body}"),
                            "message",
                            &format!(
                                ",\"peer\":{},\"session\":{},\"body_hex\":{}",
                                json_quote(&peer),
                                json_quote(&format!("{session:032x}")),
                                json_quote(&body)
                            ),
                        )?
                    }
                    Ok(Event::Rejected(error)) => emit(
                        json,
                        &format!("rejected {error}"),
                        "rejected",
                        &format!(
                            ",\"message\":{}",
                            json_quote(&bounded_detail(&error.to_string()))
                        ),
                    )?,
                    Ok(Event::Disconnected) => emit(json, "peer-closed", "peer_closed", "")?,
                    Err(vhalla_native::Error::Closed) => return Ok(()),
                    Err(error) => return Err(error.to_string()),
                }
            }
        } else {
            let expires = text(5 + offset)?
                .parse()
                .map_err(|_| "invalid expiry".to_string())?;
            let route = Route::parse(text(4 + offset)?, expires).map_err(|e| e.to_string())?;
            let result = vhalla_native::send_message(
                identity,
                peer_app,
                route,
                text(6 + offset)?.as_bytes(),
            )
            .await
            .map_err(|e| e.to_string())?;
            let peer = hex(result.acknowledgment().signer_key());
            let session = result.acknowledgment().context().session.0;
            let digest = hex(result.digest());
            emit(
                json,
                &format!("received peer={peer} session={session:032x} frame-sha256={digest}"),
                "received",
                &format!(
                    ",\"peer\":{},\"session\":{},\"frame_sha256\":{}",
                    json_quote(&peer),
                    json_quote(&format!("{session:032x}")),
                    json_quote(&digest)
                ),
            )
        }
    })
}
