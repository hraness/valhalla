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
        println!("vhalla (valhalla)\n\nvhalla identity init <new-directory>\nvhalla identity show <existing-directory>\nvhalla menubar\nvhalla outputs");
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

/// `vhalla menubar` — launch the menu-bar companion. An explicit
/// `VHALLA_MENUBAR_PATH` wins; otherwise look next to this binary, then in
/// `desktop/target` for in-repository development builds.
#[cfg(unix)]
fn menubar(args: &[std::ffi::OsString]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: vhalla menubar".into());
    }
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Some(value) = std::env::var_os("VHALLA_MENUBAR_PATH") {
        if !value.is_empty() {
            candidates.push(value.into());
        }
    } else {
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                candidates.push(dir.join("vhalla-menubar"));
            }
        }
        let target =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../desktop/target");
        candidates.push(target.join("release/vhalla-menubar"));
        candidates.push(target.join("debug/vhalla-menubar"));
    }
    let binary = candidates.into_iter().find(|path| path.is_file()).ok_or_else(|| {
        "vhalla-menubar is not built; run `cargo build --release --manifest-path desktop/Cargo.toml`"
            .to_owned()
    })?;
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
