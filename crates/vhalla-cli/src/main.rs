#![forbid(unsafe_code)]
#![allow(missing_docs)]

#[cfg(unix)]
mod intro;

#[cfg(all(unix, feature = "experimental-social"))]
mod social;

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
        println!("vhalla (valhalla)\n\nvhalla identity init <new-directory>\nvhalla identity show <existing-directory>");
        #[cfg(feature = "experimental-network")]
        println!("\nvhalla experimental listen <identity-directory> <peer-app-key>\nvhalla experimental send <identity-directory> <peer-app-key> <route> <expiry> <message>\n\nExperimental loopback chat; fixed test room, 60-second listener lifetime.");
        #[cfg(feature = "experimental-social")]
        println!("\n{}", social::HELP);
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
    if args.first().is_some_and(|s| s == "experimental") {
        #[cfg(feature = "experimental-network")]
        return network(args);
        #[cfg(not(feature = "experimental-network"))]
        return Err(
            "network commands require an explicit build with --features experimental-network"
                .into(),
        );
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

#[cfg(all(unix, feature = "experimental-network"))]
fn network(args: Vec<std::ffi::OsString>) -> Result<(), String> {
    use std::io::Write;
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
    let text = |index: usize| -> Result<&str, String> {
        args.get(index)
            .and_then(|a| a.to_str())
            .ok_or_else(|| "missing or non-UTF-8 argument".into())
    };
    let mode = text(1)?;
    if !((mode == "listen" && args.len() == 4) || (mode == "send" && args.len() == 7)) {
        return Err("see vhalla --help for experimental command arguments".into());
    }
    let peer = text(3)?;
    if peer.len() != 64 || !peer.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected full 64-hex-digit application key".into());
    }
    let mut peer_app = [0; 32];
    for (i, byte) in peer_app.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&peer[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    let identity =
        vhalla_identity::Identity::open(&args[2]).map_err(|e| format!("identity: {e:?}"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async {
        if mode == "listen" {
            let mut listener = Listener::bind(identity, peer_app)
                .await
                .map_err(|e| e.to_string())?;
            print_line(&format!(
                "route {} {}",
                listener.route().address(),
                listener.route().expires_at()
            ))?;
            loop {
                match listener.next().await {
                    Ok(Event::Joined(session)) => {
                        print_line(&format!("joined session={:032x}", session.0))?
                    }
                    Ok(Event::Message(message)) => print_line(&format!(
                        "message peer={} session={:032x} body-hex={}",
                        hex(message.signer_key()),
                        message.context().session.0,
                        hex(message.envelope().body())
                    ))?,
                    Ok(Event::Rejected(error)) => print_line(&format!("rejected {error}"))?,
                    Ok(Event::Disconnected) => print_line("peer-closed")?,
                    Err(vhalla_native::Error::Closed) => return Ok(()),
                    Err(error) => return Err(error.to_string()),
                }
            }
        } else {
            let expires = text(5)?.parse().map_err(|_| "invalid expiry".to_string())?;
            let route = Route::parse(text(4)?, expires).map_err(|e| e.to_string())?;
            let result =
                vhalla_native::send_message(identity, peer_app, route, text(6)?.as_bytes())
                    .await
                    .map_err(|e| e.to_string())?;
            print_line(&format!(
                "received peer={} session={:032x} frame-sha256={}",
                hex(result.acknowledgment().signer_key()),
                result.acknowledgment().context().session.0,
                hex(result.digest())
            ))
        }
    })
}
