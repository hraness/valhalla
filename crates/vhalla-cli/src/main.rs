#![forbid(unsafe_code)]
#![allow(missing_docs)]

mod cli;
mod help;
mod support;

#[cfg(feature = "experimental-private")]
mod endpoint;

#[cfg(all(unix, feature = "experimental-private"))]
mod private_gateway;

#[cfg(all(unix, feature = "experimental-private"))]
mod local_network;

#[cfg(all(unix, feature = "experimental-private"))]
mod private_host;

#[cfg(feature = "experimental-private")]
mod private_rooms;

#[cfg(all(unix, feature = "experimental-public"))]
mod public_network;

#[cfg(unix)]
mod control;
#[cfg(unix)]
mod intro;

#[cfg(all(unix, feature = "experimental-social"))]
mod demo;
#[cfg(all(unix, feature = "experimental-social"))]
mod json;
#[cfg(all(unix, feature = "experimental-social"))]
mod social;

#[cfg(all(unix, feature = "experimental-rooms"))]
mod rooms;
#[cfg(all(unix, feature = "experimental-rooms-node"))]
mod rooms_node;
#[cfg(all(unix, feature = "experimental-rooms-node"))]
mod rooms_overlay;
#[cfg(all(unix, feature = "experimental-rooms-tui"))]
mod rooms_submit;
#[cfg(all(unix, feature = "experimental-rooms-node"))]
mod rooms_tailcat;
#[cfg(all(unix, feature = "experimental-rooms-tui"))]
mod rooms_tui;

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).take(65).collect();
    let help = help::resolve(&args);
    if help.is_none() && args.first().is_some_and(|arg| arg == "support") && args.len() <= 64 {
        #[cfg(unix)]
        if let Some(code) = control::support(&args[1..]) {
            std::process::exit(code);
        }
        std::process::exit(support::execute(&args[1..]));
    }
    match help {
        Some(help::Help::Page(page)) => write_help(&args, &page),
        Some(help::Help::UnknownTopic(topic)) => {
            cli::report_error(&format!(
                "No help topic named \"{topic}\".\n→ vhalla --help"
            ));
            std::process::exit(2);
        }
        None => {}
    }
    if let Some(first) = args.first().and_then(|arg| arg.to_str()) {
        if !first.starts_with('-') && !cli::COMMANDS.contains(&first) {
            cli::report_error(&cli::unknown_command(first));
            std::process::exit(2);
        }
    }
    #[cfg(unix)]
    if let Some(code) = control::dispatch(&args) {
        std::process::exit(code);
    }
    #[cfg(unix)]
    {
        let useful = support::useful_result(&args);
        match run(args) {
            Ok(()) if useful => support::completed(),
            Ok(()) => {}
            Err(error) => {
                cli::report_error(&error);
                std::process::exit(1);
            }
        }
    }
    // Member-side private-room custody is portable; host, gateway and agent
    // serving lanes remain Unix-qualified for now.
    #[cfg(not(unix))]
    {
        match run(args) {
            Ok(()) => {}
            Err(error) => {
                cli::report_error(&error);
                std::process::exit(1);
            }
        }
    }
}

/// Print a help page on stdout and exit 0. Root help on an interactive
/// terminal keeps the small ASCII intro. A closed pipe (`vhalla --help |
/// head -1`) ends quietly.
fn write_help(args: &[std::ffi::OsString], page: &str) -> ! {
    use std::io::{IsTerminal, Write};
    let stdout = std::io::stdout();
    #[cfg(unix)]
    let intro = if args.len() == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help")
    {
        let term = std::env::var("TERM").ok();
        let columns = std::env::var("COLUMNS")
            .ok()
            .and_then(|value| value.parse().ok());
        intro::terminal_intro(stdout.is_terminal(), term.as_deref(), columns)
    } else {
        ""
    };
    #[cfg(not(unix))]
    let intro = {
        let _ = (args, stdout.is_terminal());
        ""
    };
    let mut writer = stdout.lock();
    let written = writer
        .write_all(intro.as_bytes())
        .and_then(|()| writer.write_all(page.as_bytes()))
        .and_then(|()| writer.flush());
    std::process::exit(match written {
        Ok(()) => 0,
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => 0,
        Err(_) => 1,
    });
}

#[cfg(unix)]
fn run(args: Vec<std::ffi::OsString>) -> Result<(), String> {
    if args.len() > 64 {
        return Err("too many arguments (maximum 64)".into());
    }
    if args.len() == 1 && (args[0] == "--version" || args[0] == "-V") {
        version();
        return Ok(());
    }
    if args.first().is_some_and(|s| s == "private-gateway") {
        #[cfg(feature = "experimental-private")]
        return private_gateway::execute(&args[1..]);
        #[cfg(not(feature = "experimental-private"))]
        return Err("private gateway tools require --features experimental-private".into());
    }
    if args.first().is_some_and(|s| s == "private-host") {
        #[cfg(feature = "experimental-private")]
        return private_host::run(&args);
        #[cfg(not(feature = "experimental-private"))]
        return Err("private host tools require --features experimental-private".into());
    }
    if args.first().is_some_and(|s| s == "private") {
        #[cfg(feature = "experimental-private")]
        return private_rooms::run(&args);
        #[cfg(not(feature = "experimental-private"))]
        return Err("private room tools require --features experimental-private".into());
    }
    if args.first().is_some_and(|s| s == "public") {
        #[cfg(feature = "experimental-public")]
        return public_network::run(args);
        #[cfg(not(feature = "experimental-public"))]
        return Err("public network tools require --features experimental-public".into());
    }
    if args.first().is_some_and(|s| s == "demo") {
        #[cfg(feature = "experimental-social")]
        return demo::run(&args[1..]);
        #[cfg(not(feature = "experimental-social"))]
        return Err("demo requires --features experimental-social".into());
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
    if args.len() != 3 || args[0] != "identity" {
        return Err(identity_usage());
    }
    identity(&args)
}

/// Windows and other non-Unix builds carry the member-side private-room
/// client and identity custody only. Host, gateway, agent serving and the
/// experimental public/social/rooms surfaces remain Unix-qualified.
#[cfg(not(unix))]
fn run(args: Vec<std::ffi::OsString>) -> Result<(), String> {
    if args.len() > 64 {
        return Err("too many arguments (maximum 64)".into());
    }
    if args.len() == 1 && (args[0] == "--version" || args[0] == "-V") {
        version();
        return Ok(());
    }
    if args.first().is_some_and(|s| s == "private") {
        #[cfg(feature = "experimental-private")]
        return private_rooms::run(&args);
        #[cfg(not(feature = "experimental-private"))]
        return Err("private room tools require --features experimental-private".into());
    }
    if args.len() != 3 || args[0] != "identity" {
        return Err(identity_usage());
    }
    identity(&args)
}

fn version() {
    // Release identity is the git tag, not the workspace crate version;
    // the feature set is what actually distinguishes one binary.
    let features: &[&str] = &[
        #[cfg(feature = "experimental-network")]
        "experimental-network",
        #[cfg(feature = "experimental-social")]
        "experimental-social",
        #[cfg(feature = "experimental-rooms")]
        "experimental-rooms",
        #[cfg(feature = "experimental-rooms-node")]
        "experimental-rooms-node",
        #[cfg(feature = "experimental-rooms-tui")]
        "experimental-rooms-tui",
        #[cfg(feature = "experimental-sync")]
        "experimental-sync",
        #[cfg(feature = "experimental-private")]
        "experimental-private",
        #[cfg(feature = "experimental-public")]
        "experimental-public",
    ];
    println!(
        "vhalla {} features=[{}]",
        env!("CARGO_PKG_VERSION"),
        features.join(",")
    );
}

fn identity_usage() -> String {
    "Use: vhalla identity <init|show|backup|restore> DIR\n→ vhalla help identity".into()
}

/// One plain sentence and next step for each identity failure. The key is
/// never regenerated, replaced or deleted to get past an error.
fn identity_error(
    action: &str,
    directory: &std::path::Path,
    error: vhalla_identity::IdentityError,
) -> String {
    use vhalla_identity::IdentityError;
    let dir = directory.display();
    match error {
        IdentityError::UnsafePath => format!(
            "{dir} isn't a private identity folder: it must be yours, not a link, and not shared with other users\n→ ls -ld {dir}"
        ),
        IdentityError::Corrupt => format!(
            "The identity in {dir} is damaged or from a newer version. Nothing was changed\nKeep the folder. You can restore the identity into a new folder from its phrase.\n→ vhalla identity restore NEW_DIR"
        ),
        IdentityError::Busy => format!(
            "Another vhalla command is using the identity in {dir}. Nothing was changed\n→ vhalla identity {action} {dir}"
        ),
        IdentityError::Entropy => {
            "Your computer couldn't provide random bytes, so no identity was created\n→ vhalla identity init NEW_DIR".into()
        }
        IdentityError::Session(_) => format!(
            "The identity in {dir} refused that request. Nothing was changed\n→ vhalla help identity"
        ),
        IdentityError::Phrase(reason) => format!(
            "That recovery phrase isn't valid: {reason}\nCheck every word and its order. Nothing was created.\n→ vhalla identity restore {dir} < phrase.txt"
        ),
        IdentityError::Io(error) if error.kind() == std::io::ErrorKind::AlreadyExists => format!(
            "{dir} already exists. Choose a new folder; an existing identity is never replaced\n→ vhalla identity {action} NEW_DIR"
        ),
        IdentityError::Io(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && matches!(action, "init" | "restore") =>
        {
            let parent = directory
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(std::path::Path::new("."));
            format!(
                "The folder that should hold {dir} doesn't exist. Nothing was created\n→ mkdir -p {}",
                parent.display()
            )
        }
        IdentityError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => format!(
            "There's no identity in {dir}\n→ vhalla identity init {dir}"
        ),
        IdentityError::Io(error) => format!(
            "Couldn't read or write {dir}: {error}\nIf this was init, check the folder before trying again: it may already hold a new key.\n→ vhalla identity show {dir}"
        ),
    }
}

/// Plain words for an invitation the paired-chat commands can't use.
#[cfg(feature = "experimental-network")]
fn invitation_error(error: vhalla_session::InvitationError) -> String {
    use vhalla_session::InvitationError;
    match error {
        InvitationError::Malformed => {
            "That invitation is damaged or incomplete. Ask the owner to send it again\n→ vhalla help experimental"
        }
        InvitationError::Key => {
            "That invitation names an invalid key, or invites its own owner\n→ vhalla help experimental"
        }
        InvitationError::Issuer => {
            "That invitation was signed by a different owner than the one you named. Check the owner key\n→ vhalla help experimental"
        }
        InvitationError::Signature => {
            "That invitation's signature doesn't check out. Don't use it; ask the owner for a new one\n→ vhalla help experimental"
        }
        InvitationError::Expired => {
            "That invitation has expired. Ask the owner for a new one\n→ vhalla help experimental"
        }
    }
    .into()
}

/// Plain words for the file that records invitations already used.
#[cfg(feature = "experimental-network")]
fn spent_error(error: vhalla_native::SpentError, path: &str) -> String {
    use vhalla_native::SpentError;
    match error {
        SpentError::AlreadySpent => {
            "That invitation was already used. Each one works once; ask the owner for a new one\n→ vhalla help experimental".into()
        }
        SpentError::Capacity => format!(
            "{path} has recorded as many used invitations as it can hold. Use a new identity folder for more\n→ vhalla identity init NEW_DIR"
        ),
        SpentError::Malformed => format!(
            "{path} is damaged, so vhalla can't tell which invitations were used. Nothing was sent. Keep the file\n→ vhalla help experimental"
        ),
        SpentError::Io => format!("Couldn't read or write {path}\n→ ls -l {path}"),
    }
}

/// The warning printed before a recovery phrase, for people at a terminal.
fn phrase_warning(audience: cli::Audience, style: cli::Style) -> Option<String> {
    (audience == cli::Audience::Human).then(|| {
        format!(
            "{} This phrase restores your identity. Store it offline; anyone with it can sign as you.\n",
            style.warn()
        )
    })
}

fn identity(args: &[std::ffi::OsString]) -> Result<(), String> {
    let action = args[1].to_string_lossy().into_owned();
    let directory = std::path::Path::new(&args[2]);
    let failed = |error| identity_error(&action, directory, error);
    let identity = if args[1] == "init" {
        vhalla_identity::Identity::create_new(&args[2])
    } else if args[1] == "show" {
        vhalla_identity::Identity::open(&args[2])
    } else if args[1] == "backup" {
        let identity = vhalla_identity::Identity::open(&args[2]).map_err(failed)?;
        let phrase = identity.backup();
        let public = identity
            .public_key()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if let Some(warning) = phrase_warning(cli::audience(), cli::Style::stderr()) {
            eprint!("{warning}");
        }
        println!("mnemonic {}", *phrase);
        println!("application-key {public}");
        return Ok(());
    } else if args[1] == "restore" {
        use std::io::Read;
        let mut phrase = String::new();
        std::io::stdin()
            .read_to_string(&mut phrase)
            .map_err(|e| format!("Couldn't read the recovery phrase from stdin: {e}\n→ vhalla identity restore {} < phrase.txt", directory.display()))?;
        vhalla_identity::Identity::restore(&phrase, &args[2])
    } else {
        return Err(identity_usage());
    }
    .map_err(failed)?;
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
/// room status and the agent outputs directory.
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

#[cfg(all(unix, feature = "experimental-network"))]
fn network(args: Vec<std::ffi::OsString>) -> Result<(), String> {
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};
    const MAX_JSON_LINE_BYTES: usize = 140_000;
    use vhalla_native::{Event, Listener, Route};
    fn hex(raw: &[u8]) -> String {
        raw.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn hex_bytes(text: &str, len: usize) -> Result<Vec<u8>, String> {
        if text.len() != len * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("expected {} hex characters", len * 2));
        }
        Ok((0..len)
            .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
            .collect())
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
    let invited = args
        .get(3 + offset)
        .and_then(|a| a.to_str())
        .is_some_and(|v| v == "invitation");
    if !((mode == "listen" && (4..=5).contains(&(args.len() - offset)) && !invited)
        || (mode == "listen" && (5..=6).contains(&(args.len() - offset)) && invited)
        || (mode == "send" && args.len() == 7 + offset && !invited)
        || (mode == "send" && args.len() == 9 + offset && invited)
        || (mode == "invite" && args.len() == 8 + offset))
    {
        return Err("see vhalla --help for experimental command arguments".into());
    }
    let identity = vhalla_identity::Identity::open(&args[2 + offset])
        .map_err(|e| identity_error("show", std::path::Path::new(&args[2 + offset]), e))?;
    if mode == "invite" {
        // invite <dir> <invitee64> <realm32> <room32> <epoch> <expiry>
        let invitee: [u8; 32] = hex_bytes(text(3 + offset)?, 32)?
            .try_into()
            .map_err(|_| "invitee key".to_string())?;
        let realm = vhalla_core::RealmId(u128::from_be_bytes(
            hex_bytes(text(4 + offset)?, 16)?
                .try_into()
                .map_err(|_| "realm".to_string())?,
        ));
        let room = vhalla_core::RoomId(u128::from_be_bytes(
            hex_bytes(text(5 + offset)?, 16)?
                .try_into()
                .map_err(|_| "room".to_string())?,
        ));
        let epoch = vhalla_core::Epoch(
            text(6 + offset)?
                .parse()
                .map_err(|_| "invalid epoch".to_string())?,
        );
        let expires_at = text(7 + offset)?
            .parse()
            .map_err(|_| "invalid expiry".to_string())?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| "entropy unavailable".to_string())?;
        let invitation = identity
            .issue_invitation(invitee, realm, room, epoch, expires_at, nonce)
            .map_err(invitation_error)?;
        let encoded = hex(&invitation.encode());
        return emit(
            json,
            &format!("invitation {encoded}"),
            "invitation",
            &format!(",\"invitation\":{}", json_quote(&encoded)),
        );
    }
    let peer_app = |text: &str| -> Result<[u8; 32], String> {
        hex_bytes(text, 32)?
            .try_into()
            .map_err(|_| "application key".to_string())
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async {
        if mode == "listen" {
            // An optional trailing IP literal picks the bind interface; the
            // advertised route carries it so a remote peer can dial in.
            let listen = args
                .get(if invited { 5 + offset } else { 4 + offset })
                .and_then(|a| a.to_str())
                .unwrap_or("127.0.0.1");
            let mut listener = if invited {
                let raw = hex_bytes(text(4 + offset)?, vhalla_native::INVITATION_BYTES)?;
                let invitation =
                    vhalla_native::Invitation::decode(&raw).map_err(invitation_error)?;
                Listener::bind_with_invitation_on(identity, invitation, listen)
                    .await
                    .map_err(|e| e.to_string())?
            } else {
                Listener::bind_on(identity, peer_app(text(3 + offset)?)?, listen)
                    .await
                    .map_err(|e| e.to_string())?
            };
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
            let (invitation, owner, route, body) = if invited {
                // send <dir> invitation <hex> <owner64> <route> <expiry> <msg>
                let raw = hex_bytes(text(4 + offset)?, vhalla_native::INVITATION_BYTES)?;
                let invitation =
                    vhalla_native::Invitation::decode(&raw).map_err(invitation_error)?;
                let owner = peer_app(text(5 + offset)?)?;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "clock before Unix epoch".to_string())?
                    .as_secs();
                invitation.verify_at(owner, now).map_err(invitation_error)?;
                // One local redemption per identity: the nonce is consumed
                // durably before dialing, so a verified invitation can never
                // be replayed from this identity after a restart.
                let spent_path = format!("{}.spent", text(2 + offset)?);
                let mut spent = vhalla_native::SpentFile::open(&spent_path)
                    .map_err(|e| spent_error(e, &spent_path))?;
                spent
                    .consume(invitation.claims().nonce)
                    .map_err(|e| spent_error(e, &spent_path))?;
                let expires = text(7 + offset)?
                    .parse()
                    .map_err(|_| "invalid expiry".to_string())?;
                let route = Route::parse(text(6 + offset)?, expires).map_err(|e| e.to_string())?;
                (Some(invitation), owner, route, text(8 + offset)?)
            } else {
                let expires = text(5 + offset)?
                    .parse()
                    .map_err(|_| "invalid expiry".to_string())?;
                let route = Route::parse(text(4 + offset)?, expires).map_err(|e| e.to_string())?;
                (None, peer_app(text(3 + offset)?)?, route, text(6 + offset)?)
            };
            let result = match invitation {
                Some(invitation) => vhalla_native::send_message_with_invitation(
                    identity,
                    owner,
                    invitation,
                    route,
                    body.as_bytes(),
                )
                .await
                .map_err(|e| e.to_string())?,
                None => vhalla_native::send_message(identity, owner, route, body.as_bytes())
                    .await
                    .map_err(|e| e.to_string())?,
            };
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

#[cfg(test)]
mod identity_copy_tests {
    use super::*;

    const PLAIN: cli::Style = cli::Style {
        color: false,
        ascii: false,
    };

    #[test]
    fn identity_errors_are_sentences_with_one_next_step() {
        use vhalla_identity::IdentityError;
        let dir = std::path::Path::new("/tmp/me");
        let cases = [
            identity_error("show", dir, IdentityError::UnsafePath),
            identity_error("show", dir, IdentityError::Corrupt),
            identity_error("show", dir, IdentityError::Busy),
            identity_error("init", dir, IdentityError::Entropy),
            identity_error("restore", dir, IdentityError::Phrase("bad checksum".into())),
            identity_error(
                "init",
                dir,
                IdentityError::Io(std::io::ErrorKind::AlreadyExists.into()),
            ),
            identity_error(
                "show",
                dir,
                IdentityError::Io(std::io::ErrorKind::NotFound.into()),
            ),
        ];
        for text in cases {
            let rendered = cli::render_error(&text, cli::Audience::Human, PLAIN);
            assert!(rendered.starts_with("✗ "), "{rendered}");
            assert_eq!(
                rendered
                    .lines()
                    .filter(|line| line.starts_with("→ "))
                    .count(),
                1,
                "{rendered}"
            );
            assert!(
                !rendered.contains("Io(") && !rendered.contains("Kind("),
                "{rendered}"
            );
        }
        assert_eq!(
            cli::render_error(
                &identity_error(
                    "show",
                    dir,
                    IdentityError::Io(std::io::ErrorKind::NotFound.into())
                ),
                cli::Audience::Human,
                PLAIN
            ),
            "✗ There's no identity in /tmp/me.\n→ vhalla identity init /tmp/me\n"
        );
        assert_eq!(
            identity_error(
                "init",
                std::path::Path::new("/tmp/missing/me"),
                IdentityError::Io(std::io::ErrorKind::NotFound.into())
            ),
            "The folder that should hold /tmp/missing/me doesn't exist. Nothing was created\n→ mkdir -p /tmp/missing"
        );
    }

    #[cfg(feature = "experimental-network")]
    #[test]
    fn invitation_and_spent_errors_read_as_sentences() {
        use vhalla_native::SpentError;
        use vhalla_session::InvitationError;
        let mut texts: Vec<String> = [
            InvitationError::Malformed,
            InvitationError::Key,
            InvitationError::Issuer,
            InvitationError::Signature,
            InvitationError::Expired,
        ]
        .into_iter()
        .map(invitation_error)
        .collect();
        for error in [
            SpentError::AlreadySpent,
            SpentError::Capacity,
            SpentError::Malformed,
            SpentError::Io,
        ] {
            texts.push(spent_error(error, "/tmp/me.spent"));
        }
        for text in texts {
            let rendered = cli::render_error(&text, cli::Audience::Human, PLAIN);
            assert!(rendered.starts_with("✗ "), "{rendered}");
            assert_eq!(rendered.matches("\n→ ").count(), 1, "{rendered}");
            assert!(!rendered.contains("Error"), "{rendered}");
        }
    }

    #[test]
    fn the_phrase_warning_is_for_people_only() {
        assert_eq!(
            phrase_warning(cli::Audience::Human, PLAIN).as_deref(),
            Some("⚠ This phrase restores your identity. Store it offline; anyone with it can sign as you.\n")
        );
        assert_eq!(phrase_warning(cli::Audience::Quiet, PLAIN), None);
        assert_eq!(phrase_warning(cli::Audience::Agent, PLAIN), None);
    }
}
