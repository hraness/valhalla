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
    if args.first().is_some_and(|s| s == "menubar") {
        return menubar(&args);
    }
    if args.first().is_some_and(|s| s == "outputs") {
        return outputs(&args);
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

/// `vhalla menubar [run|install|uninstall|status|start|refresh]` — the menu
/// bar. It is a separate unbundled binary: `run` opens it, `install` copies
/// it into the Valhalla folder and hands over to its own `install`, which
/// writes the login item through desktop-foundation's shared helper.
/// `refresh` saves room counts for the menu to show.
#[cfg(unix)]
fn menubar(args: &[std::ffi::OsString]) -> Result<(), String> {
    match args.get(1).and_then(|a| a.to_str()) {
        None if args.len() == 1 => menubar_launch(),
        Some("run" | "start") if args.len() == 2 => menubar_launch(),
        Some("install") if args.len() == 2 => menubar_install(),
        Some("uninstall") if args.len() == 2 => menubar_uninstall(),
        Some("status") if args.len() == 2 => menubar_status(),
        Some("refresh") if args.len() >= 6 => menubar_refresh(&args[2..]),
        _ => Err(
            "usage: vhalla menubar [run|install|uninstall|status]\n       vhalla menubar refresh SOCIAL_STORE REPLICA_HOME REALM NODE_HOME --config FILE"
                .into(),
        ),
    }
}

/// The login item earlier releases wrote. Install and uninstall retire it.
#[cfg(unix)]
const LEGACY_LAUNCH_AGENT: &str = "com.hraness.valhalla.menubar";

/// Bytes every `vhalla-menubar` with its own `install`, `uninstall`,
/// `status` and `start` carries. Earlier releases ignored their arguments
/// and opened the menu instead, so they must never be handed a command.
#[cfg(unix)]
const MENUBAR_LIFECYCLE_MARKER: &[u8] = b"vhalla-menubar-lifecycle:1";

#[cfg(unix)]
fn menubar_has_lifecycle(binary: &std::path::Path) -> bool {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(binary)
        .and_then(|file| file.take(256 * 1024 * 1024).read_to_end(&mut bytes))
        .is_ok()
        && bytes
            .windows(MENUBAR_LIFECYCLE_MARKER.len())
            .any(|window| window == MENUBAR_LIFECYCLE_MARKER)
}

#[cfg(unix)]
const MENUBAR_TOO_OLD: &str = "This vhalla-menubar is from an older release
It can't set up its own login item. Get the menu bar that matches this vhalla:
curl -fsSL https://vhalla.com/install.sh | sh -s -- --with-menubar
→ vhalla menubar install";

/// `vhalla-menubar` exits with this when another copy holds the menu bar.
#[cfg(unix)]
const MENUBAR_ALREADY_RUNNING: i32 = 3;

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

/// Resolution order: the installed copy, a sibling of this executable
/// (where `install.sh --with-menubar` puts it), then the in-repository
/// release build. Debug builds are deliberately absent — development
/// binaries go through `VHALLA_MENUBAR_PATH`. `install` uses the reverse
/// order (new builds first, installed copy last) so a new binary upgrades
/// the installation rather than reinstalling it onto itself.
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

/// What a person sees when no menu bar binary is on this Mac.
#[cfg(unix)]
const MENUBAR_NOT_INSTALLED: &str = "The Valhalla menu bar isn't on this Mac yet
It's a separate download. The installer can add it next to vhalla:
curl -fsSL https://vhalla.com/install.sh | sh -s -- --with-menubar
→ vhalla menubar install";

#[cfg(unix)]
fn resolve_menubar(for_install: bool) -> Result<std::path::PathBuf, String> {
    if let Some(value) = std::env::var_os("VHALLA_MENUBAR_PATH") {
        if !value.is_empty() {
            let path = std::path::PathBuf::from(value);
            return if qualified_binary(&path) {
                Ok(path)
            } else {
                Err("VHALLA_MENUBAR_PATH doesn't name a usable menu bar\nIt must be a built vhalla-menubar that only you can change.\n→ vhalla help menubar".into())
            };
        }
    }
    menubar_candidates(for_install)
        .into_iter()
        .find(|path| qualified_binary(path))
        .ok_or_else(|| MENUBAR_NOT_INSTALLED.to_owned())
}

/// How a menu bar start ended, from its exit status after a short wait.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MenubarStart {
    Running,
    AlreadyRunning,
    /// Killed at launch: on macOS this is how Gatekeeper stops an
    /// unverified download.
    Blocked,
    Failed,
}

#[cfg(unix)]
fn menubar_start_outcome(status: Option<std::process::ExitStatus>) -> MenubarStart {
    use std::os::unix::process::ExitStatusExt;
    match status {
        None => MenubarStart::Running,
        Some(status) if status.code() == Some(MENUBAR_ALREADY_RUNNING) => {
            MenubarStart::AlreadyRunning
        }
        Some(status) if status.signal() == Some(9) => MenubarStart::Blocked,
        Some(_) => MenubarStart::Failed,
    }
}

/// The recovery for a menu bar macOS stopped at launch. It follows
/// desktop-foundation's first-launch approval steps: the person decides,
/// and nothing here removes quarantine or changes Gatekeeper.
#[cfg(unix)]
fn menubar_blocked_message(binary: &std::path::Path) -> String {
    format!(
        "macOS stopped the Valhalla menu bar from opening
It may not trust {} because it was downloaded in a browser and isn't notarized.
If you trust this download, open System Settings › Privacy & Security and choose Open Anyway for vhalla-menubar, then try again.
The installer (curl -fsSL https://vhalla.com/install.sh | sh -s -- --with-menubar) fetches it without this check.
→ vhalla menubar",
        binary.file_name().and_then(|name| name.to_str()).unwrap_or("vhalla-menubar")
    )
}

#[cfg(unix)]
fn menubar_launch() -> Result<(), String> {
    let binary = resolve_menubar(false)?;
    let mut child = std::process::Command::new(&binary)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|_| MENUBAR_NOT_INSTALLED.to_owned())?;
    std::thread::sleep(std::time::Duration::from_millis(400));
    let status = child.try_wait().map_err(|e| e.to_string())?;
    let ok = if cli::Style::stdout().ascii {
        "OK"
    } else {
        "✓"
    };
    match menubar_start_outcome(status) {
        MenubarStart::Running => println!("{ok} Valhalla is in your menu bar"),
        MenubarStart::AlreadyRunning => println!("{ok} Valhalla is already in your menu bar"),
        MenubarStart::Blocked => return Err(menubar_blocked_message(&binary)),
        MenubarStart::Failed => {
            return Err(format!(
                "The Valhalla menu bar stopped while opening\nRun it directly to see why: {}\n→ vhalla menubar status",
                binary.display()
            ))
        }
    }
    Ok(())
}

/// `~/Library/LaunchAgents/com.hraness.valhalla.menubar.plist`.
#[cfg(unix)]
fn legacy_launch_agent_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from)?;
    Some(
        home.join("Library/LaunchAgents")
            .join(format!("{LEGACY_LAUNCH_AGENT}.plist")),
    )
}

/// The exact plist earlier releases wrote for `binary`.
#[cfg(unix)]
fn legacy_launch_agent_plist(binary: &std::path::Path) -> String {
    let path = binary.to_string_lossy();
    let escaped = path
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>{LEGACY_LAUNCH_AGENT}</string>\n\
         \x20 <key>ProgramArguments</key>\n  <array>\n    <string>{escaped}</string>\n  </array>\n\
         \x20 <key>RunAtLoad</key>\n  <true/>\n</dict>\n</plist>\n"
    )
}

/// Whether `plist` is exactly the file an earlier release wrote. Anything
/// else was written or edited by someone else and is left alone.
#[cfg(unix)]
fn is_legacy_launch_agent(plist: &std::path::Path, installed: &std::path::Path) -> bool {
    std::fs::symlink_metadata(plist).is_ok_and(|meta| meta.is_file() && meta.len() <= 4096)
        && std::fs::read_to_string(plist)
            .is_ok_and(|text| text == legacy_launch_agent_plist(installed))
}

/// Stops and sets aside the login item an earlier release wrote, when it is
/// exactly theirs. It unloads the old label so the old and new login items
/// never both open the menu bar.
#[cfg(unix)]
fn retire_legacy_launch_agent(installed: &std::path::Path) {
    let Some(plist) = legacy_launch_agent_path() else {
        return;
    };
    if !is_legacy_launch_agent(&plist, installed) {
        return;
    }
    if let Some(uid) = std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|text| text.trim().parse::<u32>().ok())
        .filter(|uid| *uid > 0)
    {
        let _ = std::process::Command::new("/bin/launchctl")
            .args(["bootout", &format!("gui/{uid}/{LEGACY_LAUNCH_AGENT}")])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    // Set aside, never delete: `vhalla doctor` lists it with a restore command.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let aside = std::path::PathBuf::from(format!("{}.retired-{stamp}", plist.display()));
    if std::fs::symlink_metadata(&aside).is_err() {
        let _ = std::fs::rename(&plist, aside);
    }
}

/// Runs the installed menu bar's own lifecycle command with this terminal,
/// so its notice, output and exit code reach the person unchanged.
#[cfg(unix)]
fn run_menubar_helper(binary: &std::path::Path, command: &str) -> Result<(), String> {
    let status = std::process::Command::new(binary)
        .arg(command)
        .stdin(std::process::Stdio::null())
        .status()
        .map_err(|_| MENUBAR_NOT_INSTALLED.to_owned())?;
    match menubar_start_outcome(Some(status)) {
        _ if status.success() => Ok(()),
        MenubarStart::Blocked => Err(menubar_blocked_message(binary)),
        // The helper has already said what went wrong.
        _ => std::process::exit(status.code().unwrap_or(1)),
    }
}

#[cfg(unix)]
fn copy_menubar(source: &std::path::Path, installed: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let bin_dir = installed
        .parent()
        .ok_or("the install folder has no parent")?;
    std::fs::create_dir_all(bin_dir).map_err(|e| e.to_string())?;
    std::fs::set_permissions(bin_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    let temporary = installed.with_file_name(format!(".vhalla-menubar.tmp-{}", std::process::id()));
    let copy = || -> Result<(), String> {
        std::fs::copy(source, &temporary).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
        std::fs::rename(&temporary, installed).map_err(|e| e.to_string())
    };
    copy().map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        format!("Couldn't copy the menu bar into place\n{error}\n→ vhalla menubar status")
    })
}

#[cfg(unix)]
fn menubar_install() -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("The menu bar runs only on macOS".into());
    }
    let source = resolve_menubar(true)?;
    if !menubar_has_lifecycle(&source) {
        return Err(MENUBAR_TOO_OLD.into());
    }
    let installed =
        installed_menubar().ok_or("Couldn't find your home folder\n→ vhalla help menubar")?;
    if source != installed {
        copy_menubar(&source, &installed)?;
    }
    retire_legacy_launch_agent(&installed);
    run_menubar_helper(&installed, "install")?;
    run_menubar_helper(&installed, "start")
}

#[cfg(unix)]
fn menubar_uninstall() -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("The menu bar runs only on macOS".into());
    }
    let installed =
        installed_menubar().ok_or("Couldn't find your home folder\n→ vhalla help menubar")?;
    retire_legacy_launch_agent(&installed);
    let ok = if cli::Style::stdout().ascii {
        "OK"
    } else {
        "✓"
    };
    if !qualified_binary(&installed) {
        println!("{ok} Valhalla won't open at login");
        return Ok(());
    }
    if menubar_has_lifecycle(&installed) {
        run_menubar_helper(&installed, "uninstall")?;
    } else {
        println!("{ok} Valhalla won't open at login");
    }
    std::fs::remove_file(&installed).map_err(|error| {
        format!("Valhalla no longer opens at login, but its copy couldn't be removed\n{error}\n→ vhalla menubar uninstall")
    })
}

#[cfg(unix)]
fn menubar_status() -> Result<(), String> {
    match installed_menubar() {
        Some(installed) if qualified_binary(&installed) && menubar_has_lifecycle(&installed) => {
            run_menubar_helper(&installed, "status")
        }
        Some(installed) if qualified_binary(&installed) => {
            let next = if cli::Style::stdout().ascii {
                "->"
            } else {
                "→"
            };
            println!("An older Valhalla menu bar is installed.\n{next} vhalla menubar install");
            Ok(())
        }
        _ => {
            let next = if cli::Style::stdout().ascii {
                "->"
            } else {
                "→"
            };
            println!("Valhalla's menu bar isn't installed.\n{next} vhalla menubar install");
            Ok(())
        }
    }
}

/// `menubar-status.json` in the Valhalla folder: counts from one `rooms
/// status` read and when it happened. No room names, keys or paths.
#[cfg(unix)]
fn menubar_status_json(now_ms: u128, rooms: Result<MenubarRooms, &str>) -> String {
    match rooms {
        Ok(r) => format!(
            "{{\"schemaVersion\":1,\"refreshedAt\":{now_ms},\"rooms\":{{\"count\":{},\"height\":{},\"waiting\":{},\"failed\":{},\"partial\":{}}}}}\n",
            r.count, r.height, r.waiting, r.failed, r.partial
        ),
        Err(code) => format!("{{\"schemaVersion\":1,\"refreshedAt\":{now_ms},\"error\":\"{code}\"}}\n"),
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MenubarRooms {
    count: u64,
    height: u64,
    waiting: u64,
    failed: u64,
    partial: bool,
}

/// Reads the counts the menu shows from `rooms status` JSON.
#[cfg(all(unix, feature = "experimental-rooms-tui"))]
fn menubar_rooms(stdout: &[u8]) -> Option<MenubarRooms> {
    let value: serde_json::Value = serde_json::from_slice(stdout).ok()?;
    let number = |v: &serde_json::Value| {
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    };
    let summary = value.get("pendingSummary")?;
    let count = |name: &str| summary.get(name).and_then(number).unwrap_or(0);
    Some(MenubarRooms {
        count: value.get("rooms")?.as_array()?.len() as u64,
        height: value.get("height").and_then(number).unwrap_or(0),
        waiting: count("queued") + count("submitted"),
        failed: count("collision") + count("rejected"),
        partial: matches!(value.get("partial"), Some(serde_json::Value::Bool(true)))
            || value.get("partial").and_then(|v| v.as_str()) == Some("true"),
    })
}

/// `vhalla menubar refresh SOCIAL_STORE REPLICA_HOME REALM NODE_HOME
/// --config FILE` — reads `rooms status` and saves its counts for the menu
/// bar. Read-only for rooms: it never touches identities or the stores
/// beyond what `rooms status` reads.
#[cfg(unix)]
fn menubar_refresh(args: &[std::ffi::OsString]) -> Result<(), String> {
    let root = state_directory().ok_or("Couldn't find your home folder\n→ vhalla help menubar")?;
    std::fs::create_dir_all(&root)
        .map_err(|e| format!("Couldn't create the Valhalla folder\n{e}"))?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    #[cfg(feature = "experimental-rooms-tui")]
    let (rooms, failure) = {
        let exe =
            std::env::current_exe().map_err(|e| format!("Couldn't find vhalla itself\n{e}"))?;
        let mut rooms_args: Vec<std::ffi::OsString> = vec!["rooms".into(), "status".into()];
        rooms_args.extend(args.iter().map(|a| a.to_owned()));
        let out = std::process::Command::new(exe)
            .args(&rooms_args)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("Couldn't run vhalla rooms status\n{e}"))?;
        if out.status.success() {
            match menubar_rooms(&out.stdout) {
                Some(rooms) => (Ok(rooms), None),
                None => (
                    Err("rooms-unreadable"),
                    Some(
                        "vhalla rooms status printed something the menu bar can't read".to_owned(),
                    ),
                ),
            }
        } else {
            let detail = String::from_utf8_lossy(&out.stderr);
            let detail = detail
                .lines()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("")
                .trim_start_matches("vhalla: ")
                .to_owned();
            (
                Err("rooms-unavailable"),
                Some(format!(
                    "Couldn't read your rooms\n{detail}\n→ vhalla rooms status {}",
                    args.iter()
                        .map(|a| a.to_string_lossy())
                        .collect::<Vec<_>>()
                        .join(" ")
                )),
            )
        }
    };
    #[cfg(not(feature = "experimental-rooms-tui"))]
    let (rooms, failure): (Result<MenubarRooms, &str>, Option<String>) = {
        let _ = args;
        (
            Err("not-built"),
            Some(
                "This vhalla was built without rooms, so there's no room status to show".to_owned(),
            ),
        )
    };
    let path = root.join("menubar-status.json");
    atomic_write(&path, &menubar_status_json(now_ms, rooms), 0o600)
        .map_err(|e| format!("Couldn't save room status for the menu bar\n{e}"))?;
    if let Some(message) = failure {
        return Err(message);
    }
    if let Ok(rooms) = rooms {
        let ok = if cli::Style::stdout().ascii {
            "OK"
        } else {
            "✓"
        };
        let plural = |n: u64, one: &str, many: &str| {
            if n == 1 {
                format!("1 {one}")
            } else {
                format!("{n} {many}")
            }
        };
        let mut line = format!(
            "{ok} Room status saved for the menu bar: {}",
            plural(rooms.count, "room", "rooms")
        );
        if rooms.waiting > 0 {
            line.push_str(&format!(
                ", {} waiting",
                plural(rooms.waiting, "send", "sends")
            ));
        }
        if rooms.failed > 0 {
            line.push_str(&format!(
                ", {} didn't go through",
                plural(rooms.failed, "send", "sends")
            ));
        }
        println!("{line}");
    }
    Ok(())
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

#[cfg(all(test, unix))]
mod menubar_tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    const PLAIN: cli::Style = cli::Style {
        color: false,
        ascii: false,
    };

    #[test]
    fn start_outcomes_follow_the_menu_bar_exit() {
        let exit = |code: i32| Some(std::process::ExitStatus::from_raw(code << 8));
        assert_eq!(menubar_start_outcome(None), MenubarStart::Running);
        assert_eq!(menubar_start_outcome(exit(3)), MenubarStart::AlreadyRunning);
        assert_eq!(menubar_start_outcome(exit(1)), MenubarStart::Failed);
        assert_eq!(
            menubar_start_outcome(Some(std::process::ExitStatus::from_raw(9))),
            MenubarStart::Blocked
        );
    }

    #[test]
    fn a_blocked_menu_bar_gets_the_open_anyway_steps_and_no_bypass() {
        let message =
            menubar_blocked_message(std::path::Path::new("/Users/me/Downloads/vhalla-menubar"));
        let text = cli::render_error(&message, cli::Audience::Human, PLAIN);
        assert!(
            text.starts_with("✗ macOS stopped the Valhalla menu bar from opening.\n"),
            "{text}"
        );
        assert!(
            text.contains("System Settings › Privacy & Security"),
            "{text}"
        );
        assert!(text.contains("Open Anyway"), "{text}");
        assert!(text.ends_with("→ vhalla menubar\n"), "{text}");
        assert!(!text.contains("xattr") && !text.contains("spctl"), "{text}");
        assert!(!text.contains("/Users/me"), "{text}");
    }

    #[test]
    fn the_missing_binary_copy_points_to_the_installer() {
        let text = cli::render_error(MENUBAR_NOT_INSTALLED, cli::Audience::Human, PLAIN);
        assert_eq!(
            text,
            "✗ The Valhalla menu bar isn't on this Mac yet.\n  It's a separate download. The installer can add it next to vhalla:\n  curl -fsSL https://vhalla.com/install.sh | sh -s -- --with-menubar\n→ vhalla menubar install\n"
        );
    }

    #[test]
    fn only_the_exact_legacy_login_item_is_retired() {
        let dir = std::env::temp_dir().join(format!("vhalla-legacy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let installed = dir.join("bin/vhalla-menubar");
        let plist = dir.join("legacy.plist");
        std::fs::write(&plist, legacy_launch_agent_plist(&installed)).unwrap();
        assert!(is_legacy_launch_agent(&plist, &installed));
        assert!(!is_legacy_launch_agent(&plist, &dir.join("other")));
        std::fs::write(
            &plist,
            legacy_launch_agent_plist(&installed).replace("<true/>", "<false/>"),
        )
        .unwrap();
        assert!(!is_legacy_launch_agent(&plist, &installed));
        assert!(!is_legacy_launch_agent(
            &dir.join("missing.plist"),
            &installed
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_menu_bars_with_their_own_lifecycle_get_commands() {
        let dir = std::env::temp_dir().join(format!("vhalla-marker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let old = dir.join("old");
        let new = dir.join("new");
        std::fs::write(&old, b"\x7fELF old menu bar").unwrap();
        let mut bytes = b"\xcf\xfa\xed\xfe".to_vec();
        bytes.extend_from_slice(MENUBAR_LIFECYCLE_MARKER);
        std::fs::write(&new, bytes).unwrap();
        assert!(!menubar_has_lifecycle(&old));
        assert!(menubar_has_lifecycle(&new));
        assert!(!menubar_has_lifecycle(&dir.join("missing")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_status_file_holds_counts_only() {
        let rooms = MenubarRooms {
            count: 4,
            height: 1200,
            waiting: 1,
            failed: 0,
            partial: false,
        };
        assert_eq!(
            menubar_status_json(5, Ok(rooms)),
            "{\"schemaVersion\":1,\"refreshedAt\":5,\"rooms\":{\"count\":4,\"height\":1200,\"waiting\":1,\"failed\":0,\"partial\":false}}\n"
        );
        assert_eq!(
            menubar_status_json(5, Err("rooms-unavailable")),
            "{\"schemaVersion\":1,\"refreshedAt\":5,\"error\":\"rooms-unavailable\"}\n"
        );
    }

    #[cfg(feature = "experimental-rooms-tui")]
    #[test]
    fn room_counts_come_from_rooms_status() {
        let json = br#"{"height":12,"revision":3,"partial":false,"quorum":null,"schedule":[],"rooms":[{"slug":"design"},{"slug":"ops"}],"pendingSummary":{"queued":1,"submitted":1,"committed":4,"collision":1,"rejected":0},"pending":[]}"#;
        assert_eq!(
            menubar_rooms(json),
            Some(MenubarRooms {
                count: 2,
                height: 12,
                waiting: 2,
                failed: 1,
                partial: false
            })
        );
        assert_eq!(menubar_rooms(b"not json"), None);
    }
}
