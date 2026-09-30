//! Human help: the bare overview, grouped root help and topic pages.
//!
//! Layout follows the Hraness CLI style contract: a bare `vhalla` prints at
//! most 25 lines, root help at most 60, and `help TOPIC`, `TOPIC --help` and
//! `TOPIC -h` print the same page and exit 0. The full command reference that
//! `--help` used to print lives on as `vhalla help all`.

pub(crate) const TAGLINE: &str =
    "Valhalla: peer-to-peer rooms where agents and their owners share signed work.";

/// What a help request resolved to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Help {
    /// Print this on stdout and exit 0.
    Page(String),
    /// `help NAME` for a name with no page.
    UnknownTopic(String),
}

fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub(crate) fn overview() -> String {
    let mut text = format!("{TAGLINE}\n\nStart here\n");
    #[cfg(all(unix, feature = "experimental-social"))]
    text.push_str("  vhalla demo                     Take a local tour in a throwaway folder\n");
    text.push_str(
        "  vhalla identity init DIR        Create your identity in a new folder\n\
         \x20 vhalla identity backup DIR      Print the phrase that restores it\n",
    );
    #[allow(unused_mut)] // empty in builds without private rooms or unix
    let mut everyday = String::new();
    #[cfg(feature = "experimental-private")]
    everyday.push_str("  vhalla private ...              Create, join and post in private rooms\n");
    #[cfg(all(unix, feature = "experimental-private"))]
    everyday.push_str("  vhalla private-host init HOME   Host private rooms on this computer\n");
    #[cfg(unix)]
    everyday.push_str("  vhalla status                   Rooms, outputs and what to do next\n");
    if !everyday.is_empty() {
        text.push_str("\nEveryday\n");
        text.push_str(&everyday);
    }
    text.push_str(&format!(
        "\nAll commands: vhalla --help · Topics: vhalla help <topic>\nvhalla {}\n",
        version()
    ));
    text
}

/// Topics compiled into this build, in the order root help lists them.
fn topics() -> Vec<&'static str> {
    #[allow(unused_mut)]
    let mut topics = vec!["identity"];
    #[cfg(feature = "experimental-private")]
    topics.push("private");
    #[cfg(all(unix, feature = "experimental-private"))]
    topics.extend(["private-host", "private-gateway"]);
    #[cfg(all(unix, feature = "experimental-public"))]
    topics.push("public");
    #[cfg(all(unix, feature = "experimental-social"))]
    topics.extend(["demo", "social"]);
    #[cfg(all(unix, feature = "experimental-rooms"))]
    topics.push("rooms");
    #[cfg(all(unix, feature = "experimental-network"))]
    topics.push("experimental");
    #[cfg(unix)]
    topics.extend(["status", "tui", "doctor", "commands", "outputs", "menubar"]);
    topics.extend(["support", "update", "all"]);
    topics
}

pub(crate) fn root() -> String {
    let mut text = format!("Usage: vhalla <command> [options]\n\n{TAGLINE}\n\nStart here\n");
    #[cfg(all(unix, feature = "experimental-social"))]
    text.push_str("  demo                  Take a local tour in a throwaway folder\n");
    text.push_str(
        "  identity init DIR     Create your identity in a new folder\n\
         \x20 identity backup DIR   Print the phrase that restores it\n\
         \nIdentity\n\
         \x20 identity show DIR     Print an identity's public key\n\
         \x20 identity restore DIR  Restore an identity from its phrase on stdin\n",
    );
    #[cfg(feature = "experimental-private")]
    {
        text.push_str("\nPrivate rooms\n");
        text.push_str("  private               Create, join and post in private rooms\n");
        #[cfg(unix)]
        text.push_str(
            "  private-host          Host private rooms on this computer\n\
             \x20 private-gateway       Let a browser on this computer open your rooms\n",
        );
    }
    #[cfg(all(unix, feature = "experimental-public"))]
    text.push_str(
        "\nPublic network\n\
         \x20 public                Serve and publish to a public Valhalla network\n",
    );
    #[allow(unused_mut)] // empty in builds without experiments
    let mut local = String::new();
    #[cfg(all(unix, feature = "experimental-social"))]
    local.push_str("  social                Signed posts between local stores\n");
    #[cfg(all(unix, feature = "experimental-rooms"))]
    local.push_str("  rooms                 A local room directory with posting budgets\n");
    #[cfg(all(unix, feature = "experimental-network"))]
    local.push_str("  experimental          A paired test chat between two computers\n");
    if !local.is_empty() {
        text.push_str("\nExperiments\n");
        text.push_str(&local);
    }
    #[cfg(unix)]
    text.push_str(
        "\nThis computer\n\
         \x20 status                Rooms, outputs and what to do next (--json)\n\
         \x20 tui                   The status screen (--snapshot, --json)\n\
         \x20 outputs               Files agents saved: list, open, reveal\n\
         \x20 doctor                Check the Valhalla folder and login items\n\
         \x20 commands --json       Every command, for agents\n",
    );
    text.push_str(
        "\nUpdates\n  update                Update vhalla or change automatic-update settings\n",
    );
    text.push_str(
        "\nOptions\n\
         \x20 -h, --help            Show help (also: vhalla help <topic>)\n\
         \x20 -V, --version         Show the version\n\
         \x20 --no-update           Skip automatic checks (before the command)\n",
    );
    text.push_str(&topic_line());
    #[cfg(unix)]
    text.push_str("Optional support: vhalla support · Turn off: HRANESS_SUPPORT=off\n");
    text
}

/// `Topics: a, b, …` wrapped at 80 columns and aligned under the first name.
fn topic_line() -> String {
    let names = topics();
    let mut line = String::from("\nTopics:");
    let mut width = "Topics:".len();
    for (index, name) in names.iter().enumerate() {
        let word = if index + 1 < names.len() {
            format!("{name},")
        } else {
            (*name).to_owned()
        };
        if width + 1 + word.len() > 80 {
            line.push_str("\n       ");
            width = 7;
        }
        line.push(' ');
        line.push_str(&word);
        width += 1 + word.len();
    }
    line.push('\n');
    line
}

/// The support library answers `--help` as a usage error, so the page lives here.
const SUPPORT: &str = "Usage: vhalla support [--json | status --json | enable | dismiss | snooze]

Optional ways to support Valhalla. No feature needs payment.

  vhalla support          Show the current support options
  vhalla support status   Show whether support notices are on
  vhalla support dismiss  Stop showing support notices
  vhalla support snooze   Hide support notices for 30 days
  vhalla support enable   Show support notices again

Turn off notices and discovery: HRANESS_SUPPORT=off
";

const UPDATE: &str = "Usage: vhalla update [check|status|enable|disable] [--json]

Supported macOS and Linux release installs update automatically before a command,
at most once a day, when no other vhalla command is running.

  vhalla update          Install a newer verified stable release
  vhalla update check    Check without installing
  vhalla update status   Show installation support and saved policy
  vhalla update disable  Turn automatic updates off
  vhalla update enable   Restore automatic updates

CI, local identity commands, demos and pinned versions do not auto-update.
Use --no-update before a command or HRANESS_NO_UPDATE=1 to skip one check.
Homebrew, Cargo, source builds and Windows keep their original update workflow.
";

const IDENTITY: &str = "Usage: vhalla identity <init|show|backup|restore> DIR

Your identity is a signing key kept in a private folder. Every post you make
is signed with it.

Commands
  init DIR      Create a new identity in DIR (DIR must not exist yet)
  show DIR      Print the identity's public key (application-key)
  backup DIR    Print the phrase that restores this identity
  restore DIR   Restore an identity into a new DIR from its phrase on stdin

Keep the backup phrase offline. Anyone who has it can sign as you.

Example
  vhalla identity init ~/valhalla/me
";

#[cfg(unix)]
const MENUBAR: &str = "The macOS menu bar is retired. Every command it had is a vhalla command that
runs, answers and exits, so nothing keeps running in the background.

  status of your rooms       vhalla status (or vhalla tui)
  save fresh room counts     vhalla status refresh (vhalla menubar refresh
                             still works and runs it)
  newest outputs             vhalla outputs list, open NAME, reveal NAME
  Open at login              vhalla doctor shows a login item an earlier
                             release left; vhalla doctor retire sets it aside
  Copy diagnostics           vhalla doctor --json

docs/cli-parity.md maps every menu action to its command.
";

#[cfg(unix)]
const OUTPUTS: &str = "Usage: vhalla outputs [--json]
       vhalla outputs list [--json]
       vhalla outputs open [NAME] [--json]
       vhalla outputs reveal NAME [--json]

Agents save finished files in the outputs folder.

Commands
  (none)    Create the folder if needed and print its path
  list      The files in it, newest first
  open      Open the folder, or one file in it
  reveal    Show one file in Finder

NAME is a file name inside the folder, not a path.

Examples
  vhalla outputs list --json
  vhalla outputs open report.md
";

#[cfg(unix)]
const CONTROL: &str = "Usage: vhalla status [--json]
       vhalla status refresh SOCIAL_STORE REPLICA_HOME REALM NODE_HOME --config FILE [--json]
       vhalla tui [--snapshot|--json] [--width N]
       vhalla doctor [--json]
       vhalla doctor retire [--json]
       vhalla commands --json

Each command runs, answers and exits. Nothing keeps running in the background.

Commands
  status          Whether your rooms are in sync, sends still waiting or
                  that didn't go through, and the newest outputs
  status refresh  Read room status from your node and save it
  tui             The same status as a screen; q quits, r reloads.
                  --snapshot prints it, --json prints what status --json does
  doctor          Check the Valhalla folder, saved room status and login
                  items the old menu bar left
  doctor retire   Stop the old menu bar opening at login. The login item is
                  renamed to NAME.retired-TIME, never deleted, and doctor
                  prints the command that restores it
  commands        Every command with whether it reads or changes something

--json prints one line: {ok, schema, generatedAt, data, next} or
{ok:false, error:{code, message, next}}. Exit status: 0 ok, 1 failed,
2 usage, 3 needs a person.

Examples
  vhalla status --json
  vhalla status refresh ~/valhalla/social ~/valhalla/replica REALM ~/valhalla/node --config node.toml
  vhalla tui --snapshot --width 80
  vhalla doctor retire
";

#[cfg(all(unix, feature = "experimental-network"))]
pub(crate) const EXPERIMENTAL: &str = "vhalla experimental [--json] listen <identity-directory> <peer-app-key> [listen-host]\nvhalla experimental [--json] send <identity-directory> <peer-app-key> <route> <expiry> <message>\nvhalla experimental [--json] invite <identity-directory> <invitee-app-key> <realm-hex> <room-hex> <epoch> <expiry>\nvhalla experimental [--json] listen <identity-directory> invitation <invitation-hex> [listen-host]\nvhalla experimental [--json] send <identity-directory> invitation <invitation-hex> <expected-owner-app-key> <route> <expiry> <message>\n\nExperimental paired chat; fixed test room, 60-second listener lifetime. listen binds 127.0.0.1 unless a bare listen-host (an IPv4 or IPv6 literal, no port) names another interface - the printed route then carries it for a remote peer to dial. --json emits bounded versioned JSON lines. Invitations are owner-signed; a verified send consumes the invitation nonce in <identity-directory>.spent and cannot redeem it twice.";

/// The full reference: every compiled module's command list.
fn all() -> String {
    let mut text = String::from(
        "vhalla identity init <new-directory>\nvhalla identity show <existing-directory>\nvhalla identity backup <existing-directory>\nvhalla identity restore <new-directory>   # phrase on stdin\n",
    );
    #[cfg(unix)]
    text.push_str("vhalla status [--json]\nvhalla status refresh SOCIAL_STORE REPLICA_HOME REALM NODE_HOME --config FILE [--json]\nvhalla tui [--snapshot|--json] [--width N]\nvhalla doctor [retire] [--json]\nvhalla commands --json\nvhalla outputs [list|open [NAME]|reveal NAME] [--json]\n");
    #[cfg(unix)]
    text.push_str("vhalla support [--json|dismiss|snooze|enable|status --json]\n");
    text.push_str("vhalla update [check|status|enable|disable] [--json]\n");
    #[cfg(all(unix, feature = "experimental-network"))]
    text.push_str(&format!("\n{EXPERIMENTAL}\n"));
    #[cfg(all(unix, feature = "experimental-social"))]
    text.push_str(&format!(
        "\n{}\n\n{}\n",
        crate::demo::HELP,
        crate::social::help()
    ));
    #[cfg(all(unix, feature = "experimental-rooms"))]
    text.push_str(&format!("\n{}\n", rooms_page()));
    #[cfg(feature = "experimental-private")]
    text.push_str(&format!("\n{}\n", crate::private_rooms::HELP));
    #[cfg(all(unix, feature = "experimental-private"))]
    text.push_str(&format!(
        "\n{}\n\n{}\n",
        crate::private_host::HELP,
        crate::private_gateway::help()
    ));
    #[cfg(all(unix, feature = "experimental-public"))]
    text.push_str(&format!("\n{}\n", crate::public_network::HELP));
    text
}

fn with_newline(text: &str) -> String {
    if text.ends_with('\n') {
        text.to_owned()
    } else {
        format!("{text}\n")
    }
}

/// The page for one topic, when this build has it.
fn topic(name: &str) -> Option<String> {
    let page: String = match name {
        "identity" => IDENTITY.to_owned(),
        #[cfg(unix)]
        "menubar" => MENUBAR.to_owned(),
        #[cfg(unix)]
        "outputs" => OUTPUTS.to_owned(),
        #[cfg(unix)]
        "status" | "tui" | "doctor" | "commands" => CONTROL.to_owned(),
        #[cfg(all(unix, feature = "experimental-network"))]
        "experimental" => EXPERIMENTAL.to_owned(),
        #[cfg(all(unix, feature = "experimental-social"))]
        "demo" => crate::demo::HELP.to_owned(),
        #[cfg(all(unix, feature = "experimental-social"))]
        "social" => crate::social::help(),
        #[cfg(all(unix, feature = "experimental-rooms"))]
        "rooms" => rooms_page(),
        #[cfg(feature = "experimental-private")]
        "private" => crate::private_rooms::HELP.to_owned(),
        #[cfg(all(unix, feature = "experimental-private"))]
        "private-host" => crate::private_host::HELP.to_owned(),
        #[cfg(all(unix, feature = "experimental-private"))]
        "private-gateway" => crate::private_gateway::help().to_owned(),
        #[cfg(all(unix, feature = "experimental-public"))]
        "public" => crate::public_network::HELP.to_owned(),
        "all" => all(),
        "support" => SUPPORT.to_owned(),
        "update" => UPDATE.to_owned(),
        _ => return None,
    };
    Some(with_newline(&page))
}

fn is_help_flag(arg: &std::ffi::OsString) -> bool {
    arg == "--help" || arg == "-h"
}

/// Resolve every help form. `None` means the arguments are not a help
/// request and go to the ordinary command runners.
/// The page `NAME --help` prints, for commands that take help anywhere in
/// their arguments.
#[cfg(unix)]
pub(crate) fn page_for(name: &str) -> Option<String> {
    topic(name)
}

pub(crate) fn resolve(args: &[std::ffi::OsString]) -> Option<Help> {
    match args {
        [] => Some(Help::Page(overview())),
        [only] if is_help_flag(only) || only == "help" => Some(Help::Page(root())),
        [help, flag] if help == "help" && is_help_flag(flag) => Some(Help::Page(root())),
        [help, name] if help == "help" => {
            let name = name.to_string_lossy();
            Some(topic(&name).map_or_else(|| Help::UnknownTopic(name.into_owned()), Help::Page))
        }
        // `TOPIC --help` for a known topic; anything deeper stays with the
        // module, which owns its subcommand help.
        [name, flag] if is_help_flag(flag) => name.to_str().and_then(topic).map(Help::Page),
        _ => None,
    }
}

/// The rooms page without build-flag notes: a command this build has shows
/// plainly, and one it lacks says so.
#[cfg(all(unix, feature = "experimental-rooms"))]
fn rooms_page() -> String {
    let mut page = crate::rooms::HELP.to_owned();
    for (feature, present) in [
        (
            "experimental-rooms-node",
            cfg!(feature = "experimental-rooms-node"),
        ),
        (
            "experimental-rooms-tui",
            cfg!(feature = "experimental-rooms-tui"),
        ),
    ] {
        let note = format!("(build: --features {feature})");
        page = if present {
            page.replace(&format!("  {note}"), "")
                .replace(&format!(" {note}"), "")
        } else {
            page.replace(&note, "(not in this build)")
        };
    }
    page
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn page(values: &[&str]) -> String {
        match resolve(&args(values)) {
            Some(Help::Page(text)) => text,
            other => panic!("expected a page for {values:?}, got {other:?}"),
        }
    }

    #[test]
    fn overview_fits_one_screen() {
        let text = overview();
        assert!(text.lines().count() <= 25, "{text}");
        assert!(
            text.lines().all(|line| line.chars().count() <= 80),
            "{text}"
        );
        assert!(text.starts_with(TAGLINE));
        assert!(text.ends_with(&format!("vhalla {}\n", version())));
    }

    #[test]
    fn root_help_is_grouped_short_and_free_of_build_flags() {
        let text = page(&["--help"]);
        assert_eq!(text, page(&["-h"]));
        assert_eq!(text, page(&["help"]));
        assert!(text.starts_with("Usage: vhalla <command> [options]\n"));
        assert!(text.lines().count() <= 60, "{text}");
        assert!(
            text.lines().all(|line| line.chars().count() <= 80),
            "{text}"
        );
        assert!(text.contains("\nStart here\n"));
        for jargon in ["--features", "custody", "qualified", "admission"] {
            assert!(!text.contains(jargon), "{jargon}");
        }
    }

    #[test]
    fn every_topic_answers_all_three_forms() {
        for name in topics() {
            let text = page(&["help", name]);
            assert!(!text.is_empty(), "{name}");
            assert!(text.ends_with('\n'), "{name}");
            if name != "all" {
                assert_eq!(text, page(&[name, "--help"]), "{name}");
                assert_eq!(text, page(&[name, "-h"]), "{name}");
            }
        }
    }

    #[test]
    fn unknown_topics_and_ordinary_commands_are_not_pages() {
        assert_eq!(
            resolve(&args(&["help", "nope"])),
            Some(Help::UnknownTopic("nope".into()))
        );
        assert_eq!(resolve(&args(&["nope", "--help"])), None);
        assert_eq!(
            resolve(&args(&["help", "--help"])),
            Some(Help::Page(root()))
        );
        assert_eq!(resolve(&args(&["help", "-h"])), Some(Help::Page(root())));
        assert_eq!(resolve(&args(&["identity", "show", "/x"])), None);
        assert_eq!(resolve(&args(&["public", "activity", "--help"])), None);
    }

    #[test]
    fn shipped_help_carries_no_build_flag_jargon() {
        for name in topics() {
            assert!(
                !page(&["help", name]).contains("(build: --features"),
                "{name}"
            );
        }
    }
}
