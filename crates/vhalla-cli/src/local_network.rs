//! What people see around macOS network permissions: the firewall notice
//! before a private host listens beyond this computer, and the recovery when
//! Local Network access looks blocked for a room on your network.
//!
//! The copy follows the shared `INCOMING_CONNECTIONS` and `LOCAL_NETWORK`
//! templates (Hraness permissions kit, Appendix B). Until Valhalla ships as a
//! local app, macOS names the terminal app or `vhalla`, so the copy does too.
//! TODO(df-0.8): render through `hraness-cli-kit` permissions once 0.8.0 ships.

use std::io::{BufRead, IsTerminal, Write};
use std::net::{IpAddr, SocketAddr};

use crate::cli::{self, Audience, Style};

pub(crate) const FIREWALL_PATH: &str = "System Settings › Network › Firewall";
pub(crate) const FIREWALL_URL: &str =
    "x-apple.systempreferences:com.apple.Network-Settings.extension";
pub(crate) const LOCAL_NETWORK_PATH: &str = "System Settings › Privacy & Security › Local Network";
pub(crate) const LOCAL_NETWORK_URL: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_LocalNetwork";

/// An address other computers reach over the network (not this computer only).
pub(crate) fn beyond_this_computer(address: SocketAddr) -> bool {
    !address.ip().is_loopback()
}

/// A private-network address: the kind macOS Local Network access covers.
pub(crate) fn on_local_network(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// The app macOS names in its dialog when a person runs vhalla themselves.
pub(crate) fn terminal_app(env: &dyn Fn(&str) -> Option<String>) -> String {
    match env("TERM_PROGRAM").as_deref() {
        Some("Apple_Terminal") => "Terminal".into(),
        Some("iTerm.app") => "iTerm".into(),
        Some("ghostty") => "Ghostty".into(),
        Some("WezTerm") => "WezTerm".into(),
        Some("vscode") => "Visual Studio Code".into(),
        Some("WarpTerminal") => "Warp".into(),
        _ => "your terminal app".into(),
    }
}

/// `INCOMING_CONNECTIONS`: requester is the listening executable.
pub(crate) fn incoming_notice(style: Style, confirm: bool) -> String {
    let mut text = format!(
        "{} macOS will ask to let vhalla accept incoming network connections for Valhalla.\n   Choose Allow so room members can reach this Mac. Change this any time in {FIREWALL_PATH}.\n",
        style.notice()
    );
    if confirm {
        text.push_str("   Press Enter to continue · s to skip\n");
    }
    text
}

/// The "unknown" recovery: Local Network access may be off for the requester.
pub(crate) fn local_network_recovery(requester: &str, address: SocketAddr) -> String {
    format!(
        "Valhalla couldn't connect to {address} on your local network. macOS may be blocking {requester}\n\
         Check {LOCAL_NETWORK_PATH} and turn on {requester}, then run the command again.\n\
         → open \"{LOCAL_NETWORK_URL}\""
    )
}

/// Whether the macOS application firewall is on. Reads state only.
pub(crate) fn firewall_enabled() -> bool {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
            .arg("--getglobalstate")
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()
            .is_some_and(|output| firewall_state_on(&String::from_utf8_lossy(&output.stdout)))
    }
    #[cfg(not(target_os = "macos"))]
    false
}

pub(crate) fn firewall_state_on(output: &str) -> bool {
    output.contains("enabled") || output.contains("State = 1") || output.contains("State = 2")
}

/// Whether a failed connection to a private-network address looks like macOS
/// Local Network access being off: the connect fails with "no route to host"
/// immediately. Other failures keep their own message.
pub(crate) fn looks_blocked(address: SocketAddr) -> bool {
    if !cfg!(target_os = "macos") || !on_local_network(address.ip()) {
        return false;
    }
    matches!(
        std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_secs(2)),
        Err(error) if error.kind() == std::io::ErrorKind::HostUnreachable
    )
}

/// What the person chose at a notice.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Choice {
    Continue,
    Skip,
}

/// Show the firewall notice to a person before a host listens beyond this
/// computer while the firewall is on. Enter continues, `s` skips. Scripts,
/// agents and launchd runs see nothing.
pub(crate) fn before_listening(address: SocketAddr, confirm_allowed: bool) -> Choice {
    if !beyond_this_computer(address) || cli::audience() != Audience::Human || !firewall_enabled() {
        return Choice::Continue;
    }
    let confirm =
        confirm_allowed && std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let _ = std::io::stderr().write_all(incoming_notice(Style::stderr(), confirm).as_bytes());
    if !confirm {
        return Choice::Continue;
    }
    let mut answer = String::new();
    match std::io::stdin().lock().read_line(&mut answer) {
        Ok(_) if answer.trim().eq_ignore_ascii_case("s") => Choice::Skip,
        _ => Choice::Continue,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN: Style = Style {
        color: false,
        ascii: false,
    };

    #[test]
    fn the_firewall_notice_follows_the_template() {
        assert_eq!(
            incoming_notice(PLAIN, true),
            "🔐 macOS will ask to let vhalla accept incoming network connections for Valhalla.\n   Choose Allow so room members can reach this Mac. Change this any time in System Settings › Network › Firewall.\n   Press Enter to continue · s to skip\n"
        );
        let ascii = Style {
            color: false,
            ascii: true,
        };
        let text = incoming_notice(ascii, false);
        assert!(text.starts_with("NOTE macOS will ask"));
        assert!(!text.contains("Press Enter"));
    }

    #[test]
    fn the_local_network_recovery_names_the_requester_and_the_pane() {
        let address: SocketAddr = "192.168.1.20:9473".parse().unwrap();
        let text = local_network_recovery("Ghostty", address);
        assert_eq!(
            cli::render_error(&text, Audience::Human, PLAIN),
            "✗ Valhalla couldn't connect to 192.168.1.20:9473 on your local network. macOS may be blocking Ghostty.\n  Check System Settings › Privacy & Security › Local Network and turn on Ghostty, then run the command again.\n→ open \"x-apple.systempreferences:com.apple.preference.security?Privacy_LocalNetwork\"\n"
        );
    }

    #[test]
    fn only_private_network_addresses_count_as_local() {
        for ip in ["10.0.0.2", "172.16.4.1", "192.168.1.20", "fd00::1"] {
            assert!(on_local_network(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["127.0.0.1", "8.8.8.8", "100.64.0.1", "::1", "2001:db8::1"] {
            assert!(!on_local_network(ip.parse().unwrap()), "{ip}");
        }
        assert!(!beyond_this_computer("127.0.0.1:9473".parse().unwrap()));
        assert!(beyond_this_computer("192.168.1.20:9473".parse().unwrap()));
    }

    #[test]
    fn terminal_apps_are_named_as_macos_names_them() {
        let env = |value: &'static str| {
            move |name: &str| (name == "TERM_PROGRAM").then(|| value.to_owned())
        };
        assert_eq!(terminal_app(&env("Apple_Terminal")), "Terminal");
        assert_eq!(terminal_app(&env("ghostty")), "Ghostty");
        assert_eq!(terminal_app(&|_| None), "your terminal app");
    }

    #[test]
    fn firewall_state_parsing() {
        assert!(firewall_state_on("Firewall is enabled. (State = 1)\n"));
        assert!(!firewall_state_on("Firewall is disabled. (State = 0)\n"));
    }

    #[test]
    fn loopback_and_public_addresses_are_never_reported_as_blocked() {
        assert!(!looks_blocked("127.0.0.1:1".parse().unwrap()));
        assert!(!looks_blocked("8.8.8.8:1".parse().unwrap()));
    }
}
