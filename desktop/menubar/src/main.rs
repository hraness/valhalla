//! `vhalla-menubar` — the Valhalla menu-bar companion.
//!
//! A disposable client: it renders the agent outputs directory into a
//! status-item menu so owners can see and open what their agents left for
//! them. Valhalla identities, stores, and rooms remain the authorities; this
//! binary holds no privilege of its own and reads only the outputs directory.
//!
//! Runs unbundled: the `vhalla` CLI builds and spawns this executable
//! directly. Packaging is an optional later gate.

use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use desktop_foundation::browser::{BrowserOpener, BrowserStatus};

use desktop_foundation::{
    outputs::OutputsSection, AccessibilityMetadata, DispatchOutcome, Host, MenuItem, MenuModel,
    MenuNode, Options, RenderError, RgbaIcon,
};

const SUPPORT_URL: &str = "https://account.hraness.com/support?product=valhalla&source=desktop#support";

/// Crossed-swords status mark. macOS renders `MARK_TITLE` as native colored
/// emoji text; icon-only trays use this pre-rendered 32px Twemoji bitmap
/// (U+2694, CC-BY 4.0 — https://twemoji.twitter.com).
const MARK_TITLE: &str = "⚔\u{fe0f}";
fn mark_icon() -> RgbaIcon {
    RgbaIcon {
        rgba: include_bytes!("../icons/mark.rgba").to_vec(),
        width: 32,
        height: 32,
    }
}

/// `~/Library/Application Support/Valhalla` on macOS, matching
/// `state_directory()` in `crates/vhalla-cli/src/main.rs`.
fn state_directory() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    if cfg!(target_os = "macos") {
        Some(home.join("Library/Application Support/Valhalla"))
    } else {
        let data = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share"));
        Some(data.join("valhalla"))
    }
}

/// One status item per user. A second launch exits quietly once the runtime
/// lock is held rather than double-registering an `NSStatusItem`.
fn acquire_instance_lock() -> Option<File> {
    let directory = state_directory()?;
    std::fs::create_dir_all(&directory).ok()?;
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(directory.join("menubar.lock"))
        .ok()?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Some(file)
    } else {
        None
    }
}

struct ValhallaHost {
    outputs: OutputsSection,
    browser: BrowserOpener,
}

impl Host for ValhallaHost {
    fn snapshot(&self) -> MenuModel {
        let mut nodes = vec![MenuNode::disabled("Valhalla"), MenuNode::Separator];
        nodes.extend(self.outputs.nodes());
        nodes.push(MenuNode::Separator);
        nodes.push(MenuNode::item("product.support", "Support Valhalla development (optional paid)…"));
        if matches!(self.browser.status(), BrowserStatus::Failed(_)) {
            nodes.push(MenuNode::disabled("Browser unavailable — use account.hraness.com"));
        }
        nodes.push(MenuNode::Separator);
        nodes.push(MenuNode::interactive(
            MenuItem::action(desktop_foundation::QUIT_ACTION_ID, "Quit Valhalla")
                .with_shortcut("CmdOrCtrl+Q")
                .with_accessibility(AccessibilityMetadata {
                    label: Some("Quit Valhalla".to_owned()),
                    value: None,
                    hint: Some("Exit the Valhalla menu bar companion".to_owned()),
                }),
        ));
        let mut model = MenuModel {
            tooltip: Some("Valhalla — agent outputs".to_owned()),
            nodes,
            ..MenuModel::default()
        };
        model.mark(MARK_TITLE, Some(mark_icon()));
        model
    }

    fn dispatch_result(&self, id: &str) -> DispatchOutcome {
        if id == "product.support" {
            return if self.browser.open(SUPPORT_URL).is_ok() { DispatchOutcome::Accepted } else { DispatchOutcome::Rejected };
        }
        if self.outputs.dispatch(id) {
            DispatchOutcome::Accepted
        } else {
            DispatchOutcome::Rejected
        }
    }

    fn render_failed(&self, error: RenderError) {
        eprintln!("vhalla-menubar: render failed: {error:?}");
    }
}

fn main() {
    let _instance = match acquire_instance_lock() {
        Some(lock) => lock,
        None => return,
    };
    let outputs = state_directory()
        .map(|dir| OutputsSection::new(dir.join("outputs")))
        .unwrap_or_else(|| OutputsSection::new(PathBuf::from("outputs")));
    let _ = std::fs::create_dir_all(outputs.dir());
    let host = Arc::new(ValhallaHost { outputs, browser: BrowserOpener::new() });
    let options = Options {
        refresh: Duration::from_secs(30),
        companion_window: false,
    };
    if let Err(error) = desktop_foundation::run(tauri::generate_context!(), host, options, |b| b) {
        eprintln!("vhalla-menubar: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod invitation_tests {
    use super::*;

    #[test]
    fn unavailable_outputs_offer_optional_support_without_a_newsletter_or_launch() {
        let host = ValhallaHost {
            outputs: OutputsSection::new("/dev/null/absent-outputs"),
            browser: BrowserOpener::new(),
        };
        let model = host.snapshot();
        assert!(model.nodes.iter().any(|node| matches!(node,
            MenuNode::Item { id: Some(id), enabled: true, .. } if id == "product.support")));
        assert!(!model.nodes.iter().any(|node| matches!(node,
            MenuNode::Item { id: Some(id), .. } if id == "product.updates")));
        assert_eq!(host.browser.status(), BrowserStatus::Idle);
        assert!(matches!(host.dispatch_result("unknown.action"), DispatchOutcome::Rejected));
        assert_eq!(host.browser.status(), BrowserStatus::Idle);
    }

    #[test]
    fn status_mark_is_the_crossed_swords_emoji_with_bundled_tray_art() {
        let host = ValhallaHost {
            outputs: OutputsSection::new("/dev/null/absent-outputs"),
            browser: BrowserOpener::new(),
        };
        let model = host.snapshot();
        model.validate().expect("valid model");
        if cfg!(target_os = "macos") {
            assert_eq!(model.title.as_deref(), Some("⚔\u{fe0f}"));
            assert!(model.icon.is_none());
        } else {
            let icon = model.icon.expect("icon tray art");
            assert_eq!(icon.rgba.len(), 32 * 32 * 4);
        }
    }
}
