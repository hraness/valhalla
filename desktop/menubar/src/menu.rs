//! The Valhalla menu on menu kit v2: room status at the top, the newest
//! outputs, then login, support and Quit.
//! Pure: every input is passed in, so each state has a fixture.

use std::time::SystemTime;

use desktop_foundation::{
    outputs, Alternate, ItemState, MarkTone, MenuItem, MenuModel, MenuNode, Opens, Role,
    StatusMark, Symbol,
};

use crate::status::{ago, at_ms, explain, Status, STALE_AFTER};

pub const NAME: &str = "Valhalla";
pub const APP_ID: &str = "valhalla";

pub const LOGIN: &str = "login";
pub const SUPPORT: &str = "support";
pub const DIAGNOSTICS: &str = "support.diagnostics";

/// Newest outputs shown. Three keeps the worst case within ten top-level rows.
pub const OUTPUTS_LIMIT: usize = 3;

/// The login item as the menu shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Login {
    Off,
    On,
    /// Written by Valhalla for another copy of the binary; clicking repoints it.
    Outdated,
    /// Written or edited by something else; left alone.
    NotOurs,
}

pub struct View<'a> {
    pub status: Option<&'a Status>,
    pub outputs: Vec<MenuNode>,
    pub login: Login,
    pub action_error: Option<&'a str>,
    pub now: SystemTime,
}

fn plural(count: u64, one: &str, many: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{count} {many}")
    }
}

fn rooms_row(view: &View) -> (Symbol, String, Option<String>, MarkTone) {
    let Some(status) = view.status else {
        return (
            Symbol::StatusIdle,
            "No room status yet".into(),
            Some("Run vhalla menubar refresh to see your rooms".into()),
            MarkTone::Normal,
        );
    };
    let refreshed = at_ms(status.refreshed_at);
    let updated = ago(refreshed, view.now);
    if let Some(code) = status.error.as_deref() {
        return (
            Symbol::StatusAttention,
            "Couldn't read your rooms".into(),
            Some(explain(code).trim_end_matches('.').to_owned()),
            MarkTone::Attention,
        );
    }
    let Some(rooms) = status.rooms.as_ref() else {
        return (
            Symbol::StatusIdle,
            "No room status yet".into(),
            None,
            MarkTone::Normal,
        );
    };
    if view.now.duration_since(refreshed).unwrap_or_default() >= STALE_AFTER {
        return (
            Symbol::StatusPaused,
            "Room status is out of date".into(),
            Some(format!("Last updated {updated}")),
            MarkTone::Normal,
        );
    }
    let count = if rooms.partial {
        format!("{}+ rooms", rooms.count)
    } else {
        plural(rooms.count, "room", "rooms")
    };
    if rooms.failed > 0 {
        return (
            Symbol::StatusAttention,
            format!(
                "{} didn't go through",
                plural(rooms.failed, "send", "sends")
            ),
            Some(format!("{count} · updated {updated}")),
            MarkTone::Attention,
        );
    }
    if rooms.waiting > 0 {
        return (
            Symbol::StatusSyncing,
            format!("{} waiting", plural(rooms.waiting, "send", "sends")),
            Some(format!("{count} · updated {updated}")),
            MarkTone::Normal,
        );
    }
    let label = if rooms.count == 0 {
        "No rooms yet".to_owned()
    } else {
        format!("{count} in sync")
    };
    (
        Symbol::StatusOk,
        label,
        Some(format!("Updated {updated}")),
        MarkTone::Normal,
    )
}

pub fn build(view: View) -> MenuModel {
    let (symbol, label, detail, tone) = rooms_row(&view);
    let tooltip = format!("{NAME} · {label}");
    let mut nodes = vec![
        MenuNode::header(NAME),
        MenuNode::status(symbol, label, detail),
    ];
    if let Some(error) = view.action_error {
        nodes.push(MenuNode::status(
            Symbol::StatusAttention,
            error,
            Some("Try again".to_owned()),
        ));
    }
    nodes.push(MenuNode::Separator);
    // Agents leave their work in the outputs folder, so its row is the primary action.
    nodes.extend(view.outputs.into_iter().map(|mut node| {
        if let MenuNode::Interactive { item } = &mut node {
            if item.id.as_deref() == Some(outputs::FOLDER_ID) {
                item.role = Some(Role::Primary);
                item.shortcut = Some("CmdOrCtrl+O".into());
                item.symbol = Some(Symbol::ActionFolder);
            }
        }
        node
    }));
    nodes.push(MenuNode::Separator);
    nodes.push(MenuNode::interactive(match view.login {
        Login::On => MenuItem::state(LOGIN, "Open at login", ItemState::On),
        Login::Off => MenuItem::state(LOGIN, "Open at login", ItemState::Off)
            .with_subtitle("macOS shows a notice when you turn this on"),
        Login::Outdated => MenuItem::state(LOGIN, "Open at login", ItemState::Mixed)
            .with_subtitle("Points to an older copy. Click to update it"),
        Login::NotOurs => MenuItem::state(LOGIN, "Open at login", ItemState::Mixed)
            .with_subtitle("Changed outside Valhalla, so it's left alone")
            .disabled(),
    }));
    nodes.push(MenuNode::Separator);
    nodes.push(MenuNode::interactive(
        MenuItem::action(SUPPORT, "Updates & support")
            .with_symbol(Symbol::ActionSupport)
            .opens(Opens::Browser)
            .with_alternate(
                Alternate::new(DIAGNOSTICS, "Copy diagnostics").with_symbol(Symbol::ActionCopy),
            ),
    ));
    nodes.push(MenuNode::interactive(
        MenuItem::action(desktop_foundation::QUIT_ACTION_ID, format!("Quit {NAME}"))
            .with_shortcut("CmdOrCtrl+Q"),
    ));
    let mut model = MenuModel {
        tooltip: Some(tooltip),
        nodes,
        ..MenuModel::default()
    };
    model.set_mark(StatusMark::new(Symbol::MarkPeople, "Vh").with_tone(tone));
    model
}

/// "Copy diagnostics": version and counts. No paths, names or keys.
pub fn diagnostics(status: Option<&Status>, version: &str, now: SystemTime) -> String {
    let mut lines = vec![format!("Valhalla menu bar {version}")];
    match status {
        None => lines.push("Room status: none".into()),
        Some(status) => {
            let updated = ago(at_ms(status.refreshed_at), now);
            match (&status.rooms, status.error.as_deref()) {
                (_, Some(code)) => {
                    lines.push(format!("Room status: error {code}, updated {updated}"))
                }
                (Some(rooms), None) => lines.push(format!(
                    "Room status: {} rooms{}, height {}, {} waiting, {} failed, updated {updated}",
                    rooms.count,
                    if rooms.partial { " (partial)" } else { "" },
                    rooms.height,
                    rooms.waiting,
                    rooms.failed
                )),
                (None, None) => lines.push(format!("Room status: empty, updated {updated}")),
            }
        }
    }
    lines.join("\n") + "\n"
}
