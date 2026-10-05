//! The agent-navigable surface: `status`, `status refresh`,
//! `commands`, `doctor`, `doctor retire`, `outputs [list|open|reveal]` and
//! `support --json`.
//!
//! Valhalla has no long-running owner. Every command here runs in its own
//! process, reads the Valhalla folder and answers. `--json` prints one
//! `hraness-control-kit` envelope line (`{ok, schema, generatedAt, data}` or
//! `{ok:false, schema:"hraness.error/1", error}`), and the exit status follows
//! the envelope: 0 ok, 1 failure, 2 usage, 3 needs a person.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hraness_control_kit::envelope;
use hraness_control_kit::{
    Audience, Envelope, ErrorBody, ErrorCode, NextStep, OpClass, Registry, Verb,
};
use serde::{Deserialize, Serialize};

/// The product name in schemas and the verb registry.
pub(crate) const PRODUCT: &str = "valhalla";
/// What people type.
const COMMAND: &str = "vhalla";

pub(crate) const STATUS_SCHEMA: &str = "valhalla.status/1";
pub(crate) const REFRESH_SCHEMA: &str = "valhalla.status-refresh/1";
pub(crate) const DOCTOR_SCHEMA: &str = "valhalla.doctor/1";
pub(crate) const RETIRE_SCHEMA: &str = "valhalla.doctor-retire/1";
pub(crate) const OUTPUTS_SCHEMA: &str = "valhalla.outputs/1";
pub(crate) const OUTPUTS_OPEN_SCHEMA: &str = "valhalla.outputs-open/1";
/// `support --json`: `data` is the support-foundation offer
/// (`hraness-support-offer-v1`) unchanged.
pub(crate) const SUPPORT_SCHEMA: &str = "valhalla.support/1";

/// Room counts saved by `status refresh`, read by `status`.
pub(crate) const STATUS_FILE: &str = "room-status.json";
/// The file earlier releases wrote for the menu bar. Read when
/// `STATUS_FILE` is missing, never written or removed.
pub(crate) const LEGACY_STATUS_FILE: &str = "menubar-status.json";
const MAX_STATUS_BYTES: u64 = 64 * 1024;
/// Room status older than this shows as out of date.
pub(crate) const STALE_AFTER: Duration = Duration::from_secs(60 * 60);
/// Newest outputs `status` shows. `outputs list` shows up to `LIST_LIMIT`.
const NEWEST_LIMIT: usize = 3;
const LIST_LIMIT: usize = 100;
/// Entries read from the outputs folder before giving up on the rest.
const SCAN_LIMIT: usize = 10_000;

/// Login items earlier releases wrote for the menu bar. `app.hraness.*` is
/// desktop-foundation's service helper; `com.hraness.valhalla.menubar` is
/// the older hand-written one.
pub(crate) const LEGACY_LABELS: &[&str] = &["app.hraness.valhalla", "com.hraness.valhalla.menubar"];
/// The program a login item must start to count as ours.
const LEGACY_PROGRAM: &str = "vhalla-menubar";
/// The local app `HRANESS_LOCAL_APP=1 vhalla menubar install` built in
/// v0.2.8, under `~/Applications/Hraness`. Its login item starts
/// `LEGACY_APP_PROGRAM` inside it instead of `vhalla-menubar`.
const LEGACY_APP: &str = "Applications/Hraness/Valhalla.app";
const LEGACY_APP_PROGRAM: &str = "Valhalla.app/Contents/MacOS/Valhalla";
const MAX_LOGIN_ITEM_BYTES: u64 = 64 * 1024;

/// Every verb this module answers, with its op class and schema.
pub(crate) fn registry() -> Registry {
    let mut registry = Registry::new(PRODUCT);
    let verbs = [
        Verb::new(&["update"], OpClass::Operate, crate::self_update::SCHEMA, "Install a newer verified native release"),
        Verb::new(&["update", "check"], OpClass::Read, crate::self_update::SCHEMA, "Check for a newer release without installing"),
        Verb::new(&["update", "status"], OpClass::Read, crate::self_update::SCHEMA, "Show installation support and automatic-update policy"),
        Verb::new(&["update", "enable"], OpClass::Operate, crate::self_update::SCHEMA, "Enable automatic updates for supported installations"),
        Verb::new(&["update", "disable"], OpClass::Operate, crate::self_update::SCHEMA, "Disable automatic updates"),
        Verb::new(
            &["status"],
            OpClass::Read,
            STATUS_SCHEMA,
            "Room sync, the newest outputs and leftover menu bar login items",
        ),
        Verb::new(
            &["status", "refresh"],
            OpClass::Operate,
            REFRESH_SCHEMA,
            "Read room status from your node and save it for status",
        ),
        Verb::new(
            &["commands"],
            OpClass::Read,
            hraness_control_kit::registry::COMMANDS_SCHEMA,
            "Every verb with its op class and schema",
        ),
        Verb::new(
            &["doctor"],
            OpClass::Read,
            DOCTOR_SCHEMA,
            "The Valhalla folder, room status file and leftover login items",
        ),
        Verb::new(
            &["doctor", "retire"],
            OpClass::Operate,
            RETIRE_SCHEMA,
            "Set aside menu bar login items from earlier releases (renamed, never deleted)",
        ),
        Verb::new(
            &["outputs"],
            OpClass::Read,
            OUTPUTS_SCHEMA,
            "Create the outputs folder if needed and print its path",
        ),
        Verb::new(
            &["outputs", "list"],
            OpClass::Read,
            OUTPUTS_SCHEMA,
            "Files agents saved in the outputs folder, newest first",
        ),
        Verb::new(
            &["outputs", "open"],
            OpClass::Operate,
            OUTPUTS_OPEN_SCHEMA,
            "Open the outputs folder, or one file in it",
        ),
        Verb::new(
            &["outputs", "reveal"],
            OpClass::Operate,
            OUTPUTS_OPEN_SCHEMA,
            "Show one output file in Finder",
        ),
        Verb::new(
            &["support"],
            OpClass::Read,
            SUPPORT_SCHEMA,
            "Optional ways to support Valhalla (the menu's Updates & support); protocol verbs: support protocol --json",
        ),
    ];
    for verb in verbs {
        registry.register(verb).expect("valid verb");
    }
    registry
}

// ---------------------------------------------------------------------------
// Room status file

/// Room counts from `vhalla rooms status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Rooms {
    pub(crate) count: u64,
    pub(crate) height: u64,
    /// Sends queued or submitted and not yet committed.
    pub(crate) waiting: u64,
    /// Sends that collided or were rejected.
    pub(crate) failed: u64,
    /// The room list was cut short.
    pub(crate) partial: bool,
}

/// What `status refresh` saves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RoomStatus {
    pub(crate) schema_version: u32,
    /// Milliseconds since the Unix epoch.
    pub(crate) refreshed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) rooms: Option<Rooms>,
    /// A fixed code when the last refresh couldn't read room status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
    /// The arguments the refresh ran with, so `next` can repeat it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) refresh_args: Vec<String>,
}

fn valid_code(code: &str) -> bool {
    !code.is_empty() && code.len() <= 40 && code.chars().all(|c| c.is_ascii_lowercase() || c == '-')
}

/// Reads at most `limit` bytes of a regular file this user owns, never
/// following a symlink at `path`.
fn read_regular(path: &Path, limit: u64) -> Option<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let before = std::fs::symlink_metadata(path).ok()?;
    if !before.is_file() || before.len() > limit {
        return None;
    }
    let mut file = std::fs::File::open(path).ok()?;
    let opened = file.metadata().ok()?;
    if opened.ino() != before.ino() || opened.dev() != before.dev() {
        return None;
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= limit).then_some(bytes)
}

pub(crate) fn parse_room_status(bytes: &[u8]) -> Option<RoomStatus> {
    let mut status: RoomStatus = serde_json::from_slice(bytes).ok()?;
    if status.schema_version != 1 {
        return None;
    }
    if status
        .error
        .as_deref()
        .is_some_and(|code| !valid_code(code))
    {
        status.error = Some("unknown".into());
    }
    status.refresh_args.truncate(16);
    status.refresh_args.retain(|arg| arg.len() <= 4096);
    Some(status)
}

fn read_room_status(root: &Path) -> Option<RoomStatus> {
    [STATUS_FILE, LEGACY_STATUS_FILE]
        .iter()
        .find_map(|name| read_regular(&root.join(name), MAX_STATUS_BYTES))
        .and_then(|bytes| parse_room_status(&bytes))
}

/// A plain sentence for a fixed refresh error code.
pub(crate) fn explain(code: &str) -> &'static str {
    match code {
        "rooms-unavailable" => "Check that your node is running, then refresh.",
        "rooms-unreadable" => "Room status came back in a form this vhalla can't read.",
        "not-built" => "This vhalla was built without rooms.",
        _ => "Refresh again to see why.",
    }
}

/// "just now", "4 min ago", "3 hours ago", "yesterday", "2 days ago".
pub(crate) fn ago(then_ms: u64, now_ms: u64) -> String {
    let seconds = now_ms.saturating_sub(then_ms) / 1000;
    match seconds {
        0..=59 => "just now".into(),
        60..=3_599 => format!("{} min ago", seconds / 60),
        3_600..=7_199 => "1 hour ago".into(),
        7_200..=86_399 => format!("{} hours ago", seconds / 3_600),
        86_400..=172_799 => "yesterday".into(),
        _ => format!("{} days ago", seconds / 86_400),
    }
}

fn plural(count: u64, one: &str, many: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{count} {many}")
    }
}

// ---------------------------------------------------------------------------
// Outputs folder

/// One file agents left in the outputs folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OutputFile {
    pub(crate) name: String,
    pub(crate) path: String,
    pub(crate) bytes: u64,
    /// Milliseconds since the Unix epoch.
    pub(crate) modified_at: u64,
}

/// The outputs folder and its files, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Outputs {
    pub(crate) folder: String,
    pub(crate) exists: bool,
    pub(crate) total: u64,
    pub(crate) files: Vec<OutputFile>,
}

fn ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A name `outputs open` and `outputs reveal` accept: one visible entry
/// directly inside the folder.
pub(crate) fn valid_output_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('.')
        && !name.contains('/')
        && !name.contains('\0')
}

/// Lists regular, visible files in `folder`, newest first, keeping `limit`.
pub(crate) fn list_outputs(folder: &Path, limit: usize) -> Outputs {
    let mut files = Vec::new();
    let exists = std::fs::symlink_metadata(folder).is_ok_and(|meta| meta.is_dir());
    if exists {
        if let Ok(entries) = std::fs::read_dir(folder) {
            for entry in entries.flatten().take(SCAN_LIMIT) {
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if !valid_output_name(&name) {
                    continue;
                }
                let Ok(meta) = entry.path().symlink_metadata() else {
                    continue;
                };
                if !meta.is_file() {
                    continue;
                }
                files.push(OutputFile {
                    path: folder.join(&name).display().to_string(),
                    name,
                    bytes: meta.len(),
                    modified_at: meta.modified().map(ms).unwrap_or(0),
                });
            }
        }
    }
    files.sort_by(|a, b| {
        b.modified_at
            .cmp(&a.modified_at)
            .then_with(|| a.name.cmp(&b.name))
    });
    let total = files.len() as u64;
    files.truncate(limit);
    Outputs {
        folder: folder.display().to_string(),
        exists,
        total,
        files,
    }
}

/// "812 B", "2 KB", "3.4 MB".
pub(crate) fn size(bytes: u64) -> String {
    match bytes {
        0..=999 => format!("{bytes} B"),
        1_000..=999_999 => format!("{} KB", bytes.div_ceil(1_000)),
        1_000_000..=999_999_999 => format!("{:.1} MB", bytes as f64 / 1e6),
        _ => format!("{:.1} GB", bytes as f64 / 1e9),
    }
}

// ---------------------------------------------------------------------------
// Legacy login items

/// A menu bar login item from an earlier release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginItem {
    pub(crate) label: String,
    pub(crate) path: String,
    /// It starts `vhalla-menubar` (or the v0.2.8 local `Valhalla.app`) and
    /// this user owns it: `doctor retire`
    /// sets it aside. Anything else is left alone.
    pub(crate) ours: bool,
}

fn plist_strings(text: &str) -> Vec<&str> {
    text.split("<string>")
        .skip(1)
        .filter_map(|rest| rest.split_once("</string>").map(|(value, _)| value))
        .collect()
}

/// Whether a login item's text starts the menu bar: `vhalla-menubar`
/// itself, or the executable inside the local `Valhalla.app` that v0.2.8
/// built with `HRANESS_LOCAL_APP=1`.
pub(crate) fn launches_menubar(text: &str) -> bool {
    plist_strings(text).iter().any(|s| {
        *s == LEGACY_PROGRAM
            || s.ends_with(&format!("/{LEGACY_PROGRAM}"))
            || s.ends_with(&format!("/{LEGACY_APP_PROGRAM}"))
    })
}

fn current_uid() -> Option<u32> {
    std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|text| text.trim().parse::<u32>().ok())
}

/// The text of a login item this account owns. Fails closed: when the
/// account's uid is unknown, nothing is owned.
fn owned_text(path: &Path, uid: Option<u32>) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let uid = uid?;
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.uid() != uid {
        return None;
    }
    String::from_utf8(read_regular(path, MAX_LOGIN_ITEM_BYTES)?).ok()
}

/// Every legacy label present under `home`, and whether each is ours.
pub(crate) fn find_login_items(home: &Path, uid: Option<u32>) -> Vec<LoginItem> {
    let agents = home.join("Library/LaunchAgents");
    LEGACY_LABELS
        .iter()
        .filter_map(|label| {
            let path = agents.join(format!("{label}.plist"));
            std::fs::symlink_metadata(&path).ok()?;
            let ours = owned_text(&path, uid).is_some_and(|text| launches_menubar(&text));
            Some(LoginItem {
                label: (*label).to_owned(),
                path: path.display().to_string(),
                ours,
            })
        })
        .collect()
}

/// One login item `doctor retire` set aside.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Retired {
    pub(crate) label: String,
    pub(crate) from: String,
    pub(crate) to: String,
    /// The command that puts it back.
    pub(crate) restore: String,
}

/// Keeps the receipts of items already set aside when a later one fails:
/// the detail lists each rename and every restore command is a next step.
fn with_receipts(mut error: ErrorBody, retired: &[Retired]) -> ErrorBody {
    if retired.is_empty() {
        return error;
    }
    let receipts: Vec<String> = retired
        .iter()
        .map(|item| format!("Set aside {} as {}", item.from, item.to))
        .collect();
    let detail = match error.detail.take() {
        Some(detail) => format!("{detail}\n{}", receipts.join("\n")),
        None => receipts.join("\n"),
    };
    error = error.with_detail(detail);
    for item in retired {
        error = error.with_next(NextStep::new(
            item.restore.clone(),
            format!("Put back {}, set aside before the failure", item.label),
            Audience::Human,
        ));
    }
    error
}

/// Renames each login item that is ours to `<path>.retired-<ms>` after
/// `bootout` unloads its label. Nothing is deleted; items that aren't ours,
/// symlinks and files another user owns are left alone. The rules follow
/// desktop-foundation's `retire` module. The target name is checked before
/// the label is unloaded, and an error keeps the receipts of the items
/// already set aside.
pub(crate) fn retire_login_items(
    home: &Path,
    uid: Option<u32>,
    now_ms: u64,
    bootout: &dyn Fn(&str),
) -> Result<Vec<Retired>, ErrorBody> {
    if uid.is_none() {
        return Err(ErrorBody::new(
            ErrorCode::Internal,
            "Couldn't tell which account is running. Nothing was renamed.",
        ));
    }
    let mut retired = Vec::new();
    for item in find_login_items(home, uid) {
        if !item.ours {
            continue;
        }
        let from = PathBuf::from(&item.path);
        // Check again right before acting: the item must still be ours.
        if !owned_text(&from, uid).is_some_and(|text| launches_menubar(&text)) {
            continue;
        }
        let to = PathBuf::from(format!("{}.retired-{now_ms}", item.path));
        if std::fs::symlink_metadata(&to).is_ok() {
            return Err(with_receipts(
                ErrorBody::new(
                    ErrorCode::Conflict,
                    format!(
                        "{} already exists. {} was left in place.",
                        to.display(),
                        from.display()
                    ),
                ),
                &retired,
            ));
        }
        bootout(&item.label);
        if let Err(error) = std::fs::rename(&from, &to) {
            return Err(with_receipts(
                ErrorBody::new(
                    ErrorCode::Internal,
                    format!("Couldn't set aside {}.", from.display()),
                )
                .with_detail(error.to_string()),
                &retired,
            ));
        }
        retired.push(Retired {
            restore: format!(
                "mv {} {} && launchctl bootstrap gui/$(id -u) {}",
                shell_quote(&to.display().to_string()),
                shell_quote(&item.path),
                shell_quote(&item.path)
            ),
            label: item.label,
            from: item.path,
            to: to.display().to_string(),
        });
    }
    Ok(retired)
}

fn shell_quote(text: &str) -> String {
    if text
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-+@:".contains(c))
    {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

/// Unloads one of our labels so the menu bar stops at once. It never
/// signals a process by pid.
fn launchctl_bootout(label: &str) {
    if !cfg!(target_os = "macos") || !LEGACY_LABELS.contains(&label) {
        return;
    }
    let Some(uid) = current_uid().filter(|uid| *uid > 0) else {
        return;
    };
    let _ = std::process::Command::new("/bin/launchctl")
        .args(["bootout", &format!("gui/{uid}/{label}")])
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

// ---------------------------------------------------------------------------
// Status

/// Everything `status` and `status --json` show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StatusData {
    /// `first-run`, `in-sync`, `no-rooms`, `sends-waiting`, `send-failed`,
    /// `out-of-date` or `error`.
    pub(crate) state: &'static str,
    /// One line, such as "2 sends waiting".
    pub(crate) headline: String,
    pub(crate) detail: Option<String>,
    pub(crate) attention: bool,
    pub(crate) rooms: Option<Rooms>,
    /// Milliseconds since the Unix epoch.
    pub(crate) refreshed_at: Option<u64>,
    pub(crate) error: Option<String>,
    pub(crate) outputs: Outputs,
    pub(crate) login_items: Vec<LoginItem>,
}

fn refresh_command(status: Option<&RoomStatus>) -> String {
    match status.filter(|s| !s.refresh_args.is_empty()) {
        Some(status) => format!(
            "{COMMAND} status refresh {}",
            status
                .refresh_args
                .iter()
                .map(|arg| shell_quote(arg))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        None => format!(
            "{COMMAND} status refresh SOCIAL_STORE REPLICA_HOME REALM NODE_HOME --config FILE"
        ),
    }
}

/// Builds the status from what is on disk. Pure, for goldens.
pub(crate) fn build_status(
    room_status: Option<&RoomStatus>,
    outputs: Outputs,
    login_items: Vec<LoginItem>,
    now_ms: u64,
) -> (StatusData, Vec<NextStep>) {
    let mut next = Vec::new();
    let refresh = refresh_command(room_status);
    let (state, headline, detail, attention) = match room_status {
        None => {
            next.push(NextStep::new(
                refresh.clone(),
                "No room status has been saved yet",
                Audience::Agent,
            ));
            (
                "first-run",
                "No room status yet".to_owned(),
                Some(format!("Run {COMMAND} status refresh to see your rooms")),
                false,
            )
        }
        Some(status) => {
            let updated = ago(status.refreshed_at, now_ms);
            let stale =
                now_ms.saturating_sub(status.refreshed_at) >= STALE_AFTER.as_millis() as u64;
            match (&status.error, &status.rooms) {
                (Some(code), _) => {
                    next.push(NextStep::new(
                        refresh.clone(),
                        explain(code),
                        Audience::Agent,
                    ));
                    (
                        "error",
                        "Couldn't read your rooms".to_owned(),
                        Some(explain(code).trim_end_matches('.').to_owned()),
                        true,
                    )
                }
                (None, None) => ("first-run", "No room status yet".to_owned(), None, false),
                (None, Some(_)) if stale => {
                    next.push(NextStep::new(
                        refresh.clone(),
                        "Room status is more than an hour old",
                        Audience::Agent,
                    ));
                    (
                        "out-of-date",
                        "Room status is out of date".to_owned(),
                        Some(format!("Last updated {updated}")),
                        false,
                    )
                }
                (None, Some(rooms)) => {
                    let count = if rooms.partial {
                        format!("{}+ rooms", rooms.count)
                    } else {
                        plural(rooms.count, "room", "rooms")
                    };
                    if rooms.failed > 0 {
                        (
                            "send-failed",
                            format!(
                                "{} didn't go through",
                                plural(rooms.failed, "send", "sends")
                            ),
                            Some(format!("{count} · updated {updated}")),
                            true,
                        )
                    } else if rooms.waiting > 0 {
                        (
                            "sends-waiting",
                            format!("{} waiting", plural(rooms.waiting, "send", "sends")),
                            Some(format!("{count} · updated {updated}")),
                            false,
                        )
                    } else if rooms.count == 0 {
                        (
                            "no-rooms",
                            "No rooms yet".to_owned(),
                            Some(format!("Updated {updated}")),
                            false,
                        )
                    } else {
                        (
                            "in-sync",
                            format!("{count} in sync"),
                            Some(format!("Updated {updated}")),
                            false,
                        )
                    }
                }
            }
        }
    };
    if login_items.iter().any(|item| item.ours) {
        next.push(NextStep::new(
            format!("{COMMAND} doctor retire"),
            "A menu bar login item from an earlier release is still installed",
            Audience::Agent,
        ));
    }
    let data = StatusData {
        state,
        headline,
        detail,
        attention,
        rooms: room_status.and_then(|s| s.rooms),
        refreshed_at: room_status.map(|s| s.refreshed_at),
        error: room_status.and_then(|s| s.error.clone()),
        outputs,
        login_items,
    };
    (data, next)
}

/// The status as on disk right now.
fn load_status(root: &Path, home: &Path) -> Envelope<StatusData> {
    let now_ms = ms(SystemTime::now());
    let room_status = read_room_status(root);
    let outputs = list_outputs(&root.join("outputs"), NEWEST_LIMIT);
    let login_items = find_login_items(home, current_uid());
    let (data, next) = build_status(room_status.as_ref(), outputs, login_items, now_ms);
    next.into_iter()
        .fold(Envelope::ok(STATUS_SCHEMA, data), Envelope::with_next)
}

// ---------------------------------------------------------------------------
// Text views

/// Greedy word wrap to `width` columns. The first line starts with
/// `first`; later lines start with `indent` spaces. A word longer than a
/// line is cut.
fn wrap_with(first: &str, indent: usize, text: &str, width: usize) -> Vec<String> {
    let width = width.max(indent + 8);
    let mut lines = Vec::new();
    let mut line = first.to_owned();
    let mut used = first.chars().count();
    let mut start = used;
    for word in text.split(' ').filter(|word| !word.is_empty()) {
        let mut rest: Vec<char> = word.chars().collect();
        let gap = usize::from(used > start);
        if gap == 1 && used + 1 + rest.len() > width {
            lines.push(std::mem::replace(&mut line, " ".repeat(indent)));
            used = indent;
            start = indent;
        } else if gap == 1 {
            line.push(' ');
            used += 1;
        }
        while used + rest.len() > width {
            let take = width.saturating_sub(used).max(1);
            line.extend(rest.drain(..take.min(rest.len())));
            lines.push(std::mem::replace(&mut line, " ".repeat(indent)));
            used = indent;
            start = indent;
        }
        used += rest.len();
        line.extend(rest);
    }
    lines.push(line.trim_end().to_owned());
    lines
}

fn wrap(text: &str, width: usize, indent: usize) -> Vec<String> {
    wrap_with("", indent, text, width)
}

/// A labelled row: the label column, then the value wrapped under itself.
fn row(label: &str, value: &str, width: usize) -> Vec<String> {
    const LABEL: usize = 10;
    wrap_with(&format!("{label:<LABEL$}"), LABEL, value, width)
}

pub(crate) fn status_lines(data: &StatusData, width: u16, now_ms: u64) -> Vec<String> {
    let width = width as usize;
    let mut lines = Vec::new();
    let mark = if data.attention { "! " } else { "" };
    lines.extend(row("Rooms", &format!("{mark}{}", data.headline), width));
    if let Some(detail) = &data.detail {
        lines.extend(row("", detail, width));
    }
    if let Some(rooms) = &data.rooms {
        lines.extend(row(
            "",
            &format!(
                "height {} · {} waiting · {} failed",
                rooms.height, rooms.waiting, rooms.failed
            ),
            width,
        ));
    }
    let outputs = &data.outputs;
    let summary = match outputs.total {
        0 => "No outputs yet · agents save finished files here".to_owned(),
        n => format!("{} · newest first", plural(n, "file", "files")),
    };
    lines.extend(row("Outputs", &summary, width));
    for file in &outputs.files {
        lines.extend(row(
            "",
            &format!(
                "{} · {} · {}",
                file.name,
                size(file.bytes),
                ago(file.modified_at, now_ms)
            ),
            width,
        ));
    }
    lines.extend(row("", &outputs.folder, width));
    for item in &data.login_items {
        let note = if item.ours {
            format!(
                "{} from the retired menu bar · {COMMAND} doctor retire",
                item.label
            )
        } else {
            format!("{} isn't Valhalla's, so it's left alone", item.label)
        };
        lines.extend(row("Login", &note, width));
    }
    lines
}

pub(crate) fn outputs_lines(outputs: &Outputs, width: u16, now_ms: u64) -> Vec<String> {
    let width = width as usize;
    let mut lines = wrap(&outputs.folder, width, 0);
    if outputs.files.is_empty() {
        lines.push("No outputs yet. Agents save finished files here.".to_owned());
    }
    for file in &outputs.files {
        lines.extend(wrap(
            &format!(
                "{} · {} · {}",
                file.name,
                size(file.bytes),
                ago(file.modified_at, now_ms)
            ),
            width,
            2,
        ));
    }
    if outputs.total > outputs.files.len() as u64 {
        lines.push(format!(
            "and {} more · {COMMAND} outputs list",
            outputs.total - outputs.files.len() as u64
        ));
    }
    lines
}

/// The status text for one state, sectioned by title — the same text
/// `status` prints. Pure, for goldens.
#[cfg(test)]
pub(crate) fn snapshot(data: &StatusData, width: u16, now_ms: u64) -> String {
    [
        ("Status", status_lines(data, width, now_ms)),
        ("Outputs", outputs_lines(&data.outputs, width, now_ms)),
    ]
    .iter()
    .map(|(title, lines)| {
        let mut text = format!("== {title} ==\n");
        for line in lines {
            for ch in line.chars().take(width as usize) {
                text.push(ch);
            }
            text.push('\n');
        }
        text
    })
    .collect::<Vec<_>>()
    .join("\n")
}

// ---------------------------------------------------------------------------
// Command line

/// Paths every command here needs.
struct Paths {
    home: PathBuf,
    root: PathBuf,
}

fn paths() -> Result<Paths, ErrorBody> {
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| {
            ErrorBody::new(
                ErrorCode::NotFound,
                "Couldn't find your home folder. Set HOME.",
            )
        })?;
    let root = crate::state_directory().ok_or_else(|| {
        ErrorBody::new(
            ErrorCode::NotFound,
            "Couldn't find your home folder. Set HOME.",
        )
    })?;
    Ok(Paths { home, root })
}

/// Parsed flags shared by every verb.
#[derive(Debug, Default)]
struct Flags {
    json: bool,
    positional: Vec<String>,
}

fn usage(message: impl Into<String>, command: &str) -> ErrorBody {
    ErrorBody::new(ErrorCode::Usage, message).with_next(NextStep::new(
        format!("{COMMAND} {command} --help"),
        "Show this command's usage",
        Audience::Agent,
    ))
}

fn parse(args: &[OsString], command: &str, allow: &[&str]) -> Result<Flags, ErrorBody> {
    let mut flags = Flags::default();
    for arg in args {
        let Some(arg) = arg.to_str() else {
            return Err(usage("Arguments must be UTF-8.", command));
        };
        match arg {
            "--json" if allow.contains(&"--json") => flags.json = true,
            flag if flag.starts_with("--") && !allow.contains(&"*") => {
                return Err(usage(format!("Unknown option {flag}."), command));
            }
            value => flags.positional.push(value.to_owned()),
        }
    }
    Ok(flags)
}

fn wants_json(args: &[OsString]) -> bool {
    args.iter().any(|arg| arg == "--json")
}

/// Prints an envelope as JSON, or its human form, and returns the exit status.
fn finish<T: Serialize>(
    json: bool,
    envelope: Envelope<T>,
    human: impl FnOnce(&T) -> String,
) -> i32 {
    if json {
        let stdout = std::io::stdout();
        return envelope::emit(&mut stdout.lock(), &envelope) as i32;
    }
    let code = envelope.exit_code() as i32;
    match &envelope {
        Envelope::Ok { data, .. } => {
            let text = human(data);
            let mut out = std::io::stdout().lock();
            match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
                Ok(()) => code,
                Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => code,
                Err(_) => 1,
            }
        }
        Envelope::Err { error, .. } => {
            let mut message = error.message.clone();
            if let Some(detail) = &error.detail {
                message.push('\n');
                message.push_str(detail);
            }
            if let Some(next) = error.next.first() {
                message.push_str(&format!("\n→ {}", next.command));
            }
            crate::cli::report_error(&message);
            code
        }
    }
}

fn fail<T: Serialize>(json: bool, error: ErrorBody) -> i32 {
    finish::<T>(json, Envelope::error(error), |_| String::new())
}

/// `vhalla support --json`: the support offer in the shared envelope. Every
/// other `support` form (text, and the support protocol's own argv) returns
/// `None` and stays with support-foundation.
pub(crate) fn support(args: &[OsString]) -> Option<i32> {
    if args.len() != 1 || args[0] != "--json" {
        return None;
    }
    let envelope = match crate::support::offer() {
        Ok(offer) => Envelope::ok(SUPPORT_SCHEMA, offer),
        Err(message) => Envelope::error(ErrorBody::new(ErrorCode::Internal, message)),
    };
    Some(finish(true, envelope, |_| String::new()))
}

/// Runs `args` when it is one of this module's commands. `None` hands it
/// back to the ordinary runner.
pub(crate) fn dispatch(args: &[OsString]) -> Option<i32> {
    let first = args.first()?.to_str()?;
    let second = args.get(1).and_then(|arg| arg.to_str());
    if matches!(
        first,
        "status" | "commands" | "doctor" | "outputs" | "menubar"
    ) && args.iter().any(|arg| arg == "--help" || arg == "-h")
    {
        let page = crate::help::page_for(first)?;
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(page.as_bytes()).and_then(|()| out.flush());
        return Some(0);
    }
    Some(match (first, second) {
        ("status", Some("refresh")) => status_refresh(&args[2..]),
        ("status", _) => status(&args[1..]),
        ("commands", _) => commands(&args[1..]),
        ("doctor", Some("retire")) => doctor_retire(&args[2..]),
        ("doctor", _) => doctor(&args[1..]),
        ("outputs", Some("list")) => outputs_list(&args[2..]),
        ("outputs", Some("open")) => outputs_open(&args[2..], false),
        ("outputs", Some("reveal")) => outputs_open(&args[2..], true),
        ("outputs", _) => outputs(&args[1..]),
        ("menubar", Some("refresh")) => menubar_refresh(&args[2..]),
        ("menubar", _) => menubar_retired(&args[1..]),
        _ => return None,
    })
}

/// `vhalla menubar refresh …` was a released verb that cron jobs and agent
/// scripts run. It keeps working as `status refresh` with the same
/// arguments, with a note on stderr naming the new spelling.
fn menubar_refresh(args: &[OsString]) -> i32 {
    let mut err = std::io::stderr().lock();
    let _ = writeln!(
        err,
        "{COMMAND} menubar refresh is now {COMMAND} status refresh, which takes the same arguments."
    );
    drop(err);
    status_refresh(args)
}

/// `vhalla menubar …` from an earlier release's habits: the menu bar is
/// gone, so name what replaces it. Changes nothing.
fn menubar_retired(args: &[OsString]) -> i32 {
    fail::<()>(
        wants_json(args),
        ErrorBody::new(
            ErrorCode::Product("valhalla.retired".into()),
            "The menu bar is retired. Everything it showed is in vhalla status.",
        )
        .with_detail("vhalla doctor shows a login item an earlier release left.")
        .with_next(NextStep::new(
            format!("{COMMAND} status"),
            "Rooms, outputs and what to do next",
            Audience::Human,
        )),
    )
}

fn status(args: &[OsString]) -> i32 {
    let json = wants_json(args);
    let flags = match parse(args, "status", &["--json"]) {
        Ok(flags) if flags.positional.is_empty() => flags,
        Ok(_) => return fail::<()>(json, usage("status takes no arguments.", "status")),
        Err(error) => return fail::<()>(json, error),
    };
    let paths = match paths() {
        Ok(paths) => paths,
        Err(error) => return fail::<()>(flags.json, error),
    };
    let now_ms = ms(SystemTime::now());
    let envelope = load_status(&paths.root, &paths.home);
    let next: Vec<String> = match &envelope {
        Envelope::Ok { next, .. } => next.iter().map(|n| n.command.clone()).collect(),
        Envelope::Err { .. } => Vec::new(),
    };
    finish(flags.json, envelope, |data| {
        let mut text = status_lines(data, 80, now_ms).join("\n");
        text.push('\n');
        for command in next {
            text.push_str(&format!("→ {command}\n"));
        }
        text
    })
}

fn commands(args: &[OsString]) -> i32 {
    let json = wants_json(args);
    let flags = match parse(args, "commands", &["--json"]) {
        Ok(flags) if flags.positional.is_empty() => flags,
        Ok(_) => return fail::<()>(json, usage("commands takes no arguments.", "commands")),
        Err(error) => return fail::<()>(json, error),
    };
    let registry = registry();
    let verbs = registry.verbs().to_vec();
    finish(flags.json, registry.commands_json(), |_| {
        let width = verbs.iter().map(|v| v.command().len()).max().unwrap_or(0) + COMMAND.len() + 1;
        let mut text = String::new();
        for verb in &verbs {
            text.push_str(&format!(
                "{:<width$}  {:<8} {}\n",
                format!("{COMMAND} {}", verb.command()),
                verb.op_class.as_str(),
                verb.summary
            ));
        }
        text
    })
}

/// What `doctor` reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DoctorData {
    pub(crate) state_dir: String,
    pub(crate) state_dir_exists: bool,
    pub(crate) outputs_dir: String,
    pub(crate) outputs_dir_exists: bool,
    pub(crate) room_status_file: Option<String>,
    pub(crate) room_status_readable: bool,
    pub(crate) login_items: Vec<LoginItem>,
    /// The copy of `vhalla-menubar` an earlier `vhalla menubar install`
    /// kept in the Valhalla folder. Left in place; remove it by hand.
    pub(crate) menubar_copy: Option<String>,
    /// The local `Valhalla.app` that `HRANESS_LOCAL_APP=1 vhalla menubar
    /// install` built in v0.2.8. Left in place; remove it by hand.
    pub(crate) menubar_app: Option<String>,
    /// Login items set aside earlier, with the command that restores each.
    pub(crate) retired: Vec<String>,
    pub(crate) checks: Vec<Check>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Check {
    pub(crate) name: &'static str,
    pub(crate) ok: bool,
    pub(crate) message: String,
}

fn retired_items(home: &Path) -> Vec<String> {
    let agents = home.join("Library/LaunchAgents");
    let mut found: Vec<String> = std::fs::read_dir(&agents)
        .map(|entries| {
            entries
                .flatten()
                .take(SCAN_LIMIT)
                .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
                .filter(|name| {
                    LEGACY_LABELS
                        .iter()
                        .any(|label| name.starts_with(&format!("{label}.plist.retired-")))
                })
                .map(|name| agents.join(name).display().to_string())
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
}

pub(crate) fn doctor_data(
    root: &Path,
    home: &Path,
    uid: Option<u32>,
) -> (DoctorData, Vec<NextStep>) {
    let outputs_dir = root.join("outputs");
    let status_file = [STATUS_FILE, LEGACY_STATUS_FILE]
        .iter()
        .map(|name| root.join(name))
        .find(|path| std::fs::symlink_metadata(path).is_ok());
    let readable = read_room_status(root).is_some();
    let login_items = find_login_items(home, uid);
    let copy = root.join("bin").join(LEGACY_PROGRAM);
    let menubar_copy = std::fs::symlink_metadata(&copy)
        .is_ok()
        .then(|| copy.display().to_string());
    let app = home.join(LEGACY_APP);
    let menubar_app = std::fs::symlink_metadata(&app)
        .is_ok()
        .then(|| app.display().to_string());
    let mut checks = vec![
        Check {
            name: "room-status",
            ok: readable,
            message: match (&status_file, readable) {
                (_, true) => "Room status is saved and readable".to_owned(),
                (Some(_), false) => "The room status file can't be read; refresh it".to_owned(),
                (None, false) => "No room status saved yet".to_owned(),
            },
        },
        Check {
            name: "outputs",
            ok: true,
            message: if outputs_dir.is_dir() {
                "Outputs folder exists".to_owned()
            } else {
                format!("Outputs folder is created by {COMMAND} outputs")
            },
        },
    ];
    let ours = login_items.iter().filter(|item| item.ours).count();
    checks.push(Check {
        name: "login-items",
        ok: ours == 0,
        message: match ours {
            0 => "No menu bar login item is installed".to_owned(),
            _ => format!(
                "{} from the retired menu bar",
                plural(ours as u64, "login item", "login items")
            ),
        },
    });
    let mut next = Vec::new();
    if ours > 0 {
        next.push(NextStep::new(
            format!("{COMMAND} doctor retire"),
            "Set aside the menu bar login item (renamed, never deleted)",
            Audience::Agent,
        ));
    }
    if !readable {
        next.push(NextStep::new(
            refresh_command(read_room_status(root).as_ref()),
            "Save room status for status",
            Audience::Agent,
        ));
    }
    let data = DoctorData {
        state_dir: root.display().to_string(),
        state_dir_exists: root.is_dir(),
        outputs_dir: outputs_dir.display().to_string(),
        outputs_dir_exists: outputs_dir.is_dir(),
        room_status_file: status_file.map(|p| p.display().to_string()),
        room_status_readable: readable,
        login_items,
        menubar_copy,
        menubar_app,
        retired: retired_items(home),
        checks,
    };
    (data, next)
}

fn doctor(args: &[OsString]) -> i32 {
    let json = wants_json(args);
    let flags = match parse(args, "doctor", &["--json"]) {
        Ok(flags) if flags.positional.is_empty() => flags,
        Ok(_) => {
            return fail::<()>(
                json,
                usage("doctor takes no arguments besides retire.", "doctor"),
            )
        }
        Err(error) => return fail::<()>(json, error),
    };
    let paths = match paths() {
        Ok(paths) => paths,
        Err(error) => return fail::<()>(flags.json, error),
    };
    let (data, next) = doctor_data(&paths.root, &paths.home, current_uid());
    let steps: Vec<String> = next.iter().map(|n| n.command.clone()).collect();
    let envelope = next
        .into_iter()
        .fold(Envelope::ok(DOCTOR_SCHEMA, data), Envelope::with_next);
    finish(flags.json, envelope, |data| {
        let mut text = String::new();
        for check in &data.checks {
            text.push_str(&format!(
                "{} {}\n",
                if check.ok { "ok  " } else { "todo" },
                check.message
            ));
        }
        text.push_str(&format!("Valhalla folder: {}\n", data.state_dir));
        for item in &data.login_items {
            text.push_str(&format!(
                "Login item: {}{}\n",
                item.path,
                if item.ours {
                    ""
                } else {
                    " (not ours, left alone)"
                }
            ));
        }
        if let Some(copy) = &data.menubar_copy {
            text.push_str(&format!(
                "Old menu bar copy (safe to remove by hand): {copy}\n"
            ));
        }
        if let Some(app) = &data.menubar_app {
            text.push_str(&format!(
                "Old menu bar app (safe to remove by hand): {app}\n"
            ));
        }
        for retired in &data.retired {
            text.push_str(&format!("Set aside earlier: {retired}\n"));
        }
        for step in steps {
            text.push_str(&format!("→ {step}\n"));
        }
        text
    })
}

/// What `doctor retire` did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RetireData {
    pub(crate) retired: Vec<Retired>,
    /// Items with a legacy label that aren't ours, left alone.
    pub(crate) left_alone: Vec<LoginItem>,
}

fn doctor_retire(args: &[OsString]) -> i32 {
    let json = wants_json(args);
    let flags = match parse(args, "doctor retire", &["--json"]) {
        Ok(flags) if flags.positional.is_empty() => flags,
        Ok(_) => {
            return fail::<()>(
                json,
                usage("doctor retire takes no arguments.", "doctor retire"),
            )
        }
        Err(error) => return fail::<()>(json, error),
    };
    let paths = match paths() {
        Ok(paths) => paths,
        Err(error) => return fail::<()>(flags.json, error),
    };
    let uid = current_uid();
    let result = retire_login_items(&paths.home, uid, ms(SystemTime::now()), &launchctl_bootout);
    let envelope = match result {
        Ok(retired) => Envelope::ok(
            RETIRE_SCHEMA,
            RetireData {
                retired,
                left_alone: find_login_items(&paths.home, uid)
                    .into_iter()
                    .filter(|item| !item.ours)
                    .collect(),
            },
        ),
        Err(error) => Envelope::error(error),
    };
    finish(flags.json, envelope, |data| {
        let mut text = String::new();
        if data.retired.is_empty() {
            text.push_str("No menu bar login item to set aside.\n");
        }
        for item in &data.retired {
            text.push_str(&format!(
                "Set aside {} as {}\nTo restore it: {}\n",
                item.from, item.to, item.restore
            ));
        }
        for item in &data.left_alone {
            text.push_str(&format!("Left alone (not ours): {}\n", item.path));
        }
        text
    })
}

fn outputs_folder(root: &Path) -> Result<PathBuf, ErrorBody> {
    let folder = root.join("outputs");
    std::fs::create_dir_all(&folder).map_err(|error| {
        ErrorBody::new(ErrorCode::Internal, "Couldn't create the outputs folder.")
            .with_detail(error.to_string())
    })?;
    Ok(folder)
}

fn outputs(args: &[OsString]) -> i32 {
    let json = wants_json(args);
    let flags = match parse(args, "outputs", &["--json"]) {
        Ok(flags) if flags.positional.is_empty() => flags,
        Ok(flags) => {
            return fail::<()>(
                json,
                usage(
                    format!("Unknown outputs command {}.", flags.positional[0]),
                    "outputs",
                ),
            )
        }
        Err(error) => return fail::<()>(json, error),
    };
    let folder = match paths().and_then(|paths| outputs_folder(&paths.root)) {
        Ok(folder) => folder,
        Err(error) => return fail::<()>(flags.json, error),
    };
    let envelope = Envelope::ok(OUTPUTS_SCHEMA, list_outputs(&folder, NEWEST_LIMIT));
    finish(flags.json, envelope, |data| format!("{}\n", data.folder))
}

fn outputs_list(args: &[OsString]) -> i32 {
    let json = wants_json(args);
    let flags = match parse(args, "outputs list", &["--json"]) {
        Ok(flags) if flags.positional.is_empty() => flags,
        Ok(_) => {
            return fail::<()>(
                json,
                usage("outputs list takes no arguments.", "outputs list"),
            )
        }
        Err(error) => return fail::<()>(json, error),
    };
    let root = match paths() {
        Ok(paths) => paths.root,
        Err(error) => return fail::<()>(flags.json, error),
    };
    let now_ms = ms(SystemTime::now());
    let envelope = Envelope::ok(
        OUTPUTS_SCHEMA,
        list_outputs(&root.join("outputs"), LIST_LIMIT),
    );
    finish(flags.json, envelope, |data| {
        let mut text = outputs_lines(data, 80, now_ms).join("\n");
        text.push('\n');
        text
    })
}

/// What `outputs open` and `outputs reveal` opened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Opened {
    pub(crate) path: String,
    pub(crate) reveal: bool,
}

/// Resolves the target of `outputs open|reveal [NAME]`. Pure apart from
/// reading metadata.
pub(crate) fn open_target(
    folder: &Path,
    name: Option<&str>,
    reveal: bool,
) -> Result<PathBuf, ErrorBody> {
    let Some(name) = name else {
        if reveal {
            return Err(usage("outputs reveal needs a file name.", "outputs reveal"));
        }
        return Ok(folder.to_path_buf());
    };
    if !valid_output_name(name) {
        return Err(usage(
            "Give the name of one file in the outputs folder, not a path.",
            "outputs open",
        ));
    }
    let path = folder.join(name);
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_file() => Ok(path),
        _ => Err(
            ErrorBody::new(ErrorCode::NotFound, format!("No output named {name}.")).with_next(
                NextStep::new(
                    format!("{COMMAND} outputs list --json"),
                    "List the files in the outputs folder",
                    Audience::Agent,
                ),
            ),
        ),
    }
}

fn outputs_open(args: &[OsString], reveal: bool) -> i32 {
    let command = if reveal {
        "outputs reveal"
    } else {
        "outputs open"
    };
    let json = wants_json(args);
    let flags = match parse(args, command, &["--json"]) {
        Ok(flags) if flags.positional.len() <= 1 => flags,
        Ok(_) => {
            return fail::<()>(
                json,
                usage(format!("{command} takes at most one name."), command),
            )
        }
        Err(error) => return fail::<()>(json, error),
    };
    let folder = match paths().and_then(|paths| outputs_folder(&paths.root)) {
        Ok(folder) => folder,
        Err(error) => return fail::<()>(flags.json, error),
    };
    let target = match open_target(
        &folder,
        flags.positional.first().map(String::as_str),
        reveal,
    ) {
        Ok(target) => target,
        Err(error) => return fail::<()>(flags.json, error),
    };
    if !cfg!(target_os = "macos") {
        return fail::<()>(
            flags.json,
            ErrorBody::new(
                ErrorCode::UnsupportedPlatform,
                format!(
                    "Opening files needs macOS. The file is at {}.",
                    target.display()
                ),
            ),
        );
    }
    let mut open = std::process::Command::new("/usr/bin/open");
    if reveal {
        open.arg("-R");
    }
    let status = open
        .arg("--")
        .arg(&target)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let envelope = match status {
        Ok(status) if status.success() => Envelope::ok(
            OUTPUTS_OPEN_SCHEMA,
            Opened {
                path: target.display().to_string(),
                reveal,
            },
        ),
        _ => Envelope::error(ErrorBody::new(
            ErrorCode::Internal,
            format!("Couldn't open {}.", target.display()),
        )),
    };
    finish(flags.json, envelope, |data| {
        format!(
            "{} {}\n",
            if data.reveal { "Showed" } else { "Opened" },
            data.path
        )
    })
}

// ---------------------------------------------------------------------------
// status refresh

/// What `status refresh` saved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Refreshed {
    pub(crate) path: String,
    pub(crate) rooms: Rooms,
}

#[cfg(feature = "experimental-rooms-replica")]
pub(crate) fn rooms_from_status_json(stdout: &[u8]) -> Option<Rooms> {
    let value: serde_json::Value = serde_json::from_slice(stdout).ok()?;
    let number = |v: &serde_json::Value| {
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    };
    let summary = value.get("pendingSummary")?;
    let count = |name: &str| summary.get(name).and_then(number).unwrap_or(0);
    Some(Rooms {
        count: value.get("rooms")?.as_array()?.len() as u64,
        height: value.get("height").and_then(number).unwrap_or(0),
        waiting: count("queued") + count("submitted"),
        failed: count("collision") + count("rejected"),
        partial: matches!(value.get("partial"), Some(serde_json::Value::Bool(true)))
            || value.get("partial").and_then(|v| v.as_str()) == Some("true"),
    })
}

/// Reads room status through `vhalla rooms status ARGS` and returns the
/// counts or a fixed error code with a message for people.
fn read_rooms(args: &[String]) -> Result<Rooms, (&'static str, ErrorBody)> {
    #[cfg(feature = "experimental-rooms-replica")]
    {
        let exe = std::env::current_exe().map_err(|e| {
            (
                "rooms-unavailable",
                ErrorBody::new(ErrorCode::Internal, "Couldn't find vhalla itself.")
                    .with_detail(e.to_string()),
            )
        })?;
        let out = std::process::Command::new(exe)
            .arg("rooms")
            .arg("status")
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| {
                (
                    "rooms-unavailable",
                    ErrorBody::new(ErrorCode::Internal, "Couldn't run vhalla rooms status.")
                        .with_detail(e.to_string()),
                )
            })?;
        if out.status.success() {
            return rooms_from_status_json(&out.stdout).ok_or((
                "rooms-unreadable",
                ErrorBody::new(
                    ErrorCode::Internal,
                    "vhalla rooms status printed something this vhalla can't read.",
                ),
            ));
        }
        let detail = String::from_utf8_lossy(&out.stderr);
        let detail = detail
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("")
            .trim_start_matches("vhalla: ")
            .to_owned();
        Err((
            "rooms-unavailable",
            ErrorBody::new(ErrorCode::Internal, "Couldn't read your rooms.")
                .with_detail(detail)
                .with_next(NextStep::new(
                    format!("{COMMAND} rooms status {}", args.join(" ")),
                    "See the full error",
                    Audience::Agent,
                )),
        ))
    }
    #[cfg(not(feature = "experimental-rooms-replica"))]
    {
        let _ = args;
        Err((
            "not-built",
            ErrorBody::new(
                ErrorCode::Product("valhalla.not-built".into()),
                "This vhalla was built without rooms, so there's no room status to show.",
            ),
        ))
    }
}

fn atomic_write(path: &Path, content: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let temporary = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        std::process::id()
    ));
    let write = || -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(content)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)
    };
    write().inspect_err(|_| {
        let _ = std::fs::remove_file(&temporary);
    })
}

/// Runs a refresh and saves the result, including a failed one, so
/// `status` shows why. Returns the counts or the error.
pub(crate) fn refresh(
    root: &Path,
    args: &[String],
    now_ms: u64,
) -> Result<(PathBuf, Rooms), ErrorBody> {
    std::fs::create_dir_all(root).map_err(|e| {
        ErrorBody::new(ErrorCode::Internal, "Couldn't create the Valhalla folder.")
            .with_detail(e.to_string())
    })?;
    let result = read_rooms(args);
    let saved = RoomStatus {
        schema_version: 1,
        refreshed_at: now_ms,
        rooms: result.as_ref().ok().copied(),
        error: result.as_ref().err().map(|(code, _)| (*code).to_owned()),
        refresh_args: args.to_vec(),
    };
    let mut bytes = serde_json::to_vec(&saved).expect("status serializes");
    bytes.push(b'\n');
    let path = root.join(STATUS_FILE);
    atomic_write(&path, &bytes).map_err(|e| {
        ErrorBody::new(ErrorCode::Internal, "Couldn't save room status.").with_detail(e.to_string())
    })?;
    result
        .map(|rooms| (path, rooms))
        .map_err(|(_, error)| error)
}

fn status_refresh(args: &[OsString]) -> i32 {
    let json = wants_json(args);
    // Everything but --json passes through to `vhalla rooms status`.
    let mut passthrough = Vec::new();
    for arg in args {
        match arg.to_str() {
            Some("--json") => {}
            Some(arg) => passthrough.push(arg.to_owned()),
            None => return fail::<()>(json, usage("Arguments must be UTF-8.", "status refresh")),
        }
    }
    if passthrough.len() < 4 {
        return fail::<()>(
            json,
            usage(
                "status refresh needs SOCIAL_STORE REPLICA_HOME REALM NODE_HOME --config FILE.",
                "status refresh",
            ),
        );
    }
    let root = match paths() {
        Ok(paths) => paths.root,
        Err(error) => return fail::<()>(json, error),
    };
    let envelope = match refresh(&root, &passthrough, ms(SystemTime::now())) {
        Ok((path, rooms)) => Envelope::ok(
            REFRESH_SCHEMA,
            Refreshed {
                path: path.display().to_string(),
                rooms,
            },
        )
        .with_next(NextStep::new(
            format!("{COMMAND} status --json"),
            "Show the saved status",
            Audience::Agent,
        )),
        Err(error) => Envelope::error(error),
    };
    finish(json, envelope, |data| {
        let rooms = data.rooms;
        let mut line = format!(
            "Room status saved: {}",
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
        line.push('\n');
        line
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// 2026-09-01T12:00:00Z, the clock every golden is rendered at.
    const NOW: u64 = 1_788_264_000_000;
    const MIN: u64 = 60_000;
    const FOLDER: &str = "/home/you/.local/share/valhalla/outputs";

    fn golden_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/status")
    }

    fn outputs(total: u64) -> Outputs {
        let files = (0..total.min(NEWEST_LIMIT as u64))
            .map(|n| {
                let index = total - 1 - n;
                OutputFile {
                    name: format!("summary {index}.md"),
                    path: format!("{FOLDER}/summary {index}.md"),
                    bytes: 1_800,
                    modified_at: NOW - (n + 1) * 20 * MIN,
                }
            })
            .collect();
        Outputs {
            folder: FOLDER.into(),
            exists: true,
            total,
            files,
        }
    }

    fn saved(minutes_ago: u64, rooms: Option<Rooms>, error: Option<&str>) -> RoomStatus {
        RoomStatus {
            schema_version: 1,
            refreshed_at: NOW - minutes_ago * MIN,
            rooms,
            error: error.map(str::to_owned),
            refresh_args: vec![
                "/home/you/valhalla/social".into(),
                "/home/you/valhalla/replica".into(),
                "REALM".into(),
                "/home/you/valhalla/node".into(),
                "--config".into(),
                "node.toml".into(),
            ],
        }
    }

    fn rooms(count: u64, waiting: u64, failed: u64) -> Option<Rooms> {
        Some(Rooms {
            count,
            height: 42,
            waiting,
            failed,
            partial: false,
        })
    }

    fn item(label: &str, ours: bool) -> LoginItem {
        LoginItem {
            label: label.into(),
            path: format!("/home/you/Library/LaunchAgents/{label}.plist"),
            ours,
        }
    }

    /// Every state the retired menu bar had a fixture for, by that
    /// fixture's name. `action-error` is an error envelope, not a state.
    fn fixtures() -> Vec<(&'static str, Option<RoomStatus>, Outputs, Vec<LoginItem>)> {
        vec![
            ("first-run", None, outputs(0), vec![]),
            (
                "empty",
                Some(saved(0, rooms(0, 0, 0), None)),
                outputs(0),
                vec![],
            ),
            (
                "error",
                Some(saved(2, None, Some("rooms-unavailable"))),
                outputs(0),
                vec![],
            ),
            (
                "in-sync",
                Some(saved(5, rooms(4, 0, 0), None)),
                outputs(5),
                vec![],
            ),
            (
                "out-of-date",
                Some(saved(3 * 60, rooms(4, 0, 0), None)),
                outputs(2),
                vec![],
            ),
            (
                "send-failed",
                Some(saved(1, rooms(1, 0, 1), None)),
                outputs(5),
                vec![item("app.hraness.valhalla", true)],
            ),
            (
                "sends-waiting",
                Some(saved(1, rooms(4, 2, 0), None)),
                outputs(1),
                vec![],
            ),
            (
                "login-not-ours",
                Some(saved(5, rooms(4, 0, 0), None)),
                outputs(1),
                vec![item("com.hraness.valhalla.menubar", false)],
            ),
        ]
    }

    fn at() -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(NOW)
    }

    fn json(envelope: &Envelope<impl Serialize>) -> String {
        let mut out = Vec::new();
        envelope::emit(&mut out, envelope);
        String::from_utf8(out).unwrap()
    }

    fn rendered() -> Vec<(String, String)> {
        let mut files = Vec::new();
        for (name, status, outputs, items) in fixtures() {
            let (data, next) = build_status(status.as_ref(), outputs, items, NOW);
            for width in [40u16, 80, 120] {
                files.push((format!("{name}.w{width}.txt"), snapshot(&data, width, NOW)));
            }
            let envelope = next
                .into_iter()
                .fold(Envelope::ok(STATUS_SCHEMA, data), Envelope::with_next)
                .at(at());
            files.push((format!("{name}.json"), json(&envelope)));
        }
        // The menu's "couldn't open" row: now the error `outputs open` returns.
        let error = open_target(
            Path::new("/nonexistent/outputs"),
            Some("summary 9.md"),
            false,
        )
        .unwrap_err();
        let envelope = Envelope::<()>::error(error).at(at());
        files.push(("action-error.json".into(), json(&envelope)));
        files
    }

    #[test]
    fn snapshots_and_json_match_the_goldens() {
        let dir = golden_dir();
        let update = std::env::var_os("VHALLA_UPDATE_GOLDENS").is_some();
        if update {
            std::fs::create_dir_all(&dir).unwrap();
        }
        let mut stale = Vec::new();
        for (name, text) in rendered() {
            let path = dir.join(&name);
            if update {
                std::fs::write(&path, &text).unwrap();
            } else if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
                stale.push(format!("{name}:\n{text}"));
            }
        }
        assert!(
            stale.is_empty(),
            "goldens differ (VHALLA_UPDATE_GOLDENS=1 cargo test -p vhalla-cli control):\n{}",
            stale.join("\n")
        );
    }

    #[test]
    fn snapshots_fit_their_width_and_carry_no_trailing_space() {
        for (name, text) in rendered() {
            let Some(width) = name
                .split(".w")
                .nth(1)
                .and_then(|rest| rest.strip_suffix(".txt"))
                .and_then(|w| w.parse::<usize>().ok())
            else {
                continue;
            };
            for line in text.lines() {
                assert!(line.chars().count() <= width, "{name}: {line}");
                assert_eq!(line, line.trim_end(), "{name}");
            }
        }
    }

    #[test]
    fn every_fixture_state_has_its_own_headline() {
        let states: Vec<_> = fixtures()
            .into_iter()
            .map(|(_, status, outputs, items)| {
                build_status(status.as_ref(), outputs, items, NOW).0.state
            })
            .collect();
        for state in [
            "first-run",
            "no-rooms",
            "error",
            "in-sync",
            "out-of-date",
            "send-failed",
            "sends-waiting",
        ] {
            assert!(states.contains(&state), "{state}");
        }
    }

    #[test]
    fn next_steps_repeat_the_saved_refresh_and_offer_retire() {
        let status = saved(3 * 60, rooms(1, 0, 0), None);
        let (_, next) = build_status(
            Some(&status),
            outputs(0),
            vec![item("app.hraness.valhalla", true)],
            NOW,
        );
        let commands: Vec<_> = next.iter().map(|n| n.command.as_str()).collect();
        assert_eq!(
            commands,
            [
                "vhalla status refresh /home/you/valhalla/social /home/you/valhalla/replica REALM /home/you/valhalla/node --config node.toml",
                "vhalla doctor retire",
            ]
        );
    }

    #[test]
    fn registry_lists_every_dispatched_verb() {
        let registry = registry();
        let listed: Vec<String> = registry.verbs().iter().map(|v| v.command()).collect();
        for command in [
            "status",
            "status refresh",
            "commands",
            "doctor",
            "doctor retire",
            "outputs",
            "outputs list",
            "outputs open",
            "outputs reveal",
            "support",
        ] {
            assert!(listed.iter().any(|c| c == command), "{command}");
        }
        let value = serde_json::to_value(registry.commands_json()).unwrap();
        assert_eq!(value["schema"], "hraness.commands/1");
    }

    #[test]
    fn ago_and_size_read_naturally() {
        assert_eq!(ago(NOW, NOW), "just now");
        assert_eq!(ago(NOW - 5 * MIN, NOW), "5 min ago");
        assert_eq!(ago(NOW - 60 * MIN, NOW), "1 hour ago");
        assert_eq!(ago(NOW - 180 * MIN, NOW), "3 hours ago");
        assert_eq!(ago(NOW - 25 * 60 * MIN, NOW), "yesterday");
        assert_eq!(ago(NOW - 72 * 60 * MIN, NOW), "3 days ago");
        assert_eq!(ago(NOW + MIN, NOW), "just now");
        assert_eq!(size(812), "812 B");
        assert_eq!(size(1_800), "2 KB");
        assert_eq!(size(3_400_000), "3.4 MB");
    }

    #[test]
    fn wrap_keeps_long_words_within_the_line() {
        for width in [20, 40, 80] {
            for line in row("Outputs", &"x".repeat(200), width) {
                assert!(line.chars().count() <= width, "{line}");
            }
        }
        assert_eq!(row("Rooms", "a b", 40), ["Rooms     a b"]);
    }

    #[test]
    fn saved_status_parses_and_rejects_foreign_shapes() {
        let written = serde_json::to_vec(&saved(1, rooms(2, 0, 0), None)).unwrap();
        assert_eq!(
            parse_room_status(&written),
            Some(saved(1, rooms(2, 0, 0), None))
        );
        // The legacy menu bar shape reads the same.
        let legacy = br#"{"schemaVersion":1,"refreshedAt":5,"error":"not-built"}"#;
        assert_eq!(
            parse_room_status(legacy).unwrap().error.as_deref(),
            Some("not-built")
        );
        assert!(parse_room_status(br#"{"schemaVersion":2,"refreshedAt":5}"#).is_none());
        assert!(parse_room_status(b"not json").is_none());
        let odd = br#"{"schemaVersion":1,"refreshedAt":5,"error":"<script>"}"#;
        assert_eq!(
            parse_room_status(odd).unwrap().error.as_deref(),
            Some("unknown")
        );
    }

    #[test]
    fn output_names_stay_inside_the_folder() {
        for bad in ["", ".", "..", "../x", "a/b", ".hidden", "a\0b"] {
            assert!(!valid_output_name(bad), "{bad:?}");
        }
        assert!(valid_output_name("summary 4.md"));
        let dir = scratch("names");
        std::fs::write(dir.join("real.md"), "x").unwrap();
        std::os::unix::fs::symlink(dir.join("real.md"), dir.join("link.md")).unwrap();
        assert_eq!(
            open_target(&dir, Some("real.md"), true).unwrap(),
            dir.join("real.md")
        );
        assert_eq!(open_target(&dir, None, false).unwrap(), dir);
        assert_eq!(
            open_target(&dir, Some("link.md"), false).unwrap_err().code,
            ErrorCode::NotFound
        );
        assert_eq!(
            open_target(&dir, Some("../real.md"), false)
                .unwrap_err()
                .code,
            ErrorCode::Usage
        );
        assert_eq!(
            open_target(&dir, None, true).unwrap_err().code,
            ErrorCode::Usage
        );
        let listed = list_outputs(&dir, 10);
        assert_eq!(listed.total, 1, "symlinks are not listed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- doctor retire ----

    const OURS: &str = "<?xml version=\"1.0\"?>\n<plist><dict><key>Label</key><string>app.hraness.valhalla</string>\n<key>ProgramArguments</key><array><string>/Users/you/Library/Application Support/Valhalla/bin/vhalla-menubar</string></array></dict></plist>\n";
    const FOREIGN: &str = "<plist><dict><key>ProgramArguments</key><array><string>/usr/local/bin/something-else</string></array></dict></plist>\n";

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vhalla-control-{name}-{}-{}",
            std::process::id(),
            ms(SystemTime::now())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn agents(home: &Path) -> PathBuf {
        let dir = home.join("Library/LaunchAgents");
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn my_uid(home: &Path) -> Option<u32> {
        Some(std::fs::metadata(home).unwrap().uid())
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn launches_menubar_matches_only_the_program() {
        assert!(launches_menubar(OURS));
        assert!(launches_menubar("<string>vhalla-menubar</string>"));
        assert!(!launches_menubar(FOREIGN));
        assert!(!launches_menubar(
            "<string>/bin/not-vhalla-menubar</string>"
        ));
        assert!(!launches_menubar("vhalla-menubar outside a string"));
    }

    #[test]
    fn retire_renames_only_the_correct_item() {
        let home = scratch("retire");
        let dir = agents(&home);
        std::fs::write(dir.join("app.hraness.valhalla.plist"), OURS).unwrap();
        std::fs::write(dir.join("com.hraness.valhalla.menubar.plist"), FOREIGN).unwrap();
        std::fs::write(dir.join("com.example.other.plist"), OURS).unwrap();
        let booted = std::cell::RefCell::new(Vec::new());
        let retired = retire_login_items(&home, my_uid(&home), 7, &|label| {
            booted.borrow_mut().push(label.to_owned())
        })
        .unwrap();
        assert_eq!(retired.len(), 1);
        assert_eq!(retired[0].label, "app.hraness.valhalla");
        assert!(retired[0].restore.starts_with("mv "));
        assert_eq!(*booted.borrow(), ["app.hraness.valhalla"]);
        assert_eq!(
            names(&dir),
            [
                "app.hraness.valhalla.plist.retired-7",
                "com.example.other.plist",
                "com.hraness.valhalla.menubar.plist",
            ]
        );
        // The renamed item keeps every byte.
        assert_eq!(
            std::fs::read_to_string(dir.join("app.hraness.valhalla.plist.retired-7")).unwrap(),
            OURS
        );
        // Running again finds nothing of ours and changes nothing.
        let again = retire_login_items(&home, my_uid(&home), 8, &|_| panic!("no bootout")).unwrap();
        assert!(again.is_empty());
        let (doctor, next) = doctor_data(&home.join("state"), &home, my_uid(&home));
        assert_eq!(doctor.retired.len(), 1);
        assert_eq!(
            doctor.login_items,
            [LoginItem {
                label: "com.hraness.valhalla.menubar".into(),
                path: dir
                    .join("com.hraness.valhalla.menubar.plist")
                    .display()
                    .to_string(),
                ours: false,
            }]
        );
        assert!(next.iter().all(|n| n.command != "vhalla doctor retire"));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn retire_leaves_a_symlink_alone() {
        let home = scratch("symlink");
        let dir = agents(&home);
        let target = home.join("elsewhere.plist");
        std::fs::write(&target, OURS).unwrap();
        std::os::unix::fs::symlink(&target, dir.join("app.hraness.valhalla.plist")).unwrap();
        let items = find_login_items(&home, my_uid(&home));
        assert_eq!(items.len(), 1);
        assert!(!items[0].ours);
        let retired =
            retire_login_items(&home, my_uid(&home), 7, &|_| panic!("no bootout")).unwrap();
        assert!(retired.is_empty());
        assert_eq!(names(&dir), ["app.hraness.valhalla.plist"]);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), OURS);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn retire_leaves_another_users_file_alone() {
        let home = scratch("owner");
        let dir = agents(&home);
        std::fs::write(dir.join("app.hraness.valhalla.plist"), OURS).unwrap();
        let someone_else = my_uid(&home).map(|uid| uid + 1);
        assert!(!find_login_items(&home, someone_else)[0].ours);
        let retired =
            retire_login_items(&home, someone_else, 7, &|_| panic!("no bootout")).unwrap();
        assert!(retired.is_empty());
        assert_eq!(names(&dir), ["app.hraness.valhalla.plist"]);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn retire_never_overwrites_an_earlier_retired_copy() {
        let home = scratch("clash");
        let dir = agents(&home);
        std::fs::write(dir.join("app.hraness.valhalla.plist"), OURS).unwrap();
        std::fs::write(dir.join("app.hraness.valhalla.plist.retired-7"), "earlier").unwrap();
        let error =
            retire_login_items(&home, my_uid(&home), 7, &|_| panic!("no bootout")).unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict);
        assert_eq!(
            std::fs::read_to_string(dir.join("app.hraness.valhalla.plist.retired-7")).unwrap(),
            "earlier"
        );
        assert!(dir.join("app.hraness.valhalla.plist").exists());
        let _ = std::fs::remove_dir_all(&home);
    }

    /// The item foundation v0.8's service helper wrote for
    /// `HRANESS_LOCAL_APP=1 vhalla menubar install` in v0.2.8.
    const LOCAL_APP: &str = "<?xml version=\"1.0\"?>\n<plist><dict><key>Label</key><string>app.hraness.valhalla</string>\n<key>ProgramArguments</key><array><string>/Users/you/Applications/Hraness/Valhalla.app/Contents/MacOS/Valhalla</string></array>\n<key>AssociatedBundleIdentifiers</key><array><string>app.hraness.valhalla</string></array></dict></plist>\n";

    #[test]
    fn the_v028_local_app_item_is_ours_and_its_app_is_reported() {
        assert!(launches_menubar(LOCAL_APP));
        assert!(!launches_menubar(
            "<string>/Applications/Other.app/Contents/MacOS/Valhalla</string>"
        ));
        let home = scratch("local-app");
        let dir = agents(&home);
        std::fs::write(dir.join("app.hraness.valhalla.plist"), LOCAL_APP).unwrap();
        let app = home.join("Applications/Hraness/Valhalla.app/Contents/MacOS");
        std::fs::create_dir_all(&app).unwrap();
        let (doctor, next) = doctor_data(&home.join("state"), &home, my_uid(&home));
        assert!(doctor.login_items[0].ours);
        assert!(
            !doctor
                .checks
                .iter()
                .find(|c| c.name == "login-items")
                .unwrap()
                .ok
        );
        assert!(next.iter().any(|n| n.command == "vhalla doctor retire"));
        assert_eq!(
            doctor.menubar_app.as_deref(),
            Some(
                home.join("Applications/Hraness/Valhalla.app")
                    .display()
                    .to_string()
                    .as_str()
            )
        );
        let retired = retire_login_items(&home, my_uid(&home), 7, &|_| {}).unwrap();
        assert_eq!(retired.len(), 1);
        assert_eq!(names(&dir), ["app.hraness.valhalla.plist.retired-7"]);
        // The app itself is never touched.
        assert!(app.is_dir());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn an_unknown_account_owns_nothing_and_retires_nothing() {
        let home = scratch("no-uid");
        let dir = agents(&home);
        std::fs::write(dir.join("app.hraness.valhalla.plist"), OURS).unwrap();
        assert!(!find_login_items(&home, None)[0].ours);
        let error = retire_login_items(&home, None, 7, &|_| panic!("no bootout")).unwrap_err();
        assert_eq!(error.code, ErrorCode::Internal);
        assert_eq!(names(&dir), ["app.hraness.valhalla.plist"]);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_later_clash_keeps_earlier_receipts_and_skips_its_bootout() {
        let home = scratch("partial");
        let dir = agents(&home);
        std::fs::write(dir.join("app.hraness.valhalla.plist"), OURS).unwrap();
        std::fs::write(dir.join("com.hraness.valhalla.menubar.plist"), OURS).unwrap();
        std::fs::write(
            dir.join("com.hraness.valhalla.menubar.plist.retired-7"),
            "earlier",
        )
        .unwrap();
        let booted = std::cell::RefCell::new(Vec::new());
        let error = retire_login_items(&home, my_uid(&home), 7, &|label| {
            booted.borrow_mut().push(label.to_owned())
        })
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::Conflict);
        // Only the item that was renamed was unloaded.
        assert_eq!(*booted.borrow(), ["app.hraness.valhalla"]);
        assert!(error
            .detail
            .as_deref()
            .unwrap()
            .contains("app.hraness.valhalla.plist.retired-7"));
        assert_eq!(error.next.len(), 1);
        assert!(error.next[0].command.starts_with("mv "));
        assert!(error.next[0]
            .command
            .contains("app.hraness.valhalla.plist.retired-7"));
        assert_eq!(
            names(&dir),
            [
                "app.hraness.valhalla.plist.retired-7",
                "com.hraness.valhalla.menubar.plist",
                "com.hraness.valhalla.menubar.plist.retired-7",
            ]
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn oversized_or_non_utf8_items_are_not_ours() {
        let home = scratch("odd");
        let dir = agents(&home);
        let mut big = OURS.to_owned();
        big.push_str(&" ".repeat(70 * 1024));
        std::fs::write(dir.join("app.hraness.valhalla.plist"), big).unwrap();
        std::fs::write(
            dir.join("com.hraness.valhalla.menubar.plist"),
            [0xff, 0xfe, 0x00],
        )
        .unwrap();
        assert!(find_login_items(&home, my_uid(&home))
            .iter()
            .all(|i| !i.ours));
        let _ = std::fs::remove_dir_all(&home);
    }
}
