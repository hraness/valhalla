//! Room status for the menu: `menubar-status.json` in the Valhalla folder.
//!
//! `vhalla menubar refresh …` writes it from a `rooms status` read: counts
//! only (rooms, committed height, sends waiting, sends that didn't go
//! through) and the time of the read, never room names, keys or paths. The
//! menu bar only reads it. Reads are bounded; anything unreadable counts
//! as absent.

use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

pub const STATUS_FILE: &str = "menubar-status.json";
const MAX_BYTES: u64 = 16 * 1024;
/// Older than this, the counts are shown as out of date.
pub const STALE_AFTER: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub schema_version: u32,
    /// Milliseconds since the Unix epoch.
    pub refreshed_at: u64,
    pub rooms: Option<Rooms>,
    /// A fixed code when the last refresh couldn't read room status.
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rooms {
    pub count: u64,
    pub height: u64,
    /// Sends queued or submitted and not yet committed.
    pub waiting: u64,
    /// Sends that collided or were rejected.
    pub failed: u64,
    /// The room list was cut short.
    pub partial: bool,
}

pub fn at_ms(ms: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(ms)
}

impl Status {
    pub fn read(root: &Path) -> Option<Status> {
        let path = root.join(STATUS_FILE);
        let meta = fs::symlink_metadata(&path).ok()?;
        if !meta.is_file() || meta.len() > MAX_BYTES {
            return None;
        }
        let mut bytes = Vec::new();
        fs::File::open(&path)
            .ok()?
            .take(MAX_BYTES)
            .read_to_end(&mut bytes)
            .ok()?;
        let mut status: Status = serde_json::from_slice(&bytes).ok()?;
        if status.schema_version != 1 {
            return None;
        }
        if status.error.as_deref().is_some_and(|code| {
            code.len() > 40 || !code.chars().all(|c| c.is_ascii_lowercase() || c == '-')
        }) {
            status.error = Some("unknown".into());
        }
        Some(status)
    }
}

/// "just now", "4 min ago", "3 hours ago", "yesterday", "2 days ago".
pub fn ago(then: SystemTime, now: SystemTime) -> String {
    let seconds = now.duration_since(then).unwrap_or_default().as_secs();
    match seconds {
        0..=59 => "just now".into(),
        60..=3_599 => format!("{} min ago", seconds / 60),
        3_600..=7_199 => "1 hour ago".into(),
        7_200..=86_399 => format!("{} hours ago", seconds / 3_600),
        86_400..=172_799 => "yesterday".into(),
        _ => format!("{} days ago", seconds / 86_400),
    }
}

/// A plain sentence for a fixed refresh error code.
pub fn explain(code: &str) -> &'static str {
    match code {
        "rooms-unavailable" => "Check that your node is running, then refresh.",
        "rooms-unreadable" => "The status came back in a form this menu bar can't read.",
        "not-built" => "This vhalla was built without rooms.",
        _ => "Run vhalla menubar refresh again to see why.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vhalla-status-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn reads_counts_and_errors() {
        let root = dir("read");
        std::fs::write(
            root.join(STATUS_FILE),
            r#"{"schemaVersion":1,"refreshedAt":5,"rooms":{"count":4,"height":120,"waiting":1,"failed":0,"partial":false}}"#,
        )
        .unwrap();
        let status = Status::read(&root).unwrap();
        assert_eq!(status.rooms.unwrap().waiting, 1);
        std::fs::write(
            root.join(STATUS_FILE),
            r#"{"schemaVersion":1,"refreshedAt":5,"error":"<script>"}"#,
        )
        .unwrap();
        assert_eq!(
            Status::read(&root).unwrap().error.as_deref(),
            Some("unknown")
        );
        std::fs::write(
            root.join(STATUS_FILE),
            r#"{"schemaVersion":2,"refreshedAt":5}"#,
        )
        .unwrap();
        assert_eq!(Status::read(&root), None);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn every_code_has_a_plain_sentence() {
        for code in [
            "rooms-unavailable",
            "rooms-unreadable",
            "not-built",
            "unknown",
        ] {
            assert!(explain(code).ends_with('.'));
        }
    }
}
