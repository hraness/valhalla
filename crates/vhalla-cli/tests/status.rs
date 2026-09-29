#![cfg(unix)]
//! `status`, `tui`, `commands`, `doctor` and `outputs`: one process per
//! command, the shared JSON envelope, and parity with the retired menu bar.
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

struct Home(PathBuf);

impl Home {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "vhalla-status-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn state(&self) -> PathBuf {
        if cfg!(target_os = "macos") {
            self.0.join("Library/Application Support/Valhalla")
        } else {
            self.0.join("data/valhalla")
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
            .env("HOME", &self.0)
            .env("XDG_DATA_HOME", self.0.join("data"))
            .args(args)
            .output()
            .unwrap()
    }

    fn json(&self, args: &[&str]) -> (i32, Value) {
        let out = self.run(args);
        let text = String::from_utf8(out.stdout).unwrap();
        assert_eq!(text.lines().count(), 1, "{args:?}: {text}");
        (
            out.status.code().unwrap(),
            serde_json::from_str(&text).unwrap(),
        )
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn without_stamp(mut value: Value) -> Value {
    value.as_object_mut().unwrap().remove("generatedAt");
    value
}

fn seed(home: &Home) {
    let state = home.state();
    std::fs::create_dir_all(state.join("outputs")).unwrap();
    std::fs::write(state.join("outputs/summary.md"), "# done\n").unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    std::fs::write(
        state.join("room-status.json"),
        format!(
            r#"{{"schemaVersion":1,"refreshedAt":{now},"rooms":{{"count":3,"height":9,"waiting":2,"failed":0,"partial":false}}}}"#
        ),
    )
    .unwrap();
}

#[test]
fn tui_json_is_status_json() {
    let home = Home::new("parity");
    seed(&home);
    let (code, status) = home.json(&["status", "--json"]);
    assert_eq!(code, 0);
    assert_eq!(status["ok"], true);
    assert_eq!(status["schema"], "valhalla.status/1");
    assert_eq!(status["data"]["state"], "sends-waiting");
    assert_eq!(status["data"]["headline"], "2 sends waiting");
    assert_eq!(status["data"]["outputs"]["files"][0]["name"], "summary.md");
    let (code, tui) = home.json(&["tui", "--json"]);
    assert_eq!(code, 0);
    assert_eq!(without_stamp(status), without_stamp(tui));
}

#[test]
fn tui_snapshot_prints_every_view_at_the_width_asked() {
    let home = Home::new("snapshot");
    seed(&home);
    for width in ["40", "80", "120"] {
        let out = home.run(&["tui", "--snapshot", "--width", width]);
        assert!(out.status.success());
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(text.starts_with("== Status ==\n"), "{text}");
        assert!(text.contains("\n== Outputs ==\n"), "{text}");
        assert!(text.contains("2 sends waiting"), "{text}");
        let width: usize = width.parse().unwrap();
        assert!(text.lines().all(|l| l.chars().count() <= width), "{text}");
    }
    // Not a terminal: a snapshot without asking.
    let out = home.run(&["tui"]);
    assert!(String::from_utf8(out.stdout)
        .unwrap()
        .starts_with("== Status ==\n"));
}

#[test]
fn a_menubar_status_file_is_still_read() {
    let home = Home::new("legacy");
    let state = home.state();
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(
        state.join("menubar-status.json"),
        r#"{"schemaVersion":1,"refreshedAt":1,"error":"rooms-unavailable"}"#,
    )
    .unwrap();
    let (code, status) = home.json(&["status", "--json"]);
    assert_eq!(code, 0);
    assert_eq!(status["data"]["state"], "error");
    assert_eq!(status["data"]["error"], "rooms-unavailable");
}

#[test]
fn first_run_points_at_refresh() {
    let home = Home::new("first");
    let (code, status) = home.json(&["status", "--json"]);
    assert_eq!(code, 0);
    assert_eq!(status["data"]["state"], "first-run");
    let next = status["next"][0]["command"].as_str().unwrap();
    assert!(next.starts_with("vhalla status refresh "), "{next}");
    // Reading status creates nothing.
    assert!(!home.state().exists());
}

#[test]
fn commands_json_lists_every_verb_with_its_class() {
    let home = Home::new("commands");
    let (code, value) = home.json(&["commands", "--json"]);
    assert_eq!(code, 0);
    assert_eq!(value["ok"], true);
    assert_eq!(value["schema"], "hraness.commands/1");
    assert_eq!(value["data"]["product"], "valhalla");
    let verbs = value["data"]["verbs"].as_array().unwrap();
    let find = |path: &[&str]| {
        verbs
            .iter()
            .find(|v| v["path"] == serde_json::json!(path))
            .unwrap_or_else(|| panic!("{path:?} in {value}"))
    };
    assert_eq!(find(&["status"])["opClass"], "read");
    assert_eq!(find(&["tui"])["opClass"], "read");
    assert_eq!(find(&["doctor"])["opClass"], "read");
    assert_eq!(find(&["doctor", "retire"])["opClass"], "operate");
    assert_eq!(find(&["outputs", "open"])["opClass"], "operate");
    assert_eq!(find(&["support"])["opClass"], "read");
    for verb in verbs {
        let schema = verb["schema"].as_str().unwrap();
        assert!(schema.ends_with("/1"), "{schema}");
    }
}

#[test]
fn doctor_reads_and_changes_nothing() {
    let home = Home::new("doctor");
    let agents = home.0.join("Library/LaunchAgents");
    std::fs::create_dir_all(&agents).unwrap();
    let plist = agents.join("app.hraness.valhalla.plist");
    let text = "<plist><array><string>/x/bin/vhalla-menubar</string></array></plist>";
    std::fs::write(&plist, text).unwrap();
    let (code, value) = home.json(&["doctor", "--json"]);
    assert_eq!(code, 0);
    assert_eq!(value["schema"], "valhalla.doctor/1");
    assert_eq!(value["data"]["loginItems"][0]["ours"], true);
    assert!(value["next"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["command"] == "vhalla doctor retire"));
    assert_eq!(std::fs::read_to_string(&plist).unwrap(), text);
    assert!(!home.state().exists());
}

#[test]
fn usage_errors_are_envelopes_with_exit_two() {
    let home = Home::new("usage");
    for args in [
        &["status", "--bogus", "--json"][..],
        &["tui", "--width", "5", "--json"],
        &["doctor", "extra", "--json"],
        &["outputs", "open", "../x", "--json"],
        &["status", "refresh", "--json"],
    ] {
        let (code, value) = home.json(args);
        assert_eq!(code, 2, "{args:?}");
        assert_eq!(value["ok"], false);
        assert_eq!(value["schema"], "hraness.error/1");
        assert_eq!(value["error"]["code"], "usage");
    }
}

#[test]
fn outputs_list_and_a_missing_file() {
    let home = Home::new("outputs");
    seed(&home);
    let (code, value) = home.json(&["outputs", "list", "--json"]);
    assert_eq!(code, 0);
    assert_eq!(value["schema"], "valhalla.outputs/1");
    assert_eq!(value["data"]["total"], 1);
    let (code, value) = home.json(&["outputs", "reveal", "missing.md", "--json"]);
    assert_eq!(code, 1);
    assert_eq!(value["error"]["code"], "not-found");
    assert_eq!(
        value["error"]["next"][0]["command"],
        "vhalla outputs list --json"
    );
    // The plain form still prints just the path.
    let out = home.run(&["outputs"]);
    assert!(out.status.success());
    let printed = String::from_utf8(out.stdout).unwrap();
    assert!(Path::new(printed.trim()).is_dir(), "{printed}");
}

#[test]
fn every_new_command_answers_help() {
    let home = Home::new("help");
    for command in ["status", "tui", "doctor", "commands", "outputs"] {
        for form in [
            vec![command, "--help"],
            vec![command, "-h"],
            vec!["help", command],
        ] {
            let out = home.run(&form);
            assert!(out.status.success(), "{form:?}");
            assert!(
                String::from_utf8(out.stdout)
                    .unwrap()
                    .starts_with("Usage: vhalla "),
                "{form:?}"
            );
        }
    }
    let out = home.run(&["doctor", "retire", "--help"]);
    assert!(out.status.success());
    assert!(!home.0.join("Library").exists());
}

/// `support --json` is the menu's "Updates & support" as one envelope; the
/// support protocol's own argv keeps support-foundation's shape.
#[test]
fn support_json_is_an_envelope_and_the_protocol_is_unchanged() {
    let home = Home::new("support");
    let (code, value) = home.json(&["support", "--json"]);
    assert_eq!(code, 0);
    assert_eq!(value["ok"], true);
    assert_eq!(value["schema"], "valhalla.support/1");
    assert!(value["generatedAt"].is_string(), "{value}");
    assert_eq!(value["data"]["schemaVersion"], "hraness-support-offer-v1");
    assert_eq!(value["data"]["product"]["id"], "valhalla");
    let (code, protocol) = home.json(&["support", "protocol", "--json"]);
    assert_eq!(code, 0);
    assert_eq!(protocol["schemaVersion"], "hraness-support-protocol-v1");
    assert!(protocol.get("ok").is_none(), "{protocol}");
}

/// docs/cli-parity.md names a command for every action the menu bar had,
/// and every `vhalla ...` it names is a verb `commands --json` lists, so an
/// agent that only reads the registry finds each replacement.
#[test]
fn parity_doc_covers_every_menu_action() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let doc = std::fs::read_to_string(root.join("docs/cli-parity.md")).unwrap();
    let home = Home::new("parity");
    let (_, commands) = home.json(&["commands", "--json"]);
    let registered: Vec<Vec<String>> = commands["data"]["verbs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|verb| serde_json::from_value(verb["path"].clone()).unwrap())
        .collect();
    for action in [
        "`status`",
        "`outputs.open.<file>`",
        "`outputs.reveal.<file>`",
        "`outputs.folder`",
        "`login`",
        "`support`",
        "`support.diagnostics`",
        "`quit`",
    ] {
        let row = doc
            .lines()
            .find(|line| line.starts_with(&format!("| {action} ")))
            .unwrap_or_else(|| panic!("no row for {action}"));
        assert!(row.contains("vhalla ") || row.contains("n/a"), "{row}");
        let replacement = row.rsplit(" | ").next().unwrap();
        for span in replacement.split('`').skip(1).step_by(2) {
            let Some(rest) = span.strip_prefix("vhalla ") else {
                continue;
            };
            let path: Vec<String> = rest
                .split_whitespace()
                .take_while(|word| {
                    !word.starts_with('-') && word.chars().all(|c| c.is_ascii_lowercase())
                })
                .map(str::to_owned)
                .collect();
            assert!(
                registered.contains(&path),
                "{action}: `{span}` is not a verb in commands --json"
            );
        }
    }
    for state in [
        "first-run",
        "empty",
        "error",
        "in-sync",
        "out-of-date",
        "send-failed",
        "sends-waiting",
        "login-not-ours",
        "action-error",
    ] {
        assert!(doc.contains(&format!("`{state}`")), "{state}");
        let golden = root.join(format!(
            "crates/vhalla-cli/tests/fixtures/status/{state}.json"
        ));
        assert!(golden.exists(), "{state}");
    }
}
