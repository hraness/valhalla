//! Golden checks for the human CLI surface: bare invocation, grouped help,
//! topic help, errors per audience, NO_COLOR, TERM=dumb and closed pipes
//! (Hraness CLI style contract § D9). No test creates an identity outside a
//! temporary directory.
#![allow(missing_docs)]

use std::io::Read;
use std::process::{Command, Output, Stdio};

const CLEARED: &[&str] = &[
    "AI_AGENT",
    "CLAUDECODE",
    "CODEX_SANDBOX",
    "CODEX_SANDBOX_NETWORK_DISABLED",
    "CURSOR_AGENT",
    "GEMINI_CLI",
    "HRANESS_AUDIENCE",
    "NO_COLOR",
    "FORCE_COLOR",
    "HRANESS_ASCII",
];

fn command(args: &[&str], env: &[(&str, &str)]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vhalla"));
    command.args(args).current_dir(std::env::temp_dir());
    for name in CLEARED {
        command.env_remove(name);
    }
    command
        .env("LANG", "en_US.UTF-8")
        .env("HRANESS_SUPPORT", "off")
        .env("HRANESS_SUPPORT_AUDIENCE", "off");
    for (name, value) in env {
        command.env(name, value);
    }
    command
}

fn run(args: &[&str], env: &[(&str, &str)]) -> Output {
    command(args, env).output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

const TAGLINE: &str =
    "Valhalla: peer-to-peer rooms where agents and their owners share signed work.";

#[test]
fn bare_invocation_is_a_short_overview() {
    let output = run(&[], &[]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = text(&output.stdout);
    assert!(
        stdout.starts_with(&format!("{TAGLINE}\n\nStart here\n")),
        "{stdout}"
    );
    assert!(stdout.contains("  vhalla identity init DIR "), "{stdout}");
    assert!(stdout.contains("All commands: vhalla --help · Topics: vhalla help <topic>\n"));
    assert!(stdout.ends_with(&format!("vhalla {}\n", env!("CARGO_PKG_VERSION"))));
    assert!(stdout.lines().count() <= 25);
    assert!(stdout.lines().all(|line| line.chars().count() <= 80));
}

#[test]
fn root_help_forms_agree_and_exit_zero() {
    let help = run(&["--help"], &[]);
    assert_eq!(help.status.code(), Some(0));
    for form in ["-h", "help"] {
        let other = run(&[form], &[]);
        assert_eq!(other.status.code(), Some(0), "{form}");
        assert_eq!(other.stdout, help.stdout, "{form}");
    }
    let stdout = text(&help.stdout);
    assert!(stdout.starts_with(&format!(
        "Usage: vhalla <command> [options]\n\n{TAGLINE}\n\nStart here\n"
    )));
    assert!(stdout.lines().count() <= 60, "{stdout}");
    assert!(!stdout.contains("--features"), "{stdout}");
    assert!(stdout.contains("Optional support: vhalla support · Turn off: HRANESS_SUPPORT=off"));
}

#[test]
fn topics_answer_every_form_with_exit_zero() {
    for topic in ["identity", "menubar", "outputs"] {
        let page = run(&["help", topic], &[]);
        assert_eq!(page.status.code(), Some(0), "{topic}");
        for flag in ["--help", "-h"] {
            let other = run(&[topic, flag], &[]);
            assert_eq!(other.status.code(), Some(0), "{topic} {flag}");
            assert_eq!(other.stdout, page.stdout, "{topic} {flag}");
        }
    }
    let identity = text(&run(&["help", "identity"], &[]).stdout);
    assert!(identity.starts_with("Usage: vhalla identity <init|show|backup|restore> DIR\n"));
    let all = run(&["help", "all"], &[]);
    assert_eq!(all.status.code(), Some(0));
    assert!(text(&all.stdout).contains("vhalla identity restore <new-directory>"));
    let support = run(&["help", "support"], &[]);
    assert_eq!(support.status.code(), Some(0));
}

#[test]
fn unknown_topics_and_commands_fail_with_one_next_step() {
    let topic = run(&["help", "nope"], &[("HRANESS_AUDIENCE", "human")]);
    assert_eq!(topic.status.code(), Some(2));
    assert!(topic.stdout.is_empty());
    assert_eq!(
        text(&topic.stderr),
        "✗ No help topic named \"nope\".\n→ vhalla --help\n"
    );
    let command = run(&["idenity", "show", "/x"], &[("HRANESS_AUDIENCE", "human")]);
    assert_eq!(command.status.code(), Some(2));
    assert_eq!(
        text(&command.stderr),
        "✗ Unknown command \"idenity\". Did you mean \"identity\"?\n→ vhalla --help\n"
    );
}

#[test]
fn symbols_follow_no_color_force_color_and_dumb_terminals() {
    let forced = run(
        &["help", "nope"],
        &[("HRANESS_AUDIENCE", "human"), ("FORCE_COLOR", "1")],
    );
    assert!(text(&forced.stderr).starts_with("\x1b[31m✗\x1b[0m No help topic"));
    let plain = run(
        &["help", "nope"],
        &[("HRANESS_AUDIENCE", "human"), ("NO_COLOR", "1")],
    );
    assert!(text(&plain.stderr).starts_with("✗ No help topic"));
    let dumb = run(
        &["help", "nope"],
        &[("HRANESS_AUDIENCE", "human"), ("TERM", "dumb")],
    );
    assert_eq!(
        text(&dumb.stderr),
        "FAIL No help topic named \"nope\".\n-> vhalla --help\n"
    );
}

#[test]
fn scripts_and_agents_keep_the_prefixed_error_line() {
    let quiet = run(&["identity", "show"], &[]);
    assert_eq!(quiet.status.code(), Some(1));
    assert_eq!(
        text(&quiet.stderr),
        "vhalla: Use: vhalla identity <init|show|backup|restore> DIR\n→ vhalla help identity\n"
    );
    let agent = run(&["identity", "show"], &[("CLAUDECODE", "1")]);
    assert_eq!(agent.stderr, quiet.stderr);
}

#[test]
fn identity_errors_are_sentences_for_people() {
    let missing = std::env::temp_dir().join(format!("vhalla-ux-missing-{}", std::process::id()));
    let output = run(
        &["identity", "show", missing.to_str().unwrap()],
        &[("HRANESS_AUDIENCE", "human")],
    );
    assert_eq!(output.status.code(), Some(1));
    let stderr = text(&output.stderr);
    assert!(stderr.starts_with("✗ "), "{stderr}");
    assert!(
        !stderr.contains("Io(") && !stderr.contains("identity operation failed"),
        "{stderr}"
    );
    assert_eq!(
        stderr.lines().filter(|line| line.starts_with("→ ")).count(),
        1,
        "{stderr}"
    );
    assert!(!missing.exists());
}

#[test]
fn backup_warns_people_before_the_phrase() {
    let directory = std::env::temp_dir().join(format!("vhalla-ux-backup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let path = directory.join("identity");
    std::fs::create_dir_all(&directory).unwrap();
    assert!(run(&["identity", "init", path.to_str().unwrap()], &[])
        .status
        .success());
    let human = run(
        &["identity", "backup", path.to_str().unwrap()],
        &[("HRANESS_AUDIENCE", "human")],
    );
    assert!(human.status.success());
    assert_eq!(
        text(&human.stderr),
        "⚠ This phrase restores your identity. Store it offline; anyone with it can sign as you.\n"
    );
    assert!(text(&human.stdout).starts_with("mnemonic "));
    let quiet = run(&["identity", "backup", path.to_str().unwrap()], &[]);
    assert!(quiet.stderr.is_empty());
    assert_eq!(quiet.stdout, human.stdout);
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn a_closed_pipe_ends_help_quietly() {
    let mut child = command(&["--help"], &[])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut first = [0u8; 5];
    stdout.read_exact(&mut first).unwrap();
    drop(stdout);
    let output = child.wait_with_output().unwrap();
    assert_eq!(&first, b"Usage");
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty(), "{}", text(&output.stderr));
}
