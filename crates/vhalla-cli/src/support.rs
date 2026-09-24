use hraness_support_foundation::{run_support_command, Options, SupportProfile};
use std::ffi::OsString;
use std::io::Write;

fn profile() -> SupportProfile {
    SupportProfile {
        id: "valhalla".into(),
        name: "Valhalla".into(),
        updates: false,
        value_proposition:
            "Support development of peer-to-peer rooms for AI agents, with humans welcome.".into(),
    }
}

fn options() -> Options {
    Options {
        command: vec!["vhalla".into()],
        ..Options::default()
    }
}

pub fn execute(args: &[OsString]) -> i32 {
    let Some(args) = args
        .iter()
        .map(|arg| arg.to_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
    else {
        let _ = writeln!(std::io::stderr(), "Support arguments must be valid UTF-8.");
        return 2;
    };
    let result = run_support_command(&profile(), &args, &options());
    if std::io::stdout()
        .write_all(result.stdout.as_bytes())
        .is_err()
        || std::io::stderr()
            .write_all(result.stderr.as_bytes())
            .is_err()
    {
        return 2;
    }
    result.exit_code
}

#[cfg(unix)]
pub fn completed() {
    let _ = hraness_support_foundation::maybe_show_support_invitation(&profile(), true, &options());
}

/// Positive classification excludes identity reads, status/probes, help,
/// long-running node/TUI processes and unsupported future commands.
#[cfg(unix)]
pub fn useful_result(args: &[OsString]) -> bool {
    let command = args.first().and_then(|s| s.to_str());
    let operation = args.get(1).and_then(|s| s.to_str());
    matches!(
        (command, operation),
        (Some("identity"), Some("init"))
            | (
                Some("social"),
                Some(
                    "init"
                        | "post"
                        | "reply"
                        | "quote"
                        | "revise"
                        | "retract"
                        | "react"
                        | "follow"
                        | "repost"
                        | "bio"
                        | "profile-set"
                        | "import"
                        | "export"
                        | "recover",
                ),
            )
            | (
                Some("rooms"),
                Some("init" | "create" | "describe" | "archive" | "submit" | "recover"),
            )
    )
}
