//! Audience detection, terminal symbols and the human error form from the
//! Hraness CLI style contract.
//!
//! TODO(df-0.8): use `audience::detect` and the style helpers from the
//! `hraness-cli-kit` crate in hraness/desktop-foundation once 0.8.0 ships.
//! Until then this is a verbatim copy of the shared rule.

use std::io::IsTerminal;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Audience {
    Human,
    Agent,
    Quiet,
}

/// Exact agent markers. Prefixes never count: `CODEX_HOME` is human configuration.
const AGENT_MARKERS: &[&str] = &[
    "AI_AGENT",
    "CLAUDECODE",
    "CODEX_SANDBOX",
    "CODEX_SANDBOX_NETWORK_DISABLED",
    "CURSOR_AGENT",
    "GEMINI_CLI",
];

pub(crate) fn detect(env: &dyn Fn(&str) -> Option<String>, stderr_is_tty: bool) -> Audience {
    match env("HRANESS_AUDIENCE").as_deref() {
        Some("human") => return Audience::Human,
        Some("agent") => return Audience::Agent,
        Some("quiet" | "off") => return Audience::Quiet,
        _ => {}
    }
    if AGENT_MARKERS
        .iter()
        .any(|name| env(name).is_some_and(|value| !value.is_empty()))
    {
        return Audience::Agent;
    }
    if stderr_is_tty {
        Audience::Human
    } else {
        Audience::Quiet
    }
}

pub(crate) fn audience() -> Audience {
    detect(
        &|name| std::env::var(name).ok(),
        std::io::stderr().is_terminal(),
    )
}

/// How symbols and color render on one stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Style {
    pub(crate) color: bool,
    pub(crate) ascii: bool,
}

impl Style {
    pub(crate) fn detect(env: &dyn Fn(&str) -> Option<String>, stream_is_tty: bool) -> Self {
        let term = env("TERM");
        let dumb = term.as_deref() == Some("dumb");
        let forced = env("FORCE_COLOR").as_deref() == Some("1");
        let no_color = env("NO_COLOR").is_some_and(|value| !value.is_empty());
        let color = forced || (stream_is_tty && !dumb && !no_color);
        let utf8 = ["LC_ALL", "LC_CTYPE", "LANG"].iter().any(|name| {
            env(name).is_some_and(|value| {
                let value = value.to_ascii_lowercase();
                value.contains("utf-8") || value.contains("utf8")
            })
        });
        let ascii = dumb || !utf8 || env("HRANESS_ASCII").as_deref() == Some("1");
        Style { color, ascii }
    }

    pub(crate) fn stdout() -> Self {
        Self::detect(
            &|name| std::env::var(name).ok(),
            std::io::stdout().is_terminal(),
        )
    }

    pub(crate) fn stderr() -> Self {
        Self::detect(
            &|name| std::env::var(name).ok(),
            std::io::stderr().is_terminal(),
        )
    }

    fn paint(self, symbol: &str, ascii: &str, code: &str) -> String {
        let text = if self.ascii { ascii } else { symbol };
        if self.color && !code.is_empty() {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }

    pub(crate) fn fail(self) -> String {
        self.paint("✗", "FAIL", "31")
    }
    pub(crate) fn warn(self) -> String {
        self.paint("⚠", "WARN", "33")
    }
    pub(crate) fn next(self) -> String {
        self.paint("→", "->", "2")
    }
    // Permission notices use it in builds with private hosting.
    #[allow(dead_code)]
    pub(crate) fn notice(self) -> String {
        self.paint("🔐", "NOTE", "")
    }
}

/// Ends the first line as a sentence. The case is left alone: a line may
/// start with a folder name, and changing it would name a different folder.
fn sentence(line: &str) -> String {
    let mut text = line.to_owned();
    if text.is_empty() {
        return text;
    }
    if !text.ends_with(['.', '?', '!', ':']) {
        text.push('.');
    }
    text
}

/// The stderr text for a failed command.
///
/// A person gets `✗ sentence`, indented detail lines and the `→` next step.
/// Scripts and agents keep the exact `vhalla: message` form they already parse.
pub(crate) fn render_error(error: &str, audience: Audience, style: Style) -> String {
    if audience != Audience::Human {
        return format!("vhalla: {error}\n");
    }
    let error = plain_refusal(error).unwrap_or(error);
    // Some commands answer a wrong subcommand with their usage lines. Keep
    // them exactly as written so they can be copied.
    let first = error.lines().next().unwrap_or_default();
    if first.starts_with("vhalla ") || first.starts_with("usage: ") {
        let mut text = format!(
            "{} That isn't a command vhalla knows. Usage:\n",
            style.fail()
        );
        for line in error.lines() {
            text.push_str(&format!("  {line}\n"));
        }
        return text;
    }
    let mut lines = error.lines();
    let mut text = format!(
        "{} {}\n",
        style.fail(),
        sentence(lines.next().unwrap_or_default())
    );
    for line in lines {
        if let Some(next) = line.strip_prefix("→ ") {
            text.push_str(&format!("{} {next}\n", style.next()));
        } else if line.trim().is_empty() {
            continue;
        } else {
            text.push_str(&format!("  {}\n", line.trim_start()));
        }
    }
    text
}

/// Plain words for the fixed refusal lines private rooms print. Scripts and
/// agents keep the exact line; only people see the translation.
fn plain_refusal(error: &str) -> Option<&'static str> {
    #[cfg(all(unix, feature = "experimental-private"))]
    if let Some(text) = crate::private_host::plain_refusal(error)
        .or_else(|| crate::private_gateway::plain_refusal(error))
    {
        return Some(text);
    }
    #[cfg(feature = "experimental-private")]
    if let Some(text) = crate::private_rooms::plain_refusal(error) {
        return Some(text);
    }
    let _ = error;
    None
}

pub(crate) fn report_error(error: &str) {
    use std::io::Write;
    let text = render_error(error, audience(), Style::stderr());
    let _ = std::io::stderr().write_all(text.as_bytes());
}

/// Commands `vhalla` knows by name in any build. Builds without a feature
/// still answer its command with a pointer to the feature.
pub(crate) const COMMANDS: &[&str] = &[
    "commands",
    "demo",
    "doctor",
    "experimental",
    "help",
    "identity",
    "menubar",
    "outputs",
    "private",
    "private-gateway",
    "private-host",
    "public",
    "rooms",
    "social",
    "status",
    "support",
    "tui",
];

/// Optimal string alignment distance: edits plus adjacent transpositions.
fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[a.len()][b.len()]
}

/// The usage error for a first argument that names no command.
pub(crate) fn unknown_command(input: &str) -> String {
    let suggestion = COMMANDS
        .iter()
        .map(|command| {
            (
                (
                    distance(input, command),
                    command.len().abs_diff(input.len()),
                ),
                *command,
            )
        })
        .filter(|((score, _), _)| *score <= 2)
        .min()
        .map(|(_, command)| command);
    match suggestion {
        Some(command) => {
            format!("Unknown command \"{input}\". Did you mean \"{command}\"?\n→ vhalla --help")
        }
        None => format!("Unknown command \"{input}\".\n→ vhalla --help"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn errors_keep_folder_case_and_usage_lines_verbatim() {
        let plain = Style {
            color: false,
            ascii: false,
        };
        assert_eq!(
            render_error(
                "me already exists\n→ vhalla identity init NEW_DIR",
                Audience::Human,
                plain
            ),
            "✗ me already exists.\n→ vhalla identity init NEW_DIR\n"
        );
        assert_eq!(
            render_error("vhalla private x ID\n  --flag VALUE", Audience::Human, plain),
            "✗ That isn't a command vhalla knows. Usage:\n  vhalla private x ID\n    --flag VALUE\n"
        );
    }

    use super::*;
    use std::collections::BTreeMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    const PLAIN: Style = Style {
        color: false,
        ascii: false,
    };

    #[test]
    fn audience_follows_the_shared_rule() {
        assert_eq!(detect(&env(&[]), true), Audience::Human);
        assert_eq!(detect(&env(&[]), false), Audience::Quiet);
        assert_eq!(detect(&env(&[("CLAUDECODE", "1")]), true), Audience::Agent);
        assert_eq!(detect(&env(&[("CODEX_HOME", "/x")]), true), Audience::Human);
        assert_eq!(
            detect(
                &env(&[("CLAUDECODE", "1"), ("HRANESS_AUDIENCE", "human")]),
                false
            ),
            Audience::Human
        );
        assert_eq!(
            detect(&env(&[("HRANESS_AUDIENCE", "off")]), true),
            Audience::Quiet
        );
    }

    #[test]
    fn style_respects_no_color_dumb_terminals_and_locale() {
        let utf8 = [("LANG", "en_US.UTF-8")];
        assert_eq!(Style::detect(&env(&utf8), true).fail(), "\x1b[31m✗\x1b[0m");
        let no_color = Style::detect(&env(&[("LANG", "en_US.UTF-8"), ("NO_COLOR", "1")]), true);
        assert_eq!(no_color.fail(), "✗");
        let dumb = Style::detect(&env(&[("LANG", "en_US.UTF-8"), ("TERM", "dumb")]), true);
        assert_eq!((dumb.fail(), dumb.next()), ("FAIL".into(), "->".into()));
        assert_eq!(Style::detect(&env(&[]), false).warn(), "WARN");
        assert_eq!(Style::detect(&env(&[]), false).notice(), "NOTE");
    }

    #[test]
    fn people_get_a_sentence_detail_and_next_step() {
        assert_eq!(
            render_error(
                "local relay bind refused\nKeep the host folder.\n→ vhalla private-host status HOME",
                Audience::Human,
                PLAIN
            ),
            "✗ local relay bind refused.\n  Keep the host folder.\n→ vhalla private-host status HOME\n"
        );
    }

    #[test]
    fn scripts_and_agents_keep_the_prefixed_line() {
        for audience in [Audience::Agent, Audience::Quiet] {
            assert_eq!(
                render_error("too many arguments (maximum 64)", audience, PLAIN),
                "vhalla: too many arguments (maximum 64)\n"
            );
        }
    }

    #[test]
    fn unknown_commands_suggest_the_closest_one() {
        assert_eq!(
            unknown_command("idenity"),
            "Unknown command \"idenity\". Did you mean \"identity\"?\n→ vhalla --help"
        );
        assert_eq!(
            unknown_command("zzzzzzzzz"),
            "Unknown command \"zzzzzzzzz\".\n→ vhalla --help"
        );
    }
}
