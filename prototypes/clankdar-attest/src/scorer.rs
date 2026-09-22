//! Port of the Clankdar typed answer scorer (`clankdar-score-v2`).
//!
//! The TypeScript suite remains canonical; this module mirrors
//! `ladder/family.ts` semantics so a receipt can be rescored offline. Keep the
//! family-to-format table and every canonicalization rule in sync with the
//! canonical implementation — the receipt protocol depends on both sides
//! agreeing exactly.

/// Scorer contract version mirrored from `ladder/family.ts`.
pub const SCORER_VERSION: &str = "clankdar-score-v2";

/// Maximum accepted answer length, mirrored from `MAX_ANSWER_LENGTH`.
pub const MAX_ANSWER_LENGTH: usize = 65_536;

/// Typed answer formats understood by the scorer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnswerFormat {
    /// Free text with whitespace normalized.
    Text,
    /// An optionally signed integer normalized to shortest decimal form.
    Integer,
    /// A rectangular grid of single digits.
    Grid,
    /// A nonempty string of `0`/`1`.
    Bits,
    /// Single-letter tokens separated by whitespace or commas.
    Tokens,
    /// `x=knight|knave` assignments with distinct letters.
    Assignments,
}

impl AnswerFormat {
    /// The wire spelling used inside a receipt verdict.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Integer => "integer",
            Self::Grid => "grid",
            Self::Bits => "bits",
            Self::Tokens => "tokens",
            Self::Assignments => "assignments",
        }
    }

    /// Parse a wire format name.
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "text" => Self::Text,
            "integer" => Self::Integer,
            "grid" => Self::Grid,
            "bits" => Self::Bits,
            "tokens" => Self::Tokens,
            "assignments" => Self::Assignments,
            _ => return None,
        })
    }
}

/// The declared answer format for a generated family, mirrored from
/// `answerFormat` in `ladder/family.ts`.
pub fn answer_format(family: &str) -> AnswerFormat {
    match family {
        "arithmetic" | "sequence" | "gridpath" | "registervm" | "cryptarithm" | "relayvm"
        | "algal" => AnswerFormat::Integer,
        "sudoku" | "gridxf" => AnswerFormat::Grid,
        "automata" | "sat" | "satcheck" | "bitmatrix" | "bitcircuit" | "autostep" => {
            AnswerFormat::Bits
        }
        "ordering" => AnswerFormat::Tokens,
        "knights" => AnswerFormat::Assignments,
        _ => AnswerFormat::Text,
    }
}

/// `normalize`: trim and collapse whitespace runs without touching signs,
/// punctuation, case, or token boundaries.
fn normalize(answer: &str) -> String {
    answer.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn is_separator(c: char) -> bool {
    c.is_whitespace() || c == ','
}

/// Canonicalize an answer for comparison; `None` means the answer is not in
/// the declared format. Mirrors `canonicalAnswer` exactly.
pub fn canonical_answer(answer: &str, format: AnswerFormat) -> Option<String> {
    if answer.len() > MAX_ANSWER_LENGTH
        || answer.chars().any(|c| {
            (c as u32) < 0x09
                || (0x0b..0x0d).contains(&(c as u32))
                || (0x0e..0x20).contains(&(c as u32))
                || c as u32 == 0x7f
        })
    {
        return None;
    }
    let text = answer.trim();
    if text.is_empty() {
        return None;
    }
    match format {
        AnswerFormat::Text => Some(normalize(text)),
        AnswerFormat::Integer => canonical_integer(text),
        AnswerFormat::Bits => {
            if !text.is_empty() && text.chars().all(|c| c == '0' || c == '1') {
                Some(text.to_string())
            } else {
                None
            }
        }
        AnswerFormat::Tokens => canonical_tokens(text),
        AnswerFormat::Assignments => canonical_assignments(text),
        AnswerFormat::Grid => canonical_grid(text),
    }
}

/// `^[+-]?\d+$` then `BigInt(text).toString()`: strip a leading `+`, strip
/// leading zeros, and collapse `-0` to `0`.
fn canonical_integer(text: &str) -> Option<String> {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let trimmed = digits.trim_start_matches('0');
    if trimmed.is_empty() {
        return Some("0".to_string());
    }
    Some(if negative {
        format!("-{trimmed}")
    } else {
        trimmed.to_string()
    })
}

/// `/^[a-z](?:[\s,]+[a-z])*$/i` then uppercase each token.
fn canonical_tokens(text: &str) -> Option<String> {
    let parts: Vec<&str> = text.split(is_separator).filter(|p| !p.is_empty()).collect();
    // First and last characters must be letters, and every part a single
    // letter — equivalently, a leading/trailing separator or an adjacent pair
    // of letters rejects the shape.
    if !text.chars().next()?.is_ascii_alphabetic() || !text.chars().last()?.is_ascii_alphabetic() {
        return None;
    }
    if parts.is_empty()
        || parts.len() != text.chars().filter(|c| c.is_ascii_alphabetic()).count()
        || !parts.iter().all(|p| p.chars().count() == 1)
        || !text
            .chars()
            .all(|c| c.is_ascii_alphabetic() || is_separator(c))
    {
        return None;
    }
    Some(
        parts
            .iter()
            .map(|p| p.to_ascii_uppercase())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// `x=knight|knave` rows with distinct letters, whitespace folded around `=`.
fn canonical_assignments(text: &str) -> Option<String> {
    let mut folded = String::with_capacity(text.len());
    let lowered = text.to_lowercase();
    let mut chars = lowered.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '=' {
            while folded.ends_with(char::is_whitespace) {
                folded.pop();
            }
            folded.push('=');
            while chars.peek().is_some_and(|n| n.is_whitespace()) {
                chars.next();
            }
        } else {
            folded.push(c);
        }
    }
    let mut letters = Vec::new();
    let mut parts = Vec::new();
    for part in folded.split(is_separator) {
        if part.is_empty() {
            continue;
        }
        let (letter, role) = part.split_once('=')?;
        if letter.chars().count() != 1
            || !letter.chars().next()?.is_ascii_lowercase()
            || (role != "knight" && role != "knave")
        {
            return None;
        }
        letters.push(letter.chars().next()?);
        parts.push(part);
    }
    if parts.is_empty()
        || letters
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != letters.len()
    {
        return None;
    }
    // A leading or trailing separator produces an empty edge part in the JS
    // regex semantics; the loop above dropped empties, so re-check the edges.
    if !folded.chars().next()?.is_ascii_lowercase()
        || !folded.ends_with("knight") && !folded.ends_with("knave")
    {
        return None;
    }
    Some(parts.join(" "))
}

/// Rows are single digits separated by space/tab runs, delimited by `/`
/// (with surrounding whitespace absorbed) or newlines. Canonical form is the
/// compact JSON array-of-arrays.
fn canonical_grid(text: &str) -> Option<String> {
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    // JS `split(/\s*\/\s*|\n/)`: a `/` with surrounding whitespace — newlines
    // included — is a single delimiter; a bare `\n` is another. Mark each
    // slash sandwich with NUL first so adjacent newlines merge into it.
    let chars: Vec<char> = normalized.chars().collect();
    let mut marked = String::with_capacity(normalized.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '/' {
            while marked.ends_with(|c: char| c.is_whitespace()) {
                marked.pop();
            }
            marked.push('\0');
            i += 1;
            while i < chars.len() && chars[i].is_whitespace() {
                i += 1;
            }
        } else {
            marked.push(chars[i]);
            i += 1;
        }
    }
    let mut grid: Vec<Vec<&str>> = Vec::new();
    for row in marked.split(['\0', '\n']).map(|r| r.trim()) {
        let cells: Vec<&str> = row.split([' ', '\t']).filter(|p| !p.is_empty()).collect();
        // `^[0-9](?:[ \t]+[0-9])*$`: every cell is exactly one digit and the
        // row is nonempty — split/filter also drops empty cells from leading
        // or trailing spaces, so reject rows with stray non-digit input.
        if cells.is_empty()
            || !cells
                .iter()
                .all(|p| p.len() == 1 && p.bytes().next().is_some_and(|b| b.is_ascii_digit()))
            || !row
                .chars()
                .all(|c| c.is_ascii_digit() || c == ' ' || c == '\t')
        {
            return None;
        }
        grid.push(cells);
    }
    let width = grid.first()?.len();
    if !grid.iter().all(|row| row.len() == width) {
        return None;
    }
    let mut out = String::from("[");
    for (r, row) in grid.iter().enumerate() {
        if r > 0 {
            out.push(',');
        }
        out.push('[');
        for (c, cell) in row.iter().enumerate() {
            if c > 0 {
                out.push(',');
            }
            out.push('"');
            out.push_str(cell);
            out.push('"');
        }
        out.push(']');
    }
    out.push(']');
    Some(out)
}

/// `answersMatch`: both sides canonicalize and agree.
pub fn answers_match(expected: &str, got: &str, format: AnswerFormat) -> bool {
    let canonical = canonical_answer(expected, format);
    canonical.is_some() && canonical == canonical_answer(got, format)
}

/// `extractFinalAnswer`: pull the trailing answer out of a chatty response.
pub fn extract_final_answer(response: &str, format: AnswerFormat) -> String {
    if response.len() > MAX_ANSWER_LENGTH {
        return String::new();
    }
    let normalized = response.trim().replace("\r\n", "\n").replace('\r', "\n");
    let mut lines: Vec<&str> = normalized.split('\n').collect();
    if lines.last().is_some_and(|l| l.trim() == "```") {
        lines.pop();
        // `/^```(?:[a-z]+)?\s*$/i`: optional language tag, nothing else.
        if let Some(start) = lines.iter().rposition(|l| {
            let t = l.trim();
            t.starts_with("```") && t[3..].chars().all(|c| c.is_ascii_alphabetic())
        }) {
            return lines[start + 1..].join("\n").trim().to_string();
        }
        return String::new();
    }
    if format == AnswerFormat::Grid {
        let mut tail: Vec<&str> = Vec::new();
        while let Some(last) = lines.last() {
            if !last.is_empty()
                && last
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == ' ' || c == '\t' || c == '/')
            {
                tail.push(lines.pop().unwrap());
            } else {
                break;
            }
        }
        tail.reverse();
        return tail.join("\n");
    }
    strip_answer_decorations(lines.last().copied().unwrap_or("").trim()).to_string()
}

/// `/^(?:final answer|answer)\s*:\s*/i` — the colon is required, otherwise
/// the line is returned unchanged.
fn strip_answer_prefix(line: &str) -> &str {
    for prefix in ["final answer", "answer"] {
        if line.len() >= prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(prefix) {
            let rest = line[prefix.len()..].trim_start();
            return match rest.strip_prefix(':') {
                Some(after) => after.trim_start(),
                None => line,
            };
        }
    }
    line
}

/// `/^(?:final answer|answer)\s*:\s*/i`, `/^\*\*(.+)\*\*$/`, `/^`([^`]+)`$/`.
fn strip_answer_decorations(line: &str) -> &str {
    let line = strip_answer_prefix(line);
    let line = match line.strip_prefix("**").and_then(|s| s.strip_suffix("**")) {
        Some(inner) if !inner.is_empty() => inner,
        _ => line,
    };
    match line.strip_prefix('`').and_then(|s| s.strip_suffix('`')) {
        Some(inner) if !inner.is_empty() && !inner.contains('`') => inner,
        _ => line,
    }
}

/// `scoreAnswer` result mirrored for parity with the canonical scorer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Score {
    /// The raw response is the canonical expected answer.
    pub pass: bool,
    /// The extracted final answer matches even when `pass` does not.
    pub final_answer_match: bool,
    /// Only the extracted answer matched.
    pub format_only: bool,
}

/// `scoreAnswer` mirrored from `ladder/family.ts`.
pub fn score_answer(expected: &str, response: &str, format: AnswerFormat) -> Score {
    let pass = answers_match(expected, response, format);
    let final_answer_match =
        pass || answers_match(expected, &extract_final_answer(response, format), format);
    Score {
        pass,
        final_answer_match,
        format_only: !pass && final_answer_match,
    }
}
