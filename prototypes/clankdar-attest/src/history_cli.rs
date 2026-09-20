//! Explicit local recent-result inspection; does not connect to a public service.
use super::Args;
use std::path::Path;
#[cfg(unix)]
use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use valhalla_clankdar_attest_prototype::{
    history::{check_history, HistoryCursor, HistoryExpectation},
    GatePolicy, HoldoutPool,
};

#[path = "history_oracle.rs"]
mod history_oracle;

const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_FILES: usize = 64;

#[cfg(unix)]
pub(super) fn read(path: &str, limit: usize) -> Result<Vec<u8>, String> {
    // Inspect the opened descriptor, not a path that could be swapped to a
    // FIFO after metadata() and then block in open(). Do not follow symlinks.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_NOCTTY)
        .open(path)
        .map_err(|_| "cannot open nonsymlink history input file")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect opened history input")?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("history inputs must be bounded regular files".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read bounded history input")?;
    if bytes.len() > limit {
        return Err("history input grew beyond its bound".into());
    }
    Ok(bytes)
}

#[cfg(not(unix))]
pub(super) fn read(_: &str, _: usize) -> Result<Vec<u8>, String> {
    Err("history input inspection requires Unix descriptor guards".into())
}

fn json_file(path: &str, limit: usize) -> Result<serde_json::Value, String> {
    serde_json::from_slice(&read(path, limit)?)
        .map_err(|_| "history configuration is not valid bounded JSON".into())
}

fn required<'a>(args: &'a Args, name: &str) -> Result<&'a str, String> {
    args.flags
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("history recent requires --{name}"))
}

pub(super) fn run(args: &Args) -> Result<bool, String> {
    for (name, values) in &args.flag_lists {
        if ![
            "issuer",
            "subject",
            "context",
            "policy",
            "max-age",
            "clock-skew",
            "now",
            "clankdar",
            "bun",
            "pool",
            "limit",
            "cursor",
        ]
        .contains(&name.as_str())
        {
            return Err(format!("unsupported history option --{name}"));
        }
        if name != "pool" && values.len() != 1 {
            return Err(format!("history --{name} must appear exactly once"));
        }
    }
    if args.switches.iter().any(|s| s != "no-context") {
        return Err("unsupported history switch".into());
    }
    if args.positional.first().map(String::as_str) != Some("recent")
        || !(2..=MAX_FILES + 1).contains(&args.positional.len())
    {
        return Err("history recent requires 1–64 saved admission or badge files".into());
    }
    let context = match (
        args.flags.get("context"),
        args.switches.contains("no-context"),
    ) {
        (Some(value), false) => Some(value.clone()),
        (None, true) => None,
        _ => return Err("choose exactly one of --context TEXT or --no-context".into()),
    };
    let policy = GatePolicy::parse(&json_file(required(args, "policy")?, 16 * 1024)?)
        .map_err(|e| e.to_string())?;
    let expected = HistoryExpectation {
        issuer_key: required(args, "issuer")?.into(),
        subject_key: required(args, "subject")?.into(),
        context,
        policy,
        max_age_seconds: required(args, "max-age")?
            .parse()
            .map_err(|_| "--max-age must be a nonnegative integer in seconds")?,
        future_skew_seconds: args
            .flags
            .get("clock-skew")
            .map(String::as_str)
            .unwrap_or("60")
            .parse()
            .map_err(|_| "--clock-skew must be an integer in seconds")?,
    };
    let now = match args.flags.get("now") {
        Some(value) => {
            OffsetDateTime::parse(value, &Rfc3339).map_err(|_| "--now must be an RFC3339 time")?
        }
        None => OffsetDateTime::now_utc(),
    };
    let limit: usize = args
        .flags
        .get("limit")
        .map(String::as_str)
        .unwrap_or("16")
        .parse()
        .map_err(|_| "invalid --limit")?;
    if !(1..=16).contains(&limit) {
        return Err("--limit must be 1–16".into());
    }
    let cursor = args
        .flags
        .get("cursor")
        .map(|raw| HistoryCursor::decode(raw).map_err(|e| e.to_string()))
        .transpose()?;
    if cursor.is_some() && !args.flags.contains_key("now") {
        return Err("continuing a history cursor requires the prior report's exact --now value and the same inputs".into());
    }
    let mut inputs = Vec::new();
    let mut total = 0usize;
    for path in &args.positional[1..] {
        let bytes = read(path, MAX_FILE_BYTES)?;
        total = total
            .checked_add(bytes.len())
            .filter(|sum| *sum <= MAX_TOTAL_BYTES)
            .ok_or("history inputs exceed 4 MiB total")?;
        inputs.push(bytes);
    }
    let mut pools = Vec::new();
    if let Some(paths) = args.flag_lists.get("pool") {
        if paths.len() > 4 {
            return Err("at most four disclosed holdout pools may be supplied".into());
        }
        for path in paths {
            pools
                .push(HoldoutPool::parse(&json_file(path, 64 * 1024)?).map_err(|e| e.to_string())?);
        }
    }
    let directory = Path::new(required(args, "clankdar")?);
    // The executable and source directory are local caller configuration, never
    // a URL/path learned from a puzzle or signed artifact. No credentials pass.
    let oracle = history_oracle::LocalOracle::new(Path::new(required(args, "bun")?), directory)?;
    let refs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
    let snapshot = check_history(
        &refs,
        &expected,
        now,
        Some(&pools),
        |suite, family, tier, seed| oracle.instance(suite, family, tier, seed),
    )
    .map_err(|e| e.to_string())?;
    let page = snapshot
        .page(cursor.as_ref(), limit)
        .map_err(|e| e.to_string())?;
    let (subject_passes, subject_failures) = snapshot.subject_bound_outcomes();
    let report = serde_json::json!({
        "coverage": snapshot.coverage(),
        "expectedPolicy": expected.policy,
        "expectedContext": expected.context,
        "nextCursor": page.next().map(HistoryCursor::encode),
        "observedAt": snapshot.observed_at(),
        "snapshotHash": snapshot.snapshot_hash(),
        "duplicateCount": snapshot.duplicate_count(),
        "conflicts": snapshot.conflicts(),
        "subjectBoundOutcomes": {"pass": subject_passes, "fail": subject_failures},
        "rejected": snapshot.rejected(),
        "page": page,
        "scope": "Only supplied evidence under the selected local generator; no complete attempt history, model identity, intelligence rank or network authority is established."
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|_| "could not encode history report")?
    );
    Ok(snapshot.rejected().is_empty() && snapshot.conflicts() == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_implicit_scope_or_unknown_options() {
        for argv in [
            vec!["recent", "a.json", "--no-context", "--issuerr", "wrong"],
            vec!["recent", "a.json", "--context", "room", "--no-context"],
            vec!["recent", "a.json"],
        ] {
            let args =
                super::super::parse_args(&argv.into_iter().map(str::to_string).collect::<Vec<_>>())
                    .unwrap();
            assert!(run(&args).is_err());
        }
    }
    #[cfg(unix)]
    #[test]
    fn special_inputs_do_not_enter_json_parser() {
        assert!(read("/dev/null", MAX_FILE_BYTES).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn history_input_descriptor_rejects_symlinks_and_writerless_fifo() {
        use std::{
            fs,
            os::unix::fs::symlink,
            process::Command,
            time::{Duration, Instant},
        };
        let mut nonce = [0; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        let name: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let directory = std::env::temp_dir().join(format!("clankdar-input-test-{name}"));
        fs::create_dir(&directory).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        let regular = directory.join("receipt");
        fs::write(&regular, b"{}").unwrap();
        assert_eq!(read(regular.to_str().unwrap(), 2).unwrap(), b"{}");
        assert!(read(regular.to_str().unwrap(), 1).is_err());
        let linked = directory.join("linked");
        symlink(&regular, &linked).unwrap();
        assert!(read(linked.to_str().unwrap(), 2).is_err());
        let fifo = directory.join("fifo");
        assert!(Command::new("/usr/bin/mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        let started = Instant::now();
        assert!(read(fifo.to_str().unwrap(), 2).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(read(directory.to_str().unwrap(), 2).is_err());
    }
}
