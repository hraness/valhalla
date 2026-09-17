#![cfg(unix)]
//! `vhalla game replay` over the two frozen game session vectors.
//!
//! The binary is the reproducible user journey of the Platonik session
//! adapter: it holds no key, reads one bundle, and re-derives every checkpoint
//! from its own replay. These tests drive the built binary the way the other
//! CLI tests do, assert the committed checkpoint hashes appear in its output,
//! and assert that one flipped hex digit in one record ends the run with a
//! non-zero status.

use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf, process::Command};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path =
            std::env::temp_dir().join(format!("vhalla-game-{:032x}", u128::from_be_bytes(nonce)));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn child(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

const VECTORS: [&str; 2] = ["game-v1-session-replay.txt", "game-v1-session-live.txt"];

fn vector_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../vhalla-game-platonik/tests/vectors")
        .join(name)
}

fn replay(path: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .args(["game", "replay"])
        .arg(path)
        .output()
        .unwrap()
}

/// Every `key: value` field of a vector, in file order.
fn fields(text: &str) -> Vec<(&str, &str)> {
    text.lines()
        .filter_map(|line| line.split_once(": "))
        .collect()
}

#[test]
fn replaying_each_committed_vector_reproduces_its_checkpoints_and_receipt() {
    for name in VECTORS {
        let path = vector_path(name);
        let text = fs::read_to_string(&path).unwrap();
        let output = replay(&path);
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let mut seals = 0;
        for (key, value) in fields(&text) {
            if key.ends_with(".checkpoint_hash") {
                assert!(
                    stdout.contains(&format!("checkpoint {value} matched")),
                    "{name}: {key} {value} is not in\n{stdout}"
                );
                seals += 1;
            }
            if key == "session_key" {
                assert!(stdout.contains(&format!("session {value}")), "{name}");
            }
            if key == "receipt_hash" {
                assert!(stdout.contains(&format!("receipt {value}")), "{name}");
            }
        }
        assert!(seals > 0, "{name} seals at least once");
        assert!(
            stdout.contains("verified ") && stdout.contains(&format!("{seals} seals")),
            "{name}: {stdout}"
        );
        // Every record is reported, and nothing is reported twice.
        let records: usize = fields(&text)
            .into_iter()
            .find(|(key, _)| *key == "record_count")
            .unwrap()
            .1
            .parse()
            .unwrap();
        for index in 0..records {
            assert!(
                stdout.contains(&format!("record {index} ")),
                "{name}: record {index} is not reported"
            );
        }
    }
}

#[test]
fn one_flipped_hex_digit_in_one_record_fails_the_replay() {
    let temp = Temp::new();
    for name in VECTORS {
        let text = fs::read_to_string(vector_path(name)).unwrap();
        // Flip the last hex digit of the first record's bytes: the signature
        // no longer covers the body it is delivered with.
        let mut flipped = String::with_capacity(text.len());
        let mut done = false;
        for line in text.lines() {
            if !done && line.starts_with("record[0].record: ") {
                let (key, value) = line.split_once(": ").unwrap();
                let mut bytes: Vec<char> = value.chars().collect();
                let last = bytes.len() - 1;
                bytes[last] = if bytes[last] == '0' { '1' } else { '0' };
                flipped.push_str(key);
                flipped.push_str(": ");
                flipped.extend(bytes);
                done = true;
            } else {
                flipped.push_str(line);
            }
            flipped.push('\n');
        }
        assert!(done, "{name}: no record to flip");
        assert_ne!(flipped, text);
        let path = temp.child(name);
        fs::write(&path, &flipped).unwrap();
        let output = replay(&path);
        assert!(
            !output.status.success(),
            "{name}: a flipped record was accepted:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("vhalla: "),
            "{name}: the refusal is reported"
        );
    }
}

#[test]
fn a_bundle_that_is_not_a_bundle_is_refused() {
    let temp = Temp::new();
    let path = temp.child("not-a-bundle.txt");
    fs::write(&path, "id: nothing\n").unwrap();
    let output = replay(&path);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("game_manifest"));
}
