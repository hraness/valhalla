//! Replays every committed vector file and renders the observed values, so a
//! native run and a wasm32 run can be compared byte for byte, and both can be
//! compared with the committed expectations.

use witness_restatement::vectors::{parse, render, replay};

/// The committed vector files, embedded at compile time.
pub const VECTORS: &[(&str, &str)] = &include!(concat!(env!("CARGO_MANIFEST_DIR"), "/vectors.in"));

/// Renders the replay of every vector in file order, separated by a blank
/// line, or the replay error rendered as text.
#[must_use]
pub fn run_corpus() -> String {
    let mut out = String::new();
    for (name, text) in VECTORS {
        out.push_str("file: ");
        out.push_str(name);
        out.push('\n');
        match parse(text) {
            None => out.push_str("parse: failed\n"),
            Some(vector) => match replay(&vector) {
                Ok(observed) => out.push_str(&render(&observed)),
                Err(error) => {
                    out.push_str("replay: ");
                    out.push_str(&format!("{error:?}"));
                    out.push('\n');
                }
            },
        }
        out.push('\n');
    }
    out
}

/// The committed expectations in the same shape as [`run_corpus`].
#[must_use]
pub fn expected_corpus() -> String {
    let mut out = String::new();
    for (name, text) in VECTORS {
        out.push_str("file: ");
        out.push_str(name);
        out.push('\n');
        out.push_str(text);
        out.push('\n');
    }
    out
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use wasm_bindgen::prelude::wasm_bindgen;

    /// The replay rendered as text, for the Node driver.
    #[wasm_bindgen]
    pub fn run_corpus() -> String {
        super::run_corpus()
    }

    /// The committed expectations, for the Node driver.
    #[wasm_bindgen]
    pub fn expected_corpus() -> String {
        super::expected_corpus()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn native_replay_matches_committed_vectors() {
        assert!(super::VECTORS.len() >= 28);
        assert_eq!(super::run_corpus(), super::expected_corpus());
    }
}
