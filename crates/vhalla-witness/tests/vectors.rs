//! The committed vector files are the oracle: every one renders back to its
//! own text and replays to identical digests and quantities.

mod common;

use vhalla_witness::vectors::{render, replay};

#[test]
fn committed_vectors_replay_exactly() {
    let vectors = common::vectors();
    assert!(vectors.len() >= 28, "{} vector files", vectors.len());
    for (path, vector) in vectors {
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(render(&vector), text, "{}: render", path.display());
        let observed =
            replay(&vector).unwrap_or_else(|error| panic!("{}: {error:?}", path.display()));
        assert_eq!(observed, vector, "{}: replay", path.display());
    }
}
