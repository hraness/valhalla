//! The committed vector files are the oracle: every one parses, renders back
//! to identical text, and replays to identical digests and quantities.

use std::fs;
use std::path::Path;

use witness_restatement::vectors::{parse, render, replay};

#[test]
fn committed_vectors_replay_exactly() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors");
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "txt"))
        .collect();
    files.sort();
    assert!(files.len() >= 28, "{} vector files", files.len());
    for path in files {
        let text = fs::read_to_string(&path).unwrap();
        let vector = parse(&text).unwrap_or_else(|| panic!("{}: parse", path.display()));
        assert_eq!(render(&vector), text, "{}: render", path.display());
        let observed =
            replay(&vector).unwrap_or_else(|error| panic!("{}: {error:?}", path.display()));
        assert_eq!(observed, vector, "{}: replay", path.display());
    }
}
