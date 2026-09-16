//! Loads the committed corpus vectors.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use vhalla_witness::vectors::{parse, Vector};

/// Every committed vector in file order.
pub fn vectors() -> Vec<(PathBuf, Vector)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "txt"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let text = fs::read_to_string(&path).unwrap();
            let vector = parse(&text).unwrap_or_else(|| panic!("{}: parse", path.display()));
            (path, vector)
        })
        .collect()
}

/// The vector with the given id.
pub fn vector(id: &str) -> Vector {
    vectors()
        .into_iter()
        .map(|(_, vector)| vector)
        .find(|vector| vector.id == id)
        .unwrap_or_else(|| panic!("no vector {id}"))
}
