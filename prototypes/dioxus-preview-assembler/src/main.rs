#![forbid(unsafe_code)]

//! Assemble an immutable Dioxus web preview from exact generated artifacts.
//!
//! This tool owns the shell and admission manifest only. It never authors or
//! interprets application JavaScript: the binding JS and snippets are copied
//! as generated output from the caller-selected, pinned wasm-bindgen build.

use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_FILES: usize = 512;

fn usage() -> ! {
    eprintln!("usage: vhalla-preview-assembler <output-dir> <wasm-bindgen-dir> <stylesheet>");
    std::process::exit(2);
}

fn checked_file(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input must be a regular file under the byte limit",
        ));
    }
    Ok(())
}

fn validate_tree(source: &Path, files: &mut usize) -> io::Result<()> {
    for entry in fs::read_dir(source)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "symlinked generated asset",
            ));
        }
        if metadata.is_dir() {
            validate_tree(&path, files)?;
        } else {
            checked_file(&path)?;
            *files = files.saturating_add(1);
            if *files > MAX_FILES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "too many assets",
                ));
            }
        }
    }
    Ok(())
}

fn copy_tree(
    source: &Path,
    destination: &Path,
    root: &Path,
    entries: &mut Vec<(String, u64, String)>,
) -> io::Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "non-UTF-8 generated asset name",
            )
        })?;
        if name == "." || name == ".." || name.contains('/') || name.contains('\\') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsafe asset name",
            ));
        }
        let target = destination.join(name);
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "symlinked asset",
            ));
        }
        if metadata.is_dir() {
            fs::create_dir(&target)?;
            copy_tree(&path, &target, root, entries)?;
        } else {
            checked_file(&path)?;
            if entries.len() == MAX_FILES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "too many assets",
                ));
            }
            fs::copy(&path, &target)?;
            let relative = target
                .strip_prefix(root)
                .unwrap_or(&target)
                .to_string_lossy()
                .replace('\\', "/");
            let digest = digest_file(&target)?;
            entries.push((relative, metadata.len(), digest));
        }
    }
    Ok(())
}

fn digest_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn main() -> io::Result<()> {
    let mut arguments = env::args_os().skip(1);
    let output = arguments
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| usage());
    let generated = arguments
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| usage());
    let stylesheet = arguments
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| usage());
    if arguments.next().is_some() {
        usage();
    }
    let generated_meta = fs::symlink_metadata(&generated)?;
    if !generated_meta.is_dir() || generated_meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "generated input must be a directory",
        ));
    }
    checked_file(&stylesheet)?;
    let mut generated_files = 0;
    validate_tree(&generated, &mut generated_files)?;
    // Refuse stale output instead of silently mixing artifacts from builds.
    fs::create_dir(&output)?;
    let mut entries = Vec::new();
    // Copy generated roots and nested snippets into the fresh output closure.
    copy_tree(&generated, &output, &output, &mut entries)?;
    fs::copy(&stylesheet, output.join("screen.css"))?;
    // The shell and stylesheet are owned by this assembler. A prior generated
    // copy may exist in a tool output directory, but it must not survive as a
    // second stale row in the provenance manifest.
    entries.retain(|(name, _, _)| name != "index.html" && name != "screen.css");
    entries.push((
        "screen.css".into(),
        fs::metadata(&stylesheet)?.len(),
        digest_file(&output.join("screen.css"))?,
    ));

    let mut javascript_candidates = entries
        .iter()
        .filter(|(name, _, _)| name.ends_with(".js") && !name.contains("/"))
        .map(|(name, _, _)| name.clone());
    let javascript = javascript_candidates.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing root wasm-bindgen JavaScript",
        )
    })?;
    if javascript_candidates.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "multiple root wasm-bindgen JavaScript files",
        ));
    }
    let wasm_count = entries
        .iter()
        .filter(|(name, _, _)| name.ends_with("_bg.wasm"))
        .count();
    if wasm_count != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected exactly one wasm-bindgen WASM file",
        ));
    }
    let shell = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>vhalla (valhalla)</title><link rel=\"stylesheet\" href=\"screen.css\"></head><body><div id=\"main\"></div><script type=\"module\">import init from './{javascript}'; init();</script></body></html>\n"
    );
    fs::write(output.join("index.html"), shell)?;
    entries.push((
        "index.html".into(),
        fs::metadata(output.join("index.html"))?.len(),
        digest_file(&output.join("index.html"))?,
    ));
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let mut manifest = File::create(output.join("SHA256SUMS"))?;
    writeln!(manifest, "# vhalla (valhalla) generated web closure")?;
    writeln!(
        manifest,
        "# files={} max_file_bytes={MAX_FILE_BYTES}",
        entries.len()
    )?;
    for (name, bytes, digest) in entries {
        writeln!(manifest, "{digest}  {bytes}  {name}")?;
    }
    Ok(())
}
