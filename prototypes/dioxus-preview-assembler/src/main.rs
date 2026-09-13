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

fn checked_asset_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.chars().any(|character| {
            character.is_control() || matches!(character, '\'' | '"' | '<' | '>' | '&')
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsafe asset name",
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
        checked_asset_name(name)?;
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

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0] as u32;
        let second = chunk.get(1).copied().unwrap_or(0) as u32;
        let third = chunk.get(2).copied().unwrap_or(0) as u32;
        let value = (first << 16) | (second << 8) | third;
        output.push(TABLE[((value >> 18) & 0x3f) as usize] as char);
        output.push(TABLE[((value >> 12) & 0x3f) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[((value >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(value & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    output
}

fn web_shell(javascript: &str) -> String {
    let bootstrap = format!("import init from './{javascript}'; init();");
    let mut hash = Sha256::new();
    hash.update(bootstrap.as_bytes());
    let hash = base64(&hash.finalize());
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; script-src 'self' 'wasm-unsafe-eval' 'sha256-{hash}'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'\"><title>vhalla (valhalla)</title><link rel=\"stylesheet\" href=\"screen.css\"></head><body><div id=\"main\"></div><script type=\"module\">{bootstrap}</script></body></html>\n"
    )
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
    let shell = web_shell(&javascript);
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

#[cfg(test)]
mod tests {
    use super::{checked_asset_name, web_shell};

    #[test]
    fn shell_has_hash_bound_csp_and_no_inline_fallback() {
        let shell = web_shell("vhalla_bg.js");
        assert!(shell.contains("script-src 'self' 'wasm-unsafe-eval' 'sha256-"));
        assert!(shell.contains("img-src 'self' data:"));
        assert!(!shell.contains("unsafe-inline"));
        assert_eq!(shell.matches("<div id=\"main\">").count(), 1);
        assert_eq!(shell.matches("<script type=\"module\">").count(), 1);
    }

    #[test]
    fn shell_filename_cannot_become_markup() {
        for name in [
            "bad'file.js",
            "bad\"file.js",
            "bad<script.js",
            "bad&file.js",
        ] {
            assert!(checked_asset_name(name).is_err(), "{name}");
        }
        assert!(checked_asset_name("vhalla_bg.js").is_ok());
    }
}
