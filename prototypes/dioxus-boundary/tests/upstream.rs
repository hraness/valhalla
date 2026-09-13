//! Source-derived reproductions, not an executed WebView or a renderer patch.
use std::{
    cell::RefCell,
    fs,
    sync::atomic::{AtomicU64, Ordering},
};
thread_local! { static OPENS:RefCell<Vec<String>>=const{RefCell::new(Vec::new())}; static ROOT:RefCell<std::path::PathBuf>=const{RefCell::new(std::path::PathBuf::new())}; }
fn record_external(url: &str) -> Result<(), std::convert::Infallible> {
    OPENS.with(|v| v.borrow_mut().push(url.to_owned()));
    Ok(())
}
fn get_asset_root() -> std::path::PathBuf {
    ROOT.with(|v| v.borrow().clone())
}
include!("../upstream/extracted.rs");
#[test]
fn configured_deny_callback_does_not_stop_original_external_browser_open() {
    for url in [
        "https://example.invalid/",
        "http://example.invalid/",
        "mailto:owner@example.invalid",
    ] {
        OPENS.with(|v| v.borrow_mut().clear());
        assert!(!original_navigation(
            url.to_owned(),
            &AtomicBool::new(true),
            Some(Box::new(|_| false))
        ));
        assert_eq!(OPENS.with(|v| v.borrow().clone()), vec![url]);
    }
}
#[test]
fn original_scheme_prefix_is_broader_than_exact_document_origin() {
    assert!(original_navigation(
        "http://dioxus.evil.invalid/".into(),
        &AtomicBool::new(false),
        Some(Box::new(|_| false))
    ));
}
#[test]
fn original_absolute_and_traversal_assets_escape_bundle_and_bad_percent_panics() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "vhalla-boundary-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let bundle = root.join("bundle");
    fs::create_dir(&bundle).unwrap();
    fs::create_dir(bundle.join("assets")).unwrap();
    ROOT.with(|v| *v.borrow_mut() = bundle.clone());
    let sentinel = root.join("sentinel.txt");
    fs::write(&sentinel, b"owned sentinel only").unwrap();
    assert_eq!(
        resolve_asset_path_from_filesystem(sentinel.to_str().unwrap()).unwrap(),
        sentinel
    );
    let traversal =
        resolve_asset_path_from_filesystem("/assets/%2e%2e/%2e%2e/sentinel.txt").unwrap();
    assert_eq!(
        fs::canonicalize(traversal).unwrap(),
        fs::canonicalize(&sentinel).unwrap()
    );
    assert!(std::panic::catch_unwind(|| resolve_asset_path_from_filesystem("/%FF")).is_err());
    // Check reachable resolution only. No credential/private fixture is read.
    fs::remove_dir_all(root).unwrap();
}
