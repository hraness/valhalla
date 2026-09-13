// Extracted verbatim from DioxusLabs/dioxus v0.7.10; MIT OR Apache-2.0.
// Only webbrowser::open is replaced by the safe recording stub. The asset
// root getter is a test-owned dependency; no user path is read by the tests.
use std::{path::PathBuf,sync::atomic::AtomicBool};
type NavigationHandler=Box<dyn Fn(&str)->bool>;
fn original_navigation(var:String,page_loaded:&AtomicBool,navigation_handler:Option<NavigationHandler>)->bool {
                // Serve the index and assets.
                if var.starts_with("dioxus://")
                    || var.starts_with("http://dioxus.")
                    || var.starts_with("https://dioxus.")
                {
                    // After the page has loaded once, don't allow any more navigation
                    let page_loaded = page_loaded.swap(true, std::sync::atomic::Ordering::SeqCst);
                    return !page_loaded;
                }

                // External links always open somewhere else. Prevents the webview from navigating
                if var.starts_with("http://")
                    || var.starts_with("https://")
                    || var.starts_with("mailto:")
                {
                    _ = record_external(&var);
                    return false;
                }

                // By default, external links are allowed. This keeps things like iframes working.
                // However, users can customize this to allow/disallow domains/routes/patterns.
                navigation_handler.as_ref().map(|f| f(&var)).unwrap_or(true)
}
fn resolve_asset_path_from_filesystem(path: &str) -> Option<PathBuf> {
    // If the user provided a custom asset handler, then call it and return the response if the request was handled.
    // The path is the first part of the URI, so we need to trim the leading slash.
    let mut uri_path = PathBuf::from(
        percent_encoding::percent_decode_str(path)
            .decode_utf8()
            .expect("expected URL to be UTF-8 encoded")
            .as_ref(),
    );

    // If the asset doesn't exist, or starts with `/assets/`, then we'll try to serve out of the bundle
    // This lets us handle both absolute and relative paths without being too "special"
    // It just means that our macos bundle is a little "special" because we need to place an `assets`
    // dir in the `Resources` dir.
    //
    // If there's no asset root, we use the cargo manifest dir as the root, or the current dir
    if !uri_path.exists() || uri_path.starts_with("/assets/") {
        let bundle_root = get_asset_root();
        let relative_path = uri_path.strip_prefix("/").unwrap();
        uri_path = bundle_root.join(relative_path);
    }

    // If the asset exists, return it
    uri_path.exists().then_some(uri_path)
}
