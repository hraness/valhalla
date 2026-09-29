//! Exact development-page origins permitted to use the loopback proxy.
//! This helper is used only by the opt-in local-qualification transport branch.
//!
//! The page may be served from any loopback port so that parallel checkouts
//! and a running gateway never collide. The origin must still be exactly
//! `http://127.0.0.1:<port>` or `http://localhost:<port>` with a canonical
//! decimal port: no scheme, host, path, userinfo or suffix variations.
pub fn allows_page_origin(origin: &str) -> bool {
    let Some(port) = origin
        .strip_prefix("http://127.0.0.1:")
        .or_else(|| origin.strip_prefix("http://localhost:"))
    else {
        return false;
    };
    !port.is_empty()
        && port.len() <= 5
        && !port.starts_with('0')
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}
