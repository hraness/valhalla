//! Exact development-page origins permitted to use the fixed loopback proxy.
//! This helper is used only by the opt-in local-qualification transport branch.
pub fn allows_page_origin(origin: &str) -> bool {
    matches!(
        origin,
        "http://127.0.0.1:8789" | "http://127.0.0.1:8790" | "http://localhost:8790"
    )
}
