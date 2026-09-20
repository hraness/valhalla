//! The qualification proxy must remain restricted to exact local test origins.
#[path = "../src/qualification.rs"]
mod qualification;

#[test]
fn only_explicit_local_test_origins_can_use_qualification_routes() {
    for origin in [
        "http://127.0.0.1:8789",
        "http://127.0.0.1:8790",
        "http://localhost:8790",
    ] {
        assert!(qualification::allows_page_origin(origin), "{origin}");
    }
    for origin in [
        "https://valhalla.social",
        "https://localhost:8790",
        "http://localhost:8789",
        "http://localhost:8791",
        "http://localhost.example:8790",
        "http://127.0.0.1:8790.example",
        "http://localhost:8790/",
        "http://localhost:8790@evil.example",
        "null",
        "",
    ] {
        assert!(!qualification::allows_page_origin(origin), "{origin}");
    }
}
