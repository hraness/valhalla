//! The qualification proxy must remain restricted to exact local test origins.
#[path = "../src/qualification.rs"]
mod qualification;

#[test]
fn only_explicit_local_test_origins_can_use_qualification_routes() {
    for origin in [
        "http://127.0.0.1:8789",
        "http://127.0.0.1:8790",
        "http://localhost:8790",
        "http://localhost:8789",
        "http://127.0.0.1:1",
        "http://127.0.0.1:49152",
        "http://localhost:65535",
    ] {
        assert!(qualification::allows_page_origin(origin), "{origin}");
    }
    for origin in [
        "https://valhalla.social",
        "https://localhost:8790",
        "https://127.0.0.1:8790",
        "http://localhost",
        "http://127.0.0.1",
        "http://localhost:",
        "http://127.0.0.1:0",
        "http://127.0.0.1:08790",
        "http://127.0.0.1:65536",
        "http://127.0.0.1:123456",
        "http://127.0.0.1:+8790",
        "http://127.0.0.1:-1",
        "http://localhost.example:8790",
        "http://127.0.0.1:8790.example",
        "http://127.0.0.2:8790",
        "http://[::1]:8790",
        "http://localhost:8790/",
        "http://localhost:8790@evil.example",
        "http://evil.example#http://localhost:8790",
        "HTTP://localhost:8790",
        "null",
        "",
    ] {
        assert!(!qualification::allows_page_origin(origin), "{origin}");
    }
}
