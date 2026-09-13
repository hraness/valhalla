use proptest::prelude::*;
use vhalla_dioxus_boundary_spike::*;
fn message(sequence: u64, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = b"VHUD\0\0\0\x01".to_vec();
    out.extend([7; 32]);
    out.extend(sequence.to_be_bytes());
    out.push(opcode);
    out.extend(payload);
    out
}
#[test]
fn exact_navigation_and_manifest_asset_policy_block_effectful_routes() {
    for origin in [Origin::Mac, Origin::Windows, Origin::Android] {
        let mut nav = Navigation::new(origin);
        for url in [
            "https://evil.invalid/",
            "file:///tmp/secret",
            "javascript:alert(1)",
            "data:text/html,hi",
            "dioxus://index.html.evil/",
            "http://dioxus.evil/",
            "dioxus://index.html/__file_dialog",
        ] {
            assert!(!nav.allow(url));
        }
        assert!(nav.allow(origin.document()));
        assert!(!nav.allow(origin.document()));
    }
    for path in [
        "/tmp/secret",
        "/assets/../../secret",
        "/assets/%2e%2e/secret",
        "/%FF",
        "/__events",
        "/__file_dialog",
        "/assets/icon-c3d4.svg?x=1",
        "/assets/icon-c3d4.svg#fragment",
    ] {
        assert!(asset("GET", path).is_err());
    }
    assert!(asset("POST", "/assets/app-a1b2.css").is_err());
    assert!(asset("GET", "/assets/app-a1b2.css").is_ok());
}
#[test]
fn typed_ipc_is_replay_bounded_and_never_mints_effects() {
    let mut session = Session::new(Origin::Mac, [7; 32]);
    let origin = Origin::Mac.document();
    assert_eq!(
        session.receive(origin, &message(1, 0, &[9; 32])),
        Ok(Intent::ViewPost([9; 32]))
    );
    assert_eq!(
        session.receive(origin, &message(1, 0, &[9; 32])),
        Err(Error::Replay)
    );
    assert_eq!(
        session.receive("https://evil.invalid/", &message(2, 0, &[9; 32])),
        Err(Error::Origin)
    );
    assert_eq!(
        session.receive(origin, &message(2, 255, &[9; 32])),
        Err(Error::Denied)
    );
    assert_eq!(session.last_sequence(), 1);
    assert_eq!(
        session.receive(origin, &message(2, 1, &[9; 32])),
        Ok(Intent::ProposeRead([9; 32]))
    );
    assert_eq!(
        session.receive(origin, &message(3, 2, &[0])),
        Ok(Intent::ProposeExternal(ExternalTarget::Documentation))
    );
    assert_eq!(ExternalTarget::Documentation.url(), "https://vhalla.com/");
    let mut wrong = message(4, 0, &[9; 32]);
    wrong[8] ^= 1;
    assert_eq!(session.receive(origin, &wrong), Err(Error::Encoding));
    assert_eq!(
        session.receive(origin, &[0; MAX_IPC_BYTES + 1]),
        Err(Error::Bounds)
    );
    assert_eq!(session.last_sequence(), 3);
}
#[test]
fn release_csp_is_narrow_and_never_uses_inline_or_eval_wildcards() {
    let csp = desktop_csp([7; 32], 41234).unwrap();
    assert!(csp.contains("ws://127.0.0.1:41234"));
    for absent in ["'unsafe-inline'", "'unsafe-eval'", "https:", "*", "data:"] {
        assert!(!csp.contains(absent));
    }
    assert!(csp.contains("frame-ancestors 'none'"));
    assert!(desktop_csp([0; 32], 1).is_err());
    assert!(desktop_csp([7; 32], 0).is_err());
    assert!(WEB_CSP.contains("'wasm-unsafe-eval'"));
    assert!(!WEB_CSP.contains("'unsafe-eval'"));
}
proptest! {
 #![proptest_config(ProptestConfig::with_cases(128))]
 #[test]
 fn arbitrary_frames_terminate_without_capabilities(raw in prop::collection::vec(any::<u8>(),0..300)){
  let mut session=Session::new(Origin::Mac,[7;32]);let result=session.receive(Origin::Mac.document(),&raw);
  if result.is_err() {prop_assert_eq!(session.last_sequence(),0);} else {prop_assert!(raw.len()<=MAX_IPC_BYTES);prop_assert!(session.last_sequence()>0);}
 }
 #[test]
 fn every_nonmanifest_path_is_denied(path in ".{0,300}") {
  if path!="/assets/app-a1b2.css" && path!="/assets/icon-c3d4.svg" {prop_assert!(asset("GET",&path).is_err());}
 }
}
