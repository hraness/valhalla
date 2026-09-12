#![allow(missing_docs)]

#[test]
fn untrusted_envelope_constructor_is_private() {
    trybuild::TestCases::new().compile_fail("tests/ui/*.rs");
}
