//! Compile-time enforcement tests for Phase 2 macros.

#[test]
fn endpoint_compile_tests() {
    let t = trybuild::TestCases::new();
    t.compile_fail("../tests/compile_fail/endpoint_missing_security.rs");
}
