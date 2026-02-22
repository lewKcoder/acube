//! Compile-time enforcement tests for Phase 2 macros.

#[test]
fn endpoint_compile_tests() {
    let t = trybuild::TestCases::new();
    t.compile_fail("../tests/compile_fail/endpoint_missing_security.rs");
    t.compile_fail("../tests/compile_fail/endpoint_missing_authorize.rs");
    t.compile_fail("../tests/compile_fail/endpoint_authorize_none_scopes.rs");
    t.compile_fail("../tests/compile_fail/endpoint_authorize_jwt_public.rs");
}
