//! Compile-time tests for `#[derive(A3Schema)]` and `#[derive(A3Error)]` error messages.

#[test]
fn schema_compile_fail_tests() {
    let t = trybuild::TestCases::new();
    t.compile_fail("../tests/compile_fail/schema_on_enum.rs");
    t.compile_fail("../tests/compile_fail/schema_on_tuple_struct.rs");
}

#[test]
fn error_compile_fail_tests() {
    let t = trybuild::TestCases::new();
    t.compile_fail("../tests/compile_fail/error_on_struct.rs");
    t.compile_fail("../tests/compile_fail/error_missing_status.rs");
    t.compile_fail("../tests/compile_fail/error_missing_message.rs");
}
