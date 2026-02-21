//! Compile-time tests for `#[derive(A3Schema)]` error messages.

#[test]
fn compile_fail_tests() {
    let t = trybuild::TestCases::new();
    t.compile_fail("../tests/compile_fail/schema_on_enum.rs");
    t.compile_fail("../tests/compile_fail/schema_on_tuple_struct.rs");
}
