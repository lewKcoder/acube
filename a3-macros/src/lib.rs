//! Procedural macros for the a³ framework.
//!
//! Provides `#[derive(A3Schema)]`, `#[derive(A3Error)]`, and `#[a3_endpoint]`.

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod error;
mod schema;

/// Derive macro for input/output schema validation.
///
/// Generates `impl A3Validate` and `impl A3SchemaInfo` for the annotated struct.
///
/// # Supported attributes
///
/// - `#[a3(min_length = N)]` — Minimum string length
/// - `#[a3(max_length = N)]` — Maximum string length
/// - `#[a3(min = N)]` — Minimum numeric value
/// - `#[a3(max = N)]` — Maximum numeric value
/// - `#[a3(pattern = "regex")]` — Regex pattern match
/// - `#[a3(format = "email"|"uuid")]` — Format validation
/// - `#[a3(sanitize(trim, lowercase, strip_html))]` — Input sanitization
/// - `#[a3(pii)]` — Mark field as personally identifiable information
///
/// # Example
///
/// ```ignore
/// #[derive(A3Schema, Debug, Deserialize)]
/// pub struct CreateUserInput {
///     #[a3(min_length = 3, max_length = 30, pattern = "^[a-zA-Z0-9_]+$")]
///     #[a3(sanitize(trim))]
///     pub username: String,
///
///     #[a3(format = "email", pii)]
///     #[a3(sanitize(trim, lowercase))]
///     pub email: String,
/// }
/// ```
#[proc_macro_derive(A3Schema, attributes(a3))]
pub fn derive_a3_schema(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    schema::expand(&input).into()
}

/// Derive macro for structured error responses.
///
/// Generates `impl A3ErrorInfo` and `impl IntoResponse` for the annotated enum.
///
/// # Supported attributes
///
/// - `#[a3(status = NNN)]` — HTTP status code (required)
/// - `#[a3(message = "...")]` — Error message safe to expose to clients (required)
/// - `#[a3(retryable)]` — Mark this error as retryable
///
/// # Example
///
/// ```ignore
/// #[derive(A3Error, Debug)]
/// pub enum UserError {
///     #[a3(status = 404, message = "User not found")]
///     NotFound,
///
///     #[a3(status = 409, message = "Username already taken")]
///     UsernameTaken,
///
///     #[a3(status = 502, retryable, message = "Database unavailable")]
///     DbError,
/// }
/// ```
#[proc_macro_derive(A3Error, attributes(a3))]
pub fn derive_a3_error(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    error::expand(&input).into()
}
