//! Procedural macros for the a³ framework.
//!
//! Provides `#[derive(A3Schema)]`, `#[derive(A3Error)]`, and `#[a3_endpoint]`.

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod endpoint;
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
#[proc_macro_derive(A3Error, attributes(a3))]
pub fn derive_a3_error(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    error::expand(&input).into()
}

/// Attribute macro that defines an a³ endpoint.
///
/// Transforms an async handler function into a registration function
/// that returns an `EndpointRegistration`.
///
/// Must be used with `#[a3_security(...)]`. Missing security declaration
/// is a compile error.
///
/// # Example
///
/// ```ignore
/// #[a3_endpoint(POST "/users")]
/// #[a3_security(jwt, scopes = ["users:create"])]
/// #[a3_rate_limit(10, per_minute)]
/// async fn create_user(
///     ctx: A3Context,
///     input: Valid<CreateUserInput>,
/// ) -> A3Result<Created<UserOutput>, UserError> {
///     // ...
/// }
/// ```
#[proc_macro_attribute]
pub fn a3_endpoint(attr: TokenStream, item: TokenStream) -> TokenStream {
    match endpoint::expand(attr.into(), item.into()) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Security declaration for an a³ endpoint.
///
/// Must be used together with `#[a3_endpoint]`.
/// If used standalone, produces a compile error.
#[proc_macro_attribute]
pub fn a3_security(_attr: TokenStream, _item: TokenStream) -> TokenStream {
    syn::Error::new(
        proc_macro2::Span::call_site(),
        "#[a3_security] must be placed below #[a3_endpoint]. \
         The outer attribute (#[a3_endpoint]) processes it.",
    )
    .to_compile_error()
    .into()
}

/// Authorization declaration for an a³ endpoint.
///
/// Must be used together with `#[a3_endpoint]`.
/// If used standalone, produces a compile error.
#[proc_macro_attribute]
pub fn a3_authorize(_attr: TokenStream, _item: TokenStream) -> TokenStream {
    syn::Error::new(
        proc_macro2::Span::call_site(),
        "#[a3_authorize] must be placed below #[a3_endpoint]. \
         The outer attribute (#[a3_endpoint]) processes it.",
    )
    .to_compile_error()
    .into()
}

/// Rate limit declaration for an a³ endpoint.
///
/// Must be used together with `#[a3_endpoint]`.
/// If used standalone, produces a compile error.
#[proc_macro_attribute]
pub fn a3_rate_limit(_attr: TokenStream, _item: TokenStream) -> TokenStream {
    syn::Error::new(
        proc_macro2::Span::call_site(),
        "#[a3_rate_limit] must be placed below #[a3_endpoint]. \
         The outer attribute (#[a3_endpoint]) processes it.",
    )
    .to_compile_error()
    .into()
}
