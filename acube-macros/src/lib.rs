//! Procedural macros for the acube framework.
//!
//! Provides `#[derive(AcubeSchema)]`, `#[derive(AcubeError)]`, and `#[acube_endpoint]`.

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod endpoint;
mod error;
mod schema;

/// Derive macro for input/output schema validation.
///
/// Generates `impl AcubeValidate` and `impl AcubeSchemaInfo` for the annotated struct.
///
/// # Supported attributes
///
/// - `#[acube(min_length = N)]` — Minimum string length
/// - `#[acube(max_length = N)]` — Maximum string length
/// - `#[acube(min = N)]` — Minimum numeric value
/// - `#[acube(max = N)]` — Maximum numeric value
/// - `#[acube(pattern = "regex")]` — Regex pattern match
/// - `#[acube(format = "email"|"url"|"uuid")]` — Format validation
/// - `#[acube(sanitize(trim, lowercase, strip_html))]` — Input sanitization
/// - `#[acube(pii)]` — Mark field as personally identifiable information
#[proc_macro_derive(AcubeSchema, attributes(acube))]
pub fn derive_acube_schema(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    schema::expand(&input).into()
}

/// Derive macro for structured error responses.
///
/// Generates `impl AcubeErrorInfo` and `impl IntoResponse` for the annotated enum.
///
/// # Supported attributes
///
/// - `#[acube(status = NNN)]` — HTTP status code (required)
/// - `#[acube(message = "...")]` — Error message safe to expose to clients (required)
/// - `#[acube(retryable)]` — Mark this error as retryable
#[proc_macro_derive(AcubeError, attributes(acube))]
pub fn derive_acube_error(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    error::expand(&input).into()
}

/// Attribute macro that defines an acube endpoint.
///
/// Transforms an async handler function into a registration function
/// that returns an `EndpointRegistration`.
///
/// Must be used with `#[acube_security(...)]`. Missing security declaration
/// is a compile error.
///
/// # Example
///
/// ```ignore
/// #[acube_endpoint(POST "/users")]
/// #[acube_security(jwt, scopes = ["users:create"])]
/// #[acube_rate_limit(10, per_minute)]
/// async fn create_user(
///     ctx: AcubeContext,
///     input: Valid<CreateUserInput>,
/// ) -> AcubeResult<Created<UserOutput>, UserError> {
///     // ...
/// }
/// ```
#[proc_macro_attribute]
pub fn acube_endpoint(attr: TokenStream, item: TokenStream) -> TokenStream {
    match endpoint::expand(attr.into(), item.into()) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

/// Security declaration for an acube endpoint.
///
/// Must be used together with `#[acube_endpoint]`.
/// If used standalone, produces a compile error.
#[proc_macro_attribute]
pub fn acube_security(_attr: TokenStream, _item: TokenStream) -> TokenStream {
    syn::Error::new(
        proc_macro2::Span::call_site(),
        "#[acube_security] must be placed below #[acube_endpoint]. \
         The outer attribute (#[acube_endpoint]) processes it.",
    )
    .to_compile_error()
    .into()
}

/// Authorization declaration for an acube endpoint.
///
/// Must be used together with `#[acube_endpoint]`.
/// If used standalone, produces a compile error.
#[proc_macro_attribute]
pub fn acube_authorize(_attr: TokenStream, _item: TokenStream) -> TokenStream {
    syn::Error::new(
        proc_macro2::Span::call_site(),
        "#[acube_authorize] must be placed below #[acube_endpoint]. \
         The outer attribute (#[acube_endpoint]) processes it.",
    )
    .to_compile_error()
    .into()
}

/// Rate limit declaration for an acube endpoint.
///
/// Must be used together with `#[acube_endpoint]`.
/// If used standalone, produces a compile error.
#[proc_macro_attribute]
pub fn acube_rate_limit(_attr: TokenStream, _item: TokenStream) -> TokenStream {
    syn::Error::new(
        proc_macro2::Span::call_site(),
        "#[acube_rate_limit] must be placed below #[acube_endpoint]. \
         The outer attribute (#[acube_endpoint]) processes it.",
    )
    .to_compile_error()
    .into()
}
