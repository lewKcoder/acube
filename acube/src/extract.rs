//! Axum extractors for the acube framework.
//!
//! - `Valid<T>` — Validated and sanitized request body
//! - `AcubeContext` — Request context with request ID and auth identity

use axum::async_trait;
use axum::body::Bytes;
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::Response;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use uuid::Uuid;

use crate::error::error_response;
use crate::runtime::SharedState;
use crate::schema::{check_unknown_fields, AcubeValidate, ValidationError};
use crate::security::AuthIdentity;

/// Request ID stored in request extensions by the request ID middleware.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

/// Request context available to all acube endpoint handlers.
///
/// Provides the request ID, optional authenticated identity, path parameters,
/// and shared application state.
#[derive(Clone)]
pub struct AcubeContext {
    /// Unique request identifier.
    pub request_id: String,
    /// Authenticated identity (if the endpoint requires auth and it succeeded).
    pub auth: Option<AuthIdentity>,
    /// Path parameters extracted from the URL (private — use `ctx.path::<T>("name")`).
    path_params: HashMap<String, String>,
    /// Shared application state (private — use `ctx.state::<T>()`).
    shared_state: SharedState,
}

impl std::fmt::Debug for AcubeContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcubeContext")
            .field("request_id", &self.request_id)
            .field("auth", &self.auth)
            .field("path_params", &self.path_params)
            .finish()
    }
}

impl AcubeContext {
    /// Get a path parameter by name, parsed to the desired type.
    ///
    /// # Panics
    /// Panics if the parameter is not found or cannot be parsed.
    /// This is intentional — missing path parameters are a developer configuration error,
    /// and acube's panic handler will return a structured 500 response.
    ///
    /// # Example
    /// ```rust,ignore
    /// let id: String = ctx.path("id");
    /// let page: i32 = ctx.path("page");
    /// ```
    pub fn path<T: std::str::FromStr>(&self, name: &str) -> T
    where
        T::Err: std::fmt::Display,
    {
        let value = self
            .path_params
            .get(name)
            .unwrap_or_else(|| panic!("path parameter '{}' not found", name));
        value
            .parse()
            .unwrap_or_else(|e| panic!("path parameter '{}' parse error: {}", name, e))
    }

    /// Get shared state by type, previously registered via `Service::builder().state(value)`.
    ///
    /// # Panics
    /// Panics if the state type was not registered. This is intentional —
    /// missing state is a developer configuration error.
    ///
    /// # Example
    /// ```rust,ignore
    /// let pool = ctx.state::<SqlitePool>();
    /// ```
    pub fn state<T: Clone + Send + Sync + 'static>(&self) -> T {
        self.shared_state.get::<T>().unwrap_or_else(|| {
            panic!(
                "state type '{}' not registered — call .state(value) on the ServiceBuilder",
                std::any::type_name::<T>()
            )
        })
    }

    /// Get the authenticated user's ID (JWT `sub` claim).
    ///
    /// # Panics
    /// Panics if the endpoint is not authenticated. This is intentional —
    /// calling `user_id()` on a `#[acube_security(none)]` endpoint is a developer error.
    ///
    /// # Example
    /// ```rust,ignore
    /// let user_id = ctx.user_id();
    /// ```
    pub fn user_id(&self) -> &str {
        &self
            .auth
            .as_ref()
            .expect("user_id() called on unauthenticated endpoint — use #[acube_security(jwt)]")
            .subject
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for AcubeContext
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let request_id = parts
            .extensions
            .get::<RequestId>()
            .map(|r| r.0.clone())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let auth = parts.extensions.get::<AuthIdentity>().cloned();

        // Extract all path parameters (best-effort; empty if no path params)
        let path_params =
            axum::extract::Path::<HashMap<String, String>>::from_request_parts(parts, _state)
                .await
                .map(|p| p.0)
                .unwrap_or_default();

        // Extract shared state (empty if not registered)
        let shared_state = parts
            .extensions
            .get::<SharedState>()
            .cloned()
            .unwrap_or_default();

        Ok(AcubeContext {
            request_id,
            auth,
            path_params,
            shared_state,
        })
    }
}

/// Validated and sanitized request body extractor.
///
/// Deserializes JSON, checks for unknown fields (strict mode),
/// runs validation and sanitization, then returns the typed input.
///
/// Returns a structured 400 error if any step fails.
pub struct Valid<T>(T);

impl<T> Valid<T> {
    /// Consume the wrapper and return the validated, sanitized inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

#[async_trait]
impl<T, S> FromRequest<S> for Valid<T>
where
    T: DeserializeOwned + AcubeValidate + Send,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let request_id = req
            .extensions()
            .get::<RequestId>()
            .map(|r| r.0.clone())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        // Extract body as bytes (handles payload too large from RequestBodyLimitLayer)
        let bytes = Bytes::from_request(req, state).await.map_err(|e| {
            let status = e.status();
            if status == StatusCode::PAYLOAD_TOO_LARGE {
                error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "payload_too_large",
                    "Request body too large",
                    &request_id,
                    false,
                    None,
                )
            } else {
                error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_body",
                    "Failed to read request body",
                    &request_id,
                    false,
                    None,
                )
            }
        })?;

        // Parse as JSON Value first (for strict mode check)
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_json",
                "Invalid JSON",
                &request_id,
                false,
                None,
            )
        })?;

        // Strict mode: reject unknown fields
        let unknown_errors = check_unknown_fields(&value, T::known_fields());
        if !unknown_errors.is_empty() {
            return Err(validation_error_response(&request_id, unknown_errors));
        }

        // Deserialize to the target type
        let mut input: T = serde_json::from_value(value).map_err(|e| {
            tracing::debug!(request_id = %request_id, error = %e, "deserialization failed");
            error_response(
                StatusCode::BAD_REQUEST,
                "deserialization_error",
                "Invalid request body",
                &request_id,
                false,
                None,
            )
        })?;

        // Validate + sanitize
        if let Err(errors) = input.validate() {
            return Err(validation_error_response(&request_id, errors));
        }

        Ok(Valid(input))
    }
}

/// Build a structured 400 response from validation errors.
///
/// Only field names are exposed to the client. Detailed error messages
/// (constraint values, received values) are logged server-side only.
fn validation_error_response(request_id: &str, errors: Vec<ValidationError>) -> Response {
    // Log detailed errors server-side for debugging
    for err in &errors {
        tracing::warn!(
            request_id = %request_id,
            field = %err.field,
            code = %err.code,
            message = %err.message,
            "validation failed"
        );
    }

    // Client receives only field names — no constraint details leaked
    let fields: Vec<&str> = errors.iter().map(|e| e.field.as_str()).collect();
    error_response(
        StatusCode::BAD_REQUEST,
        "validation_error",
        "Validation failed",
        request_id,
        false,
        Some(serde_json::to_value(&fields).unwrap_or_default()),
    )
}
