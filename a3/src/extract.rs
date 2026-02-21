//! Axum extractors for the a³ framework.
//!
//! - `Valid<T>` — Validated and sanitized request body
//! - `A3Context` — Request context with request ID and auth identity

use axum::async_trait;
use axum::body::Bytes;
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::Response;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::error::error_response;
use crate::schema::{check_unknown_fields, A3Validate, ValidationError};
use crate::security::AuthIdentity;

/// Request ID stored in request extensions by the request ID middleware.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

/// Request context available to all a³ endpoint handlers.
///
/// Provides the request ID and optional authenticated identity.
#[derive(Debug, Clone)]
pub struct A3Context {
    /// Unique request identifier.
    pub request_id: String,
    /// Authenticated identity (if the endpoint requires auth and it succeeded).
    pub auth: Option<AuthIdentity>,
}

#[async_trait]
impl<S> FromRequestParts<S> for A3Context
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

        Ok(A3Context { request_id, auth })
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
    T: DeserializeOwned + A3Validate + Send,
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
fn validation_error_response(request_id: &str, errors: Vec<ValidationError>) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "validation_error",
        "Validation failed",
        request_id,
        false,
        Some(serde_json::to_value(&errors).unwrap_or_default()),
    )
}
