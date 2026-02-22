//! Error types and traits for the acube framework.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::types::{ErrorBody, ErrorResponse};

/// Metadata for a single error variant (for OpenAPI generation).
#[derive(Debug, Clone)]
pub struct OpenApiErrorVariant {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

/// Trait for acube error types that can be converted to structured HTTP responses.
pub trait AcubeErrorInfo {
    /// HTTP status code for this error variant.
    fn status_code(&self) -> StatusCode;
    /// Human-readable error message (safe to expose to clients).
    fn message(&self) -> &str;
    /// Machine-readable error code (e.g., "not_found").
    fn code(&self) -> &str;
    /// Whether the client should retry this request.
    fn retryable(&self) -> bool;

    /// Return OpenAPI response metadata for all variants of this error type.
    fn openapi_responses() -> Vec<OpenApiErrorVariant>
    where
        Self: Sized,
    {
        Vec::new()
    }
}

/// Construct a structured JSON error response.
pub fn error_response(
    status: StatusCode,
    code: &str,
    message: &str,
    request_id: &str,
    retryable: bool,
    details: Option<serde_json::Value>,
) -> Response {
    let body = ErrorResponse {
        error: ErrorBody {
            code: code.to_string(),
            message: message.to_string(),
            details,
            request_id: request_id.to_string(),
            retryable,
        },
    };
    (status, axum::Json(body)).into_response()
}

/// Build an error response from an `AcubeErrorInfo` implementor.
pub fn into_acube_response(err: &(impl AcubeErrorInfo + std::fmt::Debug), request_id: &str) -> Response {
    error_response(
        err.status_code(),
        err.code(),
        err.message(),
        request_id,
        err.retryable(),
        None,
    )
}

/// Error type for custom authorization functions.
///
/// Used with `#[acube_authorize(custom = "fn_name")]` to return authorization failures.
#[derive(Debug)]
pub enum AcubeAuthError {
    /// HTTP 403 Forbidden with custom message.
    Forbidden(String),
}

impl IntoResponse for AcubeAuthError {
    fn into_response(self) -> Response {
        match self {
            AcubeAuthError::Forbidden(msg) => {
                let request_id = uuid::Uuid::new_v4().to_string();
                error_response(
                    StatusCode::FORBIDDEN,
                    "forbidden",
                    &msg,
                    &request_id,
                    false,
                    None,
                )
            }
        }
    }
}

/// Framework-level errors (not user-defined).
#[derive(Debug, thiserror::Error)]
pub enum AcubeFrameworkError {
    #[error("Not found")]
    NotFound,
    #[error("Method not allowed")]
    MethodNotAllowed,
    #[error("Payload too large")]
    PayloadTooLarge,
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Forbidden")]
    Forbidden,
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Internal server error")]
    Internal,
}

impl AcubeErrorInfo for AcubeFrameworkError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::NotFound => "Not found",
            Self::MethodNotAllowed => "Method not allowed",
            Self::PayloadTooLarge => "Payload too large",
            Self::RateLimitExceeded => "Rate limit exceeded",
            Self::Unauthorized => "Unauthorized",
            Self::Forbidden => "Forbidden",
            Self::BadRequest(msg) => msg,
            Self::Internal => "Internal server error",
        }
    }

    fn code(&self) -> &str {
        match self {
            Self::NotFound => "not_found",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::PayloadTooLarge => "payload_too_large",
            Self::RateLimitExceeded => "rate_limit_exceeded",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::BadRequest(_) => "bad_request",
            Self::Internal => "internal_error",
        }
    }

    fn retryable(&self) -> bool {
        matches!(self, Self::RateLimitExceeded | Self::Internal)
    }

    fn openapi_responses() -> Vec<OpenApiErrorVariant> {
        vec![
            OpenApiErrorVariant { status: 404, code: "not_found".to_string(), message: "Not found".to_string(), retryable: false },
            OpenApiErrorVariant { status: 405, code: "method_not_allowed".to_string(), message: "Method not allowed".to_string(), retryable: false },
            OpenApiErrorVariant { status: 413, code: "payload_too_large".to_string(), message: "Payload too large".to_string(), retryable: false },
            OpenApiErrorVariant { status: 429, code: "rate_limit_exceeded".to_string(), message: "Rate limit exceeded".to_string(), retryable: true },
            OpenApiErrorVariant { status: 401, code: "unauthorized".to_string(), message: "Unauthorized".to_string(), retryable: false },
            OpenApiErrorVariant { status: 403, code: "forbidden".to_string(), message: "Forbidden".to_string(), retryable: false },
            OpenApiErrorVariant { status: 400, code: "bad_request".to_string(), message: "Bad request".to_string(), retryable: false },
            OpenApiErrorVariant { status: 500, code: "internal_error".to_string(), message: "Internal server error".to_string(), retryable: true },
        ]
    }
}
