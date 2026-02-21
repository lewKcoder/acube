//! Core type definitions for the a³ framework.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

/// HTTP methods supported by a³ endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get => write!(f, "GET"),
            Self::Post => write!(f, "POST"),
            Self::Put => write!(f, "PUT"),
            Self::Patch => write!(f, "PATCH"),
            Self::Delete => write!(f, "DELETE"),
        }
    }
}

/// Security requirement for an endpoint.
#[derive(Debug, Clone)]
pub enum EndpointSecurity {
    /// No authentication required (explicitly declared via `#[a3_security(none)]`).
    None,
    /// JWT bearer token authentication.
    Jwt { scopes: Vec<String> },
}

/// Rate limit configuration for an endpoint.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests allowed in the window.
    pub max_requests: u32,
    /// Time window duration.
    pub window: std::time::Duration,
}

/// Structured error response returned by all a³ endpoints.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

/// Body of a structured error response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    pub request_id: String,
    pub retryable: bool,
}

/// Successful response wrapper that returns HTTP 201 Created.
#[derive(Debug)]
pub struct Created<T>(pub T);

impl<T: Serialize> IntoResponse for Created<T> {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::CREATED, axum::Json(self.0)).into_response()
    }
}

/// Result type alias for a³ endpoint handlers.
pub type A3Result<T, E> = Result<T, E>;

/// Uninhabitable error type for endpoints that never fail.
pub enum Never {}

impl std::fmt::Debug for Never {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {}
    }
}

impl IntoResponse for Never {
    fn into_response(self) -> axum::response::Response {
        match self {}
    }
}

/// Health check status.
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
}

impl HealthStatus {
    /// Create a healthy status.
    pub fn ok(version: &str) -> Self {
        Self {
            status: "ok".to_string(),
            version: version.to_string(),
        }
    }
}
