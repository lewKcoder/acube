//! Core type definitions for the a³ framework.

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

/// Authentication strategy for an endpoint.
#[derive(Debug, Clone)]
pub enum AuthStrategy {
    /// JWT bearer token authentication.
    Jwt { scopes: Vec<String> },
    /// No authentication required (must be explicitly declared).
    None,
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

/// Successful response wrapper with status code.
#[derive(Debug)]
pub struct Created<T>(pub T);

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
