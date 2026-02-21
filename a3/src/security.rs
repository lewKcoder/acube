//! Security types and middleware for the a³ framework.

use axum::http::header;

/// Security header constants — 7 headers auto-injected on every response.
pub const SECURITY_HEADERS: [(&str, &str); 7] = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("X-XSS-Protection", "0"),
    (
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains; preload",
    ),
    (
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'",
    ),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    (
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()",
    ),
];

/// Trait for authentication providers (e.g., JWT, API key).
pub trait AuthProvider: Send + Sync + 'static {
    /// Validate the request and extract the authenticated identity.
    fn authenticate(
        &self,
        req: &axum::http::Request<axum::body::Body>,
    ) -> Result<AuthIdentity, AuthError>;
}

/// Authenticated identity extracted by an `AuthProvider`.
#[derive(Debug, Clone)]
pub struct AuthIdentity {
    /// Subject identifier (e.g., user ID).
    pub subject: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
}

/// Authentication error.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Missing authorization header")]
    MissingToken,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Insufficient scopes")]
    InsufficientScopes,
}

/// A stub JWT auth provider for Phase 0.
///
/// In Phase 2+, this will perform real JWT validation.
#[derive(Debug, Clone)]
pub struct JwtAuth {
    _secret: String,
}

impl JwtAuth {
    /// Create from environment variable `JWT_SECRET`.
    pub fn from_env() -> Result<Self, std::env::VarError> {
        let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "dev-secret".to_string());
        Ok(Self { _secret: secret })
    }
}

impl AuthProvider for JwtAuth {
    fn authenticate(
        &self,
        req: &axum::http::Request<axum::body::Body>,
    ) -> Result<AuthIdentity, AuthError> {
        // Phase 0: Accept any Bearer token as valid
        let header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthError::MissingToken)?;

        if !header.starts_with("Bearer ") {
            return Err(AuthError::InvalidToken);
        }

        let token = &header[7..];
        if token.is_empty() {
            return Err(AuthError::InvalidToken);
        }

        // Stub: return a dummy identity
        Ok(AuthIdentity {
            subject: "stub-user".to_string(),
            scopes: vec!["*".to_string()],
        })
    }
}
