//! Security types and middleware for the a³ framework.

use axum::http::header;
use jsonwebtoken::{DecodingKey, Validation};
use serde::{Deserialize, Serialize};

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
    #[error("Token expired")]
    TokenExpired,
    #[error("Insufficient scopes")]
    InsufficientScopes,
}

/// JWT claims expected in the token payload.
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject (user ID).
    pub sub: String,
    /// Granted scopes (comma-separated or array).
    #[serde(default)]
    pub scopes: ScopeClaim,
    /// Expiration time (Unix timestamp).
    #[serde(default)]
    pub exp: Option<u64>,
    /// Issued-at time (Unix timestamp).
    #[serde(default)]
    pub iat: Option<u64>,
}

/// Scope claim that accepts either a JSON array or comma-separated string.
#[derive(Debug, Clone, Default)]
pub struct ScopeClaim(pub Vec<String>);

impl Serialize for ScopeClaim {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ScopeClaim {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum ScopeValue {
            Array(Vec<String>),
            String(String),
        }
        match ScopeValue::deserialize(deserializer)? {
            ScopeValue::Array(v) => Ok(ScopeClaim(v)),
            ScopeValue::String(s) => {
                if s.is_empty() {
                    Ok(ScopeClaim(Vec::new()))
                } else {
                    Ok(ScopeClaim(
                        s.split(',').map(|s| s.trim().to_string()).collect(),
                    ))
                }
            }
        }
    }
}

/// JWT authentication provider with real signature validation.
#[derive(Clone)]
pub struct JwtAuth {
    decoding_key: DecodingKey,
    validation: Validation,
}

impl std::fmt::Debug for JwtAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtAuth")
            .field("algorithm", &self.validation.algorithms)
            .finish()
    }
}

impl JwtAuth {
    /// Create from environment variable `JWT_SECRET` (HMAC-SHA256).
    ///
    /// Falls back to `"dev-secret"` if the environment variable is not set.
    /// **Warning**: In production, always set `JWT_SECRET` to a strong, random value.
    pub fn from_env() -> Result<Self, std::env::VarError> {
        let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "dev-secret".to_string());
        Ok(Self::new(&secret))
    }

    /// Create from an explicit secret (HMAC-SHA256).
    pub fn new(secret: &str) -> Self {
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.required_spec_claims.clear();
        validation.validate_exp = true;
        Self {
            decoding_key,
            validation,
        }
    }
}

impl AuthProvider for JwtAuth {
    fn authenticate(
        &self,
        req: &axum::http::Request<axum::body::Body>,
    ) -> Result<AuthIdentity, AuthError> {
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

        let token_data =
            jsonwebtoken::decode::<JwtClaims>(token, &self.decoding_key, &self.validation)
                .map_err(|e| match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                    _ => AuthError::InvalidToken,
                })?;

        Ok(AuthIdentity {
            subject: token_data.claims.sub,
            scopes: token_data.claims.scopes.0,
        })
    }
}
