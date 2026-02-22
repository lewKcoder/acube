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

/// Error type for JWT authentication configuration.
#[derive(Debug, thiserror::Error)]
pub enum JwtAuthError {
    /// The PEM key data is invalid or cannot be parsed.
    #[error("Invalid PEM key: {0}")]
    InvalidKey(String),
    /// The specified algorithm is not supported.
    #[error("Unsupported algorithm: {0}. Supported: HS256, RS256, ES256")]
    UnsupportedAlgorithm(String),
    /// A required environment variable is missing.
    #[error("Missing environment variable: {0}")]
    MissingEnvVar(String),
}

/// JWT authentication provider supporting HS256, RS256, and ES256.
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
    /// Create from environment variables.
    ///
    /// Reads `JWT_ALGORITHM` (default: `"HS256"`) and loads the appropriate key:
    /// - **HS256**: uses `JWT_SECRET` (falls back to `"dev-secret"` for development)
    /// - **RS256**: uses `JWT_PUBLIC_KEY` (RSA public key in PEM format, required)
    /// - **ES256**: uses `JWT_PUBLIC_KEY` (EC public key in PEM format, required)
    pub fn from_env() -> Result<Self, JwtAuthError> {
        let algorithm = std::env::var("JWT_ALGORITHM").unwrap_or_else(|_| "HS256".to_string());

        match algorithm.to_uppercase().as_str() {
            "HS256" => {
                let secret =
                    std::env::var("JWT_SECRET").unwrap_or_else(|_| "dev-secret".to_string());
                Ok(Self::new(&secret))
            }
            "RS256" => {
                let pem = std::env::var("JWT_PUBLIC_KEY")
                    .map_err(|_| JwtAuthError::MissingEnvVar("JWT_PUBLIC_KEY".to_string()))?;
                Self::from_rsa_pem(pem.as_bytes())
            }
            "ES256" => {
                let pem = std::env::var("JWT_PUBLIC_KEY")
                    .map_err(|_| JwtAuthError::MissingEnvVar("JWT_PUBLIC_KEY".to_string()))?;
                Self::from_ec_pem(pem.as_bytes())
            }
            other => Err(JwtAuthError::UnsupportedAlgorithm(other.to_string())),
        }
    }

    /// Create from an explicit HMAC secret (HS256).
    pub fn new(secret: &str) -> Self {
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());
        Self::with_algorithm(decoding_key, jsonwebtoken::Algorithm::HS256)
    }

    /// Create from an RSA public key in PEM format (RS256).
    pub fn from_rsa_pem(pem: &[u8]) -> Result<Self, JwtAuthError> {
        let decoding_key = DecodingKey::from_rsa_pem(pem)
            .map_err(|e| JwtAuthError::InvalidKey(e.to_string()))?;
        Ok(Self::with_algorithm(
            decoding_key,
            jsonwebtoken::Algorithm::RS256,
        ))
    }

    /// Create from an EC public key in PEM format (ES256).
    pub fn from_ec_pem(pem: &[u8]) -> Result<Self, JwtAuthError> {
        let decoding_key = DecodingKey::from_ec_pem(pem)
            .map_err(|e| JwtAuthError::InvalidKey(e.to_string()))?;
        Ok(Self::with_algorithm(
            decoding_key,
            jsonwebtoken::Algorithm::ES256,
        ))
    }

    fn with_algorithm(decoding_key: DecodingKey, algorithm: jsonwebtoken::Algorithm) -> Self {
        let mut validation = Validation::new(algorithm);
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
