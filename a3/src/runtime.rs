//! Service builder and runtime for the a³ framework.
//!
//! Pipeline stages (6段):
//! ① Route Resolution
//! ② Security (ヘッダー注入 + レート制限 + ペイロード制限)
//! ③ Auth (認証 + スコープ検証)
//! ④ Input (バリデーション + サニタイズ) — handled by `Valid<T>` extractor
//! ⑤ Handler Execution
//! ⑥ Response (エラー整形 + レスポンス構築)

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Router;
use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tower::Layer;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use uuid::Uuid;

use crate::error::error_response;
use crate::extract::RequestId;
use crate::rate_limit::{InMemoryBackend, RateLimitBackend};
use crate::security::AuthProvider;
use crate::types::{EndpointSecurity, HttpMethod, RateLimitConfig};

/// Default payload size limit (1 MB).
const DEFAULT_PAYLOAD_LIMIT: usize = 1024 * 1024;

/// An a³ endpoint registration.
pub struct EndpointRegistration {
    /// HTTP method.
    pub method: HttpMethod,
    /// URL path pattern.
    pub path: String,
    /// Axum method router (handler).
    pub handler: axum::routing::MethodRouter,
    /// Security requirement for this endpoint.
    pub security: EndpointSecurity,
    /// Rate limit configuration (None = no rate limit).
    pub rate_limit: Option<RateLimitConfig>,
}

/// Builder for constructing an a³ `Service`.
pub struct ServiceBuilder {
    name: Option<String>,
    version: Option<String>,
    endpoints: Vec<EndpointRegistration>,
    auth_provider: Option<Arc<dyn AuthProvider>>,
    rate_limit_backend: Option<Arc<dyn RateLimitBackend>>,
    payload_limit: usize,
    cors_origins: Vec<String>,
}

impl ServiceBuilder {
    fn new() -> Self {
        Self {
            name: None,
            version: None,
            endpoints: Vec::new(),
            auth_provider: None,
            rate_limit_backend: None,
            payload_limit: DEFAULT_PAYLOAD_LIMIT,
            cors_origins: Vec::new(),
        }
    }

    /// Set the service name.
    pub fn name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Set the service version.
    pub fn version(mut self, version: &str) -> Self {
        self.version = Some(version.to_string());
        self
    }

    /// Register an endpoint.
    pub fn endpoint(mut self, reg: EndpointRegistration) -> Self {
        self.endpoints.push(reg);
        self
    }

    /// Set the authentication provider.
    pub fn auth<P: AuthProvider>(mut self, provider: P) -> Self {
        self.auth_provider = Some(Arc::new(provider));
        self
    }

    /// Set the rate limit backend.
    pub fn rate_limit_backend<B: RateLimitBackend>(mut self, backend: B) -> Self {
        self.rate_limit_backend = Some(Arc::new(backend));
        self
    }

    /// Set the maximum request body size in bytes (default: 1 MB).
    pub fn payload_limit(mut self, bytes: usize) -> Self {
        self.payload_limit = bytes;
        self
    }

    /// Set allowed CORS origins.
    ///
    /// By default, no origins are allowed (all cross-origin requests denied).
    /// Call this to explicitly allow specific origins.
    pub fn cors_allow_origins(mut self, origins: &[&str]) -> Self {
        self.cors_origins = origins.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Build the service, performing startup contract validation.
    pub fn build(self) -> Result<Service, ServiceBuildError> {
        let name = self.name.ok_or(ServiceBuildError::MissingField("name"))?;
        let version = self
            .version
            .ok_or(ServiceBuildError::MissingField("version"))?;

        // Check for duplicate paths
        let mut seen = std::collections::HashSet::new();
        for ep in &self.endpoints {
            let key = format!("{} {}", ep.method, ep.path);
            if !seen.insert(key.clone()) {
                return Err(ServiceBuildError::DuplicateEndpoint(key));
            }
        }

        // Check that auth provider is set if any endpoint requires JWT
        let has_jwt = self
            .endpoints
            .iter()
            .any(|ep| matches!(ep.security, EndpointSecurity::Jwt { .. }));
        if has_jwt && self.auth_provider.is_none() {
            return Err(ServiceBuildError::MissingAuthProvider);
        }

        let rate_limiter = self
            .rate_limit_backend
            .unwrap_or_else(|| Arc::new(InMemoryBackend::new()));

        Ok(Service {
            name,
            version,
            endpoints: self.endpoints,
            auth_provider: self.auth_provider,
            rate_limiter,
            payload_limit: self.payload_limit,
            cors_origins: self.cors_origins,
        })
    }
}

/// Errors during service construction.
#[derive(Debug, thiserror::Error)]
pub enum ServiceBuildError {
    #[error("Missing required field: {0}")]
    MissingField(&'static str),
    #[error("Duplicate endpoint: {0}")]
    DuplicateEndpoint(String),
    #[error("JWT endpoints require an auth provider (call .auth() on the builder)")]
    MissingAuthProvider,
}

/// A fully configured a³ service ready to serve.
pub struct Service {
    /// Service name.
    pub name: String,
    /// Service version.
    pub version: String,
    endpoints: Vec<EndpointRegistration>,
    auth_provider: Option<Arc<dyn AuthProvider>>,
    rate_limiter: Arc<dyn RateLimitBackend>,
    payload_limit: usize,
    cors_origins: Vec<String>,
}

impl Service {
    /// Create a new `ServiceBuilder`.
    pub fn builder() -> ServiceBuilder {
        ServiceBuilder::new()
    }

    /// Build the axum `Router` with all middleware and endpoints.
    pub fn into_router(self) -> Router {
        let mut router = Router::new();

        // Group endpoints by path to avoid axum's duplicate-route panic
        let mut route_map: HashMap<String, Option<axum::routing::MethodRouter>> = HashMap::new();

        for ep in self.endpoints {
            // Apply per-endpoint layers
            let mut handler = ep.handler;

            // Rate limit layer
            if let Some(ref config) = ep.rate_limit {
                handler = handler.layer(EndpointRateLimitLayer {
                    backend: self.rate_limiter.clone(),
                    max_requests: config.max_requests,
                    window: config.window,
                });
            }

            // Auth layer for JWT endpoints (with scope verification)
            if let EndpointSecurity::Jwt { scopes } = &ep.security {
                if let Some(ref provider) = self.auth_provider {
                    handler = handler.layer(JwtAuthLayer {
                        provider: provider.clone(),
                        required_scopes: scopes.clone(),
                    });
                }
            }

            // Merge handlers for the same path
            let entry = route_map.entry(ep.path).or_insert(None);
            *entry = Some(match entry.take() {
                Some(existing) => existing.merge(handler),
                None => handler,
            });
        }

        for (path, handler) in route_map {
            if let Some(h) = handler {
                router = router.route(&path, h);
            }
        }

        // Add fallback for 404
        let fallback_handler = || async {
            let request_id = Uuid::new_v4().to_string();
            error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "Not found",
                &request_id,
                false,
                None,
            )
        };
        router = router.fallback(fallback_handler);

        // Layers are applied in reverse order: last added = outermost.
        // Request flow: cors → request_id → body_limit → security_headers → catch_panic → handler

        // Panic handler (innermost — catches panics, response flows through outer layers)
        router = router.layer(CatchPanicLayer::custom(panic_handler));

        // ⑥ Response: security headers middleware
        router = router.layer(middleware::from_fn(security_headers_middleware));

        // ② Security: payload size limit
        router = router.layer(RequestBodyLimitLayer::new(self.payload_limit));

        // ① Route Resolution: request ID middleware
        router = router.layer(middleware::from_fn(request_id_middleware));

        // CORS layer (outermost — handles preflight OPTIONS before any other processing)
        let cors = if self.cors_origins.is_empty() {
            // Safe default: deny all cross-origin requests
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(std::iter::empty::<HeaderValue>()))
                .allow_methods(AllowMethods::list([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PUT,
                    axum::http::Method::PATCH,
                    axum::http::Method::DELETE,
                ]))
                .allow_headers(AllowHeaders::list([
                    axum::http::header::CONTENT_TYPE,
                    axum::http::header::AUTHORIZATION,
                ]))
        } else {
            // Explicit origin whitelist
            let origins: Vec<HeaderValue> = self
                .cors_origins
                .iter()
                .filter_map(|o| o.parse().ok())
                .collect();
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods(AllowMethods::list([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PUT,
                    axum::http::Method::PATCH,
                    axum::http::Method::DELETE,
                ]))
                .allow_headers(AllowHeaders::list([
                    axum::http::header::CONTENT_TYPE,
                    axum::http::header::AUTHORIZATION,
                ]))
        };
        router = router.layer(cors);

        router
    }
}

// ─── Request ID middleware ───────────────────────────────────────────────────

/// Middleware that injects a unique request ID into every request and response.
async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    let request_id = Uuid::new_v4().to_string();
    req.extensions_mut().insert(RequestId(request_id.clone()));
    let mut response = next.run(req).await;
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-request-id"), val);
    }
    response
}

// ─── Security headers middleware ─────────────────────────────────────────────

static HEADER_X_CONTENT_TYPE_OPTIONS: HeaderName =
    HeaderName::from_static("x-content-type-options");
static HEADER_X_FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");
static HEADER_X_XSS_PROTECTION: HeaderName = HeaderName::from_static("x-xss-protection");
static HEADER_STRICT_TRANSPORT_SECURITY: HeaderName =
    HeaderName::from_static("strict-transport-security");
static HEADER_CONTENT_SECURITY_POLICY: HeaderName =
    HeaderName::from_static("content-security-policy");
static HEADER_REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
static HEADER_PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");

/// Middleware that injects all 7 security headers into every response.
async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(
        HEADER_X_CONTENT_TYPE_OPTIONS.clone(),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HEADER_X_FRAME_OPTIONS.clone(),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HEADER_X_XSS_PROTECTION.clone(),
        HeaderValue::from_static("0"),
    );
    headers.insert(
        HEADER_STRICT_TRANSPORT_SECURITY.clone(),
        HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );
    headers.insert(
        HEADER_CONTENT_SECURITY_POLICY.clone(),
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    headers.insert(
        HEADER_REFERRER_POLICY.clone(),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        HEADER_PERMISSIONS_POLICY.clone(),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    response
}

// ─── JWT Auth Layer (per-endpoint) ──────────────────────────────────────────

#[derive(Clone)]
struct JwtAuthLayer {
    provider: Arc<dyn AuthProvider>,
    required_scopes: Vec<String>,
}

impl<S> Layer<S> for JwtAuthLayer {
    type Service = JwtAuthService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        JwtAuthService {
            inner,
            provider: self.provider.clone(),
            required_scopes: self.required_scopes.clone(),
        }
    }
}

#[derive(Clone)]
struct JwtAuthService<S> {
    inner: S,
    provider: Arc<dyn AuthProvider>,
    required_scopes: Vec<String>,
}

impl<S> tower::Service<Request> for JwtAuthService<S>
where
    S: tower::Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let provider = self.provider.clone();
        let required_scopes = self.required_scopes.clone();

        Box::pin(async move {
            let request_id = req
                .extensions()
                .get::<RequestId>()
                .map(|r| r.0.clone())
                .unwrap_or_else(|| Uuid::new_v4().to_string());

            match provider.authenticate(&req) {
                Ok(identity) => {
                    // ③ Scope verification: check required scopes
                    if !required_scopes.is_empty() {
                        let has_wildcard = identity.scopes.iter().any(|s| s == "*");
                        if !has_wildcard {
                            for scope in &required_scopes {
                                if !identity.scopes.contains(scope) {
                                    return Ok(error_response(
                                        StatusCode::FORBIDDEN,
                                        "insufficient_scopes",
                                        "Insufficient scopes",
                                        &request_id,
                                        false,
                                        None,
                                    ));
                                }
                            }
                        }
                    }
                    req.extensions_mut().insert(identity);
                    inner.call(req).await
                }
                Err(_) => Ok(error_response(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "Unauthorized",
                    &request_id,
                    false,
                    None,
                )),
            }
        })
    }
}

// ─── Rate Limit Layer (per-endpoint) ────────────────────────────────────────

#[derive(Clone)]
struct EndpointRateLimitLayer {
    backend: Arc<dyn RateLimitBackend>,
    max_requests: u32,
    window: Duration,
}

impl<S> Layer<S> for EndpointRateLimitLayer {
    type Service = EndpointRateLimitService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        EndpointRateLimitService {
            inner,
            backend: self.backend.clone(),
            max_requests: self.max_requests,
            window: self.window,
        }
    }
}

#[derive(Clone)]
struct EndpointRateLimitService<S> {
    inner: S,
    backend: Arc<dyn RateLimitBackend>,
    max_requests: u32,
    window: Duration,
}

impl<S> tower::Service<Request> for EndpointRateLimitService<S>
where
    S: tower::Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let backend = self.backend.clone();
        let max = self.max_requests;
        let window = self.window;

        Box::pin(async move {
            let key = get_rate_limit_key(&req);
            match backend.check(&key, max, window) {
                Ok(_remaining) => inner.call(req).await,
                Err(retry_after) => {
                    let request_id = req
                        .extensions()
                        .get::<RequestId>()
                        .map(|r| r.0.clone())
                        .unwrap_or_else(|| Uuid::new_v4().to_string());
                    let mut resp = error_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        "rate_limit_exceeded",
                        "Rate limit exceeded",
                        &request_id,
                        true,
                        None,
                    );
                    if let Ok(val) = HeaderValue::from_str(&retry_after.to_string()) {
                        resp.headers_mut()
                            .insert(HeaderName::from_static("retry-after"), val);
                    }
                    Ok(resp)
                }
            }
        })
    }
}

// ─── Panic Handler ───────────────────────────────────────────────────────────

/// Handle panics from handlers by returning a structured 500 JSON response.
fn panic_handler(_err: Box<dyn std::any::Any + Send + 'static>) -> Response<Body> {
    let request_id = Uuid::new_v4().to_string();
    tracing::error!(request_id = %request_id, "handler panicked");
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "Internal server error",
        &request_id,
        false,
        None,
    )
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Extract a rate limit key from the request (client IP or fallback).
fn get_rate_limit_key(req: &Request) -> String {
    req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').next().unwrap_or("unknown").trim().to_string())
        .or_else(|| {
            req.headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}
