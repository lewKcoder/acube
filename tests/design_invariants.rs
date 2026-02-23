//! Design invariant tests — codified guarantees that make acube "acube".
//!
//! These tests verify the framework's security-by-default design principles,
//! NOT individual feature behavior. Some overlap with functional tests is
//! intentional: if a functional test breaks, it's a bug; if a design invariant
//! test breaks, acube's security contract is violated.

use acube::prelude::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

// ─── Auth provider: 3 tokens ─────────────────────────────────────────────────

struct InvariantAuth;

impl AuthProvider for InvariantAuth {
    fn authenticate(
        &self,
        req: &axum::http::Request<axum::body::Body>,
    ) -> Result<AuthIdentity, acube::security::AuthError> {
        let header = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(acube::security::AuthError::MissingToken)?;

        if !header.starts_with("Bearer ") {
            return Err(acube::security::AuthError::InvalidToken);
        }
        let token = &header[7..];

        match token {
            "valid-token" => Ok(AuthIdentity {
                subject: "test-user".to_string(),
                scopes: vec!["items:write".to_string()],
                role: Some("admin".to_string()),
            }),
            "no-write-token" => Ok(AuthIdentity {
                subject: "test-user".to_string(),
                scopes: vec!["items:read".to_string()],
                role: None,
            }),
            "no-role-token" => Ok(AuthIdentity {
                subject: "test-user".to_string(),
                scopes: vec![],
                role: Some("viewer".to_string()),
            }),
            _ => Err(acube::security::AuthError::InvalidToken),
        }
    }
}

// ─── Schema ──────────────────────────────────────────────────────────────────

#[derive(AcubeSchema, Debug, Deserialize)]
struct InvariantInput {
    #[acube(min_length = 1, max_length = 50)]
    #[acube(sanitize(trim))]
    pub name: String,
}

// ─── Endpoints ───────────────────────────────────────────────────────────────

#[acube_endpoint(GET "/health")]
#[acube_security(none)]
#[acube_authorize(public)]
#[acube_rate_limit(none)]
async fn health(_ctx: AcubeContext) -> AcubeResult<Json<HealthStatus>, Never> {
    Ok(Json(HealthStatus::ok("test")))
}

#[acube_endpoint(GET "/panic")]
#[acube_security(none)]
#[acube_authorize(public)]
#[acube_rate_limit(none)]
async fn panic_endpoint(_ctx: AcubeContext) -> AcubeResult<Json<serde_json::Value>, Never> {
    panic!("secret internal: /src/handler.rs line 42 in crate::routes::user_service");
}

#[acube_endpoint(POST "/validated")]
#[acube_security(jwt)]
#[acube_authorize(scopes = ["items:write"])]
#[acube_rate_limit(none)]
async fn validated(
    _ctx: AcubeContext,
    input: Valid<InvariantInput>,
) -> AcubeResult<Created<serde_json::Value>, Never> {
    let input = input.into_inner();
    Ok(Created(serde_json::json!({"name": input.name})))
}

#[acube_endpoint(GET "/default-rate")]
#[acube_security(none)]
#[acube_authorize(public)]
async fn default_rate(_ctx: AcubeContext) -> AcubeResult<Json<serde_json::Value>, Never> {
    Ok(Json(serde_json::json!({"ok": true})))
}

#[acube_endpoint(GET "/scoped")]
#[acube_security(jwt)]
#[acube_authorize(scopes = ["secret:scope"])]
#[acube_rate_limit(none)]
async fn scoped(_ctx: AcubeContext) -> AcubeResult<Json<serde_json::Value>, Never> {
    Ok(Json(serde_json::json!({"scoped": true})))
}

#[acube_endpoint(GET "/role-protected")]
#[acube_security(jwt)]
#[acube_authorize(role = "secret_admin")]
#[acube_rate_limit(none)]
async fn role_protected(_ctx: AcubeContext) -> AcubeResult<Json<serde_json::Value>, Never> {
    Ok(Json(serde_json::json!({"role": true})))
}

// ─── Service builders ────────────────────────────────────────────────────────

fn build_invariant_service() -> acube::runtime::Service {
    Service::builder()
        .name("invariant-test")
        .version("0.1.0")
        .endpoint(health())
        .endpoint(panic_endpoint())
        .endpoint(validated())
        .endpoint(scoped())
        .endpoint(role_protected())
        .auth(InvariantAuth)
        .build()
        .expect("failed to build invariant service")
}

fn build_default_rate_service() -> acube::runtime::Service {
    Service::builder()
        .name("default-rate-test")
        .version("0.1.0")
        .endpoint(default_rate())
        .build()
        .expect("failed to build default rate service")
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn body_string(resp: axum::http::Response<Body>) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn assert_body_excludes(body: &str, forbidden: &str, principle: &str) {
    assert!(
        !body.to_lowercase().contains(&forbidden.to_lowercase()),
        "Principle {principle} violated: response body contains \"{forbidden}\""
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Principle 1: Security headers are ALWAYS present on every response
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn invariant_1_security_headers_always_present() {
    let router = build_invariant_service().into_router();
    // Use a security:none endpoint — headers must still be present
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // All 7 security headers with exact values
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff",
        "Principle 1: X-Content-Type-Options missing or wrong"
    );
    assert_eq!(
        resp.headers().get("x-frame-options").unwrap(),
        "DENY",
        "Principle 1: X-Frame-Options missing or wrong"
    );
    assert_eq!(
        resp.headers().get("x-xss-protection").unwrap(),
        "0",
        "Principle 1: X-XSS-Protection missing or wrong"
    );
    assert_eq!(
        resp.headers().get("strict-transport-security").unwrap(),
        "max-age=63072000; includeSubDomains; preload",
        "Principle 1: Strict-Transport-Security missing or wrong"
    );
    assert_eq!(
        resp.headers().get("content-security-policy").unwrap(),
        "default-src 'none'; frame-ancestors 'none'",
        "Principle 1: Content-Security-Policy missing or wrong"
    );
    assert_eq!(
        resp.headers().get("referrer-policy").unwrap(),
        "strict-origin-when-cross-origin",
        "Principle 1: Referrer-Policy missing or wrong"
    );
    assert_eq!(
        resp.headers().get("permissions-policy").unwrap(),
        "camera=(), microphone=(), geolocation=()",
        "Principle 1: Permissions-Policy missing or wrong"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Principle 2: Security/authorize attributes are mandatory (compile-time)
//
// Enforced by compile_fail tests in tests/endpoint_compile_tests.rs.
// This cannot be tested at runtime — if it compiles, the invariant holds.
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// Principle 3: Panics never leak internal information
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn invariant_3_panic_response_leaks_nothing() {
    let router = build_invariant_service().into_router();
    let req = Request::builder()
        .uri("/panic")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body = body_string(resp).await;

    // None of these internal-looking strings should appear in the response
    for forbidden in &[
        "/src/",
        ".rs",
        "panicked",
        "handler.rs",
        "line 42",
        "crate::",
        "secret internal",
        "user_service",
        "thread",
        "stack",
        "backtrace",
    ] {
        assert_body_excludes(&body, forbidden, "3 (panic non-leakage)");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Principle 4: Unknown fields in input are always rejected
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn invariant_4_unknown_fields_rejected() {
    let router = build_invariant_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/validated")
        .header("authorization", "Bearer valid-token")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"ok","is_admin":true}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "Principle 4: unknown field 'is_admin' must be rejected"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Principle 5: Rate limiting is enabled by default (100/min)
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn invariant_5_rate_limit_default_enabled() {
    let router = build_default_rate_service().into_router();
    let req = Request::builder()
        .uri("/default-rate")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    assert_eq!(
        resp.headers()
            .get("x-ratelimit-limit")
            .expect("Principle 5: x-ratelimit-limit header missing")
            .to_str()
            .unwrap(),
        "100",
        "Principle 5: default rate limit must be 100/min"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Principle 6: CORS default denies all origins
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn invariant_6_cors_default_deny_all() {
    // Service built WITHOUT cors_allow_origins
    let router = build_default_rate_service().into_router();
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/default-rate")
        .header("origin", "https://attacker.com")
        .header("access-control-request-method", "GET")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();

    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "Principle 6: CORS must deny all origins by default"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Principle 7: Validation errors expose field names only, not values or rules
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn invariant_7_validation_errors_field_names_only() {
    let router = build_invariant_service().into_router();
    // Send a value that violates max_length (50)
    let long_name = "x".repeat(100);
    let body = format!(r#"{{"name":"{}"}}"#, long_name);
    let req = Request::builder()
        .method("POST")
        .uri("/validated")
        .header("authorization", "Bearer valid-token")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let json = body_json(resp).await;
    let body_str = serde_json::to_string(&json).unwrap();

    // Field name "name" should appear (it identifies *which* field failed)
    assert!(
        body_str.contains("name"),
        "Principle 7: validation error should mention the field name"
    );

    // The actual input value should NOT appear
    assert_body_excludes(&body_str, &"x".repeat(100), "7 (input value leakage)");

    // Constraint details should NOT appear
    for forbidden in &["max_length", "min_length", "50", "pattern"] {
        assert_body_excludes(&body_str, forbidden, "7 (constraint leakage)");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Principle 8: 403 responses never reveal required scopes or roles
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn invariant_8a_forbidden_hides_required_scope() {
    let router = build_invariant_service().into_router();
    // no-write-token has items:read, but /scoped requires secret:scope
    let req = Request::builder()
        .uri("/scoped")
        .header("authorization", "Bearer no-write-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body = body_string(resp).await;
    assert_body_excludes(&body, "secret:scope", "8a (scope leakage)");
}

#[tokio::test]
async fn invariant_8b_forbidden_hides_required_role() {
    let router = build_invariant_service().into_router();
    // no-role-token has role "viewer", but /role-protected requires "secret_admin"
    let req = Request::builder()
        .uri("/role-protected")
        .header("authorization", "Bearer no-role-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body = body_string(resp).await;
    assert_body_excludes(&body, "secret_admin", "8b (role leakage)");
}
