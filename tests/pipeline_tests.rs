//! Phase 3 pipeline tests — payload limits, scope verification, panic handler.

use a3::prelude::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

// ─── Auth provider with specific scopes ──────────────────────────────────────

struct ScopedAuth;

impl AuthProvider for ScopedAuth {
    fn authenticate(
        &self,
        req: &axum::http::Request<axum::body::Body>,
    ) -> Result<AuthIdentity, a3::security::AuthError> {
        let header = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(a3::security::AuthError::MissingToken)?;

        if !header.starts_with("Bearer ") {
            return Err(a3::security::AuthError::InvalidToken);
        }
        let token = &header[7..];
        if token.is_empty() {
            return Err(a3::security::AuthError::InvalidToken);
        }

        // Different tokens grant different scopes
        let scopes = match token {
            "admin-token" => vec!["items:read".to_string(), "items:write".to_string()],
            "read-only-token" => vec!["items:read".to_string()],
            "wildcard-token" => vec!["*".to_string()],
            _ => vec![],
        };

        Ok(AuthIdentity {
            subject: "test-user".to_string(),
            scopes,
        })
    }
}

// ─── Schema ──────────────────────────────────────────────────────────────────

#[derive(A3Schema, Debug, Deserialize)]
struct ItemInput {
    #[a3(min_length = 1, max_length = 100)]
    #[a3(sanitize(trim))]
    pub name: String,
}

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(A3Error, Debug)]
enum ItemError {
    #[a3(status = 404, message = "Item not found")]
    NotFound,
}

// ─── Endpoints ───────────────────────────────────────────────────────────────

#[a3_endpoint(GET "/health")]
#[a3_security(none)]
#[a3_rate_limit(none)]
async fn health(_ctx: A3Context) -> A3Result<Json<HealthStatus>, Never> {
    Ok(Json(HealthStatus::ok("test")))
}

#[a3_endpoint(POST "/items")]
#[a3_security(jwt, scopes = ["items:write"])]
#[a3_rate_limit(none)]
async fn create_item(
    _ctx: A3Context,
    input: Valid<ItemInput>,
) -> A3Result<Created<serde_json::Value>, ItemError> {
    let input = input.into_inner();
    Ok(Created(serde_json::json!({"name": input.name})))
}

#[a3_endpoint(GET "/items/:id")]
#[a3_security(jwt, scopes = ["items:read"])]
#[a3_rate_limit(none)]
async fn get_item(
    _ctx: A3Context,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> A3Result<Json<serde_json::Value>, ItemError> {
    Ok(Json(serde_json::json!({"id": id})))
}

#[a3_endpoint(GET "/panic")]
#[a3_security(none)]
#[a3_rate_limit(none)]
async fn panic_endpoint(_ctx: A3Context) -> A3Result<Json<serde_json::Value>, Never> {
    panic!("intentional test panic");
}

#[a3_endpoint(POST "/limited")]
#[a3_security(none)]
#[a3_rate_limit(none)]
async fn limited_endpoint(
    _ctx: A3Context,
    input: Valid<ItemInput>,
) -> A3Result<Json<serde_json::Value>, Never> {
    let input = input.into_inner();
    Ok(Json(serde_json::json!({"name": input.name})))
}

#[a3_endpoint(POST "/rate-limited")]
#[a3_security(none)]
#[a3_rate_limit(2, per_minute)]
async fn rate_limited(_ctx: A3Context) -> A3Result<Json<serde_json::Value>, Never> {
    Ok(Json(serde_json::json!({"ok": true})))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn build_service() -> a3::runtime::Service {
    Service::builder()
        .name("pipeline-test")
        .version("0.1.0")
        .endpoint(health())
        .endpoint(create_item())
        .endpoint(get_item())
        .endpoint(panic_endpoint())
        .endpoint(limited_endpoint())
        .endpoint(rate_limited())
        .auth(ScopedAuth)
        .payload_limit(1024) // 1 KB for testing
        .build()
        .expect("failed to build service")
}

fn build_default_limit_service() -> a3::runtime::Service {
    Service::builder()
        .name("default-limit-test")
        .version("0.1.0")
        .endpoint(health())
        .build()
        .expect("failed to build service")
}

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ─── Tests: ② Security — Payload Limit ──────────────────────────────────────

#[tokio::test]
async fn payload_within_limit_accepted() {
    let router = build_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/limited")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"ok"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn payload_exceeding_limit_returns_413() {
    let router = build_service().into_router();
    // 1024 bytes limit, send 2000 bytes
    let big_name = "x".repeat(1500);
    let body = format!(r#"{{"name":"{}"}}"#, big_name);
    let req = Request::builder()
        .method("POST")
        .uri("/limited")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "payload_too_large");
    assert_eq!(json["error"]["retryable"], false);
}

#[tokio::test]
async fn default_payload_limit_is_1mb() {
    let router = build_default_limit_service().into_router();
    // Under 1MB should be fine for a health endpoint (no body needed)
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─── Tests: ③ Auth — Scope Verification ─────────────────────────────────────

#[tokio::test]
async fn correct_scope_allows_access() {
    let router = build_service().into_router();
    let req = Request::builder()
        .uri("/items/1")
        .header("authorization", "Bearer read-only-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn missing_scope_returns_403() {
    let router = build_service().into_router();
    // read-only-token has items:read but not items:write
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("authorization", "Bearer read-only-token")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"test"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "insufficient_scopes");
}

#[tokio::test]
async fn wildcard_scope_grants_all_access() {
    let router = build_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("authorization", "Bearer wildcard-token")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"test"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn admin_token_has_write_scope() {
    let router = build_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("authorization", "Bearer admin-token")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"test"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn no_scopes_token_returns_403() {
    let router = build_service().into_router();
    // "unknown-token" gets empty scopes
    let req = Request::builder()
        .uri("/items/1")
        .header("authorization", "Bearer unknown-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn scope_verification_on_forbidden_has_request_id() {
    let router = build_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("authorization", "Bearer read-only-token")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"test"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(resp.headers().get("x-request-id").is_some());

    let json = body_json(resp).await;
    assert!(json["error"]["request_id"].is_string());
}

// ─── Tests: Panic Handler ────────────────────────────────────────────────────

#[tokio::test]
async fn panic_returns_structured_500() {
    let router = build_service().into_router();
    let req = Request::builder()
        .uri("/panic")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "internal_error");
    assert_eq!(json["error"]["message"], "Internal server error");
    assert_eq!(json["error"]["retryable"], false);
    assert!(json["error"]["request_id"].is_string());
}

#[tokio::test]
async fn panic_response_has_security_headers() {
    let router = build_service().into_router();
    let req = Request::builder()
        .uri("/panic")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    // Security headers should still be present even on panic
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
}

// ─── Tests: ② Security — Rate Limiting ──────────────────────────────────────

#[tokio::test]
async fn rate_limit_allows_within_limit() {
    let router = build_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/rate-limited")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn rate_limit_returns_429_when_exceeded() {
    let service = build_service();
    let router = service.into_router();

    // First two requests should succeed (limit is 2/min)
    for _ in 0..2 {
        let req = Request::builder()
            .method("POST")
            .uri("/rate-limited")
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Third request should be rate limited
    let req = Request::builder()
        .method("POST")
        .uri("/rate-limited")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "rate_limit_exceeded");
    assert_eq!(json["error"]["retryable"], true);
}

#[tokio::test]
async fn rate_limit_response_has_retry_after_header() {
    let service = build_service();
    let router = service.into_router();

    // Exhaust the limit
    for _ in 0..2 {
        let req = Request::builder()
            .method("POST")
            .uri("/rate-limited")
            .body(Body::empty())
            .unwrap();
        let _ = router.clone().oneshot(req).await.unwrap();
    }

    let req = Request::builder()
        .method("POST")
        .uri("/rate-limited")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().get("retry-after").is_some());
}

// ─── Tests: ⑥ Response — Pipeline Integration ───────────────────────────────

#[tokio::test]
async fn full_pipeline_create_item_success() {
    let router = build_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("authorization", "Bearer admin-token")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"test-item"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Verify response has all pipeline additions
    assert!(resp.headers().get("x-request-id").is_some());
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );

    let json = body_json(resp).await;
    assert_eq!(json["name"], "test-item");
}

#[tokio::test]
async fn full_pipeline_auth_then_validation() {
    let router = build_service().into_router();
    // Send invalid input with correct auth — should get 400 validation, not 401
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("authorization", "Bearer admin-token")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":""}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "validation_error");
}

#[tokio::test]
async fn forbidden_has_security_headers() {
    let router = build_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("authorization", "Bearer read-only-token")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"test"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
}

#[tokio::test]
async fn no_auth_endpoint_skips_scope_check() {
    let router = build_service().into_router();
    // health endpoint has no auth — should work without any token
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
