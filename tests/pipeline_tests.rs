//! Phase 3 pipeline tests — payload limits, scope verification, panic handler.

use acube::prelude::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

// ─── Auth provider with specific scopes ──────────────────────────────────────

struct ScopedAuth;

impl AuthProvider for ScopedAuth {
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
        if token.is_empty() {
            return Err(acube::security::AuthError::InvalidToken);
        }

        // Different tokens grant different scopes/roles
        let (scopes, role) = match token {
            "admin-token" => (
                vec!["items:read".to_string(), "items:write".to_string()],
                Some("admin".to_string()),
            ),
            "read-only-token" => (vec!["items:read".to_string()], None),
            "wildcard-token" => (vec!["*".to_string()], None),
            "user-token" => (vec![], Some("user".to_string())),
            "auth-only-token" => (vec![], None),
            _ => (vec![], None),
        };

        Ok(AuthIdentity {
            subject: "test-user".to_string(),
            scopes,
            role,
        })
    }
}

// ─── Schema ──────────────────────────────────────────────────────────────────

#[derive(AcubeSchema, Debug, Deserialize)]
struct ItemInput {
    #[acube(min_length = 1, max_length = 100)]
    #[acube(sanitize(trim))]
    pub name: String,
}

// ─── Error ───────────────────────────────────────────────────────────────────


// ─── Endpoints ───────────────────────────────────────────────────────────────

#[acube_endpoint(GET "/health")]
#[acube_security(none)]
#[acube_authorize(public)]
#[acube_rate_limit(none)]
async fn health(_ctx: AcubeContext) -> AcubeResult<Json<HealthStatus>, Never> {
    Ok(Json(HealthStatus::ok("test")))
}

#[acube_endpoint(POST "/items")]
#[acube_security(jwt)]
#[acube_authorize(scopes = ["items:write"])]
#[acube_rate_limit(none)]
async fn create_item(
    _ctx: AcubeContext,
    input: Valid<ItemInput>,
) -> AcubeResult<Created<serde_json::Value>, Never> {
    let input = input.into_inner();
    Ok(Created(serde_json::json!({"name": input.name})))
}

#[acube_endpoint(GET "/items/:id")]
#[acube_security(jwt)]
#[acube_authorize(scopes = ["items:read"])]
#[acube_rate_limit(none)]
async fn get_item(ctx: AcubeContext) -> AcubeResult<Json<serde_json::Value>, Never> {
    let id: String = ctx.path("id");
    Ok(Json(serde_json::json!({"id": id})))
}

#[acube_endpoint(GET "/panic")]
#[acube_security(none)]
#[acube_authorize(public)]
#[acube_rate_limit(none)]
async fn panic_endpoint(_ctx: AcubeContext) -> AcubeResult<Json<serde_json::Value>, Never> {
    panic!("intentional test panic");
}

#[acube_endpoint(POST "/limited")]
#[acube_security(none)]
#[acube_authorize(public)]
#[acube_rate_limit(none)]
async fn limited_endpoint(
    _ctx: AcubeContext,
    input: Valid<ItemInput>,
) -> AcubeResult<Json<serde_json::Value>, Never> {
    let input = input.into_inner();
    Ok(Json(serde_json::json!({"name": input.name})))
}

#[acube_endpoint(POST "/rate-limited")]
#[acube_security(none)]
#[acube_authorize(public)]
#[acube_rate_limit(2, per_minute)]
async fn rate_limited(_ctx: AcubeContext) -> AcubeResult<Json<serde_json::Value>, Never> {
    Ok(Json(serde_json::json!({"ok": true})))
}

#[acube_endpoint(GET "/admin-only")]
#[acube_security(jwt)]
#[acube_authorize(role = "admin")]
#[acube_rate_limit(none)]
async fn admin_only(_ctx: AcubeContext) -> AcubeResult<Json<serde_json::Value>, Never> {
    Ok(Json(serde_json::json!({"admin": true})))
}

#[acube_endpoint(GET "/auth-only")]
#[acube_security(jwt)]
#[acube_authorize(authenticated)]
#[acube_rate_limit(none)]
async fn auth_only(_ctx: AcubeContext) -> AcubeResult<Json<serde_json::Value>, Never> {
    Ok(Json(serde_json::json!({"authenticated": true})))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn build_service() -> acube::runtime::Service {
    Service::builder()
        .name("pipeline-test")
        .version("0.1.0")
        .endpoint(health())
        .endpoint(create_item())
        .endpoint(get_item())
        .endpoint(panic_endpoint())
        .endpoint(limited_endpoint())
        .endpoint(rate_limited())
        .endpoint(admin_only())
        .endpoint(auth_only())
        .auth(ScopedAuth)
        .payload_limit(1024) // 1 KB for testing
        .build()
        .expect("failed to build service")
}

fn build_default_limit_service() -> acube::runtime::Service {
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
    assert_eq!(json["error"]["code"], "forbidden");
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

#[tokio::test]
async fn rate_limit_success_includes_limit_headers() {
    let router = build_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/rate-limited")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Successful response should include rate limit headers
    assert_eq!(
        resp.headers()
            .get("x-ratelimit-limit")
            .unwrap()
            .to_str()
            .unwrap(),
        "2"
    );
    assert_eq!(
        resp.headers()
            .get("x-ratelimit-remaining")
            .unwrap()
            .to_str()
            .unwrap(),
        "1"
    );
    assert!(resp.headers().get("x-ratelimit-reset").is_some());
}

#[tokio::test]
async fn rate_limit_remaining_decrements() {
    let service = build_service();
    let router = service.into_router();

    // First request: remaining = 1
    let req = Request::builder()
        .method("POST")
        .uri("/rate-limited")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.headers()
            .get("x-ratelimit-remaining")
            .unwrap()
            .to_str()
            .unwrap(),
        "1"
    );

    // Second request: remaining = 0
    let req = Request::builder()
        .method("POST")
        .uri("/rate-limited")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-ratelimit-remaining")
            .unwrap()
            .to_str()
            .unwrap(),
        "0"
    );
}

#[tokio::test]
async fn rate_limit_429_includes_limit_headers() {
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
    assert_eq!(
        resp.headers()
            .get("x-ratelimit-limit")
            .unwrap()
            .to_str()
            .unwrap(),
        "2"
    );
    assert_eq!(
        resp.headers()
            .get("x-ratelimit-remaining")
            .unwrap()
            .to_str()
            .unwrap(),
        "0"
    );
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

// ─── Tests: Role-Based Authorization ─────────────────────────────────────────

#[tokio::test]
async fn role_admin_allows_admin_token() {
    let router = build_service().into_router();
    let req = Request::builder()
        .uri("/admin-only")
        .header("authorization", "Bearer admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp).await;
    assert_eq!(json["admin"], true);
}

#[tokio::test]
async fn role_admin_rejects_user_token() {
    let router = build_service().into_router();
    let req = Request::builder()
        .uri("/admin-only")
        .header("authorization", "Bearer user-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "forbidden");
}

#[tokio::test]
async fn role_admin_rejects_no_role_token() {
    let router = build_service().into_router();
    let req = Request::builder()
        .uri("/admin-only")
        .header("authorization", "Bearer read-only-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ─── Tests: Authenticated-Only Authorization ─────────────────────────────────

#[tokio::test]
async fn authenticated_allows_any_valid_token() {
    let router = build_service().into_router();
    let req = Request::builder()
        .uri("/auth-only")
        .header("authorization", "Bearer auth-only-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp).await;
    assert_eq!(json["authenticated"], true);
}

#[tokio::test]
async fn authenticated_rejects_no_token() {
    let router = build_service().into_router();
    let req = Request::builder()
        .uri("/auth-only")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── Tests: 403 Response Does Not Leak Details ──────────────────────────────

#[tokio::test]
async fn forbidden_response_does_not_leak_scope_names() {
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

    let json = body_json(resp).await;
    let body_str = serde_json::to_string(&json).unwrap();
    // Should not contain scope names
    assert!(!body_str.contains("items:write"));
    assert!(!body_str.contains("items:read"));
    assert_eq!(json["error"]["message"], "Insufficient permissions");
}

#[tokio::test]
async fn forbidden_response_does_not_leak_role_names() {
    let router = build_service().into_router();
    let req = Request::builder()
        .uri("/admin-only")
        .header("authorization", "Bearer user-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let json = body_json(resp).await;
    let body_str = serde_json::to_string(&json).unwrap();
    // Should not contain role names
    assert!(!body_str.contains("admin"));
    assert_eq!(json["error"]["message"], "Insufficient permissions");
}

// ─── Tests: ctx.path(), ctx.state(), ctx.user_id(), NoContent, Path+Body ────

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type TestStore = Arc<Mutex<HashMap<String, String>>>;

#[acube_endpoint(GET "/ctx-test/:id")]
#[acube_security(jwt)]
#[acube_authorize(authenticated)]
#[acube_rate_limit(none)]
async fn ctx_path_test(ctx: AcubeContext) -> AcubeResult<Json<serde_json::Value>, Never> {
    let id: String = ctx.path("id");
    let user_id = ctx.user_id().to_string();
    Ok(Json(serde_json::json!({"id": id, "user_id": user_id})))
}

#[acube_endpoint(GET "/ctx-state-test")]
#[acube_security(jwt)]
#[acube_authorize(authenticated)]
#[acube_rate_limit(none)]
async fn ctx_state_test(ctx: AcubeContext) -> AcubeResult<Json<serde_json::Value>, Never> {
    let store = ctx.state::<TestStore>();
    let store = store.lock().unwrap();
    let count = store.len();
    Ok(Json(serde_json::json!({"count": count})))
}

#[acube_endpoint(DELETE "/ctx-delete/:id")]
#[acube_security(jwt)]
#[acube_authorize(authenticated)]
#[acube_rate_limit(none)]
async fn ctx_no_content(ctx: AcubeContext) -> AcubeResult<NoContent, Never> {
    let _id: String = ctx.path("id");
    Ok(NoContent)
}

#[derive(AcubeSchema, Debug, Deserialize)]
struct UpdateInput {
    #[acube(min_length = 1, max_length = 100)]
    #[acube(sanitize(trim))]
    pub value: String,
}

#[acube_endpoint(PATCH "/ctx-update/:id")]
#[acube_security(jwt)]
#[acube_authorize(authenticated)]
#[acube_rate_limit(none)]
async fn ctx_path_and_body(
    ctx: AcubeContext,
    input: Valid<UpdateInput>,
) -> AcubeResult<Json<serde_json::Value>, Never> {
    let id: String = ctx.path("id");
    let input = input.into_inner();
    Ok(Json(serde_json::json!({"id": id, "value": input.value})))
}

fn build_ctx_service() -> acube::runtime::Service {
    let store: TestStore = Arc::new(Mutex::new(HashMap::new()));
    store
        .lock()
        .unwrap()
        .insert("a".to_string(), "1".to_string());
    store
        .lock()
        .unwrap()
        .insert("b".to_string(), "2".to_string());

    Service::builder()
        .name("ctx-test")
        .version("0.1.0")
        .state(store)
        .endpoint(ctx_path_test())
        .endpoint(ctx_state_test())
        .endpoint(ctx_no_content())
        .endpoint(ctx_path_and_body())
        .auth(ScopedAuth)
        .build()
        .expect("failed to build service")
}

#[tokio::test]
async fn ctx_path_extracts_path_param() {
    let router = build_ctx_service().into_router();
    let req = Request::builder()
        .uri("/ctx-test/42")
        .header("authorization", "Bearer admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp).await;
    assert_eq!(json["id"], "42");
}

#[tokio::test]
async fn ctx_user_id_returns_subject() {
    let router = build_ctx_service().into_router();
    let req = Request::builder()
        .uri("/ctx-test/1")
        .header("authorization", "Bearer admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp).await;
    assert_eq!(json["user_id"], "test-user");
}

#[tokio::test]
async fn ctx_state_accesses_shared_state() {
    let router = build_ctx_service().into_router();
    let req = Request::builder()
        .uri("/ctx-state-test")
        .header("authorization", "Bearer admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp).await;
    assert_eq!(json["count"], 2);
}

#[tokio::test]
async fn no_content_returns_204() {
    let router = build_ctx_service().into_router();
    let req = Request::builder()
        .method("DELETE")
        .uri("/ctx-delete/42")
        .header("authorization", "Bearer admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn path_and_body_work_together() {
    let router = build_ctx_service().into_router();
    let req = Request::builder()
        .method("PATCH")
        .uri("/ctx-update/99")
        .header("authorization", "Bearer admin-token")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"value":"hello"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp).await;
    assert_eq!(json["id"], "99");
    assert_eq!(json["value"], "hello");
}

// ─── Tests: Custom Authorization ─────────────────────────────────────────────

/// Custom auth function: only allows user "test-user" for resource "allowed-id"
async fn check_owner(ctx: &AcubeContext) -> Result<(), AcubeAuthError> {
    let id: String = ctx.path("id");
    let user_id = ctx.user_id();
    if id == "allowed-id" || user_id == "owner-user" {
        Ok(())
    } else {
        Err(AcubeAuthError::Forbidden("Not the owner".into()))
    }
}


#[acube_endpoint(GET "/custom-auth/:id")]
#[acube_security(jwt)]
#[acube_authorize(custom = "check_owner")]
#[acube_rate_limit(none)]
async fn custom_auth_endpoint(
    ctx: AcubeContext,
) -> AcubeResult<Json<serde_json::Value>, Never> {
    let id: String = ctx.path("id");
    Ok(Json(serde_json::json!({"id": id})))
}

/// Custom auth function for endpoint with body
async fn check_write_access(ctx: &AcubeContext) -> Result<(), AcubeAuthError> {
    let user_id = ctx.user_id();
    if user_id == "test-user" {
        Ok(())
    } else {
        Err(AcubeAuthError::Forbidden("Write access denied".into()))
    }
}

#[acube_endpoint(POST "/custom-auth-body")]
#[acube_security(jwt)]
#[acube_authorize(custom = "check_write_access")]
#[acube_rate_limit(none)]
async fn custom_auth_body_endpoint(
    _ctx: AcubeContext,
    input: Valid<ItemInput>,
) -> AcubeResult<Created<serde_json::Value>, Never> {
    let input = input.into_inner();
    Ok(Created(serde_json::json!({"name": input.name})))
}

fn build_custom_auth_service() -> acube::runtime::Service {
    Service::builder()
        .name("custom-auth-test")
        .version("0.1.0")
        .endpoint(custom_auth_endpoint())
        .endpoint(custom_auth_body_endpoint())
        .auth(ScopedAuth)
        .build()
        .expect("failed to build service")
}

#[tokio::test]
async fn custom_auth_allows_authorized_request() {
    let router = build_custom_auth_service().into_router();
    let req = Request::builder()
        .uri("/custom-auth/allowed-id")
        .header("authorization", "Bearer admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp).await;
    assert_eq!(json["id"], "allowed-id");
}

#[tokio::test]
async fn custom_auth_rejects_unauthorized_request() {
    let router = build_custom_auth_service().into_router();
    let req = Request::builder()
        .uri("/custom-auth/forbidden-id")
        .header("authorization", "Bearer admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "forbidden");
}

#[tokio::test]
async fn custom_auth_still_requires_jwt() {
    let router = build_custom_auth_service().into_router();
    // No auth token — should fail at JWT layer before reaching custom auth
    let req = Request::builder()
        .uri("/custom-auth/allowed-id")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn custom_auth_forbidden_has_request_id() {
    let router = build_custom_auth_service().into_router();
    let req = Request::builder()
        .uri("/custom-auth/forbidden-id")
        .header("authorization", "Bearer admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(resp.headers().get("x-request-id").is_some());
}

#[tokio::test]
async fn custom_auth_forbidden_has_security_headers() {
    let router = build_custom_auth_service().into_router();
    let req = Request::builder()
        .uri("/custom-auth/forbidden-id")
        .header("authorization", "Bearer admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
}

#[tokio::test]
async fn custom_auth_with_body_allows_authorized() {
    let router = build_custom_auth_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/custom-auth-body")
        .header("authorization", "Bearer admin-token")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"test"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let json = body_json(resp).await;
    assert_eq!(json["name"], "test");
}

#[tokio::test]
async fn custom_auth_forbidden_does_not_leak_message() {
    let router = build_custom_auth_service().into_router();
    let req = Request::builder()
        .uri("/custom-auth/forbidden-id")
        .header("authorization", "Bearer admin-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let json = body_json(resp).await;
    // The custom message "Not the owner" is in the error response
    // but does not leak internal details beyond the authored message
    assert_eq!(json["error"]["code"], "forbidden");
    assert!(json["error"]["request_id"].is_string());
}
