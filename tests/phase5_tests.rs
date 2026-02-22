//! Phase 5 tests — CORS, real JWT validation, deserialization error sanitization.

use a3::prelude::*;
use a3::security::{JwtAuth, JwtClaims, ScopeClaim};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use jsonwebtoken::{EncodingKey, Header};
use tower::ServiceExt;

// ─── JWT token helpers ──────────────────────────────────────────────────────

const TEST_SECRET: &str = "test-secret-key-for-unit-tests";

fn make_jwt(sub: &str, scopes: Vec<String>, exp: Option<u64>) -> String {
    let claims = JwtClaims {
        sub: sub.to_string(),
        scopes: ScopeClaim(scopes),
        exp,
        iat: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ),
    };
    jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
    )
    .unwrap()
}

fn make_valid_jwt(sub: &str, scopes: Vec<String>) -> String {
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600; // 1 hour from now
    make_jwt(sub, scopes, Some(exp))
}

fn make_expired_jwt(sub: &str) -> String {
    make_jwt(sub, vec!["*".to_string()], Some(1)) // Unix timestamp 1 = expired
}

// ─── Schema + Error + Endpoints ─────────────────────────────────────────────

#[derive(A3Schema, Debug, Deserialize)]
struct JwtTestInput {
    #[a3(min_length = 1, max_length = 100)]
    #[a3(sanitize(trim))]
    pub name: String,
}

#[derive(A3Error, Debug)]
enum JwtTestError {
    #[a3(status = 404, message = "Not found")]
    NotFound,
}

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
    input: Valid<JwtTestInput>,
) -> A3Result<Created<serde_json::Value>, JwtTestError> {
    let input = input.into_inner();
    Ok(Created(serde_json::json!({"name": input.name})))
}

#[a3_endpoint(GET "/items/:id")]
#[a3_security(jwt, scopes = ["items:read"])]
#[a3_rate_limit(none)]
async fn get_item(
    _ctx: A3Context,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> A3Result<Json<serde_json::Value>, JwtTestError> {
    Ok(Json(serde_json::json!({"id": id})))
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn build_jwt_service() -> a3::runtime::Service {
    Service::builder()
        .name("jwt-test")
        .version("0.1.0")
        .endpoint(health())
        .endpoint(create_item())
        .endpoint(get_item())
        .auth(JwtAuth::new(TEST_SECRET))
        .build()
        .expect("failed to build service")
}

fn build_cors_service(origins: &[&str]) -> a3::runtime::Service {
    Service::builder()
        .name("cors-test")
        .version("0.1.0")
        .endpoint(health())
        .cors_allow_origins(origins)
        .build()
        .expect("failed to build service")
}

fn build_default_cors_service() -> a3::runtime::Service {
    Service::builder()
        .name("cors-default-test")
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

// ─── Tests: JWT Real Validation ─────────────────────────────────────────────

#[tokio::test]
async fn jwt_valid_token_accepted() {
    let router = build_jwt_service().into_router();
    let token = make_valid_jwt("user-1", vec!["items:read".to_string()]);
    let req = Request::builder()
        .uri("/items/42")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp).await;
    assert_eq!(json["id"], "42");
}

#[tokio::test]
async fn jwt_expired_token_returns_401() {
    let router = build_jwt_service().into_router();
    let token = make_expired_jwt("user-1");
    let req = Request::builder()
        .uri("/items/42")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn jwt_invalid_signature_returns_401() {
    let router = build_jwt_service().into_router();
    // Token signed with a different secret
    let claims = JwtClaims {
        sub: "user-1".to_string(),
        scopes: ScopeClaim(vec!["items:read".to_string()]),
        exp: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
        ),
        iat: None,
    };
    let token = jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(b"wrong-secret"),
    )
    .unwrap();
    let req = Request::builder()
        .uri("/items/42")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_missing_token_returns_401() {
    let router = build_jwt_service().into_router();
    let req = Request::builder()
        .uri("/items/42")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_garbage_token_returns_401() {
    let router = build_jwt_service().into_router();
    let req = Request::builder()
        .uri("/items/42")
        .header("authorization", "Bearer not.a.jwt")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_scope_verification_403_on_missing_scope() {
    let router = build_jwt_service().into_router();
    // Token has items:read but endpoint requires items:write
    let token = make_valid_jwt("user-1", vec!["items:read".to_string()]);
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"test"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "insufficient_scopes");
}

#[tokio::test]
async fn jwt_wildcard_scope_grants_all() {
    let router = build_jwt_service().into_router();
    let token = make_valid_jwt("admin", vec!["*".to_string()]);
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"test"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn jwt_correct_scope_allows_access() {
    let router = build_jwt_service().into_router();
    let token = make_valid_jwt("user-1", vec!["items:write".to_string()]);
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"test"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn jwt_no_auth_endpoint_works_without_token() {
    let router = build_jwt_service().into_router();
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_comma_separated_scopes_accepted() {
    // Test that scopes can be a comma-separated string in the JWT
    let claims = serde_json::json!({
        "sub": "user-1",
        "scopes": "items:read,items:write",
        "exp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600
    });
    let token = jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
    )
    .unwrap();

    let router = build_jwt_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"test"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn jwt_error_does_not_leak_internal_info() {
    let router = build_jwt_service().into_router();
    let req = Request::builder()
        .uri("/items/42")
        .header("authorization", "Bearer invalid.token.here")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let json = body_json(resp).await;
    // Should not contain internal error details
    assert_eq!(json["error"]["message"], "Unauthorized");
    assert!(json["error"]["details"].is_null());
}

// ─── Tests: CORS ────────────────────────────────────────────────────────────

#[tokio::test]
async fn cors_default_denies_cross_origin() {
    let router = build_default_cors_service().into_router();
    // Preflight request from unknown origin
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/health")
        .header("origin", "https://evil.com")
        .header("access-control-request-method", "GET")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    // No access-control-allow-origin header = browser blocks the request
    assert!(resp.headers().get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn cors_configured_origins_allowed() {
    let router = build_cors_service(&["https://myapp.com"]).into_router();
    // Preflight request from allowed origin
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/health")
        .header("origin", "https://myapp.com")
        .header("access-control-request-method", "GET")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        "https://myapp.com"
    );
}

#[tokio::test]
async fn cors_unlisted_origin_denied() {
    let router = build_cors_service(&["https://myapp.com"]).into_router();
    // Preflight from unlisted origin
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/health")
        .header("origin", "https://evil.com")
        .header("access-control-request-method", "GET")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert!(resp.headers().get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn cors_allows_configured_methods() {
    let router = build_cors_service(&["https://myapp.com"]).into_router();
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/health")
        .header("origin", "https://myapp.com")
        .header("access-control-request-method", "POST")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let methods = resp
        .headers()
        .get("access-control-allow-methods")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(methods.contains("POST"));
}

#[tokio::test]
async fn cors_allows_configured_headers() {
    let router = build_cors_service(&["https://myapp.com"]).into_router();
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/health")
        .header("origin", "https://myapp.com")
        .header("access-control-request-method", "POST")
        .header(
            "access-control-request-headers",
            "content-type,authorization",
        )
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let headers = resp
        .headers()
        .get("access-control-allow-headers")
        .unwrap()
        .to_str()
        .unwrap()
        .to_lowercase();
    assert!(headers.contains("content-type"));
    assert!(headers.contains("authorization"));
}

#[tokio::test]
async fn cors_simple_request_includes_origin_header() {
    let router = build_cors_service(&["https://myapp.com"]).into_router();
    // Simple GET with Origin header (not preflight)
    let req = Request::builder()
        .uri("/health")
        .header("origin", "https://myapp.com")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        "https://myapp.com"
    );
}

// ─── Tests: RS256 JWT ───────────────────────────────────────────────────────

const RSA_PRIVATE_KEY: &[u8] = include_bytes!("test_keys/rsa_private.pem");
const RSA_PUBLIC_KEY: &[u8] = include_bytes!("test_keys/rsa_public.pem");

fn make_rs256_jwt(sub: &str, scopes: Vec<String>) -> String {
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let claims = JwtClaims {
        sub: sub.to_string(),
        scopes: ScopeClaim(scopes),
        exp: Some(exp),
        iat: None,
    };
    jsonwebtoken::encode(
        &Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY).unwrap(),
    )
    .unwrap()
}

fn build_rs256_service() -> a3::runtime::Service {
    Service::builder()
        .name("rs256-test")
        .version("0.1.0")
        .endpoint(health())
        .endpoint(get_item())
        .auth(JwtAuth::from_rsa_pem(RSA_PUBLIC_KEY).unwrap())
        .build()
        .expect("failed to build RS256 service")
}

#[tokio::test]
async fn rs256_valid_token_accepted() {
    let router = build_rs256_service().into_router();
    let token = make_rs256_jwt("user-1", vec!["items:read".to_string()]);
    let req = Request::builder()
        .uri("/items/99")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["id"], "99");
}

#[tokio::test]
async fn rs256_hs256_token_rejected() {
    // An HS256 token should be rejected by RS256 auth
    let router = build_rs256_service().into_router();
    let token = make_valid_jwt("user-1", vec!["items:read".to_string()]);
    let req = Request::builder()
        .uri("/items/42")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rs256_scope_verification_works() {
    let router = build_rs256_service().into_router();
    // Token has "admin" scope, endpoint requires "items:read"
    let token = make_rs256_jwt("user-1", vec!["admin".to_string()]);
    let req = Request::builder()
        .uri("/items/42")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ─── Tests: ES256 JWT ───────────────────────────────────────────────────────

const EC_PRIVATE_KEY: &[u8] = include_bytes!("test_keys/ec_private.pem");
const EC_PUBLIC_KEY: &[u8] = include_bytes!("test_keys/ec_public.pem");

fn make_es256_jwt(sub: &str, scopes: Vec<String>) -> String {
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let claims = JwtClaims {
        sub: sub.to_string(),
        scopes: ScopeClaim(scopes),
        exp: Some(exp),
        iat: None,
    };
    jsonwebtoken::encode(
        &Header::new(jsonwebtoken::Algorithm::ES256),
        &claims,
        &EncodingKey::from_ec_pem(EC_PRIVATE_KEY).unwrap(),
    )
    .unwrap()
}

fn build_es256_service() -> a3::runtime::Service {
    Service::builder()
        .name("es256-test")
        .version("0.1.0")
        .endpoint(health())
        .endpoint(get_item())
        .auth(JwtAuth::from_ec_pem(EC_PUBLIC_KEY).unwrap())
        .build()
        .expect("failed to build ES256 service")
}

#[tokio::test]
async fn es256_valid_token_accepted() {
    let router = build_es256_service().into_router();
    let token = make_es256_jwt("user-1", vec!["items:read".to_string()]);
    let req = Request::builder()
        .uri("/items/77")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["id"], "77");
}

#[tokio::test]
async fn es256_hs256_token_rejected() {
    let router = build_es256_service().into_router();
    let token = make_valid_jwt("user-1", vec!["items:read".to_string()]);
    let req = Request::builder()
        .uri("/items/42")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn es256_rs256_token_rejected() {
    let router = build_es256_service().into_router();
    let token = make_rs256_jwt("user-1", vec!["items:read".to_string()]);
    let req = Request::builder()
        .uri("/items/42")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── Tests: JwtAuth Error Cases ─────────────────────────────────────────────

#[test]
fn jwt_auth_invalid_rsa_pem_returns_error() {
    let result = JwtAuth::from_rsa_pem(b"not a valid pem");
    assert!(result.is_err());
}

#[test]
fn jwt_auth_invalid_ec_pem_returns_error() {
    let result = JwtAuth::from_ec_pem(b"not a valid pem");
    assert!(result.is_err());
}

// ─── Tests: Deserialization Error Sanitization ──────────────────────────────

#[tokio::test]
async fn deserialization_error_does_not_leak_schema() {
    let router = build_jwt_service().into_router();
    let token = make_valid_jwt("user-1", vec!["items:write".to_string()]);
    // Send invalid type (number instead of string for "name")
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name": 12345}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "deserialization_error");
    // Should NOT contain "expected a string", field names, or serde internals
    assert_eq!(json["error"]["message"], "Invalid request body");
}
