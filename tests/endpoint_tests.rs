//! Phase 2 integration tests — endpoint macros, auth enforcement, validation, structured errors.

use a3::prelude::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

// ─── Test auth provider ──────────────────────────────────────────────────────

struct TestAuth;

impl AuthProvider for TestAuth {
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

        Ok(AuthIdentity {
            subject: "test-user".to_string(),
            scopes: vec!["users:create".to_string(), "users:read".to_string()],
            role: None,
        })
    }
}

// ─── Test schema ─────────────────────────────────────────────────────────────

#[derive(A3Schema, Debug, Deserialize)]
struct TestInput {
    #[a3(min_length = 3, max_length = 30)]
    #[a3(sanitize(trim))]
    pub name: String,

    #[a3(format = "email")]
    #[a3(sanitize(trim, lowercase))]
    pub email: String,
}

// ─── Test error ──────────────────────────────────────────────────────────────

#[derive(A3Error, Debug)]
enum TestError {
    #[a3(status = 404, message = "Not found")]
    NotFound,

    #[a3(status = 409, message = "Already exists")]
    AlreadyExists,

    #[a3(status = 502, retryable, message = "Backend unavailable")]
    BackendError,
}

// ─── Endpoint handlers (using macros) ────────────────────────────────────────

#[a3_endpoint(GET "/health")]
#[a3_security(none)]
#[a3_authorize(public)]
#[a3_rate_limit(none)]
async fn test_health(_ctx: A3Context) -> A3Result<Json<HealthStatus>, Never> {
    Ok(Json(HealthStatus::ok("test")))
}

#[a3_endpoint(POST "/items")]
#[a3_security(jwt)]
#[a3_authorize(scopes = ["users:create"])]
async fn create_item(
    _ctx: A3Context,
    input: Valid<TestInput>,
) -> A3Result<Created<serde_json::Value>, TestError> {
    let input = input.into_inner();
    Ok(Created(serde_json::json!({
        "name": input.name,
        "email": input.email,
    })))
}

#[a3_endpoint(GET "/items/:id")]
#[a3_security(jwt)]
#[a3_authorize(scopes = ["users:read"])]
#[a3_rate_limit(none)]
async fn get_item(
    _ctx: A3Context,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> A3Result<Json<serde_json::Value>, TestError> {
    if id == "999" {
        return Err(TestError::NotFound);
    }
    Ok(Json(serde_json::json!({"id": id, "name": "test"})))
}

#[a3_endpoint(GET "/fail")]
#[a3_security(none)]
#[a3_authorize(public)]
#[a3_rate_limit(none)]
async fn fail_endpoint(_ctx: A3Context) -> A3Result<Json<serde_json::Value>, TestError> {
    Err(TestError::BackendError)
}

// ─── Helper ──────────────────────────────────────────────────────────────────

fn build_service() -> a3::runtime::Service {
    Service::builder()
        .name("test-service")
        .version("0.1.0")
        .endpoint(test_health())
        .endpoint(create_item())
        .endpoint(get_item())
        .endpoint(fail_endpoint())
        .auth(TestAuth)
        .build()
        .expect("failed to build service")
}

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn health_no_auth_returns_200() {
    let router = build_service().into_router();
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn auth_endpoint_without_token_returns_401() {
    let router = build_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"alice","email":"a@b.com"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "unauthorized");
    assert_eq!(json["error"]["retryable"], false);
    assert!(json["error"]["request_id"].is_string());
}

#[tokio::test]
async fn auth_endpoint_with_token_returns_201() {
    let router = build_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("authorization", "Bearer test-token")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"name":"alice","email":"alice@example.com"}"#,
        ))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let json = body_json(resp).await;
    assert_eq!(json["name"], "alice");
    assert_eq!(json["email"], "alice@example.com");
}

#[tokio::test]
async fn validation_error_returns_400_with_field_names_only() {
    let router = build_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("authorization", "Bearer test-token")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"ab","email":"not-an-email"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "validation_error");
    assert_eq!(json["error"]["message"], "Validation failed");

    // Details should contain only field names (strings), not full error objects
    let details = json["error"]["details"].as_array().unwrap();
    assert!(details.len() >= 2);

    let fields: Vec<&str> = details.iter().map(|d| d.as_str().unwrap()).collect();
    assert!(fields.contains(&"name"));
    assert!(fields.contains(&"email"));
}

#[tokio::test]
async fn unknown_fields_rejected_strict_mode() {
    let router = build_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("authorization", "Bearer test-token")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"name":"alice","email":"a@b.com","evil":"injection"}"#,
        ))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "validation_error");

    // Details should contain only field names — "evil" is the unknown field
    let details = json["error"]["details"].as_array().unwrap();
    let fields: Vec<&str> = details.iter().map(|d| d.as_str().unwrap()).collect();
    assert!(fields.contains(&"evil"));
}

#[tokio::test]
async fn invalid_json_returns_400() {
    let router = build_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("authorization", "Bearer test-token")
        .header("content-type", "application/json")
        .body(Body::from("not json"))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "invalid_json");
}

#[tokio::test]
async fn custom_error_not_found_returns_404() {
    let router = build_service().into_router();
    let req = Request::builder()
        .uri("/items/999")
        .header("authorization", "Bearer test-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "not_found");
    assert_eq!(json["error"]["message"], "Not found");
    assert_eq!(json["error"]["retryable"], false);
}

#[tokio::test]
async fn custom_error_retryable_flag() {
    let router = build_service().into_router();
    let req = Request::builder().uri("/fail").body(Body::empty()).unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    let json = body_json(resp).await;
    assert_eq!(json["error"]["code"], "backend_error");
    assert_eq!(json["error"]["retryable"], true);
}

#[tokio::test]
async fn get_item_with_auth_returns_200() {
    let router = build_service().into_router();
    let req = Request::builder()
        .uri("/items/42")
        .header("authorization", "Bearer test-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp).await;
    assert_eq!(json["id"], "42");
}

#[tokio::test]
async fn get_item_without_auth_returns_401() {
    let router = build_service().into_router();
    let req = Request::builder()
        .uri("/items/42")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn empty_bearer_token_returns_401() {
    let router = build_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("authorization", "Bearer ")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"alice","email":"a@b.com"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sanitization_trims_and_lowercases() {
    let router = build_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("authorization", "Bearer test-token")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"name":"  alice  ","email":"  ALICE@Example.COM  "}"#,
        ))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let json = body_json(resp).await;
    assert_eq!(json["name"], "alice");
    assert_eq!(json["email"], "alice@example.com");
}

#[tokio::test]
async fn all_responses_have_security_headers() {
    let router = build_service().into_router();
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();

    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
    assert!(resp
        .headers()
        .get("strict-transport-security")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("max-age=63072000"));
    assert!(resp
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("default-src 'none'"));
    assert_eq!(
        resp.headers().get("referrer-policy").unwrap(),
        "strict-origin-when-cross-origin"
    );
    assert!(resp
        .headers()
        .get("permissions-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("camera=()"));
}

#[tokio::test]
async fn auth_error_responses_have_security_headers() {
    let router = build_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"alice","email":"a@b.com"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert!(resp.headers().get("x-request-id").is_some());
}

#[tokio::test]
async fn all_responses_have_request_id() {
    let router = build_service().into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/items")
        .header("authorization", "Bearer test-token")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"alice","email":"a@b.com"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();

    let request_id = resp
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(request_id.len(), 36); // UUID v4
}

#[tokio::test]
async fn error_response_contains_request_id_in_body() {
    let router = build_service().into_router();
    let req = Request::builder()
        .uri("/items/999")
        .header("authorization", "Bearer test-token")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();

    // Header has a request ID from the middleware
    let header_id = resp
        .headers()
        .get("x-request-id")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(header_id.len(), 36);

    // Body also has a request ID
    let json = body_json(resp).await;
    let body_id = json["error"]["request_id"].as_str().unwrap();
    assert_eq!(body_id.len(), 36);
}

#[tokio::test]
async fn builder_rejects_jwt_endpoint_without_auth_provider() {
    let result = Service::builder()
        .name("test")
        .version("1.0.0")
        .endpoint(EndpointRegistration {
            method: HttpMethod::Post,
            path: "/test".to_string(),
            handler: axum::routing::post(|| async { "ok" }),
            security: EndpointSecurity::Jwt,
            authorization: EndpointAuthorization::Scopes(vec!["test".to_string()]),
            rate_limit: None,
            openapi: None,
        })
        .build();
    assert!(result.is_err());
    let err = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("expected error"),
    };
    assert!(err.contains("auth provider"));
}

#[tokio::test]
async fn builder_accepts_jwt_endpoint_with_auth_provider() {
    let result = Service::builder()
        .name("test")
        .version("1.0.0")
        .endpoint(EndpointRegistration {
            method: HttpMethod::Post,
            path: "/test".to_string(),
            handler: axum::routing::post(|| async { "ok" }),
            security: EndpointSecurity::Jwt,
            authorization: EndpointAuthorization::Scopes(vec!["test".to_string()]),
            rate_limit: None,
            openapi: None,
        })
        .auth(TestAuth)
        .build();
    assert!(result.is_ok());
}

#[tokio::test]
async fn builder_accepts_no_auth_endpoints_without_provider() {
    let result = Service::builder()
        .name("test")
        .version("1.0.0")
        .endpoint(EndpointRegistration {
            method: HttpMethod::Get,
            path: "/health".to_string(),
            handler: axum::routing::get(|| async { "ok" }),
            security: EndpointSecurity::None,
            authorization: EndpointAuthorization::Public,
            rate_limit: None,
            openapi: None,
        })
        .build();
    assert!(result.is_ok());
}
