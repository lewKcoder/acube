//! Integration tests for the a³ framework (Phase 0).

use a3::prelude::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

fn build_test_service() -> a3::runtime::Service {
    Service::builder()
        .name("test-service")
        .version("0.1.0")
        .endpoint(EndpointRegistration {
            method: HttpMethod::Get,
            path: "/health".to_string(),
            handler: axum::routing::get(health_handler),
            security: EndpointSecurity::None,
            rate_limit: None,
            openapi: None,
        })
        .build()
        .expect("failed to build service")
}

async fn health_handler() -> impl IntoResponse {
    Json(HealthStatus::ok("0.1.0"))
}

#[tokio::test]
async fn health_returns_200_with_json() {
    let router = build_test_service().into_router();
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("application/json"));
}

#[tokio::test]
async fn unknown_path_returns_404_structured_json() {
    let router = build_test_service().into_router();
    let req = Request::builder()
        .uri("/nonexistent")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], "not_found");
    assert!(json["error"]["request_id"].is_string());
}

#[tokio::test]
async fn security_header_x_content_type_options() {
    let router = build_test_service().into_router();
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.headers()
            .get("x-content-type-options")
            .unwrap()
            .to_str()
            .unwrap(),
        "nosniff"
    );
}

#[tokio::test]
async fn security_header_x_frame_options() {
    let router = build_test_service().into_router();
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.headers()
            .get("x-frame-options")
            .unwrap()
            .to_str()
            .unwrap(),
        "DENY"
    );
}

#[tokio::test]
async fn security_header_strict_transport_security() {
    let router = build_test_service().into_router();
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    let val = resp
        .headers()
        .get("strict-transport-security")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(val.contains("max-age=63072000"));
}

#[tokio::test]
async fn security_header_csp() {
    let router = build_test_service().into_router();
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    let val = resp
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(val.contains("default-src 'none'"));
}

#[tokio::test]
async fn security_header_referrer_policy() {
    let router = build_test_service().into_router();
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.headers()
            .get("referrer-policy")
            .unwrap()
            .to_str()
            .unwrap(),
        "strict-origin-when-cross-origin"
    );
}

#[tokio::test]
async fn security_header_permissions_policy() {
    let router = build_test_service().into_router();
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    let val = resp
        .headers()
        .get("permissions-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(val.contains("camera=()"));
}

#[tokio::test]
async fn response_has_request_id() {
    let router = build_test_service().into_router();
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    let request_id = resp
        .headers()
        .get("x-request-id")
        .expect("missing x-request-id header")
        .to_str()
        .unwrap();
    // UUID v4 format
    assert_eq!(request_id.len(), 36);
    assert!(request_id.contains('-'));
}

#[tokio::test]
async fn service_builder_rejects_missing_name() {
    let result = Service::builder().version("1.0.0").build();
    assert!(result.is_err());
}

#[tokio::test]
async fn service_builder_rejects_duplicate_endpoints() {
    let result = Service::builder()
        .name("dup-test")
        .version("1.0.0")
        .endpoint(EndpointRegistration {
            method: HttpMethod::Get,
            path: "/test".to_string(),
            handler: axum::routing::get(health_handler),
            security: EndpointSecurity::None,
            rate_limit: None,
            openapi: None,
        })
        .endpoint(EndpointRegistration {
            method: HttpMethod::Get,
            path: "/test".to_string(),
            handler: axum::routing::get(health_handler),
            security: EndpointSecurity::None,
            rate_limit: None,
            openapi: None,
        })
        .build();
    assert!(result.is_err());
}

// ─── Tests: CSP Customization ────────────────────────────────────────────────

#[tokio::test]
async fn custom_csp_is_applied() {
    let service = Service::builder()
        .name("csp-test")
        .version("0.1.0")
        .endpoint(EndpointRegistration {
            method: HttpMethod::Get,
            path: "/health".to_string(),
            handler: axum::routing::get(health_handler),
            security: EndpointSecurity::None,
            rate_limit: None,
            openapi: None,
        })
        .content_security_policy("default-src 'self'; script-src 'self'")
        .build()
        .expect("failed to build service");

    let router = service.into_router();
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let csp = resp
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    // Custom CSP applied
    assert!(csp.contains("default-src 'self'"));
    assert!(csp.contains("script-src 'self'"));
    // frame-ancestors auto-appended
    assert!(csp.contains("frame-ancestors 'none'"));
}

#[tokio::test]
async fn custom_csp_preserves_user_frame_ancestors() {
    let service = Service::builder()
        .name("csp-test-2")
        .version("0.1.0")
        .endpoint(EndpointRegistration {
            method: HttpMethod::Get,
            path: "/health".to_string(),
            handler: axum::routing::get(health_handler),
            security: EndpointSecurity::None,
            rate_limit: None,
            openapi: None,
        })
        .content_security_policy("default-src 'self'; frame-ancestors 'self'")
        .build()
        .expect("failed to build service");

    let router = service.into_router();
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let csp = resp
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    // User's frame-ancestors preserved (not doubled)
    assert_eq!(csp, "default-src 'self'; frame-ancestors 'self'");
}

#[tokio::test]
async fn default_csp_without_customization() {
    let router = build_test_service().into_router();
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let csp = resp
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(csp, "default-src 'none'; frame-ancestors 'none'");
}

// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn not_found_response_is_not_retryable() {
    let router = build_test_service().into_router();
    let req = Request::builder()
        .uri("/missing")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["retryable"], false);
}
