//! Tests for `#[derive(AcubeError)]` — Phase 1b.

use acube::error::AcubeErrorInfo;
use acube::prelude::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use tower::ServiceExt;

// ─── Test enums ─────────────────────────────────────────────────────────────

#[derive(AcubeError, Debug)]
pub enum UserError {
    #[acube(status = 404, message = "User not found")]
    NotFound,

    #[acube(status = 409, message = "Username already taken")]
    UsernameTaken,

    #[acube(status = 409, message = "Email already registered")]
    EmailTaken,

    #[acube(status = 502, retryable, message = "Database unavailable")]
    DbError,
}

#[derive(AcubeError, Debug)]
pub enum AuthError {
    #[acube(status = 401, message = "Invalid credentials")]
    InvalidCredentials,

    #[acube(status = 403, message = "Insufficient permissions")]
    Forbidden,

    #[acube(status = 429, retryable, message = "Too many login attempts")]
    RateLimited,
}

#[derive(AcubeError, Debug)]
pub enum SingleVariantError {
    #[acube(status = 500, retryable, message = "Internal server error")]
    Internal,
}

// ─── AcubeErrorInfo trait tests ────────────────────────────────────────────────

#[test]
fn status_code_404() {
    assert_eq!(UserError::NotFound.status_code(), StatusCode::NOT_FOUND);
}

#[test]
fn status_code_409() {
    assert_eq!(UserError::UsernameTaken.status_code(), StatusCode::CONFLICT);
}

#[test]
fn status_code_502() {
    assert_eq!(UserError::DbError.status_code(), StatusCode::BAD_GATEWAY);
}

#[test]
fn status_code_401() {
    assert_eq!(
        AuthError::InvalidCredentials.status_code(),
        StatusCode::UNAUTHORIZED
    );
}

#[test]
fn status_code_429() {
    assert_eq!(
        AuthError::RateLimited.status_code(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[test]
fn message_matches() {
    assert_eq!(UserError::NotFound.message(), "User not found");
    assert_eq!(UserError::UsernameTaken.message(), "Username already taken");
    assert_eq!(UserError::EmailTaken.message(), "Email already registered");
    assert_eq!(UserError::DbError.message(), "Database unavailable");
}

#[test]
fn code_is_snake_case() {
    assert_eq!(UserError::NotFound.code(), "not_found");
    assert_eq!(UserError::UsernameTaken.code(), "username_taken");
    assert_eq!(UserError::EmailTaken.code(), "email_taken");
    assert_eq!(UserError::DbError.code(), "db_error");
}

#[test]
fn retryable_false_by_default() {
    assert!(!UserError::NotFound.retryable());
    assert!(!UserError::UsernameTaken.retryable());
}

#[test]
fn retryable_true_when_marked() {
    assert!(UserError::DbError.retryable());
    assert!(AuthError::RateLimited.retryable());
}

// ─── IntoResponse tests ────────────────────────────────────────────────────

#[tokio::test]
async fn into_response_status_code() {
    let resp = UserError::NotFound.into_response();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn into_response_json_body() {
    let resp = UserError::UsernameTaken.into_response();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["error"]["code"], "username_taken");
    assert_eq!(json["error"]["message"], "Username already taken");
    assert_eq!(json["error"]["retryable"], false);
    assert!(json["error"]["request_id"].is_string());
}

#[tokio::test]
async fn into_response_retryable_in_body() {
    let resp = UserError::DbError.into_response();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["error"]["retryable"], true);
}

#[tokio::test]
async fn into_response_no_internal_info_leaked() {
    let resp = UserError::DbError.into_response();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Only expected fields exist under "error"
    let error_obj = json["error"].as_object().unwrap();
    let keys: Vec<&String> = error_obj.keys().collect();
    assert!(keys.contains(&&"code".to_string()));
    assert!(keys.contains(&&"message".to_string()));
    assert!(keys.contains(&&"request_id".to_string()));
    assert!(keys.contains(&&"retryable".to_string()));
    // No stack trace, no variant name, no internal details
    assert!(!keys.contains(&&"stack".to_string()));
    assert!(!keys.contains(&&"source".to_string()));
    assert!(!keys.contains(&&"backtrace".to_string()));
}

#[tokio::test]
async fn into_response_has_request_id() {
    let resp = UserError::NotFound.into_response();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let request_id = json["error"]["request_id"].as_str().unwrap();
    assert_eq!(request_id.len(), 36); // UUID v4
}

// ─── Integration: error in axum handler ─────────────────────────────────────

#[tokio::test]
async fn error_through_axum_handler() {
    async fn handler() -> Result<Json<serde_json::Value>, UserError> {
        Err(UserError::NotFound)
    }

    let router = axum::Router::new().route("/test", axum::routing::get(handler));
    let req = Request::builder().uri("/test").body(Body::empty()).unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], "not_found");
}
