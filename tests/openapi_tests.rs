//! OpenAPI 3.0 generation tests for the a³ framework.

use a3::prelude::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

// ─── Test types ─────────────────────────────────────────────────────────────

#[derive(A3Schema, Debug, serde::Deserialize)]
struct OpenApiTestInput {
    #[a3(min_length = 3, max_length = 30, pattern = "^[a-zA-Z0-9_]+$")]
    #[a3(sanitize(trim))]
    pub username: String,

    #[a3(format = "email", pii)]
    #[a3(sanitize(trim, lowercase))]
    pub email: String,

    #[a3(min = 0, max = 120)]
    pub age: i32,

    pub nickname: Option<String>,

    #[a3(min_length = 1, max_length = 20)]
    pub tags: Vec<String>,
}

#[derive(A3Error, Debug)]
enum OpenApiTestError {
    #[a3(status = 404, message = "Not found")]
    NotFound,

    #[a3(status = 409, message = "Already exists")]
    AlreadyExists,

    #[a3(status = 502, retryable, message = "Backend unavailable")]
    BackendError,
}

// ─── Test auth provider ────────────────────────────────────────────────────

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
        Ok(AuthIdentity {
            subject: "test-user".to_string(),
            scopes: vec!["users:create".to_string(), "users:read".to_string()],
            role: None,
        })
    }
}

// ─── Test endpoints ─────────────────────────────────────────────────────────

#[a3_endpoint(GET "/health")]
#[a3_security(none)]
#[a3_authorize(public)]
#[a3_rate_limit(none)]
async fn oa_health(_ctx: A3Context) -> A3Result<Json<HealthStatus>, Never> {
    Ok(Json(HealthStatus::ok("test")))
}

#[a3_endpoint(POST "/users")]
#[a3_security(jwt)]
#[a3_authorize(scopes = ["users:create"])]
#[a3_rate_limit(10, per_minute)]
async fn oa_create_user(
    _ctx: A3Context,
    input: Valid<OpenApiTestInput>,
) -> A3Result<Created<serde_json::Value>, OpenApiTestError> {
    let input = input.into_inner();
    Ok(Created(serde_json::json!({ "username": input.username })))
}

#[a3_endpoint(GET "/users/:id")]
#[a3_security(jwt)]
#[a3_authorize(scopes = ["users:read"])]
#[a3_rate_limit(none)]
async fn oa_get_user(
    _ctx: A3Context,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> A3Result<Json<serde_json::Value>, OpenApiTestError> {
    Ok(Json(serde_json::json!({ "id": id })))
}

// ─── Schema generation tests ───────────────────────────────────────────────

#[test]
fn openapi_schema_has_correct_type() {
    let schema = OpenApiTestInput::openapi_schema();
    assert_eq!(schema["type"], "object");
}

#[test]
fn openapi_schema_has_properties() {
    let schema = OpenApiTestInput::openapi_schema();
    assert!(schema["properties"].is_object());
    assert!(schema["properties"]["username"].is_object());
    assert!(schema["properties"]["email"].is_object());
    assert!(schema["properties"]["age"].is_object());
    assert!(schema["properties"]["nickname"].is_object());
    assert!(schema["properties"]["tags"].is_object());
}

#[test]
fn openapi_schema_string_constraints() {
    let schema = OpenApiTestInput::openapi_schema();
    let username = &schema["properties"]["username"];
    assert_eq!(username["type"], "string");
    assert_eq!(username["minLength"], 3);
    assert_eq!(username["maxLength"], 30);
    assert_eq!(username["pattern"], "^[a-zA-Z0-9_]+$");
}

#[test]
fn openapi_schema_email_format() {
    let schema = OpenApiTestInput::openapi_schema();
    let email = &schema["properties"]["email"];
    assert_eq!(email["type"], "string");
    assert_eq!(email["format"], "email");
}

#[test]
fn openapi_schema_integer_constraints() {
    let schema = OpenApiTestInput::openapi_schema();
    let age = &schema["properties"]["age"];
    assert_eq!(age["type"], "integer");
    assert_eq!(age["format"], "int32");
    assert_eq!(age["minimum"], 0.0);
    assert_eq!(age["maximum"], 120.0);
}

#[test]
fn openapi_schema_optional_not_required() {
    let schema = OpenApiTestInput::openapi_schema();
    let required = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(required.contains(&"username"));
    assert!(required.contains(&"email"));
    assert!(required.contains(&"age"));
    assert!(required.contains(&"tags"));
    assert!(!required.contains(&"nickname"));
}

#[test]
fn openapi_schema_vec_is_array() {
    let schema = OpenApiTestInput::openapi_schema();
    let tags = &schema["properties"]["tags"];
    assert_eq!(tags["type"], "array");
    assert_eq!(tags["items"]["type"], "string");
}

#[test]
fn openapi_schema_additional_properties_false() {
    let schema = OpenApiTestInput::openapi_schema();
    assert_eq!(schema["additionalProperties"], false);
}

// ─── Error responses tests ─────────────────────────────────────────────────

#[test]
fn openapi_responses_returns_all_variants() {
    let responses = OpenApiTestError::openapi_responses();
    assert_eq!(responses.len(), 3);
}

#[test]
fn openapi_responses_status_codes() {
    let responses = OpenApiTestError::openapi_responses();
    let statuses: Vec<u16> = responses.iter().map(|r| r.status).collect();
    assert!(statuses.contains(&404));
    assert!(statuses.contains(&409));
    assert!(statuses.contains(&502));
}

#[test]
fn openapi_responses_codes() {
    let responses = OpenApiTestError::openapi_responses();
    let codes: Vec<&str> = responses.iter().map(|r| r.code.as_str()).collect();
    assert!(codes.contains(&"not_found"));
    assert!(codes.contains(&"already_exists"));
    assert!(codes.contains(&"backend_error"));
}

#[test]
fn openapi_responses_retryable() {
    let responses = OpenApiTestError::openapi_responses();
    let backend = responses.iter().find(|r| r.code == "backend_error").unwrap();
    assert!(backend.retryable);
    let not_found = responses.iter().find(|r| r.code == "not_found").unwrap();
    assert!(!not_found.retryable);
}

// ─── Full document tests ────────────────────────────────────────────────────

fn build_openapi_service() -> a3::runtime::Service {
    Service::builder()
        .name("test-api")
        .version("1.0.0")
        .description("Test API for OpenAPI generation")
        .endpoint(oa_health())
        .endpoint(oa_create_user())
        .endpoint(oa_get_user())
        .auth(TestAuth)
        .openapi(true)
        .build()
        .expect("failed to build service")
}

#[test]
fn openapi_json_has_correct_version() {
    let service = build_openapi_service();
    let json: serde_json::Value = serde_json::from_str(&service.openapi_json()).unwrap();
    assert_eq!(json["openapi"], "3.0.3");
}

#[test]
fn openapi_json_has_info() {
    let service = build_openapi_service();
    let json: serde_json::Value = serde_json::from_str(&service.openapi_json()).unwrap();
    assert_eq!(json["info"]["title"], "test-api");
    assert_eq!(json["info"]["version"], "1.0.0");
    assert_eq!(json["info"]["description"], "Test API for OpenAPI generation");
}

#[test]
fn openapi_json_has_paths() {
    let service = build_openapi_service();
    let json: serde_json::Value = serde_json::from_str(&service.openapi_json()).unwrap();
    let paths = json["paths"].as_object().unwrap();
    assert!(paths.contains_key("/health"));
    assert!(paths.contains_key("/users"));
    assert!(paths.contains_key("/users/{id}"));
}

#[test]
fn openapi_json_path_params_converted() {
    let service = build_openapi_service();
    let json: serde_json::Value = serde_json::from_str(&service.openapi_json()).unwrap();
    // :id should be converted to {id}
    assert!(json["paths"]["/users/{id}"].is_object());
    // Original :id should NOT appear
    assert!(json["paths"]["/users/:id"].is_null());
}

#[test]
fn openapi_json_path_parameters_listed() {
    let service = build_openapi_service();
    let json: serde_json::Value = serde_json::from_str(&service.openapi_json()).unwrap();
    let get_user = &json["paths"]["/users/{id}"]["get"];
    let params = get_user["parameters"].as_array().unwrap();
    assert_eq!(params.len(), 1);
    assert_eq!(params[0]["name"], "id");
    assert_eq!(params[0]["in"], "path");
    assert_eq!(params[0]["required"], true);
}

#[test]
fn openapi_json_security_schemes() {
    let service = build_openapi_service();
    let json: serde_json::Value = serde_json::from_str(&service.openapi_json()).unwrap();
    let schemes = &json["components"]["securitySchemes"];
    assert_eq!(schemes["bearerAuth"]["type"], "http");
    assert_eq!(schemes["bearerAuth"]["scheme"], "bearer");
    assert_eq!(schemes["bearerAuth"]["bearerFormat"], "JWT");
}

#[test]
fn openapi_json_jwt_endpoint_has_security() {
    let service = build_openapi_service();
    let json: serde_json::Value = serde_json::from_str(&service.openapi_json()).unwrap();
    let post_users = &json["paths"]["/users"]["post"];
    let security = post_users["security"].as_array().unwrap();
    assert!(!security.is_empty());
    assert!(security[0]["bearerAuth"].is_array());
}

#[test]
fn openapi_json_no_auth_endpoint_has_empty_security() {
    let service = build_openapi_service();
    let json: serde_json::Value = serde_json::from_str(&service.openapi_json()).unwrap();
    let get_health = &json["paths"]["/health"]["get"];
    let security = get_health["security"].as_array().unwrap();
    assert!(security.is_empty());
}

#[test]
fn openapi_json_request_body_ref() {
    let service = build_openapi_service();
    let json: serde_json::Value = serde_json::from_str(&service.openapi_json()).unwrap();
    let post_users = &json["paths"]["/users"]["post"];
    let schema_ref = post_users["requestBody"]["content"]["application/json"]["schema"]["$ref"]
        .as_str()
        .unwrap();
    assert_eq!(schema_ref, "#/components/schemas/OpenApiTestInput");
}

#[test]
fn openapi_json_schema_in_components() {
    let service = build_openapi_service();
    let json: serde_json::Value = serde_json::from_str(&service.openapi_json()).unwrap();
    let schema = &json["components"]["schemas"]["OpenApiTestInput"];
    assert_eq!(schema["type"], "object");
    assert!(schema["properties"]["username"].is_object());
}

#[test]
fn openapi_json_error_response_schema() {
    let service = build_openapi_service();
    let json: serde_json::Value = serde_json::from_str(&service.openapi_json()).unwrap();
    let err_schema = &json["components"]["schemas"]["ErrorResponse"];
    assert_eq!(err_schema["type"], "object");
    assert!(err_schema["properties"]["error"].is_object());
}

#[test]
fn openapi_json_rate_limit_extension() {
    let service = build_openapi_service();
    let json: serde_json::Value = serde_json::from_str(&service.openapi_json()).unwrap();
    let post_users = &json["paths"]["/users"]["post"];
    assert_eq!(post_users["x-rate-limit"]["max_requests"], 10);
    assert_eq!(post_users["x-rate-limit"]["window_seconds"], 60);
}

#[test]
fn openapi_json_success_status_201_for_created() {
    let service = build_openapi_service();
    let json: serde_json::Value = serde_json::from_str(&service.openapi_json()).unwrap();
    let post_users = &json["paths"]["/users"]["post"];
    assert!(post_users["responses"]["201"].is_object());
}

#[test]
fn openapi_json_success_status_200_for_json() {
    let service = build_openapi_service();
    let json: serde_json::Value = serde_json::from_str(&service.openapi_json()).unwrap();
    let get_user = &json["paths"]["/users/{id}"]["get"];
    assert!(get_user["responses"]["200"].is_object());
}

#[test]
fn openapi_json_error_responses_included() {
    let service = build_openapi_service();
    let json: serde_json::Value = serde_json::from_str(&service.openapi_json()).unwrap();
    let post_users = &json["paths"]["/users"]["post"];
    let responses = post_users["responses"].as_object().unwrap();
    // Error variants: 404, 409, 502
    assert!(responses.contains_key("404"));
    assert!(responses.contains_key("409"));
    assert!(responses.contains_key("502"));
    // Common JWT errors
    assert!(responses.contains_key("401"));
    assert!(responses.contains_key("403"));
    // Rate limit
    assert!(responses.contains_key("429"));
}

// ─── GET /openapi.json endpoint tests ───────────────────────────────────────

#[tokio::test]
async fn openapi_endpoint_returns_200() {
    let service = build_openapi_service();
    let router = service.into_router();
    let req = Request::builder()
        .uri("/openapi.json")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn openapi_endpoint_returns_valid_json() {
    let service = build_openapi_service();
    let router = service.into_router();
    let req = Request::builder()
        .uri("/openapi.json")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["openapi"], "3.0.3");
}

#[tokio::test]
async fn openapi_endpoint_has_security_headers() {
    let service = build_openapi_service();
    let router = service.into_router();
    let req = Request::builder()
        .uri("/openapi.json")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert!(resp.headers().get("x-request-id").is_some());
}

#[tokio::test]
async fn openapi_endpoint_has_json_content_type() {
    let service = build_openapi_service();
    let router = service.into_router();
    let req = Request::builder()
        .uri("/openapi.json")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("application/json"));
}

// ─── NoContent endpoint tests ─────────────────────────────────────────────

#[a3_endpoint(DELETE "/users/:id")]
#[a3_security(jwt)]
#[a3_authorize(scopes = ["users:delete"])]
#[a3_rate_limit(none)]
async fn oa_delete_user(_ctx: A3Context) -> A3Result<NoContent, OpenApiTestError> {
    Ok(NoContent)
}

fn build_openapi_service_with_nocontent() -> a3::runtime::Service {
    Service::builder()
        .name("test-api-nc")
        .version("1.0.0")
        .endpoint(oa_health())
        .endpoint(oa_create_user())
        .endpoint(oa_get_user())
        .endpoint(oa_delete_user())
        .auth(TestAuth)
        .openapi(true)
        .build()
        .expect("failed to build service")
}

#[test]
fn openapi_json_nocontent_status_204() {
    let service = build_openapi_service_with_nocontent();
    let json: serde_json::Value = serde_json::from_str(&service.openapi_json()).unwrap();
    let delete_user = &json["paths"]["/users/{id}"]["delete"];
    assert!(delete_user["responses"]["204"].is_object());
    assert_eq!(delete_user["responses"]["204"]["description"], "No content");
}

// ─── Default disabled tests ────────────────────────────────────────────────

#[tokio::test]
async fn openapi_disabled_by_default_returns_404() {
    let service = Service::builder()
        .name("no-openapi")
        .version("1.0.0")
        .endpoint(oa_health())
        .build()
        .expect("failed to build");
    let router = service.into_router();
    let req = Request::builder()
        .uri("/openapi.json")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
