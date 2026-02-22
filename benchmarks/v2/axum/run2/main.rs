use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// JWT
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct TokenClaims {
    sub: String,
    #[allow(dead_code)]
    exp: Option<u64>,
}

fn jwt_secret() -> String {
    env::var("JWT_SECRET").unwrap_or_else(|_| "default-dev-secret".into())
}

fn decode_bearer(headers: &HeaderMap) -> Result<String, ApiError> {
    let header_val = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::unauthorized("Missing Authorization header"))?;

    let token = header_val
        .strip_prefix("Bearer ")
        .ok_or(ApiError::unauthorized("Malformed Authorization header"))?;

    let secret = jwt_secret();
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();

    let data = decode::<TokenClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|e| ApiError::unauthorized(&format!("Invalid token: {e}")))?;

    Ok(data.claims.sub)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, msg: &str) -> Self {
        Self {
            status,
            message: msg.to_owned(),
        }
    }
    fn bad_request(msg: &str) -> Self { Self::new(StatusCode::BAD_REQUEST, msg) }
    fn unauthorized(msg: &str) -> Self { Self::new(StatusCode::UNAUTHORIZED, msg) }
    fn forbidden(msg: &str) -> Self { Self::new(StatusCode::FORBIDDEN, msg) }
    fn not_found(msg: &str) -> Self { Self::new(StatusCode::NOT_FOUND, msg) }
    fn conflict(msg: &str) -> Self { Self::new(StatusCode::CONFLICT, msg) }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorBody {
            error: self.message,
        });
        (self.status, body).into_response()
    }
}

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
struct UserProfile {
    id: String,
    username: String,
    email: String,
    display_name: String,
    owner_id: String,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct CreateUserPayload {
    username: Option<String>,
    email: Option<String>,
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateUserPayload {
    display_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct FullProfileView {
    id: String,
    username: String,
    email: String,
    display_name: String,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct PublicProfileView {
    id: String,
    username: String,
    display_name: String,
}

#[derive(Debug, Serialize)]
struct DeletedResponse {
    deleted: bool,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
}

// ---------------------------------------------------------------------------
// App State
// ---------------------------------------------------------------------------

type ProfileStore = Arc<Mutex<HashMap<String, UserProfile>>>;

#[derive(Clone)]
struct AppCtx {
    profiles: ProfileStore,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn validate_username(val: &str) -> Result<(), ApiError> {
    if val.len() < 3 || val.len() > 30 {
        return Err(ApiError::bad_request(
            "username must be between 3 and 30 characters",
        ));
    }
    if !val
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(ApiError::bad_request(
            "username may only contain alphanumeric characters and underscores",
        ));
    }
    Ok(())
}

fn validate_email(val: &str) -> Result<(), ApiError> {
    let parts: Vec<&str> = val.splitn(2, '@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(ApiError::bad_request("email format is invalid"));
    }
    if !parts[1].contains('.') {
        return Err(ApiError::bad_request("email format is invalid"));
    }
    Ok(())
}

fn validate_display_name(val: &str) -> Result<(), ApiError> {
    if val.is_empty() || val.len() > 100 {
        return Err(ApiError::bad_request(
            "display_name must be between 1 and 100 characters",
        ));
    }
    Ok(())
}

fn iso_now() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let naive = chrono::DateTime::from_timestamp(secs as i64, 0).unwrap();
    naive.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health_check() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".into(),
    })
}

async fn create_user(
    State(ctx): State<AppCtx>,
    headers: HeaderMap,
    Json(body): Json<CreateUserPayload>,
) -> Result<impl IntoResponse, ApiError> {
    let subject = decode_bearer(&headers)?;

    let username = body
        .username
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("username is required"))?;
    let email = body
        .email
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("email is required"))?;
    let display_name = body
        .display_name
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("display_name is required"))?;

    validate_username(username)?;
    validate_email(email)?;
    validate_display_name(display_name)?;

    let mut store = ctx.profiles.lock().unwrap();

    for existing in store.values() {
        if existing.username == username {
            return Err(ApiError::conflict("username already taken"));
        }
        if existing.email == email {
            return Err(ApiError::conflict("email already taken"));
        }
    }

    let profile = UserProfile {
        id: Uuid::new_v4().to_string(),
        username: username.to_owned(),
        email: email.to_owned(),
        display_name: display_name.to_owned(),
        owner_id: subject,
        created_at: iso_now(),
    };

    let resp = FullProfileView {
        id: profile.id.clone(),
        username: profile.username.clone(),
        email: profile.email.clone(),
        display_name: profile.display_name.clone(),
        created_at: profile.created_at.clone(),
    };

    store.insert(profile.id.clone(), profile);

    Ok((StatusCode::CREATED, Json(resp)))
}

async fn get_user(
    State(ctx): State<AppCtx>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Response, ApiError> {
    let subject = decode_bearer(&headers)?;
    let store = ctx.profiles.lock().unwrap();

    let profile = store
        .get(&user_id)
        .ok_or_else(|| ApiError::not_found("user not found"))?;

    if profile.owner_id == subject {
        let view = FullProfileView {
            id: profile.id.clone(),
            username: profile.username.clone(),
            email: profile.email.clone(),
            display_name: profile.display_name.clone(),
            created_at: profile.created_at.clone(),
        };
        Ok(Json(view).into_response())
    } else {
        let view = PublicProfileView {
            id: profile.id.clone(),
            username: profile.username.clone(),
            display_name: profile.display_name.clone(),
        };
        Ok(Json(view).into_response())
    }
}

async fn update_user(
    State(ctx): State<AppCtx>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Json(body): Json<UpdateUserPayload>,
) -> Result<impl IntoResponse, ApiError> {
    let subject = decode_bearer(&headers)?;

    let new_display = body
        .display_name
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("display_name is required"))?;
    validate_display_name(new_display)?;

    let mut store = ctx.profiles.lock().unwrap();

    let profile = store
        .get_mut(&user_id)
        .ok_or_else(|| ApiError::not_found("user not found"))?;

    if profile.owner_id != subject {
        return Err(ApiError::forbidden("not authorized to update this profile"));
    }

    profile.display_name = new_display.to_owned();

    let resp = FullProfileView {
        id: profile.id.clone(),
        username: profile.username.clone(),
        email: profile.email.clone(),
        display_name: profile.display_name.clone(),
        created_at: profile.created_at.clone(),
    };

    Ok(Json(resp))
}

async fn delete_user(
    State(ctx): State<AppCtx>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let subject = decode_bearer(&headers)?;
    let mut store = ctx.profiles.lock().unwrap();

    let profile = store
        .get(&user_id)
        .ok_or_else(|| ApiError::not_found("user not found"))?;

    if profile.owner_id != subject {
        return Err(ApiError::forbidden("not authorized to delete this profile"));
    }

    store.remove(&user_id);
    Ok(Json(DeletedResponse { deleted: true }))
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let ctx = AppCtx {
        profiles: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/users", post(create_user))
        .route("/users/:id", get(get_user))
        .route("/users/:id", put(update_user))
        .route("/users/:id", delete(delete_user))
        .with_state(ctx);

    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".into());
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();
    println!("Listening on {bind_addr}");
    axum::serve(listener, app).await.unwrap();
}
