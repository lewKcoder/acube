use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::IntoResponse,
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
// Domain types
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
struct Profile {
    id: String,
    username: String,
    email: String,
    display_name: String,
    owner_id: String,
    created_at: u64,
}

#[derive(Deserialize)]
struct CreateProfilePayload {
    username: Option<String>,
    email: Option<String>,
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct UpdateProfilePayload {
    display_name: Option<String>,
}

#[derive(Serialize)]
struct FullProfileView {
    id: String,
    username: String,
    email: String,
    display_name: String,
    created_at: u64,
}

#[derive(Serialize)]
struct PublicProfileView {
    id: String,
    username: String,
    display_name: String,
}

#[derive(Serialize)]
struct DeletedResponse {
    deleted: bool,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

// ---------------------------------------------------------------------------
// JWT
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct TokenClaims {
    sub: String,
}

fn jwt_secret() -> Vec<u8> {
    env::var("JWT_SECRET")
        .unwrap_or_else(|_| "development-secret-key".into())
        .into_bytes()
}

fn extract_subject(headers: &HeaderMap) -> Result<String, (StatusCode, Json<ErrorBody>)> {
    let header_val = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "Missing authorization header"))?;

    let token = header_val
        .strip_prefix("Bearer ")
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "Malformed authorization header"))?;

    let secret = jwt_secret();
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;

    let data = decode::<TokenClaims>(token, &DecodingKey::from_secret(&secret), &validation)
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "Invalid token"))?;

    Ok(data.claims.sub)
}

fn err(code: StatusCode, msg: &str) -> (StatusCode, Json<ErrorBody>) {
    (
        code,
        Json(ErrorBody {
            error: msg.to_string(),
        }),
    )
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

type ProfileStore = Arc<Mutex<HashMap<String, Profile>>>;

#[derive(Clone)]
struct ServiceState {
    profiles: ProfileStore,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn validate_username(raw: &str) -> Result<(), String> {
    let len = raw.len();
    if len < 3 || len > 30 {
        return Err("username must be between 3 and 30 characters".into());
    }
    if !raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err("username must contain only alphanumeric characters and underscores".into());
    }
    Ok(())
}

fn validate_email(raw: &str) -> Result<(), String> {
    let parts: Vec<&str> = raw.splitn(2, '@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err("invalid email format".into());
    }
    if !parts[1].contains('.') {
        return Err("invalid email format".into());
    }
    Ok(())
}

fn validate_display_name(raw: &str) -> Result<(), String> {
    let len = raw.len();
    if len < 1 || len > 100 {
        return Err("display_name must be between 1 and 100 characters".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health_check() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".into(),
    })
}

async fn create_profile(
    State(state): State<ServiceState>,
    headers: HeaderMap,
    Json(body): Json<CreateProfilePayload>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorBody>)> {
    let owner = extract_subject(&headers)?;

    let username = body
        .username
        .as_deref()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "username is required"))?;
    let email = body
        .email
        .as_deref()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "email is required"))?;
    let display_name = body
        .display_name
        .as_deref()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "display_name is required"))?;

    validate_username(username).map_err(|e| err(StatusCode::BAD_REQUEST, &e))?;
    validate_email(email).map_err(|e| err(StatusCode::BAD_REQUEST, &e))?;
    validate_display_name(display_name).map_err(|e| err(StatusCode::BAD_REQUEST, &e))?;

    let mut store = state.profiles.lock().unwrap();

    let username_taken = store
        .values()
        .any(|p| p.username.eq_ignore_ascii_case(username));
    if username_taken {
        return Err(err(StatusCode::CONFLICT, "username already exists"));
    }

    let email_taken = store
        .values()
        .any(|p| p.email.eq_ignore_ascii_case(email));
    if email_taken {
        return Err(err(StatusCode::CONFLICT, "email already exists"));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let profile = Profile {
        id: Uuid::new_v4().to_string(),
        username: username.to_string(),
        email: email.to_string(),
        display_name: display_name.to_string(),
        owner_id: owner,
        created_at: now,
    };

    let view = FullProfileView {
        id: profile.id.clone(),
        username: profile.username.clone(),
        email: profile.email.clone(),
        display_name: profile.display_name.clone(),
        created_at: profile.created_at,
    };

    store.insert(profile.id.clone(), profile);

    Ok((StatusCode::CREATED, Json(view)))
}

async fn get_profile(
    State(state): State<ServiceState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorBody>)> {
    let requester = extract_subject(&headers)?;

    let store = state.profiles.lock().unwrap();
    let profile = store
        .get(&profile_id)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "profile not found"))?;

    if requester == profile.owner_id {
        let view = FullProfileView {
            id: profile.id.clone(),
            username: profile.username.clone(),
            email: profile.email.clone(),
            display_name: profile.display_name.clone(),
            created_at: profile.created_at,
        };
        Ok(Json(serde_json::to_value(view).unwrap()).into_response())
    } else {
        let view = PublicProfileView {
            id: profile.id.clone(),
            username: profile.username.clone(),
            display_name: profile.display_name.clone(),
        };
        Ok(Json(serde_json::to_value(view).unwrap()).into_response())
    }
}

async fn update_profile(
    State(state): State<ServiceState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
    Json(body): Json<UpdateProfilePayload>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorBody>)> {
    let requester = extract_subject(&headers)?;

    let new_display_name = body
        .display_name
        .as_deref()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "display_name is required"))?;

    validate_display_name(new_display_name).map_err(|e| err(StatusCode::BAD_REQUEST, &e))?;

    let mut store = state.profiles.lock().unwrap();
    let profile = store
        .get_mut(&profile_id)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "profile not found"))?;

    if requester != profile.owner_id {
        return Err(err(StatusCode::FORBIDDEN, "not authorized to update this profile"));
    }

    profile.display_name = new_display_name.to_string();

    let view = FullProfileView {
        id: profile.id.clone(),
        username: profile.username.clone(),
        email: profile.email.clone(),
        display_name: profile.display_name.clone(),
        created_at: profile.created_at,
    };

    Ok(Json(view))
}

async fn delete_profile(
    State(state): State<ServiceState>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorBody>)> {
    let requester = extract_subject(&headers)?;

    let mut store = state.profiles.lock().unwrap();
    let profile = store
        .get(&profile_id)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "profile not found"))?;

    if requester != profile.owner_id {
        return Err(err(StatusCode::FORBIDDEN, "not authorized to delete this profile"));
    }

    store.remove(&profile_id);

    Ok(Json(DeletedResponse { deleted: true }))
}

// ---------------------------------------------------------------------------
// Application bootstrap
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let state = ServiceState {
        profiles: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/users", post(create_profile))
        .route("/users/{id}", get(get_profile))
        .route("/users/{id}", put(update_profile))
        .route("/users/{id}", delete(delete_profile))
        .with_state(state);

    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".into());
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();
    println!("listening on {bind_addr}");
    axum::serve(listener, app).await.unwrap();
}
