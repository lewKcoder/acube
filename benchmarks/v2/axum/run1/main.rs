use axum::{
    extract::{Json, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post, put},
    Router,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    users: Arc<Mutex<HashMap<String, StoredUser>>>,
    jwt_secret: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredUser {
    id: String,
    username: String,
    email: String,
    display_name: String,
    owner_id: String,
    created_at: String,
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: Option<String>,
    email: Option<String>,
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct UpdateUserRequest {
    display_name: Option<String>,
}

#[derive(Serialize)]
struct FullProfileResponse {
    id: String,
    username: String,
    email: String,
    display_name: String,
    created_at: String,
}

#[derive(Serialize)]
struct PublicProfileResponse {
    id: String,
    username: String,
    display_name: String,
}

#[derive(Serialize)]
struct DeleteResponse {
    deleted: bool,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct JwtClaims {
    sub: String,
    #[serde(default)]
    exp: Option<u64>,
}

fn extract_jwt_sub(headers: &HeaderMap, jwt_secret: &str) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Missing authorization header".to_string(),
                }),
            )
        })?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid authorization header format".to_string(),
                }),
            )
        })?;

    let mut validation = Validation::default();
    validation.validate_exp = false;
    validation.required_spec_claims.clear();

    let token_data = decode::<JwtClaims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid token".to_string(),
            }),
        )
    })?;

    Ok(token_data.claims.sub)
}

fn validate_username(username: &str) -> Result<(), String> {
    if username.len() < 3 || username.len() > 30 {
        return Err("Username must be between 3 and 30 characters".to_string());
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err("Username must contain only alphanumeric characters and underscores".to_string());
    }
    Ok(())
}

fn validate_email(email: &str) -> Result<(), String> {
    let parts: Vec<&str> = email.splitn(2, '@').collect();
    if parts.len() != 2 {
        return Err("Invalid email format".to_string());
    }
    let (local, domain) = (parts[0], parts[1]);
    if local.is_empty() || domain.is_empty() {
        return Err("Invalid email format".to_string());
    }
    if !domain.contains('.') {
        return Err("Invalid email format".to_string());
    }
    let domain_parts: Vec<&str> = domain.rsplitn(2, '.').collect();
    if domain_parts.len() != 2 || domain_parts[0].is_empty() || domain_parts[1].is_empty() {
        return Err("Invalid email format".to_string());
    }
    Ok(())
}

fn validate_display_name(display_name: &str) -> Result<(), String> {
    if display_name.is_empty() || display_name.len() > 100 {
        return Err("Display name must be between 1 and 100 characters".to_string());
    }
    Ok(())
}

fn now_iso8601() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    let mut y = 1970i64;
    let mut remaining_days = days as i64;

    loop {
        let days_in_year = if is_leap_year(y) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        y += 1;
    }

    let month_days = if is_leap_year(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut m = 0usize;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining_days < md {
            m = i;
            break;
        }
        remaining_days -= md;
    }

    let d = remaining_days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m + 1,
        d,
        hours,
        minutes,
        seconds
    )
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

async fn health() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok".to_string(),
        }),
    )
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateUserRequest>,
) -> impl IntoResponse {
    let owner_id = match extract_jwt_sub(&headers, &state.jwt_secret) {
        Ok(sub) => sub,
        Err(e) => return e.into_response(),
    };

    let username = match body.username {
        Some(u) => u,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "username is required".to_string(),
                }),
            )
                .into_response()
        }
    };

    let email = match body.email {
        Some(e) => e,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "email is required".to_string(),
                }),
            )
                .into_response()
        }
    };

    let display_name = match body.display_name {
        Some(d) => d,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "display_name is required".to_string(),
                }),
            )
                .into_response()
        }
    };

    if let Err(msg) = validate_username(&username) {
        return (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg })).into_response();
    }

    if let Err(msg) = validate_email(&email) {
        return (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg })).into_response();
    }

    if let Err(msg) = validate_display_name(&display_name) {
        return (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg })).into_response();
    }

    let mut users = state.users.lock().unwrap();

    for existing in users.values() {
        if existing.username == username {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "Username already exists".to_string(),
                }),
            )
                .into_response();
        }
        if existing.email == email {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "Email already exists".to_string(),
                }),
            )
                .into_response();
        }
    }

    let id = Uuid::new_v4().to_string();
    let created_at = now_iso8601();

    let user = StoredUser {
        id: id.clone(),
        username,
        email,
        display_name,
        owner_id,
        created_at,
    };

    users.insert(id.clone(), user.clone());

    (
        StatusCode::CREATED,
        Json(FullProfileResponse {
            id: user.id,
            username: user.username,
            email: user.email,
            display_name: user.display_name,
            created_at: user.created_at,
        }),
    )
        .into_response()
}

async fn get_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let requester_id = match extract_jwt_sub(&headers, &state.jwt_secret) {
        Ok(sub) => sub,
        Err(e) => return e.into_response(),
    };

    let users = state.users.lock().unwrap();

    let user = match users.get(&id) {
        Some(u) => u.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "User not found".to_string(),
                }),
            )
                .into_response()
        }
    };

    if requester_id == user.owner_id {
        (
            StatusCode::OK,
            Json(FullProfileResponse {
                id: user.id,
                username: user.username,
                email: user.email,
                display_name: user.display_name,
                created_at: user.created_at,
            }),
        )
            .into_response()
    } else {
        (
            StatusCode::OK,
            Json(PublicProfileResponse {
                id: user.id,
                username: user.username,
                display_name: user.display_name,
            }),
        )
            .into_response()
    }
}

async fn update_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateUserRequest>,
) -> impl IntoResponse {
    let requester_id = match extract_jwt_sub(&headers, &state.jwt_secret) {
        Ok(sub) => sub,
        Err(e) => return e.into_response(),
    };

    let display_name = match body.display_name {
        Some(d) => d,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "display_name is required".to_string(),
                }),
            )
                .into_response()
        }
    };

    if let Err(msg) = validate_display_name(&display_name) {
        return (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: msg })).into_response();
    }

    let mut users = state.users.lock().unwrap();

    let user = match users.get_mut(&id) {
        Some(u) => u,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "User not found".to_string(),
                }),
            )
                .into_response()
        }
    };

    if requester_id != user.owner_id {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Not authorized".to_string(),
            }),
        )
            .into_response();
    }

    user.display_name = display_name;

    let updated = user.clone();

    (
        StatusCode::OK,
        Json(FullProfileResponse {
            id: updated.id,
            username: updated.username,
            email: updated.email,
            display_name: updated.display_name,
            created_at: updated.created_at,
        }),
    )
        .into_response()
}

async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let requester_id = match extract_jwt_sub(&headers, &state.jwt_secret) {
        Ok(sub) => sub,
        Err(e) => return e.into_response(),
    };

    let mut users = state.users.lock().unwrap();

    let user = match users.get(&id) {
        Some(u) => u.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "User not found".to_string(),
                }),
            )
                .into_response()
        }
    };

    if requester_id != user.owner_id {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Not authorized".to_string(),
            }),
        )
            .into_response();
    }

    users.remove(&id);

    (StatusCode::OK, Json(DeleteResponse { deleted: true })).into_response()
}

#[tokio::main]
async fn main() {
    let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| "secret".to_string());

    let state = AppState {
        users: Arc::new(Mutex::new(HashMap::new())),
        jwt_secret,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/users", post(create_user))
        .route("/users/{id}", get(get_user))
        .route("/users/{id}", put(update_user))
        .route("/users/{id}", delete(delete_user))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();

    axum::serve(listener, app).await.unwrap();
}
