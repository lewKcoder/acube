use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;

// ─── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct User {
    id: String,
    username: String,
    email: String,
    display_name: String,
}

#[derive(Debug, Deserialize)]
struct CreateUserRequest {
    username: String,
    email: String,
    display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

type UserStore = Arc<RwLock<HashMap<String, User>>>;

#[derive(Clone)]
struct AppState {
    store: UserStore,
}

// ─── Helper: verify JWT ────────────────────────────────────────────────────────

fn verify_token(headers: &HeaderMap) -> Result<Claims, (StatusCode, Json<serde_json::Value>)> {
    let auth = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Missing Authorization header"})),
        ))?;

    let token = auth.strip_prefix("Bearer ").ok_or((
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error": "Invalid token format"})),
    ))?;

    let secret = std::env::var("JWT_SECRET").unwrap_or("secret".into());
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": format!("Invalid token: {}", e)})),
        )
    })?;

    Ok(data.claims)
}

// ─── Handlers ──────────────────────────────────────────────────────────────────

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_token(&headers)?;

    // Validate username
    if body.username.len() < 3 || body.username.len() > 30 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Username must be between 3 and 30 characters"})),
        ));
    }
    if !body.username.chars().all(|c| c.is_alphanumeric()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Username must be alphanumeric"})),
        ));
    }

    // Validate email (simple check)
    if !body.email.contains('@') || !body.email.contains('.') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid email format"})),
        ));
    }

    // Validate display_name
    if body.display_name.is_empty() || body.display_name.len() > 100 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Display name must be 1-100 characters"})),
        ));
    }

    let user = User {
        id: Uuid::new_v4().to_string(),
        username: body.username,
        email: body.email,
        display_name: body.display_name,
    };

    state.store.write().await.insert(user.id.clone(), user.clone());

    Ok((StatusCode::CREATED, Json(user)))
}

async fn get_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<User>, (StatusCode, Json<serde_json::Value>)> {
    verify_token(&headers)?;

    let store = state.store.read().await;
    let user = store.get(&id).ok_or((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "User not found"})),
    ))?;

    Ok(Json(user.clone()))
}

async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    verify_token(&headers)?;

    let mut store = state.store.write().await;
    store.remove(&id).ok_or((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "User not found"})),
    ))?;

    Ok(StatusCode::NO_CONTENT)
}

// ─── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let state = AppState {
        store: Arc::new(RwLock::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/users", post(create_user))
        .route("/users/:id", get(get_user).delete(delete_user))
        .with_state(state);

    println!("Listening on 0.0.0.0:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
