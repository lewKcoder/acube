use axum::{
    body::Body,
    extract::{Path, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;

// ─── Models ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: u16,
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<HashMap<String, String>>,
}

impl ApiError {
    fn new(code: StatusCode, error: &str, message: &str) -> (StatusCode, Json<ApiError>) {
        (
            code,
            Json(ApiError {
                code: code.as_u16(),
                error: error.to_string(),
                message: message.to_string(),
                fields: None,
            }),
        )
    }

    fn validation(fields: HashMap<String, String>) -> (StatusCode, Json<ApiError>) {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                code: 400,
                error: "ValidationError".to_string(),
                message: "One or more fields failed validation".to_string(),
                fields: Some(fields),
            }),
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    #[serde(default)]
    pub iat: usize,
}

// ─── State ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub users: Arc<RwLock<HashMap<String, User>>>,
    pub jwt_secret: String,
}

// ─── Auth Middleware ───────────────────────────────────────────────────────────

async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "Unauthorized",
                "Missing Authorization header",
            )
            .into_response()
        })?;

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "Unauthorized",
            "Authorization header must start with 'Bearer '",
        )
        .into_response()
    })?;

    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "Unauthorized",
            &format!("Invalid token: {}", e),
        )
        .into_response()
    })?;

    // Store claims in request extensions for handlers to access
    req.extensions_mut().insert(claims.claims);

    Ok(next.run(req).await)
}

// ─── Validation ────────────────────────────────────────────────────────────────

fn validate_create_user(req: &CreateUserRequest) -> Result<(), HashMap<String, String>> {
    let mut errors = HashMap::new();

    // Username: 3-30 alphanumeric characters
    let username_re = Regex::new(r"^[a-zA-Z0-9]{3,30}$").unwrap();
    if !username_re.is_match(&req.username) {
        errors.insert(
            "username".to_string(),
            "Must be 3-30 alphanumeric characters".to_string(),
        );
    }

    // Email validation
    let email_re =
        Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    if !email_re.is_match(&req.email) {
        errors.insert("email".to_string(), "Must be a valid email address".to_string());
    }

    // Display name: 1-100 characters
    let trimmed = req.display_name.trim();
    if trimmed.is_empty() || trimmed.len() > 100 {
        errors.insert(
            "display_name".to_string(),
            "Must be between 1 and 100 characters".to_string(),
        );
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// ─── Handlers ──────────────────────────────────────────────────────────────────

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION", "0.1.0"),
    }))
}

async fn create_user(
    State(state): State<AppState>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, Response> {
    // Validate
    if let Err(field_errors) = validate_create_user(&payload) {
        return Err(ApiError::validation(field_errors).into_response());
    }

    let mut users = state.users.write().await;

    // Check uniqueness
    let username_taken = users
        .values()
        .any(|u| u.username.eq_ignore_ascii_case(&payload.username));
    if username_taken {
        return Err(
            ApiError::new(StatusCode::CONFLICT, "Conflict", "Username is already taken")
                .into_response(),
        );
    }

    let email_taken = users
        .values()
        .any(|u| u.email.eq_ignore_ascii_case(&payload.email));
    if email_taken {
        return Err(
            ApiError::new(StatusCode::CONFLICT, "Conflict", "Email is already registered")
                .into_response(),
        );
    }

    let now = chrono::Utc::now().to_rfc3339();
    let user = User {
        id: Uuid::new_v4().to_string(),
        username: payload.username,
        email: payload.email,
        display_name: payload.display_name.trim().to_string(),
        created_at: now.clone(),
        updated_at: now,
    };

    users.insert(user.id.clone(), user.clone());

    Ok((StatusCode::CREATED, Json(user)).into_response())
}

async fn get_user(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<User>, Response> {
    // Validate UUID format
    if Uuid::parse_str(&user_id).is_err() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "BadRequest",
            "Invalid user ID format",
        )
        .into_response());
    }

    let users = state.users.read().await;
    let user = users.get(&user_id).ok_or_else(|| {
        ApiError::new(StatusCode::NOT_FOUND, "NotFound", "User not found").into_response()
    })?;

    Ok(Json(user.clone()))
}

async fn delete_user(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse, Response> {
    // Validate UUID format
    if Uuid::parse_str(&user_id).is_err() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "BadRequest",
            "Invalid user ID format",
        )
        .into_response());
    }

    let mut users = state.users.write().await;
    users.remove(&user_id).ok_or_else(|| {
        ApiError::new(StatusCode::NOT_FOUND, "NotFound", "User not found").into_response()
    })?;

    Ok(StatusCode::NO_CONTENT)
}

// ─── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let jwt_secret =
        std::env::var("JWT_SECRET").unwrap_or_else(|_| "super-secret-key".to_string());

    let state = AppState {
        users: Arc::new(RwLock::new(HashMap::new())),
        jwt_secret,
    };

    // Routes that require authentication
    let protected_routes = Router::new()
        .route("/users", post(create_user))
        .route("/users/:id", get(get_user))
        .route("/users/:id", delete(delete_user))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state.clone());

    // Public routes
    let public_routes = Router::new().route("/health", get(health_check));

    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes);

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    tracing::info!("Starting server on {}", bind_addr);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
