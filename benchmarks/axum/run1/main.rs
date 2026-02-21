use axum::{
    async_trait,
    extract::{FromRequestParts, Path, State},
    http::{request::Parts, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
};
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
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Vec<ValidationError>>,
}

#[derive(Debug, Serialize)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

// ─── JWT Claims ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

// ─── App State ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub users: Arc<RwLock<HashMap<String, User>>>,
    pub jwt_secret: String,
}

// ─── Auth Extractor ────────────────────────────────────────────────────────────

pub struct AuthenticatedUser {
    pub user_id: String,
}

#[async_trait]
impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: ErrorDetail {
                            code: "UNAUTHORIZED".to_string(),
                            message: "Missing authorization header".to_string(),
                            details: None,
                        },
                    }),
                )
                    .into_response()
            })?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: ErrorDetail {
                            code: "UNAUTHORIZED".to_string(),
                            message: "Invalid authorization header format".to_string(),
                            details: None,
                        },
                    }),
                )
                    .into_response()
            })?;

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        code: "UNAUTHORIZED".to_string(),
                        message: "Invalid or expired token".to_string(),
                        details: None,
                    },
                }),
            )
                .into_response()
        })?;

        Ok(AuthenticatedUser {
            user_id: token_data.claims.sub,
        })
    }
}

// ─── Validation ────────────────────────────────────────────────────────────────

fn validate_create_user(req: &CreateUserRequest) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    // Validate username: 3-30 chars, alphanumeric
    let username_re = Regex::new(r"^[a-zA-Z0-9]{3,30}$").unwrap();
    if !username_re.is_match(&req.username) {
        errors.push(ValidationError {
            field: "username".to_string(),
            message: "Username must be 3-30 alphanumeric characters".to_string(),
        });
    }

    // Validate email format
    let email_re = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    if !email_re.is_match(&req.email) {
        errors.push(ValidationError {
            field: "email".to_string(),
            message: "Invalid email format".to_string(),
        });
    }

    // Validate display_name: 1-100 chars
    if req.display_name.is_empty() || req.display_name.len() > 100 {
        errors.push(ValidationError {
            field: "display_name".to_string(),
            message: "Display name must be between 1 and 100 characters".to_string(),
        });
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
        "status": "ok",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

async fn create_user(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
    Json(payload): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, Response> {
    // Validate the request
    if let Err(validation_errors) = validate_create_user(&payload) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: ErrorDetail {
                    code: "VALIDATION_ERROR".to_string(),
                    message: "Request validation failed".to_string(),
                    details: Some(validation_errors),
                },
            }),
        )
            .into_response());
    }

    // Check for duplicate username
    let users = state.users.read().await;
    let username_exists = users
        .values()
        .any(|u| u.username.to_lowercase() == payload.username.to_lowercase());
    drop(users);

    if username_exists {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: ErrorDetail {
                    code: "CONFLICT".to_string(),
                    message: "Username already exists".to_string(),
                    details: None,
                },
            }),
        )
            .into_response());
    }

    // Check for duplicate email
    let users = state.users.read().await;
    let email_exists = users
        .values()
        .any(|u| u.email.to_lowercase() == payload.email.to_lowercase());
    drop(users);

    if email_exists {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: ErrorDetail {
                    code: "CONFLICT".to_string(),
                    message: "Email already exists".to_string(),
                    details: None,
                },
            }),
        )
            .into_response());
    }

    let now = chrono::Utc::now().to_rfc3339();
    let user = User {
        id: Uuid::new_v4().to_string(),
        username: payload.username,
        email: payload.email,
        display_name: payload.display_name,
        created_at: now.clone(),
        updated_at: now,
    };

    let mut users = state.users.write().await;
    users.insert(user.id.clone(), user.clone());

    Ok((StatusCode::CREATED, Json(user)))
}

async fn get_user(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, Response> {
    let users = state.users.read().await;

    match users.get(&id) {
        Some(user) => Ok(Json(user.clone())),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: ErrorDetail {
                    code: "NOT_FOUND".to_string(),
                    message: format!("User with id '{}' not found", id),
                    details: None,
                },
            }),
        )
            .into_response()),
    }
}

async fn delete_user(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, Response> {
    let mut users = state.users.write().await;

    match users.remove(&id) {
        Some(_) => Ok(StatusCode::NO_CONTENT.into_response()),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: ErrorDetail {
                    code: "NOT_FOUND".to_string(),
                    message: format!("User with id '{}' not found", id),
                    details: None,
                },
            }),
        )
            .into_response()),
    }
}

// ─── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let state = AppState {
        users: Arc::new(RwLock::new(HashMap::new())),
        jwt_secret: std::env::var("JWT_SECRET").unwrap_or_else(|_| "secret".to_string()),
    };

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/users", post(create_user))
        .route("/users/:id", get(get_user))
        .route("/users/:id", delete(delete_user))
        .with_state(state);

    let addr = "0.0.0.0:3000";
    println!("Server running on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
