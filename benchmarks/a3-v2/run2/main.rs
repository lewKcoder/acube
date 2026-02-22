//! User CRUD service built with the a3 framework.
//!
//! Endpoints:
//!   POST   /users    - Create a new user (JWT required)
//!   GET    /users/:id - Retrieve a user by ID (JWT required)
//!   DELETE /users/:id - Delete a user by ID (JWT required)
//!   GET    /health    - Health check (no auth)
//!
//! Usage:
//!   export JWT_SECRET="my-secret"
//!   cargo run
//!
//!   curl http://localhost:3000/health
//!   curl -X POST http://localhost:3000/users \
//!     -H "Authorization: Bearer <token>" \
//!     -H "Content-Type: application/json" \
//!     -d '{"username":"alice_42","email":"alice@example.com","display_name":"Alice W."}'

use a3::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ─── Input schema ────────────────────────────────────────────────────────────

/// Validated input for creating a user.
#[derive(A3Schema, Debug, Deserialize)]
pub struct CreateUserInput {
    /// Username: 3-30 alphanumeric or underscore characters.
    #[a3(min_length = 3, max_length = 30, pattern = "^[a-zA-Z0-9_]+$")]
    #[a3(sanitize(trim))]
    pub username: String,

    /// Valid email address (PII — logged with care).
    #[a3(format = "email", pii)]
    #[a3(sanitize(trim, lowercase))]
    pub email: String,

    /// Display name: 1-100 characters, HTML stripped.
    #[a3(min_length = 1, max_length = 100)]
    #[a3(sanitize(trim, strip_html))]
    pub display_name: String,
}

// ─── Output types ────────────────────────────────────────────────────────────

/// User resource returned from the API.
#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub created_at: String,
}

/// Wrapper for delete confirmation.
#[derive(Debug, Serialize)]
pub struct DeleteConfirmation {
    pub deleted: bool,
}

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(A3Error, Debug)]
pub enum UserError {
    #[a3(status = 404, message = "User not found")]
    NotFound,

    #[a3(status = 409, message = "Username already taken")]
    UsernameConflict,

    #[a3(status = 409, message = "Email already registered")]
    EmailConflict,
}

// ─── State ───────────────────────────────────────────────────────────────────

/// Thread-safe in-memory user store.
type UserStore = Arc<Mutex<UserDb>>;

struct UserDb {
    users: HashMap<String, User>,
    next_id: u64,
}

impl UserDb {
    fn new() -> Self {
        Self {
            users: HashMap::new(),
            next_id: 1,
        }
    }
}

fn new_store() -> UserStore {
    Arc::new(Mutex::new(UserDb::new()))
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// Create a new user.
#[a3_endpoint(POST "/users")]
#[a3_security(jwt)]
#[a3_rate_limit(30, per_minute)]
async fn create_user(
    _ctx: A3Context,
    axum::extract::Extension(store): axum::extract::Extension<UserStore>,
    input: Valid<CreateUserInput>,
) -> A3Result<Created<User>, UserError> {
    let input = input.into_inner();
    let mut db = store.lock().unwrap();

    // Check for duplicate username
    let username_exists = db.users.values().any(|u| u.username == input.username);
    if username_exists {
        return Err(UserError::UsernameConflict);
    }

    // Check for duplicate email
    let email_exists = db.users.values().any(|u| u.email == input.email);
    if email_exists {
        return Err(UserError::EmailConflict);
    }

    let id = db.next_id.to_string();
    db.next_id += 1;

    let user = User {
        id: id.clone(),
        username: input.username,
        email: input.email,
        display_name: input.display_name,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    db.users.insert(id, user.clone());
    Ok(Created(user))
}

/// Get a user by ID.
#[a3_endpoint(GET "/users/:id")]
#[a3_security(jwt)]
async fn get_user(
    _ctx: A3Context,
    axum::extract::Extension(store): axum::extract::Extension<UserStore>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> A3Result<Json<User>, UserError> {
    let db = store.lock().unwrap();
    match db.users.get(&id) {
        Some(user) => Ok(Json(user.clone())),
        None => Err(UserError::NotFound),
    }
}

/// Delete a user by ID.
#[a3_endpoint(DELETE "/users/:id")]
#[a3_security(jwt)]
async fn delete_user(
    _ctx: A3Context,
    axum::extract::Extension(store): axum::extract::Extension<UserStore>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> A3Result<Json<DeleteConfirmation>, UserError> {
    let mut db = store.lock().unwrap();
    if db.users.remove(&id).is_some() {
        Ok(Json(DeleteConfirmation { deleted: true }))
    } else {
        Err(UserError::NotFound)
    }
}

/// Health check endpoint — no authentication required.
#[a3_endpoint(GET "/health")]
#[a3_security(none)]
#[a3_rate_limit(none)]
async fn health(_ctx: A3Context) -> A3Result<Json<HealthStatus>, Never> {
    Ok(Json(HealthStatus::ok("1.0.0")))
}

// ─── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    a3::init_tracing();

    let store = new_store();

    let service = Service::builder()
        .name("user-crud-service")
        .version("1.0.0")
        .endpoint(create_user())
        .endpoint(get_user())
        .endpoint(delete_user())
        .endpoint(health())
        .auth(JwtAuth::from_env()?)
        .rate_limit_backend(InMemoryBackend::new())
        .build()?;

    let router = service
        .into_router()
        .layer(axum::extract::Extension(store));

    let addr = "0.0.0.0:3000";
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("listening on {}", addr);
    axum::serve(listener, router).await?;

    Ok(())
}
