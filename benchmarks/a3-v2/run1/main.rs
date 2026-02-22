//! User CRUD Service — built with the a3 framework.
//!
//! Endpoints:
//!   POST   /users     — Create a user (JWT required)
//!   GET    /users/:id — Get a user by ID (JWT required)
//!   DELETE /users/:id — Delete a user by ID (JWT required)
//!   GET    /health    — Health check (no auth)
//!
//! Run:
//!   JWT_SECRET=my-secret cargo run
//!
//! Test:
//!   curl http://localhost:3000/health
//!   curl -X POST http://localhost:3000/users \
//!     -H "Authorization: Bearer <token>" \
//!     -H "Content-Type: application/json" \
//!     -d '{"username":"alice","email":"alice@example.com","display_name":"Alice"}'

use a3::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ─── Input schema ────────────────────────────────────────────────────────────

#[derive(A3Schema, Debug, Deserialize)]
pub struct CreateUserInput {
    #[a3(min_length = 3, max_length = 30, pattern = "^[a-zA-Z0-9_]+$")]
    #[a3(sanitize(trim))]
    pub username: String,

    #[a3(format = "email", pii)]
    #[a3(sanitize(trim, lowercase))]
    pub email: String,

    #[a3(min_length = 1, max_length = 100)]
    #[a3(sanitize(trim, strip_html))]
    pub display_name: String,
}

// ─── Output schema ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct UserOutput {
    pub id: String,
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteResponse {
    pub deleted: bool,
}

// ─── Error types ─────────────────────────────────────────────────────────────

#[derive(A3Error, Debug)]
pub enum UserError {
    #[a3(status = 404, message = "User not found")]
    NotFound,

    #[a3(status = 409, message = "Username already taken")]
    UsernameTaken,

    #[a3(status = 409, message = "Email already registered")]
    EmailTaken,
}

// ─── In-memory store ─────────────────────────────────────────────────────────

type UserStore = Arc<Mutex<HashMap<String, UserOutput>>>;

fn new_store() -> UserStore {
    Arc::new(Mutex::new(HashMap::new()))
}

// ─── Handlers ────────────────────────────────────────────────────────────────

#[a3_endpoint(POST "/users")]
#[a3_security(jwt, scopes = ["users:create"])]
#[a3_rate_limit(10, per_minute)]
async fn create_user(
    _ctx: A3Context,
    axum::extract::Extension(store): axum::extract::Extension<UserStore>,
    input: Valid<CreateUserInput>,
) -> A3Result<Created<UserOutput>, UserError> {
    let input = input.into_inner();
    let mut store = store.lock().unwrap();

    // Check for duplicate username
    if store.values().any(|u| u.username == input.username) {
        return Err(UserError::UsernameTaken);
    }

    // Check for duplicate email
    if store.values().any(|u| u.email == input.email) {
        return Err(UserError::EmailTaken);
    }

    let id = (store.len() + 1).to_string();
    let user = UserOutput {
        id: id.clone(),
        username: input.username,
        email: input.email,
        display_name: input.display_name,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    store.insert(id, user.clone());

    Ok(Created(user))
}

#[a3_endpoint(GET "/users/:id")]
#[a3_security(jwt, scopes = ["users:read"])]
async fn get_user(
    _ctx: A3Context,
    axum::extract::Extension(store): axum::extract::Extension<UserStore>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> A3Result<Json<UserOutput>, UserError> {
    let store = store.lock().unwrap();
    let user = store.get(&id).cloned().ok_or(UserError::NotFound)?;
    Ok(Json(user))
}

#[a3_endpoint(DELETE "/users/:id")]
#[a3_security(jwt, scopes = ["users:delete"])]
async fn delete_user(
    _ctx: A3Context,
    axum::extract::Extension(store): axum::extract::Extension<UserStore>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> A3Result<Json<DeleteResponse>, UserError> {
    let mut store = store.lock().unwrap();
    store.remove(&id).ok_or(UserError::NotFound)?;
    Ok(Json(DeleteResponse { deleted: true }))
}

#[a3_endpoint(GET "/health")]
#[a3_security(none)]
#[a3_rate_limit(none)]
async fn health_check(_ctx: A3Context) -> A3Result<Json<HealthStatus>, Never> {
    Ok(Json(HealthStatus::ok("1.0.0")))
}

// ─── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    a3::init_tracing();

    let store = new_store();

    let service = Service::builder()
        .name("user-service")
        .version("1.0.0")
        .endpoint(create_user())
        .endpoint(get_user())
        .endpoint(delete_user())
        .endpoint(health_check())
        .auth(JwtAuth::from_env()?)
        .build()?;

    let router = service.into_router().layer(axum::extract::Extension(store));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    tracing::info!("user-service listening on 0.0.0.0:3000");
    axum::serve(listener, router).await?;
    Ok(())
}
