/// User CRUD microservice built on top of the a3 security framework.
///
/// Endpoints:
///   POST   /users      - register a new user
///   GET    /users/:id  - fetch user by id
///   DELETE /users/:id  - remove a user
///   GET    /health     - liveness probe (no auth required)
///
/// Example usage:
///
/// ```sh
/// curl http://localhost:3000/health
///
/// curl -X POST http://localhost:3000/users \
///   -H "Authorization: Bearer <token>" \
///   -H "Content-Type: application/json" \
///   -d '{"username":"dana","email":"dana@test.io","display_name":"Dana K"}'
///
/// curl http://localhost:3000/users/1 -H "Authorization: Bearer <token>"
///
/// curl -X DELETE http://localhost:3000/users/1 -H "Authorization: Bearer <token>"
/// ```

use a3::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Validated input for the user creation endpoint.
#[derive(A3Schema, Debug, Deserialize)]
pub struct NewUserPayload {
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

/// JSON representation returned for user resources.
#[derive(Debug, Clone, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub created_at: String,
}

/// Thin wrapper for the delete confirmation body.
#[derive(Serialize)]
pub struct DeleteConfirmation {
    pub deleted: bool,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(A3Error, Debug)]
pub enum UserServiceError {
    #[a3(status = 404, message = "User not found")]
    NotFound,

    #[a3(status = 409, message = "Username already taken")]
    DuplicateUsername,

    #[a3(status = 409, message = "Email already registered")]
    DuplicateEmail,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Shared, thread-safe map of user records keyed by ID.
type Db = Arc<Mutex<HashMap<String, UserResponse>>>;

fn empty_db() -> Db {
    Arc::new(Mutex::new(HashMap::new()))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Register a new user after validating the payload and checking for
/// duplicate usernames / emails.
#[a3_endpoint(POST "/users")]
#[a3_security(jwt, scopes = ["users:create"])]
#[a3_rate_limit(10, per_minute)]
async fn register_user(
    _ctx: A3Context,
    axum::extract::Extension(db): axum::extract::Extension<Db>,
    payload: Valid<NewUserPayload>,
) -> A3Result<Created<UserResponse>, UserServiceError> {
    let body = payload.into_inner();
    let mut table = db.lock().unwrap();

    // Uniqueness checks
    if table.values().any(|u| u.username == body.username) {
        return Err(UserServiceError::DuplicateUsername);
    }
    if table.values().any(|u| u.email == body.email) {
        return Err(UserServiceError::DuplicateEmail);
    }

    let next_id = (table.len() + 1).to_string();
    let record = UserResponse {
        id: next_id.clone(),
        username: body.username,
        email: body.email,
        display_name: body.display_name,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    table.insert(next_id, record.clone());

    Ok(Created(record))
}

/// Retrieve a single user by their ID.
#[a3_endpoint(GET "/users/:id")]
#[a3_security(jwt, scopes = ["users:read"])]
async fn fetch_user(
    _ctx: A3Context,
    axum::extract::Extension(db): axum::extract::Extension<Db>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> A3Result<Json<UserResponse>, UserServiceError> {
    let table = db.lock().unwrap();
    let record = table.get(&user_id).cloned().ok_or(UserServiceError::NotFound)?;
    Ok(Json(record))
}

/// Permanently remove a user by their ID.
#[a3_endpoint(DELETE "/users/:id")]
#[a3_security(jwt, scopes = ["users:delete"])]
async fn remove_user(
    _ctx: A3Context,
    axum::extract::Extension(db): axum::extract::Extension<Db>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> A3Result<Json<DeleteConfirmation>, UserServiceError> {
    let mut table = db.lock().unwrap();
    table.remove(&user_id).ok_or(UserServiceError::NotFound)?;
    Ok(Json(DeleteConfirmation { deleted: true }))
}

/// Simple liveness check -- no authentication required.
#[a3_endpoint(GET "/health")]
#[a3_security(none)]
#[a3_rate_limit(none)]
async fn health(_ctx: A3Context) -> A3Result<Json<HealthStatus>, Never> {
    Ok(Json(HealthStatus::ok("1.0.0")))
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    a3::init_tracing();

    let db = empty_db();

    let svc = Service::builder()
        .name("user-crud")
        .version("1.0.0")
        .endpoint(register_user())
        .endpoint(fetch_user())
        .endpoint(remove_user())
        .endpoint(health())
        .auth(JwtAuth::from_env()?)
        .build()?;

    let app = svc.into_router().layer(axum::extract::Extension(db));

    let addr = "0.0.0.0:3000";
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("user-crud service up on {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}
