//! User service example — CRUD + auth + validation.
//!
//! Run: `cargo run --example user_service -p a3`
//!
//! Test:
//!   curl -i http://localhost:3000/health
//!   curl -i -X POST http://localhost:3000/users \
//!     -H "Authorization: Bearer test-token" \
//!     -H "Content-Type: application/json" \
//!     -d '{"username":"alice","email":"alice@example.com","display_name":"Alice"}'
//!   curl -i http://localhost:3000/users/1 -H "Authorization: Bearer test-token"
//!   curl -i -X DELETE http://localhost:3000/users/1 -H "Authorization: Bearer test-token"

use a3::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ─── Schema definitions ─────────────────────────────────────────────────────

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

#[derive(Debug, Clone, Serialize)]
pub struct UserOutput {
    pub id: String,
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub created_at: String,
}

// ─── Error definitions ──────────────────────────────────────────────────────

#[derive(A3Error, Debug)]
pub enum UserError {
    #[a3(status = 404, message = "User not found")]
    NotFound,

    #[a3(status = 409, message = "Username already taken")]
    UsernameTaken,

    #[a3(status = 409, message = "Email already registered")]
    EmailTaken,

    #[a3(status = 502, retryable, message = "Database unavailable")]
    DbError,
}

// ─── In-memory store ────────────────────────────────────────────────────────

type UserStore = Arc<Mutex<HashMap<String, UserOutput>>>;

fn user_store() -> UserStore {
    Arc::new(Mutex::new(HashMap::new()))
}

// ─── Endpoints ──────────────────────────────────────────────────────────────

#[a3_endpoint(POST "/users")]
#[a3_security(jwt)]
#[a3_authorize(scopes = ["users:create"])]
#[a3_rate_limit(10, per_minute)]
async fn create_user(
    ctx: A3Context,
    input: Valid<CreateUserInput>,
) -> A3Result<Created<UserOutput>, UserError> {
    let input = input.into_inner();
    let store = ctx.state::<UserStore>();
    let mut store = store.lock().unwrap();

    // Check uniqueness
    if store.values().any(|u| u.username == input.username) {
        return Err(UserError::UsernameTaken);
    }
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
#[a3_security(jwt)]
#[a3_authorize(scopes = ["users:read"])]
async fn get_user(ctx: A3Context) -> A3Result<Json<UserOutput>, UserError> {
    let id: String = ctx.path("id");
    let store = ctx.state::<UserStore>();
    let store = store.lock().unwrap();
    let user = store.get(&id).cloned().ok_or(UserError::NotFound)?;
    Ok(Json(user))
}

#[a3_endpoint(DELETE "/users/:id")]
#[a3_security(jwt)]
#[a3_authorize(scopes = ["users:delete"])]
async fn delete_user(ctx: A3Context) -> A3Result<NoContent, UserError> {
    let id: String = ctx.path("id");
    let store = ctx.state::<UserStore>();
    let mut store = store.lock().unwrap();
    store.remove(&id).ok_or(UserError::NotFound)?;
    Ok(NoContent)
}

#[a3_endpoint(GET "/health")]
#[a3_security(none)]
#[a3_authorize(public)]
#[a3_rate_limit(none)]
async fn health_check(_ctx: A3Context) -> A3Result<Json<HealthStatus>, Never> {
    Ok(Json(HealthStatus::ok("1.0.0")))
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    a3::init_tracing();

    let store = user_store();

    // Build the service (endpoint() requires EndpointRegistration)
    let service = Service::builder()
        .name("user-service")
        .version("1.0.0")
        .state(store) // Shared state — accessible via ctx.state::<UserStore>()
        .endpoint(create_user())
        .endpoint(get_user())
        .endpoint(delete_user())
        .endpoint(health_check())
        .auth(JwtAuth::from_env()?)
        .cors_allow_origins(&["http://localhost:3001"])
        .build()?;

    a3::serve(service, "0.0.0.0:3000").await
}
