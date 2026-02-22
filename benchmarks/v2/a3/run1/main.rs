use a3::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ─── Input schemas ──────────────────────────────────────────────────────────

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

#[derive(A3Schema, Debug, Deserialize)]
pub struct UpdateUserInput {
    #[a3(min_length = 1, max_length = 100)]
    #[a3(sanitize(trim, strip_html))]
    pub display_name: String,
}

// ─── Output types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct UserProfile {
    pub id: String,
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicUserProfile {
    pub id: String,
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteResponse {
    pub deleted: bool,
}

// ─── Errors ─────────────────────────────────────────────────────────────────

#[derive(A3Error, Debug)]
pub enum UserError {
    #[a3(status = 400, message = "Validation failed")]
    ValidationFailed,

    #[a3(status = 403, message = "Not authorized to modify this profile")]
    Forbidden,

    #[a3(status = 404, message = "User not found")]
    NotFound,

    #[a3(status = 409, message = "Username already taken")]
    UsernameTaken,

    #[a3(status = 409, message = "Email already registered")]
    EmailTaken,
}

// ─── State ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct StoredUser {
    id: String,
    username: String,
    email: String,
    display_name: String,
    owner_id: String,
    created_at: String,
}

struct UserDb {
    users: HashMap<String, StoredUser>,
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

type UserStore = Arc<Mutex<UserDb>>;

fn new_store() -> UserStore {
    Arc::new(Mutex::new(UserDb::new()))
}

// ─── Handlers ───────────────────────────────────────────────────────────────

#[a3_endpoint(POST "/users")]
#[a3_security(jwt)]
#[a3_rate_limit(30, per_minute)]
async fn create_user(
    ctx: A3Context,
    axum::extract::Extension(store): axum::extract::Extension<UserStore>,
    input: Valid<CreateUserInput>,
) -> A3Result<Created<UserProfile>, UserError> {
    let auth = ctx.auth.ok_or(UserError::Forbidden)?;
    let input = input.into_inner();
    let mut db = store.lock().unwrap();

    if db.users.values().any(|u| u.username == input.username) {
        return Err(UserError::UsernameTaken);
    }
    if db.users.values().any(|u| u.email == input.email) {
        return Err(UserError::EmailTaken);
    }

    let id = db.next_id.to_string();
    db.next_id += 1;

    let now = chrono::Utc::now().to_rfc3339();
    let stored = StoredUser {
        id: id.clone(),
        username: input.username,
        email: input.email,
        display_name: input.display_name,
        owner_id: auth.subject,
        created_at: now,
    };
    db.users.insert(id, stored.clone());

    Ok(Created(UserProfile {
        id: stored.id,
        username: stored.username,
        email: stored.email,
        display_name: stored.display_name,
        created_at: stored.created_at,
    }))
}

#[a3_endpoint(GET "/users/:id")]
#[a3_security(jwt)]
async fn get_user(
    ctx: A3Context,
    axum::extract::Extension(store): axum::extract::Extension<UserStore>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> A3Result<Json<serde_json::Value>, UserError> {
    let auth = ctx.auth.ok_or(UserError::Forbidden)?;
    let db = store.lock().unwrap();
    let user = db.users.get(&id).ok_or(UserError::NotFound)?;

    if auth.subject == user.owner_id {
        Ok(Json(serde_json::json!({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "display_name": user.display_name,
            "created_at": user.created_at,
        })))
    } else {
        Ok(Json(serde_json::json!({
            "id": user.id,
            "username": user.username,
            "display_name": user.display_name,
        })))
    }
}

#[a3_endpoint(PUT "/users/:id")]
#[a3_security(jwt)]
async fn update_user(
    ctx: A3Context,
    axum::extract::Extension(store): axum::extract::Extension<UserStore>,
    axum::extract::Path(id): axum::extract::Path<String>,
    input: Valid<UpdateUserInput>,
) -> A3Result<Json<UserProfile>, UserError> {
    let auth = ctx.auth.ok_or(UserError::Forbidden)?;
    let input = input.into_inner();
    let mut db = store.lock().unwrap();
    let user = db.users.get_mut(&id).ok_or(UserError::NotFound)?;

    if auth.subject != user.owner_id {
        return Err(UserError::Forbidden);
    }

    user.display_name = input.display_name;

    let profile = UserProfile {
        id: user.id.clone(),
        username: user.username.clone(),
        email: user.email.clone(),
        display_name: user.display_name.clone(),
        created_at: user.created_at.clone(),
    };

    Ok(Json(profile))
}

#[a3_endpoint(DELETE "/users/:id")]
#[a3_security(jwt)]
async fn delete_user(
    ctx: A3Context,
    axum::extract::Extension(store): axum::extract::Extension<UserStore>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> A3Result<Json<DeleteResponse>, UserError> {
    let auth = ctx.auth.ok_or(UserError::Forbidden)?;
    let mut db = store.lock().unwrap();
    let user = db.users.get(&id).ok_or(UserError::NotFound)?;

    if auth.subject != user.owner_id {
        return Err(UserError::Forbidden);
    }

    db.users.remove(&id);
    Ok(Json(DeleteResponse { deleted: true }))
}

#[a3_endpoint(GET "/health")]
#[a3_security(none)]
#[a3_rate_limit(none)]
async fn health(_ctx: A3Context) -> A3Result<Json<serde_json::Value>, Never> {
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    a3::init_tracing();

    let store = new_store();

    let service = Service::builder()
        .name("user-profile-service")
        .version("1.0.0")
        .endpoint(create_user())
        .endpoint(get_user())
        .endpoint(update_user())
        .endpoint(delete_user())
        .endpoint(health())
        .auth(JwtAuth::from_env()?)
        .build()?;

    let router = service
        .into_router()
        .layer(axum::extract::Extension(store));

    let addr = "0.0.0.0:3000";
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("user-profile-service listening on {}", addr);
    axum::serve(listener, router).await?;

    Ok(())
}
