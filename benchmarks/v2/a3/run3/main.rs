use a3::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(A3Schema, Debug, Deserialize)]
pub struct ProfilePayload {
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
pub struct ProfilePatch {
    #[a3(min_length = 1, max_length = 100)]
    #[a3(sanitize(trim, strip_html))]
    pub display_name: String,
}

#[derive(Debug, Clone)]
struct ProfileRecord {
    id: String,
    username: String,
    email: String,
    display_name: String,
    owner_id: String,
    created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FullProfile {
    pub id: String,
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicProfile {
    pub id: String,
    pub username: String,
    pub display_name: String,
}

#[derive(Serialize)]
pub struct Deleted {
    pub deleted: bool,
}

impl From<&ProfileRecord> for FullProfile {
    fn from(r: &ProfileRecord) -> Self {
        Self {
            id: r.id.clone(),
            username: r.username.clone(),
            email: r.email.clone(),
            display_name: r.display_name.clone(),
            created_at: r.created_at.clone(),
        }
    }
}

impl From<&ProfileRecord> for PublicProfile {
    fn from(r: &ProfileRecord) -> Self {
        Self {
            id: r.id.clone(),
            username: r.username.clone(),
            display_name: r.display_name.clone(),
        }
    }
}

#[derive(A3Error, Debug)]
pub enum ProfileError {
    #[a3(status = 400, message = "Validation failed")]
    Invalid,

    #[a3(status = 403, message = "Forbidden")]
    Forbidden,

    #[a3(status = 404, message = "Profile not found")]
    Missing,

    #[a3(status = 409, message = "Username already taken")]
    DuplicateUsername,

    #[a3(status = 409, message = "Email already registered")]
    DuplicateEmail,
}

struct ProfileDb {
    records: HashMap<String, ProfileRecord>,
    seq: u64,
}

impl ProfileDb {
    fn empty() -> Self {
        Self {
            records: HashMap::new(),
            seq: 0,
        }
    }

    fn next_id(&mut self) -> String {
        self.seq += 1;
        self.seq.to_string()
    }
}

type Store = Arc<Mutex<ProfileDb>>;

fn build_store() -> Store {
    Arc::new(Mutex::new(ProfileDb::empty()))
}

fn caller_subject(ctx: &A3Context) -> String {
    ctx.auth
        .as_ref()
        .map(|identity| identity.subject.clone())
        .unwrap_or_default()
}

#[a3_endpoint(POST "/users")]
#[a3_security(jwt)]
#[a3_rate_limit(20, per_minute)]
async fn add_profile(
    ctx: A3Context,
    axum::extract::Extension(store): axum::extract::Extension<Store>,
    payload: Valid<ProfilePayload>,
) -> A3Result<Created<FullProfile>, ProfileError> {
    let body = payload.into_inner();
    let subject = caller_subject(&ctx);
    let mut db = store.lock().unwrap();

    if db.records.values().any(|r| r.username == body.username) {
        return Err(ProfileError::DuplicateUsername);
    }
    if db.records.values().any(|r| r.email == body.email) {
        return Err(ProfileError::DuplicateEmail);
    }

    let id = db.next_id();
    let record = ProfileRecord {
        id: id.clone(),
        username: body.username,
        email: body.email,
        display_name: body.display_name,
        owner_id: subject,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    db.records.insert(id, record.clone());

    Ok(Created(FullProfile::from(&record)))
}

#[a3_endpoint(GET "/users/:id")]
#[a3_security(jwt)]
async fn lookup_profile(
    ctx: A3Context,
    axum::extract::Extension(store): axum::extract::Extension<Store>,
    axum::extract::Path(profile_id): axum::extract::Path<String>,
) -> A3Result<axum::response::Response, ProfileError> {
    let subject = caller_subject(&ctx);
    let db = store.lock().unwrap();
    let record = db.records.get(&profile_id).ok_or(ProfileError::Missing)?;

    if record.owner_id == subject {
        Ok(Json(FullProfile::from(record)).into_response())
    } else {
        Ok(Json(PublicProfile::from(record)).into_response())
    }
}

#[a3_endpoint(PUT "/users/:id")]
#[a3_security(jwt)]
async fn modify_profile(
    ctx: A3Context,
    axum::extract::Extension(store): axum::extract::Extension<Store>,
    axum::extract::Path(profile_id): axum::extract::Path<String>,
    patch: Valid<ProfilePatch>,
) -> A3Result<Json<FullProfile>, ProfileError> {
    let subject = caller_subject(&ctx);
    let body = patch.into_inner();
    let mut db = store.lock().unwrap();

    let record = db.records.get_mut(&profile_id).ok_or(ProfileError::Missing)?;
    if record.owner_id != subject {
        return Err(ProfileError::Forbidden);
    }

    record.display_name = body.display_name;

    Ok(Json(FullProfile::from(&*record)))
}

#[a3_endpoint(DELETE "/users/:id")]
#[a3_security(jwt)]
async fn remove_profile(
    ctx: A3Context,
    axum::extract::Extension(store): axum::extract::Extension<Store>,
    axum::extract::Path(profile_id): axum::extract::Path<String>,
) -> A3Result<Json<Deleted>, ProfileError> {
    let subject = caller_subject(&ctx);
    let mut db = store.lock().unwrap();

    let record = db.records.get(&profile_id).ok_or(ProfileError::Missing)?;
    if record.owner_id != subject {
        return Err(ProfileError::Forbidden);
    }

    db.records.remove(&profile_id);
    Ok(Json(Deleted { deleted: true }))
}

#[a3_endpoint(GET "/health")]
#[a3_security(none)]
#[a3_rate_limit(none)]
async fn liveness(_ctx: A3Context) -> A3Result<Json<serde_json::Value>, Never> {
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    a3::init_tracing();

    let store = build_store();

    let svc = Service::builder()
        .name("profile-service")
        .version("0.1.0")
        .endpoint(add_profile())
        .endpoint(lookup_profile())
        .endpoint(modify_profile())
        .endpoint(remove_profile())
        .endpoint(liveness())
        .auth(JwtAuth::from_env()?)
        .build()?;

    let app = svc.into_router().layer(axum::extract::Extension(store));

    let bind_addr = "0.0.0.0:3000";
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!("profile-service ready on {}", bind_addr);
    axum::serve(listener, app).await?;

    Ok(())
}
