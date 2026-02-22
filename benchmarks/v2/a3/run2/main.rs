use a3::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(A3Schema, Debug, Deserialize)]
pub struct NewProfilePayload {
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
pub struct UpdateProfilePayload {
    #[a3(min_length = 1, max_length = 100)]
    #[a3(sanitize(trim, strip_html))]
    pub display_name: String,
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

#[derive(Debug, Clone)]
struct StoredProfile {
    id: String,
    username: String,
    email: String,
    display_name: String,
    owner_id: String,
    created_at: String,
}

impl StoredProfile {
    fn to_full(&self) -> FullProfile {
        FullProfile {
            id: self.id.clone(),
            username: self.username.clone(),
            email: self.email.clone(),
            display_name: self.display_name.clone(),
            created_at: self.created_at.clone(),
        }
    }

    fn to_public(&self) -> PublicProfile {
        PublicProfile {
            id: self.id.clone(),
            username: self.username.clone(),
            display_name: self.display_name.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DeletionResult {
    pub deleted: bool,
}

#[derive(A3Error, Debug)]
pub enum ProfileError {
    #[a3(status = 400, message = "Invalid input")]
    BadInput,

    #[a3(status = 403, message = "Not authorized to modify this profile")]
    Forbidden,

    #[a3(status = 404, message = "Profile not found")]
    Missing,

    #[a3(status = 409, message = "Username already taken")]
    DuplicateUsername,

    #[a3(status = 409, message = "Email already registered")]
    DuplicateEmail,
}

struct ProfileDatabase {
    records: HashMap<String, StoredProfile>,
    sequence: u64,
}

impl ProfileDatabase {
    fn empty() -> Self {
        Self {
            records: HashMap::new(),
            sequence: 1,
        }
    }

    fn allocate_id(&mut self) -> String {
        let current = self.sequence;
        self.sequence += 1;
        current.to_string()
    }

    fn has_username(&self, name: &str) -> bool {
        self.records.values().any(|p| p.username == name)
    }

    fn has_email(&self, addr: &str) -> bool {
        self.records.values().any(|p| p.email == addr)
    }
}

type ProfileStore = Arc<Mutex<ProfileDatabase>>;

fn create_store() -> ProfileStore {
    Arc::new(Mutex::new(ProfileDatabase::empty()))
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
async fn register_profile(
    ctx: A3Context,
    axum::extract::Extension(store): axum::extract::Extension<ProfileStore>,
    input: Valid<NewProfilePayload>,
) -> A3Result<Created<FullProfile>, ProfileError> {
    let payload = input.into_inner();
    let subject = caller_subject(&ctx);
    let mut db = store.lock().unwrap();

    if db.has_username(&payload.username) {
        return Err(ProfileError::DuplicateUsername);
    }

    if db.has_email(&payload.email) {
        return Err(ProfileError::DuplicateEmail);
    }

    let profile_id = db.allocate_id();
    let now = chrono::Utc::now().to_rfc3339();

    let record = StoredProfile {
        id: profile_id.clone(),
        username: payload.username,
        email: payload.email,
        display_name: payload.display_name,
        owner_id: subject,
        created_at: now,
    };

    let output = record.to_full();
    db.records.insert(profile_id, record);

    Ok(Created(output))
}

#[a3_endpoint(GET "/users/:id")]
#[a3_security(jwt)]
async fn fetch_profile(
    ctx: A3Context,
    axum::extract::Extension(store): axum::extract::Extension<ProfileStore>,
    axum::extract::Path(profile_id): axum::extract::Path<String>,
) -> A3Result<axum::response::Response, ProfileError> {
    let db = store.lock().unwrap();
    let record = db.records.get(&profile_id).ok_or(ProfileError::Missing)?;

    let subject = caller_subject(&ctx);

    if subject == record.owner_id {
        Ok(Json(record.to_full()).into_response())
    } else {
        Ok(Json(record.to_public()).into_response())
    }
}

#[a3_endpoint(PUT "/users/:id")]
#[a3_security(jwt)]
async fn modify_profile(
    ctx: A3Context,
    axum::extract::Extension(store): axum::extract::Extension<ProfileStore>,
    axum::extract::Path(profile_id): axum::extract::Path<String>,
    input: Valid<UpdateProfilePayload>,
) -> A3Result<Json<FullProfile>, ProfileError> {
    let payload = input.into_inner();
    let subject = caller_subject(&ctx);
    let mut db = store.lock().unwrap();

    let record = db
        .records
        .get_mut(&profile_id)
        .ok_or(ProfileError::Missing)?;

    if record.owner_id != subject {
        return Err(ProfileError::Forbidden);
    }

    record.display_name = payload.display_name;

    Ok(Json(record.to_full()))
}

#[a3_endpoint(DELETE "/users/:id")]
#[a3_security(jwt)]
async fn remove_profile(
    ctx: A3Context,
    axum::extract::Extension(store): axum::extract::Extension<ProfileStore>,
    axum::extract::Path(profile_id): axum::extract::Path<String>,
) -> A3Result<Json<DeletionResult>, ProfileError> {
    let subject = caller_subject(&ctx);
    let mut db = store.lock().unwrap();

    let record = db
        .records
        .get(&profile_id)
        .ok_or(ProfileError::Missing)?;

    if record.owner_id != subject {
        return Err(ProfileError::Forbidden);
    }

    db.records.remove(&profile_id);

    Ok(Json(DeletionResult { deleted: true }))
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

    let store = create_store();

    let service = Service::builder()
        .name("profile-service")
        .version("0.1.0")
        .endpoint(register_profile())
        .endpoint(fetch_profile())
        .endpoint(modify_profile())
        .endpoint(remove_profile())
        .endpoint(liveness())
        .auth(JwtAuth::from_env()?)
        .build()?;

    let app = service
        .into_router()
        .layer(axum::extract::Extension(store));

    let bind_addr = "0.0.0.0:3000";
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!("profile-service up at {}", bind_addr);
    axum::serve(listener, app).await?;

    Ok(())
}
