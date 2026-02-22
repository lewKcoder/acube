use a3::prelude::*;
use jsonwebtoken::{encode, EncodingKey, Header};

// ─── Schema ─────────────────────────────────────────────────────────────────

#[derive(A3Schema, Debug, Deserialize)]
pub struct CreateTaskInput {
    #[a3(min_length = 3, max_length = 50)]
    #[a3(sanitize(trim))]
    pub name: String,

    #[a3(max_length = 200)]
    #[a3(sanitize(strip_html))]
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskOutput {
    pub id: String,
    pub name: String,
    pub description: String,
}

// ─── Errors ─────────────────────────────────────────────────────────────────

#[derive(A3Error, Debug)]
pub enum TaskError {
    #[a3(status = 400, message = "Invalid task input")]
    InvalidInput,
}

// ─── Endpoints ──────────────────────────────────────────────────────────────

#[a3_endpoint(GET "/health")]
#[a3_security(none)]
#[a3_authorize(public)]
#[a3_rate_limit(none)]
async fn health_check(_ctx: A3Context) -> A3Result<Json<HealthStatus>, Never> {
    Ok(Json(HealthStatus::ok("1.0.0")))
}

#[a3_endpoint(POST "/tasks")]
#[a3_security(jwt)]
#[a3_authorize(scopes = ["tasks:create"])]
#[a3_rate_limit(100, per_minute)]
async fn create_task(
    _ctx: A3Context,
    input: Valid<CreateTaskInput>,
) -> A3Result<Created<TaskOutput>, TaskError> {
    let input = input.into_inner();
    Ok(Created(TaskOutput {
        id: "1".to_string(),
        name: input.name,
        description: input.description,
    }))
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a JWT token for benchmarking and print to stdout
    let secret = "dev-secret";
    let claims = JwtClaims {
        sub: "bench-user".to_string(),
        scopes: ScopeClaim(vec!["tasks:create".to_string()]),
        role: None,
        exp: Some(chrono::Utc::now().timestamp() as u64 + 86400),
        iat: Some(chrono::Utc::now().timestamp() as u64),
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;
    // Print token to stdout so the benchmark script can read it
    println!("JWT_TOKEN={}", token);

    let service = Service::builder()
        .name("a3-full-bench")
        .version("1.0.0")
        .endpoint(health_check())
        .endpoint(create_task())
        .auth(JwtAuth::new(secret))
        .build()?;

    eprintln!("a3_full_server listening on 0.0.0.0:3003");
    a3::serve(service, "0.0.0.0:3003").await
}
