use acube::prelude::*;
use jsonwebtoken::{encode, EncodingKey, Header};

// ─── Schema ─────────────────────────────────────────────────────────────────

#[derive(AcubeSchema, Debug, Deserialize)]
pub struct CreateTaskInput {
    #[acube(min_length = 3, max_length = 50)]
    #[acube(sanitize(trim))]
    pub name: String,

    #[acube(max_length = 200)]
    #[acube(sanitize(strip_html))]
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskOutput {
    pub id: String,
    pub name: String,
    pub description: String,
}

// ─── Errors ─────────────────────────────────────────────────────────────────

#[derive(AcubeError, Debug)]
pub enum TaskError {
    #[acube(status = 400, message = "Invalid task input")]
    InvalidInput,
}

// ─── Endpoints ──────────────────────────────────────────────────────────────

#[acube_endpoint(GET "/health")]
#[acube_security(none)]
#[acube_authorize(public)]
#[acube_rate_limit(none)]
async fn health_check(_ctx: AcubeContext) -> AcubeResult<Json<HealthStatus>, Never> {
    Ok(Json(HealthStatus::ok("1.0.0")))
}

#[acube_endpoint(POST "/tasks")]
#[acube_security(jwt)]
#[acube_authorize(scopes = ["tasks:create"])]
#[acube_rate_limit(100, per_minute)]
async fn create_task(
    _ctx: AcubeContext,
    input: Valid<CreateTaskInput>,
) -> AcubeResult<Created<TaskOutput>, TaskError> {
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
        .name("acube-full-bench")
        .version("1.0.0")
        .endpoint(health_check())
        .endpoint(create_task())
        .auth(JwtAuth::new(secret))
        .build()?;

    eprintln!("acube_full_server listening on 0.0.0.0:3003");
    acube::serve(service, "0.0.0.0:3003").await
}
