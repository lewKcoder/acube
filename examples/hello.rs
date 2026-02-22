//! Minimal a³ example — health check endpoint with security headers.
//!
//! Run: `cargo run --example hello -p a3`
//! Test: `curl -i http://localhost:3000/health`

use a3::prelude::*;

#[a3_endpoint(GET "/health")]
#[a3_security(none)]
#[a3_authorize(public)]
#[a3_rate_limit(none)]
async fn health_check(_ctx: A3Context) -> A3Result<Json<HealthStatus>, Never> {
    Ok(Json(HealthStatus::ok("0.1.0")))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    a3::init_tracing();

    let service = Service::builder()
        .name("hello-service")
        .version("0.1.0")
        .endpoint(health_check())
        .build()?;

    a3::serve(service, "0.0.0.0:3000").await
}
