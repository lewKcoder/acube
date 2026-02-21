//! Minimal a³ example — health check endpoint with security headers.
//!
//! Run: `cargo run --example hello -p a3`
//! Test: `curl -i http://localhost:3000/health`

use a3::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    a3::init_tracing();

    let service = Service::builder()
        .name("hello-service")
        .version("0.1.0")
        .endpoint(EndpointRegistration {
            method: HttpMethod::Get,
            path: "/health".to_string(),
            handler: axum::routing::get(health_handler),
        })
        .build()?;

    a3::serve(service, "0.0.0.0:3000").await
}

async fn health_handler() -> impl IntoResponse {
    Json(HealthStatus::ok("0.1.0"))
}
