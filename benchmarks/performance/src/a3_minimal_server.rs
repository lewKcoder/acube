use a3::prelude::*;

#[a3_endpoint(GET "/health")]
#[a3_security(none)]
#[a3_authorize(public)]
#[a3_rate_limit(none)]
async fn health_check(_ctx: A3Context) -> A3Result<Json<HealthStatus>, Never> {
    Ok(Json(HealthStatus::ok("1.0.0")))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = Service::builder()
        .name("a3-minimal-bench")
        .version("1.0.0")
        .endpoint(health_check())
        .build()?;

    eprintln!("a3_minimal_server listening on 0.0.0.0:3002");
    a3::serve(service, "0.0.0.0:3002").await
}
