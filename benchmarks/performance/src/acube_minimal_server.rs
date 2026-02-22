use acube::prelude::*;

#[acube_endpoint(GET "/health")]
#[acube_security(none)]
#[acube_authorize(public)]
#[acube_rate_limit(none)]
async fn health_check(_ctx: AcubeContext) -> AcubeResult<Json<HealthStatus>, Never> {
    Ok(Json(HealthStatus::ok("1.0.0")))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = Service::builder()
        .name("acube-minimal-bench")
        .version("1.0.0")
        .endpoint(health_check())
        .build()?;

    eprintln!("acube_minimal_server listening on 0.0.0.0:3002");
    acube::serve(service, "0.0.0.0:3002").await
}
