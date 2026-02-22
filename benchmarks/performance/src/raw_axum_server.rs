use axum::{extract::Json, routing::get, Router};
use serde::Serialize;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: "1.0.0",
    })
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/health", get(health_check));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap();
    eprintln!("raw_axum_server listening on 0.0.0.0:3001");
    axum::serve(listener, app).await.unwrap();
}
