//! # a³ (エースリー)
//!
//! AI が生成するサーバーコードのセキュリティを、フレームワークの構文レベルで強制する Rust ライブラリ。
//!
//! ## 設計原則
//!
//! 1. **安全性は構文で強制** — セキュリティはオプトアウト。書かないとコンパイルエラー
//! 2. **三重検証** — Rust コンパイラ (型) → a³ 契約 (起動時) → パイプライン (実行時)
//! 3. **Rust の慣習に従う** — derive macro, trait, Result, Option。独自構文は最小限

pub mod error;
pub mod extract;
pub mod rate_limit;
pub mod runtime;
pub mod schema;
pub mod security;
pub mod types;

// Re-export axum so that generated code from a3_endpoint macro can reference it
// without requiring users to add axum as a direct dependency.
#[doc(hidden)]
pub use axum;

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::error::{A3ErrorInfo, A3FrameworkError};
    pub use crate::extract::{A3Context, Valid};
    pub use crate::rate_limit::{
        InMemoryBackend, RateLimitBackend, RateLimitOutcome, RateLimitRejection,
    };
    pub use crate::runtime::{EndpointRegistration, Service};
    pub use crate::schema::{A3SchemaInfo, A3Validate, ValidationError};
    pub use crate::security::{
        AuthIdentity, AuthProvider, JwtAuth, JwtAuthError, JwtClaims, ScopeClaim,
    };
    pub use crate::types::*;

    pub use axum::extract::Json;
    pub use axum::http::StatusCode;
    pub use axum::response::IntoResponse;
    pub use serde::{Deserialize, Serialize};

    pub use a3_macros::{a3_endpoint, A3Error, A3Schema};
}

/// Initialize structured tracing (logging).
pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .json()
        .init();
}

/// Serve an a³ service on the given address.
pub async fn serve(
    service: runtime::Service,
    addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let router = service.into_router();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("a³ service listening on {}", addr);
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Wait for SIGTERM or Ctrl+C for graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
