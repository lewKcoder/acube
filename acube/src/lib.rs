//! # acube (エースリー)
//!
//! AI が生成するサーバーコードのセキュリティを、フレームワークの構文レベルで強制する Rust ライブラリ。
//!
//! ## 設計原則
//!
//! 1. **安全性は構文で強制** — セキュリティはオプトアウト。書かないとコンパイルエラー
//! 2. **三重検証** — Rust コンパイラ (型) → acube 契約 (起動時) → パイプライン (実行時)
//! 3. **Rust の慣習に従う** — derive macro, trait, Result, Option。独自構文は最小限

pub mod error;
pub mod extract;
pub mod rate_limit;
pub mod runtime;
pub mod schema;
pub mod security;
pub mod types;

// Re-export axum and uuid so that generated code from macros can reference them
// without requiring users to add these as direct dependencies.
#[doc(hidden)]
pub use axum;
#[doc(hidden)]
pub use uuid;

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::error::{AcubeAuthError, AcubeErrorInfo, AcubeFrameworkError, OpenApiErrorVariant};
    pub use crate::extract::{AcubeContext, Valid};
    pub use crate::rate_limit::{
        InMemoryBackend, RateLimitBackend, RateLimitOutcome, RateLimitRejection,
    };
    pub use crate::runtime::{EndpointOpenApi, EndpointRegistration, Service};
    pub use crate::schema::{AcubeSchemaInfo, AcubeValidate, FieldConstraints, ValidationError};
    pub use crate::security::{
        AuthIdentity, AuthProvider, JwtAuth, JwtAuthError, JwtClaims, ScopeClaim,
    };
    pub use crate::types::*;

    pub use axum::extract::Json;
    pub use axum::http::StatusCode;
    pub use axum::response::IntoResponse;
    pub use serde::{Deserialize, Serialize};

    pub use acube_macros::{acube_authorize, acube_endpoint, AcubeError, AcubeSchema};
}

/// Initialize structured tracing (logging).
pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .json()
        .init();
}

/// Serve an acube service on the given address.
pub async fn serve(
    service: runtime::Service,
    addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let router = service.into_router();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("acube service listening on {}", addr);
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
