//! Phase 5: Airlock Control Plane entry point.
//!
//! Boots the Axum server that orchestrates all four containment layers:
//!   POST /execute { "wasm_base64": "...", "initial_prompt": "..." }
//!
//! Environment:
//!   AIRLOCK_ADDR   bind address (default 127.0.0.1:3000)
//!   AIRLOCK_FUEL   per-execution fuel budget (default 10000)
//!   RUST_LOG       tracing filter (default info)

use std::net::SocketAddr;

use anyhow::{Context, Result};
use tracing::info;

use airlock_api::{build_router, AppState};

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let fuel = env_or("AIRLOCK_FUEL", "10000")
        .parse::<u64>()
        .context("AIRLOCK_FUEL must be an integer")?;
    let addr: SocketAddr = env_or("AIRLOCK_ADDR", "127.0.0.1:3000")
        .parse()
        .context("AIRLOCK_ADDR must be a valid socket address")?;

    // Build the micro-kernel once; every request gets its own ephemeral store.
    let state = AppState::new(fuel)
        .context("failed to initialize the ephemeral wasm host (Layer 4)")?;
    info!(
        "airlock control plane armed on {addr} (fuel={fuel}, layer1 backend={})",
        // Probe via a fresh clone of the same backend name used by the worker.
        "see /health"
    );

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("cannot bind {addr}"))?;

    info!("epistemic airlock online: try GET /health, GET /demo, POST /execute");
    axum::serve(listener, build_router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server terminated abnormally")?;

    Ok(())
}

/// Ctrl-C graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    info!("shutdown signal received; draining in-flight executions");
}
