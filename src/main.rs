mod crypto;
mod db;
mod error;
mod handlers;
mod middleware;
mod models;
mod network;
mod state;
mod wallet;

use axum::{
    middleware as axum_middleware,
    routing::{get, post},
    Router,
};
use db::SqliteDatabase;
use state::AppState;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::info;

const SERVER_ADDRESS: &str = "127.0.0.1:3000";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    initialize_tracing();

    let data_dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "data".to_string());
    let db_path = format!("{}/wallets.db", data_dir);

    std::fs::create_dir_all(&data_dir)?;
    let db = SqliteDatabase::new(&db_path)?;
    let state = AppState::new(Arc::new(db));

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(SERVER_ADDRESS).await?;

    log_api_endpoints();
    info!("Database initialized at: {}", db_path);
    info!("Server listening on http://{}", SERVER_ADDRESS);

    axum::serve(listener, app).await?;

    Ok(())
}

fn initialize_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter("custodian=info,tower_http=info")
        .with_target(false)
        .compact()
        .init();
}

fn build_router(state: AppState) -> Router {
    let protected_routes = Router::new()
        .route(
            "/:network/wallets",
            post(handlers::create_wallet).get(handlers::list_wallets),
        )
        .route(
            "/:network/wallets/:wallet_id/balance",
            get(handlers::get_balance),
        )
        .route(
            "/:network/wallets/:wallet_id/address",
            get(handlers::get_new_address),
        )
        .route(
            "/:network/wallets/:wallet_id/transaction",
            post(handlers::create_transaction),
        )
        .layer(axum_middleware::from_fn(middleware::api_key_auth))
        .with_state(state.clone());

    Router::new()
        .route("/health", get(handlers::health_check))
        .merge(protected_routes)
        .layer(CorsLayer::permissive())
}

fn log_api_endpoints() {
    info!("API endpoints:");
    info!("  GET  /health");
    info!("  POST /:network/wallets");
    info!("  GET  /:network/wallets");
    info!("  GET  /:network/wallets/:wallet_id/balance");
    info!("  GET  /:network/wallets/:wallet_id/address");
    info!("  POST /:network/wallets/:wallet_id/transaction");
    info!("Supported networks: bitcoin, testnet, signet, regtest");
}
