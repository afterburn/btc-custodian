use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::fmt;

#[derive(Debug)]
#[allow(dead_code)]
pub enum ApiError {
    WalletAlreadyExists(String),
    WalletNotFound(String),
    InvalidMnemonic(String),
    WalletCreationFailed(String),
    DatabaseError(String),
    NetworkError(String),
    InvalidAddress(String),
    TransactionBuildFailed(String),
    TransactionSignFailed(String),
    TransactionBroadcastFailed(String),
    SyncFailed(String),
    InsufficientFunds,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WalletAlreadyExists(id) => write!(f, "Wallet '{}' already exists", id),
            Self::WalletNotFound(id) => write!(f, "Wallet '{}' not found", id),
            Self::InvalidMnemonic(msg) => write!(f, "Invalid mnemonic: {}", msg),
            Self::WalletCreationFailed(msg) => write!(f, "Wallet creation failed: {}", msg),
            Self::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            Self::NetworkError(msg) => write!(f, "Network error: {}", msg),
            Self::InvalidAddress(msg) => write!(f, "Invalid address: {}", msg),
            Self::TransactionBuildFailed(msg) => write!(f, "Transaction build failed: {}", msg),
            Self::TransactionSignFailed(msg) => write!(f, "Transaction signing failed: {}", msg),
            Self::TransactionBroadcastFailed(msg) => {
                write!(f, "Transaction broadcast failed: {}", msg)
            }
            Self::SyncFailed(msg) => write!(f, "Sync failed: {}", msg),
            Self::InsufficientFunds => write!(f, "Insufficient funds"),
        }
    }
}

impl std::error::Error for ApiError {}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::WalletAlreadyExists(_) => (StatusCode::CONFLICT, self.to_string()),
            Self::WalletNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            Self::InvalidMnemonic(_) | Self::InvalidAddress(_) => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            Self::InsufficientFunds | Self::TransactionBuildFailed(_) => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        (status, Json(ErrorResponse { error: message })).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
