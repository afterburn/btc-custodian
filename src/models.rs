use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct CreateWalletRequest {
    pub name: String,
    pub password: String,  // User password to encrypt mnemonic
    #[serde(default)]
    pub mnemonic: Option<String>,
}

#[derive(Serialize)]
pub struct CreateWalletResponse {
    pub id: Uuid,
    pub name: String,
    pub mnemonic: String,
    pub descriptor: String,
}

#[derive(Serialize)]
pub struct BalanceResponse {
    pub confirmed: u64,
    pub unconfirmed: u64,
    pub total: u64,
}

#[derive(Serialize)]
pub struct AddressResponse {
    pub address: String,
    pub index: u32,
}

#[derive(Deserialize)]
pub struct CreateTransactionRequest {
    pub recipient: String,
    pub amount: u64,
    pub password: String,  // User password to decrypt mnemonic for signing
}

#[derive(Serialize)]
pub struct TransactionResponse {
    pub txid: String,
}

#[derive(Serialize)]
pub struct WalletItem {
    pub id: Uuid,
    pub name: String,
}

#[derive(Serialize)]
pub struct WalletListResponse {
    pub wallets: Vec<WalletItem>,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
}
