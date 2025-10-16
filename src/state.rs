use crate::db::WalletDatabase;
use bdk::database::MemoryDatabase;
use bdk::Wallet;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub wallets: Arc<Mutex<HashMap<Uuid, WalletInfo>>>,
    pub db: Arc<dyn WalletDatabase>,
}

impl AppState {
    pub fn new(db: Arc<dyn WalletDatabase>) -> Self {
        Self {
            wallets: Arc::new(Mutex::new(HashMap::new())),
            db,
        }
    }
}

#[derive(Clone)]
pub struct WalletInfo {
    pub wallet: Arc<Mutex<Wallet<MemoryDatabase>>>,
    pub synced: Arc<Mutex<bool>>,
}

impl WalletInfo {
    pub fn new_watch_only(wallet: Wallet<MemoryDatabase>, _name: String, _descriptor: String) -> Self {
        Self {
            wallet: Arc::new(Mutex::new(wallet)),
            synced: Arc::new(Mutex::new(false)),
        }
    }
}
