use crate::crypto::{decrypt_mnemonic, encrypt_mnemonic};
use crate::db::WalletRecord;
use crate::error::{ApiError, ApiResult};
use crate::models::*;
use crate::network::{get_electrum_url, parse_network};
use crate::state::{AppState, WalletInfo};
use crate::wallet::WalletBuilder;
use axum::{
    extract::{Path, State},
    Json,
};
use bdk::bitcoin::Address;
use bdk::blockchain::ElectrumBlockchain;
use bdk::electrum_client::{Client, ElectrumApi};
use bdk::SyncOptions;
use std::str::FromStr;
use tracing::{debug, error, info};
use uuid::Uuid;

pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        service: "Bitcoin Wallet API".to_string(),
    })
}

pub async fn create_wallet(
    Path(network_str): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<CreateWalletRequest>,
) -> ApiResult<Json<CreateWalletResponse>> {
    let network = parse_network(&network_str)
        .ok_or_else(|| ApiError::InvalidAddress(format!("Invalid network: {}", network_str)))?;

    let wallet_id = Uuid::new_v4();

    debug!("Creating wallet: {} ({}) on network: {:?}", payload.name, wallet_id, network);

    let (wallet, mnemonic, descriptor) = WalletBuilder::new(wallet_id, network)
        .with_mnemonic(payload.mnemonic)
        .build()?;

    let (encrypted_mnemonic, salt) = encrypt_mnemonic(&mnemonic, &payload.password)?;

    let wallet_record = WalletRecord {
        id: wallet_id,
        name: payload.name.clone(),
        encrypted_mnemonic,
        salt,
        descriptor: descriptor.clone(),
        network,
    };
    state.db.save_wallet(&wallet_record)?;

    drop(wallet);

    let watch_only_wallet = bdk::Wallet::new(
        &descriptor,
        None,
        network,
        bdk::database::MemoryDatabase::default(),
    )
    .map_err(|e| ApiError::WalletCreationFailed(e.to_string()))?;

    let wallet_info = WalletInfo::new_watch_only(
        watch_only_wallet,
        payload.name.clone(),
        descriptor.clone(),
    );

    state
        .wallets
        .lock()
        .unwrap()
        .insert(wallet_id, wallet_info);

    info!("Wallet created: {} ({}) on network: {:?}", payload.name, wallet_id, network);

    Ok(Json(CreateWalletResponse {
        id: wallet_id,
        name: payload.name,
        mnemonic,
        descriptor,
    }))
}

pub async fn list_wallets(
    Path(network_str): Path<String>,
    State(state): State<AppState>,
) -> ApiResult<Json<WalletListResponse>> {
    let network = parse_network(&network_str)
        .ok_or_else(|| ApiError::InvalidAddress(format!("Invalid network: {}", network_str)))?;

    // Load wallets from database
    let wallet_records = state.db.list_wallets(network)?;
    let wallet_items: Vec<WalletItem> = wallet_records
        .iter()
        .map(|record| WalletItem {
            id: record.id,
            name: record.name.clone(),
        })
        .collect();

    Ok(Json(WalletListResponse {
        wallets: wallet_items,
    }))
}

pub async fn get_balance(
    Path((network_str, wallet_id_str)): Path<(String, String)>,
    State(state): State<AppState>,
) -> ApiResult<Json<BalanceResponse>> {
    let network = parse_network(&network_str)
        .ok_or_else(|| ApiError::InvalidAddress(format!("Invalid network: {}", network_str)))?;

    let wallet_id = Uuid::parse_str(&wallet_id_str)
        .map_err(|_| ApiError::WalletNotFound(wallet_id_str.clone()))?;

    let wallet_info = get_or_load_wallet(&state, wallet_id, network)?;
    auto_sync_wallet(&wallet_info, network)?;

    let wallet = wallet_info.wallet.lock().unwrap();
    let balance = wallet.get_balance().map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok(Json(BalanceResponse {
        confirmed: balance.confirmed,
        unconfirmed: balance.trusted_pending + balance.untrusted_pending,
        total: balance.get_total(),
    }))
}

fn auto_sync_wallet(wallet_info: &WalletInfo, network: bdk::bitcoin::Network) -> ApiResult<()> {
    let is_synced = *wallet_info.synced.lock().unwrap();

    let wallet = wallet_info.wallet.lock().unwrap();
    let electrum_url = get_electrum_url(network);

    let client = Client::new(electrum_url)
        .map_err(|e| ApiError::NetworkError(e.to_string()))?;

    let blockchain = ElectrumBlockchain::from(client);

    wallet
        .sync(&blockchain, SyncOptions::default())
        .map_err(|e| ApiError::SyncFailed(e.to_string()))?;

    if !is_synced {
        *wallet_info.synced.lock().unwrap() = true;
    }

    Ok(())
}

fn get_or_load_wallet(
    state: &AppState,
    wallet_id: Uuid,
    network: bdk::bitcoin::Network,
) -> ApiResult<WalletInfo> {
    {
        let wallets = state.wallets.lock().unwrap();
        if let Some(wallet_info) = wallets.get(&wallet_id) {
            return Ok(wallet_info.clone());
        }
    }

    let wallet_record = state.db.get_wallet(wallet_id)?
        .ok_or_else(|| ApiError::WalletNotFound(wallet_id.to_string()))?;

    let wallet = bdk::Wallet::new(
        &wallet_record.descriptor,
        None,
        network,
        bdk::database::MemoryDatabase::default(),
    )
    .map_err(|e| ApiError::WalletCreationFailed(e.to_string()))?;

    let wallet_info = WalletInfo::new_watch_only(
        wallet,
        wallet_record.name.clone(),
        wallet_record.descriptor,
    );

    state
        .wallets
        .lock()
        .unwrap()
        .insert(wallet_id, wallet_info.clone());

    Ok(wallet_info)
}

pub async fn get_new_address(
    Path((network_str, wallet_id_str)): Path<(String, String)>,
    State(state): State<AppState>,
) -> ApiResult<Json<AddressResponse>> {
    let network = parse_network(&network_str)
        .ok_or_else(|| ApiError::InvalidAddress(format!("Invalid network: {}", network_str)))?;

    let wallet_id = Uuid::parse_str(&wallet_id_str)
        .map_err(|_| ApiError::WalletNotFound(wallet_id_str.clone()))?;

    let wallet_info = get_or_load_wallet(&state, wallet_id, network)?;

    let wallet = wallet_info.wallet.lock().unwrap();
    let address_info = wallet
        .get_address(bdk::wallet::AddressIndex::New)
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok(Json(AddressResponse {
        address: address_info.address.to_string(),
        index: address_info.index,
    }))
}

pub async fn create_transaction(
    Path((network_str, wallet_id_str)): Path<(String, String)>,
    State(state): State<AppState>,
    Json(payload): Json<CreateTransactionRequest>,
) -> ApiResult<Json<TransactionResponse>> {
    let network = parse_network(&network_str)
        .ok_or_else(|| ApiError::InvalidAddress(format!("Invalid network: {}", network_str)))?;

    let wallet_id = Uuid::parse_str(&wallet_id_str)
        .map_err(|_| ApiError::WalletNotFound(wallet_id_str.clone()))?;

    debug!(
        "Creating transaction for wallet: {} to recipient: {} amount: {} on network: {:?}",
        wallet_id, payload.recipient, payload.amount, network
    );

    // Load wallet record from database to get encrypted mnemonic
    let wallet_record = state.db.get_wallet(wallet_id)?
        .ok_or_else(|| ApiError::WalletNotFound(wallet_id.to_string()))?;

    // Decrypt mnemonic with user password
    let mnemonic = decrypt_mnemonic(
        &wallet_record.encrypted_mnemonic,
        &wallet_record.salt,
        &payload.password,
    )?;

    // Create temporary FULL wallet (with private keys) for signing
    // This wallet will be dropped after signing - never stored in memory
    let (full_wallet, _, _) = WalletBuilder::new(wallet_id, network)
        .with_mnemonic(Some(mnemonic))
        .build()?;

    // Auto-sync the full wallet before creating transaction
    let electrum_url = get_electrum_url(network);
    let client = Client::new(electrum_url)
        .map_err(|e| ApiError::NetworkError(e.to_string()))?;
    let blockchain = ElectrumBlockchain::from(client);

    full_wallet
        .sync(&blockchain, SyncOptions::default())
        .map_err(|e| ApiError::SyncFailed(e.to_string()))?;

    let wallet = full_wallet;  // Use the full wallet for signing

    // Check current balance to determine if this is a "send max" transaction
    let balance = wallet.get_balance()
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;
    let total_balance = balance.get_total();

    let recipient_address = Address::from_str(&payload.recipient)
        .map_err(|e| ApiError::InvalidAddress(e.to_string()))?
        .require_network(network)
        .map_err(|e| ApiError::InvalidAddress(format!("Address network mismatch: {}", e)))?;

    let mut tx_builder = wallet.build_tx();

    // If amount equals total balance, drain wallet (subtracts fee automatically)
    if payload.amount == total_balance {
        debug!("Using drain_wallet to send max balance");
        tx_builder
            .drain_wallet()
            .drain_to(recipient_address.script_pubkey())
            .enable_rbf();
    } else {
        tx_builder
            .add_recipient(recipient_address.script_pubkey(), payload.amount)
            .enable_rbf();
    }

    let (mut psbt, _details) = tx_builder
        .finish()
        .map_err(|e| ApiError::TransactionBuildFailed(e.to_string()))?;

    let finalized = wallet
        .sign(&mut psbt, Default::default())
        .map_err(|e| ApiError::TransactionSignFailed(e.to_string()))?;

    if !finalized {
        error!("Transaction not finalized after signing");
        return Err(ApiError::TransactionSignFailed(
            "Transaction not finalized".to_string(),
        ));
    }

    let tx = psbt.extract_tx();
    let txid = tx.txid();
    let electrum_url = get_electrum_url(network);

    let client = Client::new(electrum_url)
        .map_err(|e| ApiError::NetworkError(e.to_string()))?;

    client
        .transaction_broadcast(&tx)
        .map_err(|e| ApiError::TransactionBroadcastFailed(e.to_string()))?;

    info!("Transaction broadcast: {}", txid);

    Ok(Json(TransactionResponse {
        txid: txid.to_string(),
    }))
}
