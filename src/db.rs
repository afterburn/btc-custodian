use crate::error::ApiResult;
use bdk::bitcoin::Network;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Represents a wallet record in the database
#[derive(Debug, Clone)]
pub struct WalletRecord {
    pub id: Uuid,
    pub name: String,
    pub encrypted_mnemonic: String,  // Base64-encoded encrypted mnemonic
    pub salt: String,                 // Base64-encoded salt for Argon2
    pub descriptor: String,
    pub network: Network,
}

/// Trait defining the database adapter interface
/// This allows easy switching between different database implementations (SQLite, PostgreSQL, etc.)
pub trait WalletDatabase: Send + Sync {
    /// Save a wallet to the database
    fn save_wallet(&self, wallet: &WalletRecord) -> ApiResult<()>;

    /// Get a wallet by ID
    fn get_wallet(&self, id: Uuid) -> ApiResult<Option<WalletRecord>>;

    /// List all wallets for a specific network
    fn list_wallets(&self, network: Network) -> ApiResult<Vec<WalletRecord>>;

    /// Delete a wallet by ID
    #[allow(dead_code)]
    fn delete_wallet(&self, id: Uuid) -> ApiResult<()>;

    /// Check if a wallet exists
    #[allow(dead_code)]
    fn wallet_exists(&self, id: Uuid) -> ApiResult<bool>;
}

/// SQLite implementation of the WalletDatabase trait
pub struct SqliteDatabase {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteDatabase {
    /// Create a new SQLite database connection
    pub fn new<P: AsRef<Path>>(path: P) -> ApiResult<Self> {
        let conn = Connection::open(path)
            .map_err(|e| crate::error::ApiError::DatabaseError(e.to_string()))?;

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };

        db.init_schema()?;
        Ok(db)
    }

    /// Initialize the database schema
    fn init_schema(&self) -> ApiResult<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "CREATE TABLE IF NOT EXISTS wallets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                encrypted_mnemonic TEXT NOT NULL,
                salt TEXT NOT NULL,
                descriptor TEXT NOT NULL,
                network TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )",
            [],
        )
        .map_err(|e| crate::error::ApiError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Convert Network enum to string for storage
    fn network_to_string(network: Network) -> &'static str {
        match network {
            Network::Bitcoin => "bitcoin",
            Network::Testnet => "testnet",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
            _ => "unknown",
        }
    }

    /// Convert string to Network enum
    fn string_to_network(s: &str) -> ApiResult<Network> {
        match s {
            "bitcoin" => Ok(Network::Bitcoin),
            "testnet" => Ok(Network::Testnet),
            "signet" => Ok(Network::Signet),
            "regtest" => Ok(Network::Regtest),
            _ => Err(crate::error::ApiError::DatabaseError(format!(
                "Unknown network: {}",
                s
            ))),
        }
    }
}

impl WalletDatabase for SqliteDatabase {
    fn save_wallet(&self, wallet: &WalletRecord) -> ApiResult<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO wallets (id, name, encrypted_mnemonic, salt, descriptor, network)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                wallet.id.to_string(),
                wallet.name,
                wallet.encrypted_mnemonic,
                wallet.salt,
                wallet.descriptor,
                Self::network_to_string(wallet.network),
            ],
        )
        .map_err(|e| crate::error::ApiError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    fn get_wallet(&self, id: Uuid) -> ApiResult<Option<WalletRecord>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn
            .prepare("SELECT id, name, encrypted_mnemonic, salt, descriptor, network FROM wallets WHERE id = ?1")
            .map_err(|e| crate::error::ApiError::DatabaseError(e.to_string()))?;

        let result = stmt
            .query_row(params![id.to_string()], |row| {
                Ok(WalletRecord {
                    id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap(),
                    name: row.get(1)?,
                    encrypted_mnemonic: row.get(2)?,
                    salt: row.get(3)?,
                    descriptor: row.get(4)?,
                    network: Self::string_to_network(&row.get::<_, String>(5)?).unwrap(),
                })
            })
            .optional()
            .map_err(|e| crate::error::ApiError::DatabaseError(e.to_string()))?;

        Ok(result)
    }

    fn list_wallets(&self, network: Network) -> ApiResult<Vec<WalletRecord>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn
            .prepare("SELECT id, name, encrypted_mnemonic, salt, descriptor, network FROM wallets WHERE network = ?1 ORDER BY created_at DESC")
            .map_err(|e| crate::error::ApiError::DatabaseError(e.to_string()))?;

        let wallets = stmt
            .query_map(params![Self::network_to_string(network)], |row| {
                Ok(WalletRecord {
                    id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap(),
                    name: row.get(1)?,
                    encrypted_mnemonic: row.get(2)?,
                    salt: row.get(3)?,
                    descriptor: row.get(4)?,
                    network: Self::string_to_network(&row.get::<_, String>(5)?).unwrap(),
                })
            })
            .map_err(|e| crate::error::ApiError::DatabaseError(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| crate::error::ApiError::DatabaseError(e.to_string()))?;

        Ok(wallets)
    }

    fn delete_wallet(&self, id: Uuid) -> ApiResult<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute("DELETE FROM wallets WHERE id = ?1", params![id.to_string()])
            .map_err(|e| crate::error::ApiError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    fn wallet_exists(&self, id: Uuid) -> ApiResult<bool> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn
            .prepare("SELECT COUNT(*) FROM wallets WHERE id = ?1")
            .map_err(|e| crate::error::ApiError::DatabaseError(e.to_string()))?;

        let count: i64 = stmt
            .query_row(params![id.to_string()], |row| row.get(0))
            .map_err(|e| crate::error::ApiError::DatabaseError(e.to_string()))?;

        Ok(count > 0)
    }
}
