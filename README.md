# Custodian - Bitcoin Wallet API

A **zero-knowledge custodial** Bitcoin wallet API built with BDK (Bitcoin Development Kit) and Axum.

**The Best of Both Worlds:**
- **Custodial convenience** - We host the infrastructure and handle blockchain synchronization
- **Non-custodial security** - We cannot access your funds (password-encrypted mnemonics)

Your keys, your coins, our infrastructure.

## Features

### Security (Zero-Knowledge)
- **Password-protected wallets** - User passwords required for wallet creation and transaction signing
- **Encrypted mnemonic storage** - Mnemonics encrypted with Argon2 + AES-256-GCM
- **Zero-knowledge security** - Service provider cannot access user funds without password
- **Watch-only wallets** - Balance checks and address generation without exposing private keys
- **SQLite persistence** - Wallet data stored in `data/wallets.db`, persists across restarts

### Wallet Operations
- Create and manage Bitcoin wallets with BIP39 mnemonic phrases (12 words)
- Segwit (P2WPKH) address support only
- Automatic blockchain synchronization via Electrum
- Balance checking (watch-only, no password required)
- Address generation (watch-only, no password required)
- Transaction creation and broadcasting (password required)
- List all wallets by network

## Prerequisites

- Rust 1.70 or higher
- Internet connection (for blockchain synchronization)

## Installation

```bash
cargo build --release
```

## Running the Server

1. Copy the example environment file and set your API key:
```bash
cp .env.example .env
```

2. Edit `.env` and configure:
```
API_KEY=your_secure_api_key_here
DATA_DIR=data
```

3. Start the server:
```bash
cargo run
```

The server will start on `http://127.0.0.1:3000`.

**Note:** Network is now specified in the URL path. Supported networks:
- `bitcoin` or `mainnet` - Bitcoin mainnet
- `testnet` or `testnet3` - Bitcoin testnet
- `signet` - Bitcoin signet
- `regtest` - Bitcoin regtest

## API Authentication

All API endpoints (except `/health`) require API key authentication via the `X-API-Key` header:

```bash
curl -H "X-API-Key: your_api_key_here" http://127.0.0.1:3000/testnet/wallets
```

The API key is configured in the `.env` file, allowing organizations to secure their deployment. The `/health` endpoint remains public for monitoring purposes.

## API Endpoints

### Health Check
```bash
GET /health
```

### Create Wallet
Create a new wallet with an automatically generated UUID and mnemonic. You provide a friendly name and a password to encrypt the mnemonic.

**Security:** The password encrypts your mnemonic using Argon2 + AES-256-GCM. Without the password, the mnemonic cannot be recovered - not even by the service provider.

```bash
POST /:network/wallets
Content-Type: application/json

{
  "name": "My Personal Wallet",
  "password": "your_secure_password_here"
}
```

Example for testnet:
```bash
POST /testnet/wallets
Content-Type: application/json

{
  "name": "My Test Wallet",
  "password": "super_secret_123"
}
```

Or with an existing mnemonic:
```bash
{
  "name": "My Test Wallet",
  "password": "super_secret_123",
  "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
}
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "My Test Wallet",
  "mnemonic": "word1 word2 word3 ...",
  "descriptor": "wpkh(...)"
}
```
**IMPORTANT:**
- Save your wallet ID, mnemonic, AND password securely!
- The mnemonic is displayed only once - store it safely
- Your password is never stored - if lost, funds cannot be recovered
- Without the password, transactions cannot be signed

### List Wallets
```bash
GET /:network/wallets
```

Example:
```bash
GET /testnet/wallets
```

Response:
```json
{
  "wallets": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "My Test Wallet"
    },
    {
      "id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      "name": "Savings Wallet"
    }
  ]
}
```

### Get Balance
Get the balance of a wallet. The wallet is automatically synced with the blockchain before returning the balance.

**Watch-Only:** This operation uses the public descriptor only - no password required.

```bash
GET /:network/wallets/{wallet_id}/balance
```

Example:
```bash
GET /testnet/wallets/550e8400-e29b-41d4-a716-446655440000/balance
```

Response:
```json
{
  "confirmed": 100000,
  "unconfirmed": 50000,
  "total": 150000
}
```
Amounts are in satoshis (1 BTC = 100,000,000 satoshis).

### Generate New Address
Get a new segwit receiving address. Uses BIP32 hierarchical deterministic derivation from the public key.

**Watch-Only:** This operation uses the public descriptor only - no password required.

```bash
GET /:network/wallets/{wallet_id}/address
```

Example:
```bash
GET /testnet/wallets/550e8400-e29b-41d4-a716-446655440000/address
```

Response:
```json
{
  "address": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
  "index": 0
}
```

### Create Transaction
Create, sign, and broadcast a transaction. Requires your password to decrypt the mnemonic for signing.

**Password Required:** The password decrypts your mnemonic, creates a temporary wallet for signing, then immediately discards it. The wallet is automatically synced before creating the transaction.

**Security Flow:**
1. Password decrypts mnemonic from database
2. Temporary wallet created in memory
3. Transaction signed with private key
4. Wallet immediately discarded (never stored)
5. Transaction broadcasted to network

```bash
POST /:network/wallets/{wallet_id}/transaction
Content-Type: application/json

{
  "recipient": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
  "amount": 10000,
  "password": "your_wallet_password"
}
```

Example:
```bash
POST /testnet/wallets/550e8400-e29b-41d4-a716-446655440000/transaction
Content-Type: application/json

{
  "recipient": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
  "amount": 10000,
  "password": "super_secret_123"
}
```

Response (Success):
```json
{
  "txid": "abc123..."
}
```

Response (Wrong Password):
```json
{
  "error": "Invalid mnemonic: Decryption failed - wrong password?"
}
```

## Example Usage

Using testnet as an example:

1. **Create a wallet** (API key + password required):
```bash
curl -X POST http://127.0.0.1:3000/testnet/wallets \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key_here" \
  -d '{"name": "My Test Wallet", "password": "super_secret_123"}'
```

Save the `id`, `mnemonic`, and your password from the response.

2. **Get a receiving address** (API key required, no password needed):
```bash
curl -H "X-API-Key: your_api_key_here" \
  http://127.0.0.1:3000/testnet/wallets/{WALLET_ID}/address
```

3. **Check balance** (API key required, no password needed, auto-syncs):
```bash
curl -H "X-API-Key: your_api_key_here" \
  http://127.0.0.1:3000/testnet/wallets/{WALLET_ID}/balance
```

4. **Send a transaction** (API key + password required):
```bash
curl -X POST http://127.0.0.1:3000/testnet/wallets/{WALLET_ID}/transaction \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key_here" \
  -d '{
    "recipient": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
    "amount": 10000,
    "password": "super_secret_123"
  }'
```

## Project Structure

The codebase follows a modular architecture for maintainability and clarity:

```
src/
├── main.rs       # Application entry point and server configuration
├── crypto.rs     # Mnemonic encryption/decryption (Argon2 + AES-256-GCM)
├── db.rs         # Database adapter trait and SQLite implementation
├── error.rs      # Custom error types and error handling
├── middleware.rs # API key authentication middleware
├── models.rs     # Request/Response data structures
├── state.rs      # Application state and shared data
├── network.rs    # Network parsing and configuration
├── wallet.rs     # Wallet creation and BDK operations
└── handlers.rs   # API route handlers
```

## Network Selection

Network is specified in the URL path for each request. This allows managing wallets across different networks simultaneously.

Supported networks:
- `bitcoin` or `mainnet` - Bitcoin mainnet
- `testnet` or `testnet3` - Bitcoin testnet
- `signet` - Bitcoin signet
- `regtest` - Bitcoin regtest

**WARNING:** Always test thoroughly on testnet before using mainnet!

## Security Architecture

### Current Implementation

**Zero-Knowledge Security:**
- **Encrypted mnemonics** - Argon2 password hashing + AES-256-GCM encryption
- **Zero-knowledge** - Service provider cannot access user funds without password
- **Watch-only wallets** - Read operations use public descriptors only
- **Temporary signing wallets** - Private keys loaded only during transaction signing, then immediately discarded
- **SQLite persistence** - Encrypted wallet data persists across restarts
- **Unique salts** - Each wallet has a unique salt to prevent rainbow table attacks

**Database Security:**
```
data/wallets.db contains:
- Wallet ID (public)
- Wallet name (public)
- Encrypted mnemonic (AES-256-GCM with user password)
- Salt (unique per wallet, for Argon2)
- Descriptor (public key info, safe to expose)
- Network type (public)
```

**Threat Model:**

Even if an attacker:
- Steals the database file
- Gains root access to the server
- Is a malicious employee

They **CANNOT** recover mnemonics or steal funds without each user's password.

### Production Recommendations

For production deployment, additionally implement:
- **API authentication** - Basic API key authentication is implemented; consider JWT tokens or OAuth for more advanced use cases
- **Rate limiting** - Protect against brute-force password attacks
- **HTTPS/TLS** - Encrypt all network traffic
- **Input validation** - Sanitize all user inputs
- **Audit logging** - Track all wallet operations
- **Backup strategy** - Regular encrypted database backups
- **Password complexity** - Enforce strong password requirements
- **2FA for transactions** - Optional additional security layer
- **IP whitelisting** - Restrict API access to known IPs

## Development

Run with logging:
```bash
RUST_LOG=info cargo run
```

## Testing

### Integration Tests

**Note:** Integration tests need to be updated to include password parameters for wallet creation and transaction signing.

The project includes comprehensive integration tests that test the full API against a running server on testnet.

**Prerequisites:**
1. Start the server in one terminal:
```bash
cargo run
```

2. Run the integration tests in another terminal:
```bash
cargo test --test integration_test -- --test-threads=1
```

The `--test-threads=1` flag ensures tests run sequentially to avoid conflicts when creating wallets.

**Test Coverage:**
- Health check endpoint
- Wallet creation (with password and optional mnemonic)
- Wallet listing
- Balance checking (watch-only)
- Address generation (watch-only)
- Transaction signing (with password)
- Error handling (invalid IDs, missing wallets, invalid networks, wrong passwords)
- Full wallet lifecycle test

**Running a single test:**
```bash
cargo test --test integration_test test_create_wallet
```

**Running with output:**
```bash
cargo test --test integration_test -- --nocapture
```

### Unit Tests

Cryptography unit tests (encryption/decryption):
```bash
cargo test --lib crypto
```

All unit tests:
```bash
cargo test --lib
```

## License

MIT
