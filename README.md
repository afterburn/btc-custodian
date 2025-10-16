# Custodian

Drop-in Bitcoin wallet API for applications that need custody. Built with Rust, BDK, and Axum.

## Features

- Create and manage Bitcoin wallets (mainnet, testnet, signet, regtest)
- Password-encrypted mnemonic storage (Argon2 + AES-256-GCM)
- Watch-only balance checking and address generation
- Transaction signing and broadcasting
- Automatic blockchain synchronization via Electrum
- SQLite persistence
- API key authentication
- Segwit (P2WPKH) addresses

## Quick Start

```bash
# Clone and build
git clone https://github.com/yourusername/custodian
cd custodian
cargo build --release

# Configure
cp .env.example .env
# Edit .env and set your API_KEY

# Run
cargo run
```

Server starts on `http://127.0.0.1:3000`

## API Overview

All endpoints require `X-API-Key` header (except `/health`).

### Create Wallet
```bash
POST /:network/wallets
{
  "name": "My Wallet",
  "password": "secure_password"
}
```

Returns wallet ID, mnemonic, and descriptor. Save these securely.

### Get Balance
```bash
GET /:network/wallets/{id}/balance
```

### Generate Address
```bash
GET /:network/wallets/{id}/address
```

### Send Transaction
```bash
POST /:network/wallets/{id}/transaction
{
  "recipient": "tb1q...",
  "amount": 10000,
  "password": "secure_password"
}
```

Amount in satoshis. To send max balance (minus fee), set amount to total balance.

## Networks

Specify network in URL path:
- `bitcoin` or `mainnet` - Bitcoin mainnet
- `testnet` - Bitcoin testnet
- `signet` - Bitcoin signet
- `regtest` - Bitcoin regtest

## Example

```bash
# Create wallet
curl -X POST http://127.0.0.1:3000/testnet/wallets \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_key" \
  -d '{"name": "Test", "password": "pass123"}'

# Get address
curl -H "X-API-Key: your_key" \
  http://127.0.0.1:3000/testnet/wallets/{id}/address

# Check balance
curl -H "X-API-Key: your_key" \
  http://127.0.0.1:3000/testnet/wallets/{id}/balance

# Send transaction
curl -X POST http://127.0.0.1:3000/testnet/wallets/{id}/transaction \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_key" \
  -d '{"recipient": "tb1q...", "amount": 10000, "password": "pass123"}'
```

## Testing

```bash
# Start server
cargo run

# Run tests (in another terminal)
cargo test --test integration_test -- --test-threads=1
```

## Security Notes

- Mnemonics are encrypted with user passwords (Argon2 + AES-256-GCM)
- Passwords are never stored - keep them safe
- Private keys are only loaded temporarily during transaction signing
- For production: add rate limiting, HTTPS, audit logging, and backups

## License

MIT
