use crate::error::{ApiError, ApiResult};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, consts::U12},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{rand_core::RngCore, SaltString},
    Argon2, PasswordHasher,
};

const NONCE_SIZE: usize = 12; // 96 bits for AES-GCM

/// Encrypt a mnemonic phrase with a user password
/// Returns (encrypted_data, salt) as base64-encoded strings
pub fn encrypt_mnemonic(mnemonic: &str, password: &str) -> ApiResult<(String, String)> {
    // Generate random salt for Argon2
    let salt = SaltString::generate(&mut OsRng);

    // Derive encryption key from password using Argon2
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| ApiError::DatabaseError(format!("Failed to hash password: {}", e)))?;

    // Extract the hash bytes (32 bytes for AES-256)
    let key_bytes = password_hash.hash.ok_or_else(|| {
        ApiError::DatabaseError("Failed to extract hash from password".to_string())
    })?;
    let key_bytes = key_bytes.as_bytes();

    // Ensure we have exactly 32 bytes for AES-256
    if key_bytes.len() < 32 {
        return Err(ApiError::DatabaseError(
            "Derived key too short".to_string(),
        ));
    }
    let key: [u8; 32] = key_bytes[..32]
        .try_into()
        .map_err(|_| ApiError::DatabaseError("Failed to create key array".to_string()))?;

    // Create cipher
    let cipher = Aes256Gcm::new(&key.into());

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = <&Nonce<U12>>::from(&nonce_bytes);

    // Encrypt the mnemonic
    let ciphertext = cipher
        .encrypt(nonce, mnemonic.as_bytes())
        .map_err(|e| ApiError::DatabaseError(format!("Encryption failed: {}", e)))?;

    // Combine nonce + ciphertext and encode as base64
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);
    let encrypted_b64 = base64_encode(&combined);

    // Return encrypted data and salt (both base64 encoded)
    Ok((encrypted_b64, salt.to_string()))
}

/// Decrypt a mnemonic phrase with a user password
pub fn decrypt_mnemonic(
    encrypted_b64: &str,
    salt_str: &str,
    password: &str,
) -> ApiResult<String> {
    // Decode base64 encrypted data
    let combined = base64_decode(encrypted_b64)?;

    if combined.len() < NONCE_SIZE {
        return Err(ApiError::DatabaseError(
            "Encrypted data too short".to_string(),
        ));
    }

    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = combined.split_at(NONCE_SIZE);
    let nonce = <&Nonce<U12>>::try_from(nonce_bytes)
        .map_err(|_| ApiError::DatabaseError("Invalid nonce size".to_string()))?;

    // Parse salt
    let salt = SaltString::from_b64(salt_str)
        .map_err(|e| ApiError::DatabaseError(format!("Invalid salt: {}", e)))?;

    // Derive the same encryption key from password using Argon2
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| ApiError::DatabaseError(format!("Failed to hash password: {}", e)))?;

    // Extract the hash bytes
    let key_bytes = password_hash.hash.ok_or_else(|| {
        ApiError::DatabaseError("Failed to extract hash from password".to_string())
    })?;
    let key_bytes = key_bytes.as_bytes();

    if key_bytes.len() < 32 {
        return Err(ApiError::DatabaseError(
            "Derived key too short".to_string(),
        ));
    }
    let key: [u8; 32] = key_bytes[..32]
        .try_into()
        .map_err(|_| ApiError::DatabaseError("Failed to create key array".to_string()))?;

    // Create cipher
    let cipher = Aes256Gcm::new(&key.into());

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| ApiError::InvalidMnemonic("Decryption failed - wrong password?".to_string()))?;

    // Convert to string
    String::from_utf8(plaintext)
        .map_err(|e| ApiError::DatabaseError(format!("Invalid UTF-8 in decrypted data: {}", e)))
}

/// Base64 encode bytes
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Base64 decode string
fn base64_decode(data: &str) -> ApiResult<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| ApiError::DatabaseError(format!("Base64 decode error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let password = "super_secret_password_123";

        // Encrypt
        let (encrypted, salt) = encrypt_mnemonic(mnemonic, password).unwrap();

        // Decrypt with correct password
        let decrypted = decrypt_mnemonic(&encrypted, &salt, password).unwrap();
        assert_eq!(decrypted, mnemonic);

        // Decrypt with wrong password should fail
        let wrong_result = decrypt_mnemonic(&encrypted, &salt, "wrong_password");
        assert!(wrong_result.is_err());
    }

    #[test]
    fn test_different_salts_produce_different_ciphertexts() {
        let mnemonic = "test mnemonic phrase";
        let password = "password123";

        let (encrypted1, _) = encrypt_mnemonic(mnemonic, password).unwrap();
        let (encrypted2, _) = encrypt_mnemonic(mnemonic, password).unwrap();

        // Even with same mnemonic and password, different salts produce different ciphertexts
        assert_ne!(encrypted1, encrypted2);
    }
}
