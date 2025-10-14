use rand::{distributions::Alphanumeric, Rng};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{Engine as _, engine::general_purpose};

pub fn generate_random_password() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

/// Derive encryption key from password using PBKDF2
/// Uses same parameters as frontend (100,000 iterations)
fn derive_key_from_password(password: &str, salt: &[u8]) -> Vec<u8> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    
    let mut key = vec![0u8; 32]; // 256-bit key for AES-256
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        salt,
        100_000, // Match frontend crypto.js
        &mut key
    );
    key
}

/// Generate random encryption key for TOTP secrets (32 bytes = 256 bits)
pub fn generate_totp_encryption_key() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    rand::thread_rng().fill(&mut key[..]);
    key
}

/// Encrypt the TOTP encryption key with user's password hash
/// This wraps the random key so it can be stored in database
pub fn encrypt_encryption_key_with_password(
    encryption_key: &[u8],
    password_hash: &str,
    user_id: &str,
) -> Result<String, String> {
    if encryption_key.len() != 32 {
        return Err("Encryption key must be 32 bytes".to_string());
    }
    
    // Use user_id in salt for uniqueness (but this salt is stored, so it's okay)
    let salt = format!("timeline_key_wrap_{}", user_id);
    let salt_bytes = &salt.as_bytes()[..16.min(salt.len())];
    let mut salt_padded = [0u8; 16];
    salt_padded[..salt_bytes.len()].copy_from_slice(salt_bytes);
    
    let key_bytes = derive_key_from_password(password_hash, &salt_padded);
    let cipher_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(cipher_key);
    
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, encryption_key)
        .map_err(|e| format!("Encryption error: {}", e))?;
    
    // Combine salt + nonce + ciphertext
    let mut combined = Vec::new();
    combined.extend_from_slice(&salt_padded);
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    
    Ok(general_purpose::STANDARD.encode(&combined))
}

/// Decrypt the TOTP encryption key using user's password hash
pub fn decrypt_encryption_key_with_password(
    encrypted_key: &str,
    password_hash: &str,
) -> Result<Vec<u8>, String> {
    let combined = general_purpose::STANDARD.decode(encrypted_key)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    
    if combined.len() < 28 {
        return Err("Invalid encrypted key length".to_string());
    }
    
    let (salt, rest) = combined.split_at(16);
    let (nonce_bytes, ciphertext) = rest.split_at(12);
    
    let key_bytes = derive_key_from_password(password_hash, salt);
    let cipher_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption error: {}", e))?;
    
    Ok(plaintext)
}

/// Encrypt TOTP secret with random encryption key (NOT password-derived)
/// This provides true zero-knowledge encryption for 2FA secrets
pub fn encrypt_totp_secret_secure(
    secret: &str,
    encryption_key: &[u8],
) -> Result<String, String> {
    if encryption_key.len() != 32 {
        return Err("Encryption key must be 32 bytes".to_string());
    }
    
    let cipher_key = aes_gcm::Key::<Aes256Gcm>::from_slice(encryption_key);
    let cipher = Aes256Gcm::new(cipher_key);
    
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, secret.as_bytes())
        .map_err(|e| format!("Encryption error: {}", e))?;
    
    // Just nonce + ciphertext (no salt needed - key is random)
    let mut combined = Vec::new();
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    
    Ok(general_purpose::STANDARD.encode(&combined))
}

/// Decrypt TOTP secret with random encryption key
pub fn decrypt_totp_secret_secure(
    encrypted: &str,
    encryption_key: &[u8],
) -> Result<String, String> {
    if encryption_key.len() != 32 {
        return Err("Encryption key must be 32 bytes".to_string());
    }
    
    let combined = general_purpose::STANDARD.decode(encrypted)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    
    if combined.len() < 12 {
        return Err("Invalid encrypted data length".to_string());
    }
    
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    
    let cipher_key = aes_gcm::Key::<Aes256Gcm>::from_slice(encryption_key);
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption error: {}", e))?;
    
    String::from_utf8(plaintext)
        .map_err(|e| format!("UTF-8 error: {}", e))
}

