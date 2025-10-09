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

pub async fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    let password = password.to_string();
    tokio::task::spawn_blocking(move || {
        bcrypt::hash(password, bcrypt::DEFAULT_COST)
    }).await.unwrap()
}

pub async fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    let password = password.to_string();
    let hash = hash.to_string();
    tokio::task::spawn_blocking(move || {
        bcrypt::verify(password, &hash)
    }).await.unwrap()
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

/// Encrypt TOTP secret with password
/// Format: base64(salt || nonce || ciphertext)
pub fn encrypt_totp_secret(secret: &str, password: &str, user_id: &str) -> Result<String, String> {
    // Use user_id as salt (deterministic per user)
    let salt = format!("timeline_2fa_{}", user_id);
    let salt_bytes = &salt.as_bytes()[..16.min(salt.len())];
    let mut salt_padded = [0u8; 16];
    salt_padded[..salt_bytes.len()].copy_from_slice(salt_bytes);
    
    // Derive encryption key
    let key_bytes = derive_key_from_password(password, &salt_padded);
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    
    // Generate random nonce
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt
    let ciphertext = cipher.encrypt(nonce, secret.as_bytes())
        .map_err(|e| format!("Encryption error: {}", e))?;
    
    // Combine salt + nonce + ciphertext
    let mut combined = Vec::new();
    combined.extend_from_slice(&salt_padded);
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    
    Ok(general_purpose::STANDARD.encode(&combined))
}

/// Decrypt TOTP secret with password
pub fn decrypt_totp_secret(encrypted: &str, password: &str) -> Result<String, String> {
    let combined = general_purpose::STANDARD.decode(encrypted)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    
    if combined.len() < 28 {  // 16 (salt) + 12 (nonce) minimum
        return Err("Invalid encrypted data length".to_string());
    }
    
    // Extract components
    let (salt, rest) = combined.split_at(16);
    let (nonce_bytes, ciphertext) = rest.split_at(12);
    
    // Derive key from password
    let key_bytes = derive_key_from_password(password, salt);
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Decrypt
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption error: {}", e))?;
    
    String::from_utf8(plaintext)
        .map_err(|e| format!("UTF-8 error: {}", e))
}

/// Derive a consistent password hash for TOTP encryption
/// This is used client-side and server-side to encrypt/decrypt TOTP secrets
/// Uses PBKDF2 with a fixed salt to derive a deterministic hash from password
pub fn derive_password_hash(password: &str) -> String {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    
    let salt = b"timeline_auth_hash"; // Fixed salt for auth hash derivation
    let mut hash = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100_000, &mut hash);
    
    hex::encode(hash)
}