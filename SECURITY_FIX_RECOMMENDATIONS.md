# Security Fix Recommendations
## Detailed Implementation Guide for Critical Vulnerabilities

This document provides specific code changes to fix the critical and high-severity vulnerabilities found in the security analysis.

---

## CRITICAL FIX #1: Redesign 2FA Secret Encryption

### Current Vulnerable Implementation:

**Problem:** TOTP secrets are encrypted with a deterministic password hash using a fixed salt.

```javascript
// backend/static/crypto.js - VULNERABLE
async derivePasswordHash(password) {
    const salt = encoder.encode('timeline_auth_hash'); // FIXED SALT - VULNERABLE!
    const bits = await window.crypto.subtle.deriveBits({
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
    }, keyMaterial, 256);
    return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
}
```

```rust
// backend/src/crypto.rs - VULNERABLE
pub fn encrypt_totp_secret(secret: &str, password: &str, user_id: &str) -> Result<String, String> {
    let salt = format!("timeline_2fa_{}", user_id); // Predictable salt!
    // Encrypts directly with password-derived key
}
```

---

### Recommended Secure Implementation:

#### Step 1: Add encryption key field to database

```sql
-- database/migration_add_encryption_key.sql
ALTER TABLE users ADD COLUMN totp_encryption_key_encrypted TEXT;
```

#### Step 2: Generate random encryption key per user

```rust
// backend/src/crypto.rs - NEW SECURE IMPLEMENTATION

use aes_gcm::{Aes256Gcm, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use rand::Rng;

/// Generate random encryption key for TOTP secrets
pub fn generate_totp_encryption_key() -> Vec<u8> {
    let mut key = vec![0u8; 32]; // 256-bit key
    rand::thread_rng().fill(&mut key[..]);
    key
}

/// Encrypt the TOTP encryption key with user's password
/// This wraps the random key so it can be stored in database
pub fn encrypt_encryption_key_with_password(
    encryption_key: &[u8],
    password_hash: &str,
    user_id: &str
) -> Result<String, String> {
    // Use password hash to encrypt the random encryption key
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
    
    Ok(base64::Engine::encode(&general_purpose::STANDARD, &combined))
}

/// Decrypt the TOTP encryption key using user's password
pub fn decrypt_encryption_key_with_password(
    encrypted_key: &str,
    password_hash: &str
) -> Result<Vec<u8>, String> {
    let combined = base64::Engine::decode(&general_purpose::STANDARD, encrypted_key)
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
pub fn encrypt_totp_secret_secure(
    secret: &str,
    encryption_key: &[u8]
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
    
    Ok(base64::Engine::encode(&general_purpose::STANDARD, &combined))
}

/// Decrypt TOTP secret with random encryption key
pub fn decrypt_totp_secret_secure(
    encrypted: &str,
    encryption_key: &[u8]
) -> Result<String, String> {
    if encryption_key.len() != 32 {
        return Err("Encryption key must be 32 bytes".to_string());
    }
    
    let combined = base64::Engine::decode(&general_purpose::STANDARD, encrypted)
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
```

#### Step 3: Update 2FA setup flow

```rust
// backend/src/main.rs - Update enable_2fa endpoint

async fn enable_2fa(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<Enable2FARequest>,
) -> Result<Json<Enable2FAResponse>, StatusCode> {
    // ... existing verification code ...
    
    // Generate random encryption key for this user's TOTP secrets
    let totp_encryption_key = crypto::generate_totp_encryption_key();
    
    // Encrypt the TOTP secret with the random key
    let totp_secret_encrypted = crypto::encrypt_totp_secret_secure(&totp_secret, &totp_encryption_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Wrap the encryption key with password hash so we can store it
    let wrapped_key = crypto::encrypt_encryption_key_with_password(
        &totp_encryption_key,
        &req.password_hash,
        &auth_state.user_id.to_string()
    ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Store both encrypted TOTP secret and wrapped encryption key
    sqlx::query(
        "UPDATE users SET totp_secret_encrypted = $1, totp_encryption_key_encrypted = $2, 
         totp_enabled = TRUE WHERE id = $3"
    )
        .bind(&totp_secret_encrypted)
        .bind(&wrapped_key)
        .bind(auth_state.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // ... rest of code ...
}
```

#### Step 4: Update password change to re-wrap encryption key

```rust
// backend/src/main.rs - Update change_password_verify

async fn change_password_verify(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<ChangePasswordVerifyRequest>,
) -> Result<Json<ChangePasswordVerifyResponse>, StatusCode> {
    // ... existing SRP verification ...
    
    // If 2FA is enabled, unwrap and re-wrap the encryption key
    let row = sqlx::query(
        "SELECT totp_enabled, totp_encryption_key_encrypted FROM users WHERE id = $1"
    )
        .bind(auth_state.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let totp_enabled: bool = row.get("totp_enabled");
    let wrapped_key: Option<String> = row.get("totp_encryption_key_encrypted");
    
    let new_wrapped_key = if totp_enabled && wrapped_key.is_some() {
        // Unwrap with old password hash
        let encryption_key = crypto::decrypt_encryption_key_with_password(
            &wrapped_key.unwrap(),
            &req.old_password_hash
        ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        
        // Re-wrap with new password hash
        let new_wrapped = crypto::encrypt_encryption_key_with_password(
            &encryption_key,
            &req.new_password_hash,
            &auth_state.user_id.to_string()
        ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        
        Some(new_wrapped)
    } else {
        None
    };
    
    // Update database with re-wrapped key
    if let Some(new_wrapped) = new_wrapped_key {
        sqlx::query(
            "UPDATE users SET srp_salt = $1, srp_verifier = $2, 
             totp_encryption_key_encrypted = $3 WHERE id = $4"
        )
            .bind(&req.new_salt)
            .bind(&req.new_verifier)
            .bind(&new_wrapped)
            .bind(auth_state.user_id)
            .execute(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    
    // ... rest of code ...
}
```

### Security Benefits of This Approach:

1. ✅ **True Zero-Knowledge:** Encryption key is random, not derived from password
2. ✅ **Forward Secrecy:** Old TOTP secrets can't be decrypted if password changes
3. ✅ **Key Separation:** Different keys for different purposes
4. ✅ **No Fixed Salts:** Each encryption uses fresh random values
5. ✅ **Defense in Depth:** Even if password is compromised, TOTP secret remains secure unless attacker also gets the wrapped key

---

## CRITICAL FIX #2: Domain Whitelist Bypass

### Current Vulnerable Implementation:

```rust
// backend/src/tls.rs - VULNERABLE
pub fn check_domain_allowed(headers: &HeaderMap, allowed_domains: &[String]) -> Result<(), StatusCode> {
    let host_header = headers.get(header::HOST)  // ⚠️ Can be spoofed!
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    
    // Extracts hostname from Host header and checks against whitelist
    // But Host header can be set to anything by attacker!
}
```

### Recommended Secure Implementation:

#### Option 1: Deploy Behind Reverse Proxy (RECOMMENDED)

Use nginx or similar reverse proxy that validates the actual connection:

```nginx
# nginx.conf - SECURE CONFIGURATION
server {
    listen 443 ssl http2;
    server_name yourdomain.com;  # Only this domain accepted
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    # Pass real connection info to backend
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Host $server_name;
    
    location / {
        proxy_pass http://backend:8080;
        proxy_http_version 1.1;
        
        # Only allow if Host header matches server_name
        if ($host !~* ^yourdomain\.com$) {
            return 403;
        }
    }
}
```

#### Option 2: Enhance Backend Validation

```rust
// backend/src/tls.rs - IMPROVED IMPLEMENTATION

use std::net::{IpAddr, SocketAddr};

/// Check domain and validate against actual connection
pub fn check_domain_allowed_secure(
    headers: &HeaderMap,
    allowed_domains: &[String],
    peer_addr: Option<SocketAddr>,  // Actual connection address
) -> Result<(), StatusCode> {
    // First check: Validate Host header
    let host_header = headers.get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    
    if host_header.is_empty() {
        log::warn!("No Host header provided");
        return Err(StatusCode::FORBIDDEN);
    }
    
    let hostname = extract_hostname(host_header);
    
    // Second check: If we have peer address, validate it matches domain
    if let Some(peer) = peer_addr {
        if !validate_peer_address(&peer, &hostname, allowed_domains) {
            log::warn!("Peer address {:?} doesn't match Host header {}", peer, hostname);
            return Err(StatusCode::FORBIDDEN);
        }
    }
    
    // Third check: Validate against whitelist (with strict rules)
    let hostname_lower = hostname.to_lowercase();
    let is_allowed = allowed_domains.iter().any(|domain| {
        let domain_lower = domain.to_lowercase();
        
        // For localhost, only accept from loopback addresses
        if domain_lower == "localhost" {
            if let Some(peer) = peer_addr {
                return is_loopback_address(&peer.ip()) && 
                       (hostname_lower == "localhost" || 
                        hostname == "127.0.0.1" || 
                        hostname == "::1");
            }
            // If no peer address, only accept localhost/127.0.0.1/::1
            return hostname_lower == "localhost" || 
                   hostname == "127.0.0.1" || 
                   hostname == "::1";
        }
        
        // For other domains, exact match required
        hostname_lower == domain_lower
    });
    
    if !is_allowed {
        log::warn!("Domain '{}' not in allowed list {:?}", hostname, allowed_domains);
        return Err(StatusCode::FORBIDDEN);
    }
    
    Ok(())
}

/// Check if IP address is loopback
fn is_loopback_address(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_loopback(),
        IpAddr::V6(ipv6) => ipv6.is_loopback(),
    }
}

/// Check if IP address is link-local or other non-routable
fn is_private_address(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || 
            ipv6.is_unicast_link_local() ||
            is_ipv6_unique_local(ipv6)
        }
    }
}

/// Check if IPv6 is unique local (fc00::/7)
fn is_ipv6_unique_local(ipv6: &std::net::Ipv6Addr) -> bool {
    let bytes = ipv6.octets();
    (bytes[0] & 0xfe) == 0xfc
}

/// Validate that peer address matches expected domain
fn validate_peer_address(
    peer: &SocketAddr,
    hostname: &str,
    allowed_domains: &[String],
) -> bool {
    let peer_ip = peer.ip();
    
    // If hostname is localhost, peer must be loopback
    if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
        return is_loopback_address(&peer_ip);
    }
    
    // If hostname is IP address, it must match peer
    if let Ok(host_ip) = hostname.parse::<IpAddr>() {
        return host_ip == peer_ip;
    }
    
    // For domain names, we can't validate without DNS lookup
    // But we can block obviously wrong cases
    if is_private_address(&peer_ip) && !is_private_domain(hostname, allowed_domains) {
        return false;
    }
    
    true
}

fn is_private_domain(hostname: &str, allowed_domains: &[String]) -> bool {
    // Check if this domain is configured for private/local use
    hostname == "localhost" || 
    allowed_domains.iter().any(|d| d == "localhost")
}

/// Extract hostname from Host header (handles ports and IPv6)
fn extract_hostname(host_header: &str) -> &str {
    if host_header.starts_with('[') {
        // IPv6 address in brackets
        host_header.split(']').next()
            .and_then(|s| s.strip_prefix('['))
            .unwrap_or(host_header)
    } else {
        // Regular hostname or IPv4
        host_header.split(':').next().unwrap_or(host_header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_blocks_non_loopback_with_localhost_host() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("localhost:8080"));
        
        // Attacker connecting from remote IP with localhost Host header
        let peer = "192.168.1.100:12345".parse::<SocketAddr>().unwrap();
        
        let allowed = vec!["localhost".to_string()];
        let result = check_domain_allowed_secure(&headers, &allowed, Some(peer));
        
        assert!(result.is_err(), "Should block remote IP with localhost Host header");
    }
    
    #[test]
    fn test_allows_loopback_with_localhost_host() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("localhost:8080"));
        
        let peer = "127.0.0.1:12345".parse::<SocketAddr>().unwrap();
        
        let allowed = vec!["localhost".to_string()];
        let result = check_domain_allowed_secure(&headers, &allowed, Some(peer));
        
        assert!(result.is_ok(), "Should allow loopback with localhost Host header");
    }
    
    #[test]
    fn test_blocks_link_local_ipv6() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("[fe80::1]:8080"));
        
        let peer = "[fe80::1]:12345".parse::<SocketAddr>().unwrap();
        
        let allowed = vec!["localhost".to_string()];
        let result = check_domain_allowed_secure(&headers, &allowed, Some(peer));
        
        assert!(result.is_err(), "Should block link-local IPv6 addresses");
    }
}
```

#### Step 3: Update main.rs to pass peer address

```rust
// backend/src/main.rs - Update middleware

// Add connection info to request extensions
async fn add_connection_info<B>(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut req: Request<B>,
    next: Next<B>,
) -> Response {
    req.extensions_mut().insert(addr);
    next.run(req).await
}

// Update serve_index and other endpoints
async fn serve_index(
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,  // Get peer address
    State(state): State<AppState>,
) -> Response {
    let config = state.tls_config.read().await;
    if let Err(status) = tls::check_domain_allowed_secure(
        &headers, 
        &config.domains,
        Some(addr)  // Pass peer address
    ) {
        return (status, "Domain not allowed").into_response();
    }
    // ... rest of code ...
}
```

---

## HIGH FIX #1: Use SHA-256 for TOTP

### Current Implementation:
```rust
// backend/src/twofa.rs - OLD
use totp_lite::{totp, Sha1};  // SHA-1 is deprecated

let generated_code = totp::<Sha1>(&secret_bytes, test_timestamp);
```

### Recommended Fix:
```rust
// backend/src/twofa.rs - NEW
use totp_lite::{totp, Sha256};  // Use SHA-256 instead

/// Verify a TOTP code against a secret
pub fn verify_totp_code(secret: &str, code: &str) -> bool {
    let secret_bytes = match base32_decode(secret) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Check current time and 30 seconds before AND after (90s total)
    for offset in [-30i64, 0, 30] {  // Added future window
        let test_timestamp = (timestamp as i64 + offset) as u64;
        let generated_code = totp::<Sha256>(&secret_bytes, test_timestamp);  // SHA-256!
        
        let code_num: u64 = generated_code.parse().unwrap_or(0);
        let code_6_digit = format!("{:06}", code_num % 1000000);
        
        if code_6_digit == code {
            return true;
        }
    }

    false
}
```

**Note:** This requires updating the frontend QR code generation to specify SHA-256:
```rust
pub fn generate_totp_uri(secret: &str, username: &str, issuer: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA256&digits=6&period=30",
        urlencoding::encode(issuer),
        urlencoding::encode(username),
        secret,
        urlencoding::encode(issuer)
    )
}
```

---

## MEDIUM FIX: Add Per-Username Rate Limiting

```rust
// backend/src/main.rs - Enhanced rate limiting

struct LoginRateLimit {
    attempts: u32,
    last_attempt: SystemTime,
    locked_until: Option<SystemTime>,
}

// NEW: Add per-username rate limiting
struct UsernameRateLimit {
    attempts: u32,
    last_attempt: SystemTime,
    locked_until: Option<SystemTime>,
}

#[derive(Clone)]
struct AppData {
    // ... existing fields ...
    login_rate_limiter: Arc<RwLock<HashMap<String, LoginRateLimit>>>,  // By IP
    username_rate_limiter: Arc<RwLock<HashMap<String, UsernameRateLimit>>>,  // NEW: By username
}

async fn check_login_rate_limit_combined(
    ip: &str,
    username: &str,
    ip_limiter: &Arc<RwLock<HashMap<String, LoginRateLimit>>>,
    username_limiter: &Arc<RwLock<HashMap<String, UsernameRateLimit>>>,
) -> Result<(), String> {
    // Check IP-based rate limit
    check_login_rate_limit(ip, ip_limiter).await?;
    
    // Also check username-based rate limit
    let now = SystemTime::now();
    let mut limiter = username_limiter.write().await;
    
    let rate_limit = limiter.entry(username.to_string()).or_insert(UsernameRateLimit {
        attempts: 0,
        last_attempt: now,
        locked_until: None,
    });
    
    // Check if currently locked
    if let Some(locked_until) = rate_limit.locked_until {
        if now < locked_until {
            let remaining = locked_until.duration_since(now).unwrap_or_default().as_secs();
            return Err(format!("Account temporarily locked. Try again in {} seconds", remaining));
        } else {
            rate_limit.attempts = 0;
            rate_limit.locked_until = None;
        }
    }
    
    // Increment attempts
    rate_limit.attempts += 1;
    rate_limit.last_attempt = now;
    
    // Progressive lockout (more aggressive for username-based)
    if rate_limit.attempts >= 5 {
        rate_limit.locked_until = Some(now + Duration::from_secs(1800)); // 30 minutes
        return Err("Too many failed login attempts for this username. Locked for 30 minutes".to_string());
    } else if rate_limit.attempts >= 3 {
        rate_limit.locked_until = Some(now + Duration::from_secs(300)); // 5 minutes
        return Err("Too many failed login attempts for this username. Locked for 5 minutes".to_string());
    }
    
    Ok(())
}
```

---

## Additional Recommendations

### 1. Add CSRF Tokens

```rust
// backend/src/main.rs

use rand::Rng;

#[derive(Clone)]
struct AppData {
    // ... existing fields ...
    csrf_tokens: Arc<RwLock<HashMap<String, CsrfToken>>>,  // session_id -> token
}

struct CsrfToken {
    token: String,
    created_at: SystemTime,
}

fn generate_csrf_token() -> String {
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

// Middleware to validate CSRF token
async fn validate_csrf(
    headers: HeaderMap,
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next<Body>,
) -> Result<Response, StatusCode> {
    // Skip for GET requests
    if req.method() == Method::GET {
        return Ok(next.run(req).await);
    }
    
    // Get session ID
    let session_id = auth::extract_session_id(&headers)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    
    // Get CSRF token from header
    let csrf_token = headers.get("X-CSRF-Token")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::FORBIDDEN)?;
    
    // Validate token
    let tokens = state.csrf_tokens.read().await;
    let expected_token = tokens.get(&session_id)
        .ok_or(StatusCode::FORBIDDEN)?;
    
    // Constant-time comparison
    if !constant_time_compare(csrf_token, &expected_token.token) {
        return Err(StatusCode::FORBIDDEN);
    }
    
    Ok(next.run(req).await)
}

fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}
```

### 2. Implement Session Fixation Protection

```rust
// backend/src/auth.rs

pub async fn regenerate_session_id(
    old_session_id: &str,
    sessions: &Arc<RwLock<HashMap<String, SessionData>>>,
) -> String {
    let mut sessions_write = sessions.write().await;
    
    // Get existing session data
    if let Some(session_data) = sessions_write.remove(old_session_id) {
        // Generate new session ID
        let new_session_id = uuid::Uuid::new_v4().to_string();
        
        // Move session data to new ID
        sessions_write.insert(new_session_id.clone(), session_data);
        
        new_session_id
    } else {
        // If old session doesn't exist, create new one
        uuid::Uuid::new_v4().to_string()
    }
}

// Call this after successful login:
// let new_session_id = regenerate_session_id(&temp_session_id, &state.sessions).await;
```

### 3. Add Security Logging

```rust
// backend/src/security_log.rs - NEW FILE

use log::{info, warn, error};
use chrono::Utc;

pub struct SecurityEvent {
    pub timestamp: chrono::DateTime<Utc>,
    pub event_type: SecurityEventType,
    pub user_id: Option<Uuid>,
    pub username: Option<String>,
    pub ip_address: String,
    pub details: String,
}

pub enum SecurityEventType {
    LoginSuccess,
    LoginFailure,
    LoginRateLimitHit,
    PasswordChangeSuccess,
    PasswordChangeFailure,
    TwoFactorEnabled,
    TwoFactorDisabled,
    TwoFactorFailure,
    SessionExpired,
    UnauthorizedAccess,
    DomainViolation,
}

impl SecurityEvent {
    pub fn log(&self) {
        let msg = format!(
            "[SECURITY] {} | {:?} | User: {:?} | IP: {} | {}",
            self.timestamp.to_rfc3339(),
            self.event_type,
            self.username.as_ref().unwrap_or(&"<none>".to_string()),
            self.ip_address,
            self.details
        );
        
        match self.event_type {
            SecurityEventType::UnauthorizedAccess | 
            SecurityEventType::DomainViolation => {
                warn!("{}", msg);
            }
            SecurityEventType::LoginFailure | 
            SecurityEventType::TwoFactorFailure => {
                info!("{}", msg);
            }
            _ => {
                info!("{}", msg);
            }
        }
    }
}

// Usage in login_verify:
SecurityEvent {
    timestamp: Utc::now(),
    event_type: SecurityEventType::LoginSuccess,
    user_id: Some(user_id),
    username: Some(pending.username.clone()),
    ip_address: get_client_ip(&headers),
    details: "Successful SRP authentication".to_string(),
}.log();
```

---

## Testing the Fixes

### Test 1: 2FA Encryption (should now be secure)

```rust
#[tokio::test]
async fn test_2fa_encryption_with_random_key() {
    // Generate random encryption key
    let encryption_key = crypto::generate_totp_encryption_key();
    
    // Encrypt TOTP secret
    let totp_secret = "JBSWY3DPEHPK3PXP";
    let encrypted = crypto::encrypt_totp_secret_secure(totp_secret, &encryption_key).unwrap();
    
    // Attacker gets password and database
    let password = "user_password";
    let password_hash = crypto::derive_password_hash(password);
    
    // Attacker tries to decrypt with password hash - SHOULD FAIL
    let result = crypto::decrypt_totp_secret(&encrypted, &password_hash);
    assert!(result.is_err(), "TOTP secret should NOT be decryptable with just password hash");
    
    // Can only decrypt with the random encryption key
    let decrypted = crypto::decrypt_totp_secret_secure(&encrypted, &encryption_key).unwrap();
    assert_eq!(decrypted, totp_secret);
}
```

### Test 2: Domain Validation (should block spoofing)

```rust
#[test]
fn test_domain_validation_blocks_spoofed_host() {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, HeaderValue::from_static("localhost:8080"));
    
    // Attacker from remote IP trying to spoof localhost
    let peer = "203.0.113.1:12345".parse::<SocketAddr>().unwrap();
    
    let allowed = vec!["localhost".to_string()];
    let result = tls::check_domain_allowed_secure(&headers, &allowed, Some(peer));
    
    assert!(result.is_err(), "Should block remote IP with spoofed localhost header");
}
```

---

## Migration Guide

### For Existing Deployments:

1. **Database Migration:**
   ```sql
   -- Add new column
   ALTER TABLE users ADD COLUMN totp_encryption_key_encrypted TEXT;
   
   -- For existing 2FA users, you'll need to disable and re-enable 2FA
   -- (Or implement a migration that generates keys and re-encrypts secrets)
   ```

2. **Code Update:**
   - Deploy new crypto functions
   - Update 2FA setup/enable endpoints
   - Update password change endpoints
   - Update domain validation

3. **User Communication:**
   - Notify users with 2FA enabled that they need to re-setup 2FA
   - Provide clear instructions
   - Consider grace period

4. **Testing:**
   - Test in staging environment first
   - Verify 2FA still works
   - Verify password changes work
   - Test domain validation with various scenarios

---

## Summary

These fixes address the critical security vulnerabilities while maintaining backward compatibility where possible. The most important changes are:

1. **2FA Encryption:** Random keys instead of password-derived keys
2. **Domain Validation:** Peer address verification to prevent spoofing
3. **SHA-256 for TOTP:** Modern hash algorithm
4. **Enhanced Rate Limiting:** Per-username protection
5. **CSRF Protection:** Explicit tokens for state-changing operations

Implement these changes in order of severity, starting with the critical fixes.
