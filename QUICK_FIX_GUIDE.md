# 🚀 Quick Fix Guide - 2FA Security Issues

## TL;DR - What You Need to Fix

**4 CRITICAL vulnerabilities in 2FA. Fix these BEFORE production deployment.**

---

## 🔴 Critical Fix #1: Encrypt TOTP Secrets

### Current Problem:
```sql
-- database/init.sql line 12
totp_secret TEXT,  -- ❌ PLAINTEXT!
```

### Fix:
```sql
-- database/init.sql
totp_secret_encrypted TEXT,  -- ✅ ENCRYPTED!
```

### Implementation Steps:

#### 1. Update Database Schema:
```sql
ALTER TABLE users 
  DROP COLUMN totp_secret,
  ADD COLUMN totp_secret_encrypted TEXT;
```

#### 2. Encrypt on Enable (Backend):
```rust
// backend/src/main.rs - enable_2fa function

// Instead of storing plaintext:
// .bind(&req.secret)  // ❌ BAD

// Encrypt with user's password-derived key:
let encrypted_secret = encrypt_totp_secret(&secret, &password)?;  // ✅ GOOD
.bind(&encrypted_secret)
```

#### 3. Decrypt on Verify (Backend):
```rust
// backend/src/main.rs - verify_2fa_login function

// Get encrypted secret from database:
let encrypted_secret: String = sqlx::query_scalar(
    "SELECT totp_secret_encrypted FROM users WHERE id = $1"
).bind(user_id).fetch_one(&state.db).await?;

// Decrypt with user's password (you have it during login):
let secret = decrypt_totp_secret(&encrypted_secret, &password)?;

// Then verify TOTP:
let code_valid = twofa::verify_totp_code(&secret, &req.totp_code);
```

#### 4. Add Encryption Functions:
```rust
// backend/src/twofa.rs

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use rand::Rng;

pub fn encrypt_totp_secret(secret: &str, password: &str) -> Result<String, Error> {
    // Derive key from password
    let key = derive_key_from_password(password)?;
    
    // Generate random nonce
    let nonce_bytes = rand::thread_rng().gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt
    let cipher = Aes256Gcm::new(Key::from_slice(&key));
    let ciphertext = cipher.encrypt(nonce, secret.as_bytes())?;
    
    // Combine nonce + ciphertext
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    
    Ok(base64::encode(result))
}

pub fn decrypt_totp_secret(encrypted: &str, password: &str) -> Result<String, Error> {
    // Decode
    let data = base64::decode(encrypted)?;
    
    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Derive key
    let key = derive_key_from_password(password)?;
    
    // Decrypt
    let cipher = Aes256Gcm::new(Key::from_slice(&key));
    let plaintext = cipher.decrypt(nonce, ciphertext)?;
    
    Ok(String::from_utf8(plaintext)?)
}

fn derive_key_from_password(password: &str) -> Result<Vec<u8>, Error> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    
    let mut key = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        b"timeline-2fa-salt",  // Use a proper salt
        100_000,
        &mut key
    );
    Ok(key)
}
```

**Effort**: 4-6 hours  
**Priority**: 🔴 CRITICAL

---

## 🔴 Critical Fix #2: Require Password for Setup

### Current Problem:
```rust
// backend/src/main.rs - setup_2fa function
async fn setup_2fa(headers: HeaderMap, ...) {
    verify_session(...)?;  // ❌ Only checks session, no password!
    let secret = generate_totp_secret();
    // ...
}
```

### Fix:
```rust
#[derive(Deserialize)]
struct Setup2FARequest {
    password: String,  // ✅ Add password requirement
}

async fn setup_2fa(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<Setup2FARequest>,  // ✅ Require request body
) -> Result<Json<Setup2FAResponse>, StatusCode> {
    // Verify session
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // ✅ VERIFY PASSWORD
    let password_hash: String = sqlx::query_scalar(
        "SELECT password_hash FROM users WHERE id = $1"
    )
    .bind(auth_state.user_id)
    .fetch_one(&state.db)
    .await?;
    
    if !verify_password(&req.password, &password_hash).await? {
        return Err(StatusCode::UNAUTHORIZED);
    }
    
    // Check if already enabled
    let already_enabled: bool = sqlx::query_scalar(
        "SELECT totp_enabled FROM users WHERE id = $1"
    )
    .bind(auth_state.user_id)
    .fetch_one(&state.db)
    .await?;
    
    if already_enabled {
        return Ok(Json(Setup2FAResponse {
            success: false,
            message: Some("2FA is already enabled".to_string()),
            secret: None,
            qr_uri: None,
        }));
    }
    
    // Generate secret
    let secret = twofa::generate_totp_secret();
    let qr_uri = twofa::generate_totp_uri(&secret, &auth_state.username, "Timeline");
    
    Ok(Json(Setup2FAResponse {
        success: true,
        secret: Some(secret),
        qr_uri: Some(qr_uri),
        message: None,
    }))
}
```

### Update Frontend:
```javascript
// backend/static/app.js

async continueEnable2FAStep1() {
    // Get password from user
    const password = prompt("Enter your password to continue:");
    if (!password) return;
    
    try {
        const response = await fetch('/api/2fa/setup', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ password }),  // ✅ Send password
            credentials: 'include'
        });
        // ... rest of code
    }
}
```

**Effort**: 2-3 hours  
**Priority**: 🔴 CRITICAL

---

## 🔴 Critical Fix #3: Server-Controlled Secrets

### Current Problem:
```rust
// Client provides the secret
#[derive(Deserialize)]
struct Enable2FARequest {
    secret: String,  // ❌ Client controls this!
    totp_code: String,
    password: String,
}
```

### Fix Architecture:

**Current Flow (BAD):**
```
Client → setup → get secret → client stores → enable with client's secret
                                                         ↑ PROBLEM!
```

**New Flow (GOOD):**
```
Client → setup (password) → server generates & stores temporarily
Client → enable (code, password) → server verifies against stored secret
                                                         ↑ SECURE!
```

### Implementation:

#### 1. Add Temporary Storage:
```rust
// backend/src/main.rs

#[derive(Clone)]
struct AppData {
    db: PgPool,
    sessions: Arc<RwLock<HashMap<String, Uuid>>>,
    pending_2fa: Arc<RwLock<HashMap<String, Pending2FAAuth>>>,
    twofa_protection: Arc<TwoFABruteForceProtection>,
    
    // ✅ Add this:
    pending_2fa_secrets: Arc<RwLock<HashMap<Uuid, PendingSecret>>>,
}

#[derive(Clone)]
struct PendingSecret {
    secret: String,
    created_at: SystemTime,
}

impl AppState {
    fn new(data: AppData) -> Self {
        Arc::new(data)
    }
}

// In main():
let app_state = AppState::new(AppData {
    db,
    sessions: Arc::new(RwLock::new(HashMap::new())),
    pending_2fa: Arc::new(RwLock::new(HashMap::new())),
    twofa_protection: Arc::new(TwoFABruteForceProtection::new()),
    pending_2fa_secrets: Arc::new(RwLock::new(HashMap::new())),  // ✅ Add this
});
```

#### 2. Update setup_2fa:
```rust
async fn setup_2fa(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<Setup2FARequest>,
) -> Result<Json<Setup2FAResponse>, StatusCode> {
    // ... verify session and password ...
    
    // Generate secret
    let secret = twofa::generate_totp_secret();
    
    // ✅ Store temporarily (expires in 10 minutes)
    state.pending_2fa_secrets.write().await.insert(
        auth_state.user_id,
        PendingSecret {
            secret: secret.clone(),
            created_at: SystemTime::now(),
        }
    );
    
    let qr_uri = twofa::generate_totp_uri(&secret, &auth_state.username, "Timeline");
    
    // Return for QR display only
    Ok(Json(Setup2FAResponse {
        success: true,
        secret: Some(secret),  // For QR code only
        qr_uri: Some(qr_uri),
        message: None,
    }))
}
```

#### 3. Update enable_2fa:
```rust
#[derive(Deserialize)]
struct Enable2FARequest {
    // ❌ Remove: secret: String,
    totp_code: String,
    password: String,
}

async fn enable_2fa(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<Enable2FARequest>,
) -> Result<Json<Enable2FAResponse>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // ✅ Get secret from server storage, not from client!
    let pending_secret = {
        let secrets = state.pending_2fa_secrets.read().await;
        secrets.get(&auth_state.user_id).cloned()
    };
    
    let pending = match pending_secret {
        Some(p) => p,
        None => {
            return Ok(Json(Enable2FAResponse {
                success: false,
                message: Some("No 2FA setup in progress. Call /api/2fa/setup first.".to_string()),
            }));
        }
    };
    
    // Check expiration (10 minutes)
    if pending.created_at.elapsed().unwrap_or_default() > Duration::from_secs(600) {
        state.pending_2fa_secrets.write().await.remove(&auth_state.user_id);
        return Ok(Json(Enable2FAResponse {
            success: false,
            message: Some("Setup expired. Please start again.".to_string()),
        }));
    }
    
    // Verify password
    let password_hash: String = sqlx::query_scalar(
        "SELECT password_hash FROM users WHERE id = $1"
    )
    .bind(auth_state.user_id)
    .fetch_one(&state.db)
    .await?;
    
    if !verify_password(&req.password, &password_hash).await? {
        return Ok(Json(Enable2FAResponse {
            success: false,
            message: Some("Invalid password".to_string()),
        }));
    }
    
    // ✅ Verify TOTP against SERVER's secret, not client's
    if !twofa::verify_totp_code(&pending.secret, &req.totp_code) {
        return Ok(Json(Enable2FAResponse {
            success: false,
            message: Some("Invalid 2FA code".to_string()),
        }));
    }
    
    // Enable 2FA with SERVER's secret (encrypted!)
    let encrypted_secret = encrypt_totp_secret(&pending.secret, &req.password)?;
    
    sqlx::query(
        "UPDATE users SET totp_secret_encrypted = $1, totp_enabled = true, totp_enabled_at = NOW() WHERE id = $2"
    )
    .bind(&encrypted_secret)
    .bind(auth_state.user_id)
    .execute(&state.db)
    .await?;
    
    // Clean up temporary storage
    state.pending_2fa_secrets.write().await.remove(&auth_state.user_id);
    
    Ok(Json(Enable2FAResponse {
        success: true,
        message: None,
    }))
}
```

#### 4. Update Frontend:
```javascript
// backend/static/app.js

async finishEnable2FA(e) {
    e.preventDefault();
    
    const totpCode = document.getElementById('verify-totp-code').value;
    const password = document.getElementById('enable-2fa-password').value;
    
    // ❌ Remove: secret: this.temp2FASecret
    
    try {
        const response = await fetch('/api/2fa/enable', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                totp_code: totpCode,
                password: password
                // ✅ No secret sent from client!
            }),
            credentials: 'include'
        });
        // ... rest of code
    }
}
```

**Effort**: 6-8 hours  
**Priority**: 🔴 CRITICAL

---

## 🟠 Medium Fix #4: Fix TOTP Time Window

### Current Problem:
```rust
// backend/src/twofa.rs lines 121-123
for offset in [-30i64, 0, 30] {  // ❌ 90-second window!
```

### Fix:
```rust
// backend/src/twofa.rs

pub fn verify_totp_code(secret: &str, code: &str) -> bool {
    let secret_bytes = match base32_decode(secret) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // ✅ Only check current and previous window (60 seconds total)
    for offset in [-30i64, 0] {  // ✅ Changed from [-30, 0, 30]
        let test_timestamp = (timestamp as i64 + offset) as u64;
        let generated_code = totp::<Sha1>(&secret_bytes, test_timestamp);
        
        let code_num: u64 = generated_code.parse().unwrap_or(0);
        let code_6_digit = format!("{:06}", code_num % 1000000);
        
        if code_6_digit == code {
            return true;
        }
    }

    false
}
```

**Effort**: 15 minutes  
**Priority**: 🟠 MEDIUM

---

## ✅ Testing After Fixes

### Test Script:
```bash
#!/bin/bash
echo "🧪 Testing 2FA Security Fixes..."

# Test 1: TOTP secrets should be encrypted
echo "Test 1: Check TOTP secrets in database..."
docker exec timeline-database-1 psql -U timeline_user -d timeline \
  -c "SELECT username, totp_secret_encrypted FROM users WHERE totp_enabled = true LIMIT 1;"
echo "✅ Should see encrypted data, not plaintext secret"

# Test 2: Setup should require password
echo ""
echo "Test 2: Try setup without password..."
curl -s -b cookies.txt -X POST http://localhost:8080/api/2fa/setup | jq .
echo "❌ Should fail with 400 Bad Request (missing password)"

echo ""
echo "Test 3: Try setup with password..."
curl -s -b cookies.txt -X POST http://localhost:8080/api/2fa/setup \
  -H "Content-Type: application/json" \
  -d '{"password":"correct_password"}' | jq .
echo "✅ Should succeed and return secret"

# Test 3: Enable should not accept client secret
echo ""
echo "Test 4: Try enable with custom secret..."
curl -s -b cookies.txt -X POST http://localhost:8080/api/2fa/enable \
  -H "Content-Type: application/json" \
  -d '{"totp_code":"123456","password":"pass"}' | jq .
echo "✅ Should use server's secret (client cannot provide)"

echo ""
echo "🎉 All tests complete!"
```

---

## 📋 Checklist

### Before Starting:
- [ ] Backup database
- [ ] Backup code
- [ ] Create feature branch: `git checkout -b fix/2fa-security`
- [ ] Review all 4 fixes

### Fix #1: Encrypt TOTP Secrets
- [ ] Update database schema
- [ ] Add encryption functions
- [ ] Update enable_2fa to encrypt
- [ ] Update verify_2fa_login to decrypt
- [ ] Test encryption/decryption

### Fix #2: Require Password for Setup
- [ ] Add password field to Setup2FARequest
- [ ] Add password verification in setup_2fa
- [ ] Update frontend to prompt for password
- [ ] Test with correct password
- [ ] Test with wrong password

### Fix #3: Server-Controlled Secrets
- [ ] Add pending_2fa_secrets storage
- [ ] Update setup_2fa to store secret
- [ ] Remove secret field from Enable2FARequest
- [ ] Update enable_2fa to use stored secret
- [ ] Add expiration check (10 minutes)
- [ ] Update frontend to not send secret
- [ ] Test full flow

### Fix #4: Fix Time Window
- [ ] Update verify_totp_code
- [ ] Remove +30 second offset
- [ ] Test with current code
- [ ] Test with old code (should still work)
- [ ] Test with future code (should NOT work)

### After Fixes:
- [ ] Run all tests
- [ ] Test with real 2FA app
- [ ] Update documentation
- [ ] Commit changes: `git commit -m "Fix 4 critical 2FA vulnerabilities"`
- [ ] Push to repository
- [ ] Create pull request
- [ ] Request security re-test

---

## 🚀 Deployment Steps

1. **Development**:
   ```bash
   git checkout -b fix/2fa-security
   # Make fixes
   cargo test
   cargo run
   # Manual testing
   ```

2. **Staging**:
   ```bash
   git push origin fix/2fa-security
   # Deploy to staging
   # Run penetration tests again
   # Verify all vulnerabilities fixed
   ```

3. **Production**:
   ```bash
   # After successful staging tests
   git checkout main
   git merge fix/2fa-security
   git push origin main
   # Deploy to production
   ```

---

## ⏱️ Time Estimates

| Fix | Priority | Effort | Testing |
|-----|----------|--------|---------|
| #1: Encrypt secrets | 🔴 CRITICAL | 4-6h | 2h |
| #2: Password for setup | 🔴 CRITICAL | 2-3h | 1h |
| #3: Server-controlled | 🔴 CRITICAL | 6-8h | 2h |
| #4: Time window | 🟠 MEDIUM | 15min | 30min |
| **Total** | | **13-17h** | **5.5h** |

**Total Project Time**: 18.5-22.5 hours (2-3 weeks part-time)

---

## 📞 Need Help?

If you get stuck on any of these fixes:

1. Check the full report: `SECURITY_PENTEST_REPORT.md`
2. Review code examples in: `CODE_REVIEW.md`
3. See visual guide: `FINDINGS_VISUAL.md`
4. Reference this guide: `QUICK_FIX_GUIDE.md`

**Remember**: These are CRITICAL security issues. Take the time to implement them correctly!

---

**Last Updated**: 2025-01-30  
**Status**: Fixes Required Before Production  
**Next Review**: After implementing fixes
