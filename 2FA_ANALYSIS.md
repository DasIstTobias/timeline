# 2FA Implementation Analysis

## Backend Implementation Analysis (main.rs + twofa.rs)

### 1. TOTP Secret Generation (`twofa.rs` lines 91-104)
```rust
pub fn generate_totp_secret() -> String {
    const BASE32_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut rng = rand::thread_rng();
    
    let secret: String = (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..BASE32_CHARS.len());
            BASE32_CHARS[idx] as char
        })
        .collect();
    
    secret
}
```
**Analysis**: Generates a 32-character base32 secret (160 bits). Uses cryptographically secure RNG.

### 2. TOTP Code Verification (`twofa.rs` lines 107-136)
```rust
pub fn verify_totp_code(secret: &str, code: &str) -> bool {
    let secret_bytes = match base32_decode(secret) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Check current time and 30 seconds before/after to account for clock skew
    for offset in [-30i64, 0, 30] {
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
**Analysis**: 
- Uses standard TOTP with SHA1 (standard for TOTP)
- Accepts codes within ±30 seconds window (3 time windows total)
- This is a potential vulnerability - allows for time drift attacks

### 3. 2FA Setup Endpoint (`main.rs` lines 1021-1058)
```rust
async fn setup_2fa(...) -> Result<Json<Setup2FAResponse>, StatusCode> {
    let auth_state = verify_session(&headers, &state.sessions, &state.db).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    if auth_state.is_admin {
        return Err(StatusCode::FORBIDDEN);
    }
    
    // Check if 2FA is already enabled
    let already_enabled: bool = sqlx::query_scalar("SELECT totp_enabled FROM users WHERE id = $1")
        .bind(auth_state.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    if already_enabled {
        return Ok(Json(Setup2FAResponse {
            success: false,
            secret: None,
            qr_uri: None,
            message: Some("2FA is already enabled".to_string()),
        }));
    }
    
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
**CRITICAL VULNERABILITY #1**: Setup endpoint generates secret but DOESN'T require password!
- Anyone with a valid session can call `/api/2fa/setup`
- The secret is returned in plaintext over the wire
- Secret is NOT stored in database yet - only returned to client
- If an attacker has session access, they can generate a secret for any user

### 4. 2FA Enable Endpoint (`main.rs` lines 1073-1149)
```rust
async fn enable_2fa(...) -> Result<Json<Enable2FAResponse>, StatusCode> {
    // ... validation ...
    
    // Verify password
    let password_hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
        .bind(auth_state.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let password_valid = verify_password(&req.password, &password_hash).await.unwrap_or(false);
    if !password_valid {
        return Ok(Json(Enable2FAResponse {
            success: false,
            message: Some("Invalid password".to_string()),
        }));
    }
    
    // Verify TOTP code
    if !twofa::verify_totp_code(&req.secret, &req.totp_code) {
        return Ok(Json(Enable2FAResponse {
            success: false,
            message: Some("Invalid 2FA code".to_string()),
        }));
    }
    
    // Enable 2FA
    sqlx::query("UPDATE users SET totp_secret = $1, totp_enabled = true, totp_enabled_at = NOW() WHERE id = $2")
        .bind(&req.secret)
        .bind(auth_state.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(Enable2FAResponse {
        success: true,
        message: None,
    }))
}
```
**Analysis**: 
- Requires valid session + password + valid TOTP code
- Secret comes from CLIENT, not from server!
- This means client controls what secret is stored

**CRITICAL VULNERABILITY #2**: Client-provided secret!
- The secret parameter comes from the client in the request body
- An attacker could provide their own secret instead of using the one from setup
- Combined with vulnerability #1, this is dangerous

### 5. 2FA Login Flow (`main.rs` lines 169-268 and 857-979)
```rust
async fn login(...) -> Result<(HeaderMap, Json<LoginResponse>), StatusCode> {
    // ... password verification ...
    
    if is_valid_user && password_valid {
        if let Some((user_id, username, is_admin)) = user_data {
            if !is_admin && totp_enabled {
                let temp_session_id = uuid::Uuid::new_v4().to_string();
                
                state.pending_2fa.write().await.insert(temp_session_id.clone(), Pending2FAAuth {
                    user_id,
                    username: username.clone(),
                    is_admin,
                    remember_me: req.remember_me.unwrap_or(false),
                    created_at: std::time::SystemTime::now(),
                });
                
                return Ok((HeaderMap::new(), Json(LoginResponse {
                    success: true,
                    user_type: Some("user".to_string()),
                    message: None,
                    requires_2fa: Some(true),
                    temp_session_id: Some(temp_session_id),
                })));
            }
            // ... create full session if no 2FA ...
        }
    }
}
```

**CRITICAL VULNERABILITY #3**: Password verification BEFORE 2FA!
- Login returns success=true with user_type="user" BEFORE 2FA verification
- Returns temp_session_id which is stored in memory
- An attacker who knows the password learns:
  1. The password is correct
  2. The username exists  
  3. The user_type (user vs admin)
  4. Gets a temp_session_id

Let me test if temp_session_id can be used to access data...

### 6. Database Storage
From `init.sql`:
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    display_name_encrypted TEXT,
    settings_encrypted TEXT,
    is_admin BOOLEAN DEFAULT FALSE,
    totp_secret TEXT,  -- STORED IN PLAINTEXT!
    totp_enabled BOOLEAN DEFAULT FALSE,
    totp_enabled_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

**CRITICAL VULNERABILITY #4**: TOTP secret stored in PLAINTEXT in database!
- The `totp_secret` field is TEXT, not encrypted
- Anyone with database access can read TOTP secrets
- This completely bypasses 2FA for anyone with backend/database access
