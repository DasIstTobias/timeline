# Comprehensive Security Code Review

## All Files in Repository:
1. `/backend/src/main.rs` - Main server code (1231 lines)
2. `/backend/src/auth.rs` - Authentication module (56 lines)
3. `/backend/src/twofa.rs` - 2FA implementation (201 lines)
4. `/backend/src/crypto.rs` - Password hashing (24 lines)
5. `/backend/src/models.rs` - Data models
6. `/backend/static/app.js` - Frontend application (2108 lines)
7. `/backend/static/crypto.js` - Client-side encryption (103 lines)
8. `/backend/static/index.html` - HTML interface
9. `/backend/static/style.css` - Styling
10. `/backend/Cargo.toml` - Rust dependencies
11. `/database/init.sql` - Database schema (55 lines)
12. `/docker-compose.yml` - Docker configuration

## Security Issues Found by Category:

### CRITICAL - 2FA Implementation (HIGH PRIORITY)

#### 1. TOTP Secret Stored in Plaintext (CRITICAL)
**File**: `database/init.sql` line 12
```sql
totp_secret TEXT,  -- Stored in plaintext!
```
**Impact**: Anyone with database access can read all TOTP secrets and bypass 2FA
**Risk Level**: CRITICAL
**Recommendation**: Encrypt TOTP secrets using user's password-derived key

#### 2. 2FA Setup Without Password (CRITICAL)
**File**: `backend/src/main.rs` lines 1021-1058
**Issue**: `/api/2fa/setup` endpoint only requires valid session, no password
**Impact**: Attacker with stolen session can generate 2FA secrets
**Risk Level**: CRITICAL
**Recommendation**: Require password verification in setup endpoint

#### 3. Client-Controlled TOTP Secret (CRITICAL)
**File**: `backend/src/main.rs` lines 1073-1149
**Issue**: Enable 2FA accepts secret from client, not server-generated
**Impact**: Attacker can enable 2FA with their own known secret
**Risk Level**: CRITICAL
**Recommendation**: Server should generate and store secret, client should only provide TOTP code

#### 4. Extended TOTP Time Window (MEDIUM)
**File**: `backend/src/twofa.rs` lines 121-123
```rust
for offset in [-30i64, 0, 30] {  // 90-second window!
```
**Impact**: 90-second window instead of standard 60 seconds
**Risk Level**: MEDIUM
**Recommendation**: Remove +30 second future window, only accept current and -30s

#### 5. Password Verification Before 2FA (MEDIUM)
**File**: `backend/src/main.rs` lines 213-235
**Issue**: Login returns success=true and user_type before 2FA verification
**Impact**: Information leak - attacker learns password is valid before 2FA
**Risk Level**: MEDIUM
**Recommendation**: Return generic "requires authentication" until fully authenticated

### HIGH - Session and Authentication

#### 6. No Session Expiration (HIGH)
**File**: `backend/src/main.rs` lines 92-96
**Issue**: Sessions stored in memory HashMap with no expiration
**Impact**: Sessions never expire until server restart
**Risk Level**: HIGH
**Recommendation**: Implement session timeout (e.g., 24 hours)

#### 7. Pending 2FA Session Timeout (MEDIUM)
**File**: `backend/src/main.rs` lines 900-911
**Issue**: 5-minute timeout for pending 2FA sessions
**Impact**: Acceptable but could be shorter
**Risk Level**: LOW-MEDIUM
**Recommendation**: Consider reducing to 2-3 minutes

### MEDIUM - Input Validation

#### 8. Input Validation Present (GOOD)
**File**: `backend/src/main.rs` lines 26-47
**Finding**: Good input validation for null bytes and control characters
**Status**: SECURE

#### 9. SQL Injection Protection (GOOD)
**Finding**: All database queries use parameterized queries
**Status**: SECURE - Tested and confirmed

### LOW - General Security

#### 10. Admin Cannot Use 2FA (DESIGN CHOICE)
**File**: `backend/src/main.rs` lines 1028-1030
**Issue**: Admin accounts cannot enable 2FA
**Impact**: Admin account less secure
**Risk Level**: LOW
**Recommendation**: Allow admin to use 2FA

#### 11. CORS Permissive (MEDIUM)
**File**: `backend/src/main.rs` line 124
```rust
.layer(CorsLayer::permissive())
```
**Impact**: Allows cross-origin requests from any domain
**Risk Level**: MEDIUM
**Recommendation**: Restrict CORS to specific domains in production

### POSITIVE FINDINGS - Zero-Knowledge Encryption

#### 12. Strong Zero-Knowledge Implementation (EXCELLENT)
**Files**: `backend/static/crypto.js`, all encrypted fields
**Finding**: 
- Client-side AES-GCM encryption
- PBKDF2 key derivation (100,000 iterations)
- Password never sent to server
- All user data encrypted
**Status**: SECURE - Tested and confirmed server cannot decrypt data

#### 13. Secure Password Hashing (EXCELLENT)
**File**: `backend/src/crypto.rs`
**Finding**: bcrypt with cost factor 12
**Status**: SECURE

#### 14. HttpOnly Cookies (GOOD)
**File**: `backend/src/main.rs` lines 244-248
**Finding**: Session cookies use HttpOnly flag
**Status**: SECURE - Protects against XSS theft
