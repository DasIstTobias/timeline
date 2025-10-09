# Timeline Application - Comprehensive Security Penetration Testing Report

## Executive Summary

The Timeline application claims to use "zero-knowledge encryption" where all user data is encrypted client-side before transmission to the server. This report evaluates the effectiveness of this security model and identifies vulnerabilities.

**Overall Security Rating: B+ (Good with Minor Concerns)**

---

## PART 1: ZERO-KNOWLEDGE ENCRYPTION TESTS

### Test 1.1: Admin with Full System Access (No User Password)

**Scenario**: System administrator has:
- Full database access
- Backend source code access
- Admin account credentials
- NO access to user's password

**Test Results**:

#### API Layer Protection
✅ **PASS**: Admin cannot access user data through API
- `/api/events` returns 403 Forbidden for admin
- `/api/notes` returns 403 Forbidden for admin
- Proper role-based access control

#### Database Layer Analysis
All sensitive user data is encrypted:
- Events (title, description): AES-256-GCM encrypted
- Notes: AES-256-GCM encrypted  
- Settings, display name: AES-256-GCM encrypted
- Profile pictures: AES-256-GCM encrypted

**Encryption Details**:
- Algorithm: AES-256-GCM
- Key Derivation: PBKDF2 with SHA-256, 100,000 iterations
- Salt: 16 bytes random per encryption
- IV: 12 bytes random per encryption
- Key derived directly from user password

✅ **VERDICT**: Without user password, admin CANNOT decrypt user data

#### Metadata Leakage Issues

⚠️ **FINDING 1: Plaintext Event Timestamps**
- Event timestamps stored unencrypted: `event_timestamp TIMESTAMP WITH TIME ZONE`
- Example leaked: `2025-10-09 16:24:25.497+00`
- **Impact**: Attacker knows WHEN events occurred
- **Severity**: LOW - Metadata leakage
- **Recommendation**: Encrypt timestamps or use relative offsets

⚠️ **FINDING 2: User Creation Times**
- User account creation times visible: `created_at TIMESTAMP WITH TIME ZONE`
- **Impact**: Attacker knows when account was created
- **Severity**: LOW - Metadata leakage

### Test 1.2: Password Recovery Attempts

**Scenario**: Attempt to recover user password from database

#### Bcrypt Analysis
- Password hash: `$2b$12$/jqTlDOh5UyD4I0RZWEG9enz4M8oQa97T64qdE8mdCzu08S5filkC`
- Algorithm: bcrypt
- Cost factor: 12 (2^12 = 4,096 iterations)
- Salt: Embedded in hash

✅ **PASS**: Very resistant to brute force
- Estimated crack time: Years to decades
- Rainbow tables ineffective due to salt
- **Verdict**: Cannot recover password

### Test 1.3: Zero-Knowledge Effectiveness

✅ **CONFIRMED**: Zero-knowledge encryption works as designed
- Admin with full system access CANNOT access user data
- All sensitive data properly encrypted
- Encryption keys never stored on server
- Only minor metadata leakage (timestamps)

---

## PART 2: NO CREDENTIALS ATTACK (Maximum Data Extraction)

### Test 2.1: Unauthenticated Access

**Scenario**: Attacker with no credentials attempts to extract data

**Results**:
- `/api/events` - 401 Unauthorized
- `/api/notes` - 401 Unauthorized
- `/api/settings` - 401 Unauthorized
- `/api/tags` - 401 Unauthorized
- All API endpoints require authentication

✅ **PASS**: No data accessible without authentication

### Test 2.2: Direct Database Access

**Publicly Visible Information**:
1. Usernames (not encrypted): `admin`, `testuser`
2. User IDs (UUIDs)
3. Account creation timestamps
4. Event timestamps (plaintext)
5. Number of events per user
6. Password hashes (cannot be reversed)

**Encrypted (Inaccessible)**:
- Event titles and descriptions
- Notes content
- User settings
- Display names
- Profile pictures
- TOTP secrets

✅ **VERDICT**: Limited metadata exposed, no sensitive content accessible

---

## PART 3: WEB-ONLY ATTACKS (NO BACKEND ACCESS)

### Test 3.1: SQL Injection

**Test**: Attempted SQL injection via login
```json
{"username": "admin' OR '1'='1", "password": "test"}
```

✅ **PASS**: All queries use parameterized statements ($1, $2, etc.)
- No SQL injection vulnerabilities found
- Proper input validation

### Test 3.2: Cross-Site Scripting (XSS)

**Analysis**: 
- User input escaped with `escapeHtml()` function
- Uses `textContent` API for safe escaping
- Content Security Policy headers present

✅ **MOSTLY SAFE**: Proper XSS protection in place

⚠️ **POTENTIAL ISSUE**: Event deletion button uses onclick with escaped HTML
```javascript
onclick="app.deleteEvent('${event.id}', '${this.escapeHtml(event.title)}')"
```
- Escaped HTML inside JavaScript string context
- Could potentially be bypassed with careful crafting
- **Recommendation**: Use event listeners instead of onclick attributes

### Test 3.3: Buffer Overflow / Denial of Service

**Test**: Send 10MB+ payload
```bash
curl -X POST /api/events -d '{"title_encrypted": "A"*10000000, ...}'
```

**Result**: `length limit exceeded`

✅ **PASS**: Request body size limit enforced
- Protection against DoS via large payloads

### Test 3.4: Null Byte Injection

**Test**: Username with null byte: `admin\x00malicious`

✅ **PASS**: Null bytes detected and rejected
- Proper input validation in place

### Test 3.5: Session Hijacking

**Session Cookie Analysis**:
```
Set-Cookie: session_id=UUID; HttpOnly; Path=/; SameSite=Strict
```

✅ **GOOD SECURITY**:
- HttpOnly flag prevents JavaScript access
- SameSite=Strict prevents CSRF
- Random UUID session IDs
- 24-hour session timeout

⚠️ **MISSING**: Secure flag not set
- **Impact**: Sessions could be hijacked over HTTP
- **Recommendation**: Always set Secure flag when using HTTPS

---

## PART 4: PASSWORD RECONSTRUCTION ATTEMPTS

### Test 4.1: TOTP Secret Analysis

🔴 **CRITICAL FINDING 3: Deterministic TOTP Salt**

**Location**: `backend/src/crypto.rs:51`
```rust
let salt = format!("timeline_2fa_{}", user_id);
```

**Issue**: TOTP secrets encrypted with deterministic salt
- Salt is predictable: `"timeline_2fa_" + user_id`
- user_id is stored in database
- Attacker with database access knows the salt

**Attack Scenario**:
1. Attacker obtains database access
2. Attacker knows user_id (e.g., `10301efa-3e8f-48b1-95fe-236df9f1e466`)
3. Attacker guesses/brute-forces user password
4. Attacker can decrypt TOTP secret using known salt
5. Attacker can bypass 2FA

**Impact**: HIGH
- Reduces 2FA security
- If password is weak or compromised, 2FA can be defeated
- Breaks defense-in-depth principle

**Recommendation**: Use random salt for TOTP encryption
```rust
let salt: [u8; 16] = rand::random();
// Store salt alongside encrypted TOTP secret
```

### Test 4.2: Password Storage

✅ **PASS**: Bcrypt with proper cost factor
- No feasible password reconstruction
- Salted and hashed properly

### Test 4.3: Password in Memory

⚠️ **FINDING 4: Password Stored During 2FA Login**

**Location**: `backend/src/main.rs:531`
```rust
password: req.password.clone(), // Store password temporarily
```

- Password kept in memory during 2FA verification
- `Drop` implementation attempts to zero memory
- However, Rust strings can't reliably be zeroed

**Impact**: MEDIUM
- Memory dump could reveal passwords during 2FA flow
- Short exposure window (30 seconds max)

**Recommendation**: Use secure string library like `secrecy` crate

---

## PART 5: CODE REVIEW FINDINGS

### Security Headers

✅ **EXCELLENT**: Comprehensive security headers
```
Content-Security-Policy: default-src 'self'; script-src 'self'; ...
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### CORS Configuration

✅ **GOOD**: Restrictive CORS policy
- Only allows configured domains
- Credentials allowed only for same-origin

### Rate Limiting

✅ **PRESENT**: Login rate limiting
- 3 attempts: 30 second lockout
- 5 attempts: 5 minute lockout
- 10+ attempts: 1 hour lockout

### 2FA Implementation

✅ **MOSTLY SECURE**: 
- TOTP standard implementation
- Brute-force protection
- Time window for clock skew (-30s, current)

🔴 **ISSUE**: Deterministic salt (see Finding 3)

---

## PART 6: SSL/TLS AND DOMAIN BLOCKING

### Test 6.1: Domain Whitelist

**Configuration**: `DOMAIN=localhost` in docker-compose.yml

**Tests**:
```bash
curl -H "Host: evil.com" http://localhost:8080/
# Result: 403 Forbidden - Domain not allowed

curl -H "Host: 192.168.1.1" http://localhost:8080/
# Result: 403 Forbidden - Domain not allowed
```

✅ **PASS**: Domain whitelist works correctly

**Analysis**:
- Checks both Host header and :authority pseudo-header
- Case-insensitive matching
- Handles IPv6 addresses
- Logs all checks

### Test 6.2: SSL/TLS Configuration

**Options**:
- `USE_SELF_SIGNED_SSL`: Generate self-signed cert
- `REQUIRE_TLS`: Enforce HTTPS connections
- Both can be independently configured

✅ **FLEXIBLE**: Good configuration options

⚠️ **FINDING 5: Self-Signed Certificates**

**Issue**: Application can generate self-signed certificates
- Users may ignore browser warnings
- No certificate validation possible
- Opens door to MITM attacks

**Impact**: MEDIUM (only when USE_SELF_SIGNED_SSL=true)

**Recommendation**: 
- Warn users about self-signed cert risks
- Recommend proper TLS setup with Let's Encrypt
- Document secure deployment practices

### Test 6.3: TLS Enforcement

**When REQUIRE_TLS=true**:
- Checks X-Forwarded-Proto header
- Rejects non-HTTPS requests
- Supports reverse proxy setups

✅ **GOOD**: Proper TLS enforcement

⚠️ **FINDING 6: No HSTS Header**

**Issue**: Missing HTTP Strict Transport Security header
- Users could be downgraded to HTTP
- Vulnerable to SSL stripping attacks

**Recommendation**: Add HSTS header when REQUIRE_TLS=true
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### Test 6.4: Domain Blocking Bypass Attempts

**Tested**:
1. ✅ Different domain names - BLOCKED
2. ✅ IP addresses not in whitelist - BLOCKED  
3. ✅ Missing Host header - BLOCKED
4. ✅ IPv6 addresses - HANDLED CORRECTLY

**No bypasses found**

---

## PART 7: 2FA SECURITY ASSESSMENT

### Current Security Level

**Without 2FA** (Password Only):
- Security depends entirely on password strength
- Single point of failure
- Vulnerable to: password reuse, phishing, brute force

**With 2FA** (Password + TOTP):
- Two factors required for access
- Significantly more secure
- Resistant to password compromise alone

### 2FA Effectiveness

**Strengths**:
- ✅ TOTP standard (RFC 6238)
- ✅ 6-digit codes
- ✅ 30-second time window
- ✅ Brute-force protection
- ✅ QR code for easy setup

**Weaknesses**:
- 🔴 Deterministic salt (Finding 3)
- ⚠️ TOTP secret stored encrypted (can be decrypted with password)
- ⚠️ No backup codes
- ⚠️ No recovery mechanism if 2FA device lost

### Security Improvement: Password vs Password+2FA

**Estimated Security Increase**: 100-1000x

**Attack Scenarios**:

| Attack Type | Password Only | Password + 2FA |
|------------|---------------|----------------|
| Phishing | ❌ Vulnerable | ⚠️ Reduced risk |
| Password reuse | ❌ Vulnerable | ✅ Protected |
| Brute force | ⚠️ Mitigated by bcrypt | ✅ Nearly impossible |
| Database breach | ⚠️ Depends on password | ✅ Protected (unless password weak) |
| Keylogger | ❌ Compromised | ⚠️ Requires TOTP device |

### Recommendations for 2FA Improvement

1. **Fix deterministic salt** (CRITICAL)
   - Use random salt per encryption
   - Store salt with encrypted TOTP secret

2. **Add backup codes**
   - Generate one-time use backup codes
   - Encrypt and store in database
   - Allow recovery if TOTP device lost

3. **Add recovery mechanism**
   - Admin-assisted account recovery
   - Time-delayed recovery process
   - Security questions (optional)

4. **Consider WebAuthn/FIDO2**
   - Hardware security keys
   - Phishing-resistant
   - Better UX than TOTP

---

## SUMMARY OF ALL VULNERABILITIES

### Critical (Fix Immediately)

🔴 **FINDING 3: Deterministic TOTP Salt**
- **Severity**: HIGH
- **File**: `backend/src/crypto.rs:51`
- **Impact**: 2FA can be bypassed if password known
- **Fix**: Use random salt, store with encrypted secret

### High Priority

⚠️ **FINDING 1: Plaintext Event Timestamps**
- **Severity**: LOW-MEDIUM
- **Impact**: Metadata leakage
- **Fix**: Encrypt timestamps or use relative time

⚠️ **FINDING 6: Missing HSTS Header**
- **Severity**: MEDIUM
- **Impact**: SSL stripping vulnerability
- **Fix**: Add HSTS header when TLS required

### Medium Priority

⚠️ **FINDING 4: Password in Memory During 2FA**
- **Severity**: MEDIUM
- **Impact**: Memory dumps could reveal passwords
- **Fix**: Use secure string library

⚠️ **FINDING 5: Self-Signed Certificate Warnings**
- **Severity**: MEDIUM (user education)
- **Impact**: Users may ignore security warnings
- **Fix**: Document proper TLS setup

⚠️ **XSS Risk in onclick Attributes**
- **Severity**: LOW
- **Impact**: Potential XSS if escaping bypassed
- **Fix**: Use addEventListener instead of onclick

### Low Priority

- Session cookies missing Secure flag
- No session cookie rotation
- No backup codes for 2FA
- No rate limiting on 2FA verification (has brute force protection though)

---

## DATA SUCCESSFULLY EXTRACTED

During testing, the following data could be extracted:

### With Admin Access (No User Password):
1. ❌ Event titles - ENCRYPTED, NOT ACCESSIBLE
2. ❌ Event descriptions - ENCRYPTED, NOT ACCESSIBLE
3. ❌ Notes content - ENCRYPTED, NOT ACCESSIBLE
4. ❌ User passwords - HASHED, NOT RECOVERABLE
5. ✅ Event timestamps - PLAINTEXT, ACCESSIBLE
6. ✅ Usernames - PLAINTEXT, ACCESSIBLE
7. ✅ Account creation dates - PLAINTEXT, ACCESSIBLE
8. ✅ Number of events per user - COUNTABLE

### With No Access (Web Only):
1. ❌ No user data accessible
2. ❌ No admin functionality accessible
3. ✅ Login page accessible (expected)

**CONCLUSION**: Zero-knowledge encryption effectively protects user data from system administrators and attackers.

---

## RECOMMENDATIONS SUMMARY

### Immediate Actions (Critical)
1. Fix deterministic TOTP salt
2. Add HSTS header
3. Document self-signed cert risks

### Short Term (High Priority)
1. Encrypt event timestamps
2. Use secure string library for passwords
3. Replace onclick with addEventListener

### Long Term (Enhancement)
1. Implement backup codes for 2FA
2. Add WebAuthn/FIDO2 support
3. Implement session key rotation
4. Add security audit logs
5. Implement account recovery mechanism

### Best Practices for Deployment
1. Always use proper TLS certificates (Let's Encrypt)
2. Set REQUIRE_TLS=true in production
3. Use strong domain whitelist
4. Monitor authentication logs
5. Implement intrusion detection
6. Regular security audits
7. Keep dependencies updated

---

## FINAL VERDICT

**Zero-Knowledge Encryption: ✅ EFFECTIVE**
- Admin cannot access user data without password
- Encryption implementation is sound
- Minor metadata leakage only

**Overall Security: B+ (Good)**
- Strong encryption
- Good input validation
- Minor vulnerabilities found
- One critical issue (TOTP salt)

**Production Ready: ⚠️ YES WITH FIXES**
- Fix critical TOTP salt issue first
- Add HSTS header
- Follow deployment best practices
- Consider this a solid foundation

The application successfully implements zero-knowledge encryption and protects user data from server administrators. The main security concern is the deterministic TOTP salt which should be fixed before production deployment.
