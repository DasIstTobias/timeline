# Security Testing Methodology

## Overview

This document describes the comprehensive security testing methodology used to evaluate the Timeline application's zero-knowledge encryption claims and overall security posture.

## Testing Environment

- **Application**: Timeline v0.1.0
- **Test Date**: 2025-10-09
- **Testing Approach**: Combined Black Box + White Box
- **Access Level**: Full system access (simulating worst-case scenario)

## Test Accounts Created

1. **Admin Account**
   - Username: `admin`
   - Auto-generated password
   - Full administrative privileges

2. **Test User Account**
   - Username: `testuser`
   - Auto-generated password
   - Regular user with encrypted data

## Test Data Created

**Events:**
- Title: "Secret Meeting"
- Description: Sensitive information including passwords
- Timestamp: Recorded

**Notes:**
- Bank account information
- PIN codes
- Social Security Number
- API keys
- Email passwords

## Testing Phases

### Phase 1: Zero-Knowledge Encryption Tests

#### Test 1.1: Admin with Full System Access
**Scenario**: System administrator with:
- Database access (PostgreSQL)
- Backend source code access
- Server shell access
- Admin account credentials
- NO user password

**Tests Performed:**
1. Direct database queries to extract encrypted data
2. API endpoint access attempts as admin
3. Password hash analysis and cracking attempts
4. TOTP secret examination
5. Metadata analysis

**Expected Result**: Admin cannot decrypt user data
**Actual Result**: ✅ PASS - Cannot decrypt without user password

#### Test 1.2: No Credentials Attack
**Scenario**: Attacker with:
- Database access
- Backend source code
- NO account credentials

**Tests Performed:**
1. Unauthenticated API access attempts
2. Database analysis for unencrypted data
3. User enumeration
4. Metadata extraction

**Expected Result**: Minimal data exposure
**Actual Result**: ✅ PASS - Only metadata visible

#### Test 1.3: Password Reconstruction
**Scenario**: Attempt to recover user passwords

**Tests Performed:**
1. Bcrypt hash analysis
2. Dictionary attacks (theoretical)
3. Rainbow table attacks (theoretical)
4. TOTP secret decryption attempts

**Expected Result**: Password recovery infeasible
**Actual Result**: ✅ PASS - Cannot recover passwords

### Phase 2: Web Application Security Tests

#### Test 2.1: SQL Injection
**Method**: Input validation testing

**Payloads Tested:**
```
admin' OR '1'='1
admin'--
admin'; DROP TABLE users;--
```

**Result**: ✅ All blocked - Parameterized queries

#### Test 2.2: Cross-Site Scripting (XSS)
**Method**: Code review + payload testing

**Findings:**
- HTML properly escaped
- CSP headers present
- Minor risk in onclick attributes

**Result**: ✅ Mostly protected

#### Test 2.3: Buffer Overflow / DoS
**Method**: Large payload testing

**Test:** 10MB+ request bodies

**Result**: ✅ Request size limit enforced

#### Test 2.4: Null Byte Injection
**Method**: Null byte in inputs

**Payloads:**
```
admin\x00malicious
```

**Result**: ✅ Detected and rejected

#### Test 2.5: Session Security
**Method**: Cookie analysis

**Tests:**
- Session fixation
- Session hijacking
- CSRF attacks
- Cookie security flags

**Result**: ✅ Good security (missing Secure flag)

### Phase 3: Infrastructure Security Tests

#### Test 3.1: Domain Whitelist Bypass
**Method**: Host header manipulation

**Tests:**
```bash
curl -H "Host: evil.com" http://localhost:8080/
curl -H "Host: 192.168.1.1" http://localhost:8080/
curl -H "Host: [::1]:8080" http://localhost:8080/
```

**Result**: ✅ All properly blocked

#### Test 3.2: TLS/SSL Configuration
**Method**: Configuration review

**Findings:**
- Self-signed cert option available
- REQUIRE_TLS option available
- Missing HSTS header

**Result**: ⚠️ Good with recommendations

#### Test 3.3: CORS Policy
**Method**: Configuration analysis

**Result**: ✅ Restrictive policy

### Phase 4: Code Review

#### Files Reviewed:
1. `backend/src/main.rs` - Main application logic
2. `backend/src/auth.rs` - Authentication
3. `backend/src/crypto.rs` - Cryptography (CRITICAL FINDING)
4. `backend/src/tls.rs` - TLS configuration
5. `backend/src/twofa.rs` - 2FA implementation
6. `backend/static/app.js` - Frontend logic
7. `backend/static/crypto.js` - Client-side crypto
8. `database/init.sql` - Database schema

#### Analysis Focus:
- Encryption implementation
- Key management
- Input validation
- SQL query construction
- Session management
- Authentication logic
- 2FA implementation

#### Critical Finding:
**Deterministic TOTP Salt** in `crypto.rs:51`

### Phase 5: 2FA Security Assessment

#### Tests Performed:
1. TOTP implementation review
2. Secret storage analysis
3. Brute-force protection testing
4. Clock skew handling
5. Backup code availability

#### Findings:
- TOTP correctly implemented
- Brute-force protection present
- **Critical**: Deterministic salt weakness
- Missing backup codes

### Phase 6: Cryptographic Analysis

#### Client-Side Encryption:
- **Algorithm**: AES-256-GCM ✅
- **Key Derivation**: PBKDF2-SHA256 ✅
- **Iterations**: 100,000 ✅
- **Salt**: 16 bytes random ✅
- **IV**: 12 bytes random ✅

#### Server-Side Hashing:
- **Algorithm**: Bcrypt ✅
- **Cost Factor**: 12 ✅
- **Salt**: Per-password ✅

#### Findings:
- Strong cryptographic primitives
- Proper implementation
- Key never leaves client

## Data Extraction Results

### Accessible Data (With Full Admin Access):
| Data Type | Status | Notes |
|-----------|--------|-------|
| Event titles | ❌ Encrypted | AES-256-GCM |
| Event descriptions | ❌ Encrypted | AES-256-GCM |
| Notes content | ❌ Encrypted | AES-256-GCM |
| User passwords | ❌ Hashed | Bcrypt (infeasible to crack) |
| Settings | ❌ Encrypted | AES-256-GCM |
| Display names | ❌ Encrypted | AES-256-GCM |
| Profile pictures | ❌ Encrypted | AES-256-GCM |
| TOTP secrets | ❌ Encrypted | But with weak salt |
| Event timestamps | ✅ Plaintext | Metadata leakage |
| Usernames | ✅ Plaintext | Expected |
| User IDs | ✅ Plaintext | Expected |
| Account creation dates | ✅ Plaintext | Metadata |

## Tools and Techniques Used

### Testing Tools:
- `curl` - API testing
- `psql` - Database queries
- `grep` - Code analysis
- Browser DevTools - Frontend analysis
- Chromium - UI testing

### Techniques:
- Black box testing
- White box testing
- Code review
- Database analysis
- Cryptographic analysis
- Threat modeling

## Vulnerabilities Discovered

### Critical (1):
1. Deterministic TOTP salt

### High (2):
2. Plaintext timestamps
3. Missing HSTS header

### Medium (3):
4. Password in memory during 2FA
5. Self-signed certificate warnings
6. XSS risk in onclick attributes

### Low Priority:
- Missing Secure flag on cookies
- No session rotation
- No 2FA backup codes

## Verification Methods

### Zero-Knowledge Claims:
1. ✅ Direct database access test
2. ✅ Admin API access test
3. ✅ Encrypted data examination
4. ✅ Password recovery attempt
5. ✅ Key derivation analysis

### Security Claims:
1. ✅ SQL injection testing
2. ✅ XSS testing
3. ✅ Input validation testing
4. ✅ Session security testing
5. ✅ Rate limiting verification

## Conclusion

The security testing was comprehensive and covered:
- ✅ Zero-knowledge encryption verification
- ✅ Web application security
- ✅ Infrastructure security
- ✅ Code review
- ✅ Cryptographic analysis
- ✅ 2FA assessment
- ✅ Data extraction attempts

**Overall Assessment**: Application successfully implements zero-knowledge encryption with one critical vulnerability that must be fixed before production deployment.

## Recommendations Implemented

All findings documented in:
- `SECURITY_AUDIT_REPORT.md` - Detailed analysis
- `SECURITY_SUMMARY.md` - Quick reference

Both reports provide actionable recommendations for fixing identified issues.
