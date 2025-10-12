# Security Fix: 2FA Password Verification

## Issue Description

**CVE/Issue**: 2FA can be enabled without the correct password

**Severity**: High - Could lead to account lockout and security bypass

**Original Problem**: 
Users could enable 2FA with any password, not just their actual password. This happened because the password verification mechanism was fundamentally flawed:

1. Client would derive a hash from ANY password entered
2. Client would encrypt a verification string using that hash
3. Client would send both the hash and encrypted string to server
4. Server would decrypt using the SAME client-provided hash
5. Decryption always succeeded regardless of password correctness

This created two serious issues:
- **Accidental lockout**: Users could enable 2FA with the wrong password, then be unable to login because the correct password couldn't decrypt the 2FA secret
- **Security bypass**: An attacker with a stolen session cookie could enable 2FA without knowing the password, locking out the legitimate user

## The Fix

The fix replaces the flawed password verification with proper SRP (Secure Remote Password) authentication, the same cryptographic protocol used for login.

### How It Works Now

1. **Password Verification via SRP**:
   - User enters password in step 1 of 2FA setup
   - Client initiates SRP authentication: `POST /api/2fa/verify-password/init`
   - Server returns salt and ephemeral public value from user's actual credentials
   - Client computes SRP proof using entered password
   - Client sends proof to: `POST /api/2fa/verify-password/verify`
   - Server verifies proof against stored verifier (derived from actual password)
   - **Only if password is correct** does verification succeed

2. **2FA Secret Generation**:
   - After successful password verification, server sets `password_verified = true` flag
   - Client can then call `POST /api/2fa/setup` to generate QR code
   - Server checks `password_verified` flag before generating secret
   - If flag is not set, request is rejected

3. **Time Limits**:
   - Password verification state expires after 10 minutes
   - SRP verification sessions expire after 5 minutes
   - User must complete entire 2FA setup within time window

### Security Properties

✅ **Password Required**: User must know actual password to enable 2FA
✅ **No Lockout**: Wrong password is detected immediately, before 2FA is enabled
✅ **Session Security**: Stolen session cookie alone cannot enable 2FA
✅ **Zero-Knowledge**: Password never sent to server (SRP property)
✅ **Proven Crypto**: Uses same SRP-6a protocol as login, RFC 5054 compliant
✅ **Time-Bounded**: Verification state expires automatically

## Technical Changes

### Backend (Rust) - `backend/src/main.rs`

1. **Added New Data Structures**:
   ```rust
   struct PendingSecret {
       secret: String,
       created_at: SystemTime,
       password_verified: bool,  // NEW FIELD
   }
   
   // NEW: Track SRP sessions for 2FA password verification
   pending_2fa_password_verify: Arc<RwLock<HashMap<String, PendingSrpAuth>>>
   ```

2. **New API Endpoints**:
   - `POST /api/2fa/verify-password/init` - Starts SRP authentication
   - `POST /api/2fa/verify-password/verify` - Completes SRP verification

3. **Modified Endpoint**:
   - `POST /api/2fa/setup` - Now requires `password_verified = true`
   - Removed `password_hash` and `password_verification` parameters

4. **Added Cleanup Task**:
   - Expires 2FA password verification sessions after 5 minutes
   - Prevents memory leaks from abandoned verification attempts

### Frontend (JavaScript) - `backend/static/app.js`

1. **Modified Function**: `continueEnable2FAStep1()`
   - Now performs full SRP authentication
   - Calls new password verification endpoints
   - Verifies server proof M2
   - Only proceeds to QR code after successful verification

2. **Modified Function**: `setupEnable2FAStep2()`
   - Simplified to just call `/api/2fa/setup`
   - No longer sends password_hash or password_verification
   - Relies on server-side password_verified flag

3. **Removed Code**:
   - Password hash derivation for verification
   - Verification string encryption
   - All flawed circular verification logic

## Testing the Fix

### Manual Test - Correct Password

1. Login to Timeline application
2. Navigate to Settings → Security → Enable 2FA
3. Enter your **correct** password
4. Result: ✅ Should proceed to QR code screen
5. Complete 2FA setup with authenticator app
6. Result: ✅ 2FA should work on next login

### Manual Test - Wrong Password

1. Login to Timeline application
2. Navigate to Settings → Security → Enable 2FA
3. Enter a **wrong** password
4. Result: ✅ Should show "Invalid password" error
5. Should NOT proceed to QR code screen
6. 2FA should NOT be enabled

### Manual Test - Session Without Password

1. Obtain a valid session cookie (e.g., from browser dev tools)
2. Try to call `/api/2fa/setup` directly without password verification
3. Result: ✅ Should return error "Password verification required"
4. 2FA should NOT be enabled

## Backwards Compatibility

⚠️ **Breaking Change**: The `/api/2fa/setup` endpoint no longer accepts `password_hash` and `password_verification` parameters.

**Impact**: 
- Existing clients attempting to enable 2FA will fail
- Users must update to the new frontend code
- Already-enabled 2FA continues to work normally
- No database migration required

**Mitigation**:
- Frontend and backend must be deployed together
- Recommend atomic deployment via Docker Compose
- Already-enabled 2FA is unaffected

## Security Audit Notes

### Attack Scenarios Mitigated

1. ✅ **Wrong Password Attack**: Attacker cannot enable 2FA with wrong password
2. ✅ **Session Hijacking**: Attacker with session cookie cannot enable 2FA without password
3. ✅ **Replay Attack**: SRP ephemeral values are one-time use
4. ✅ **Timing Attack**: SRP implementation uses constant-time comparisons
5. ✅ **MITM Attack**: TLS required (enforced by application config)

### Potential Concerns Addressed

**Q**: What if the cleanup task fails?
**A**: Expired states accumulate but don't affect security. Worst case: memory usage increases until next cleanup succeeds.

**Q**: What if user refreshes page during setup?
**A**: Password verification state persists for 10 minutes. User can re-enter password to continue.

**Q**: Can attacker bypass by calling setup before verification expires?
**A**: No. The `password_verified` flag is checked on every setup request. Attacker would need to complete SRP authentication first.

**Q**: What about existing 2FA users?
**A**: Not affected. This fix only applies to new 2FA enablement. Existing users continue normally.

## References

- SRP Protocol: RFC 5054 - Using the Secure Remote Password (SRP) Protocol for TLS Authentication
- SRP-6a: https://datatracker.ietf.org/doc/html/rfc5054
- Timeline Issue: "2FA can be enabled without password"

## Author

Fix implemented by: GitHub Copilot
Date: 2025-10-12
Reviewed by: [Pending]
