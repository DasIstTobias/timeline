# SRP Authentication System - Deployment Guide

## Overview

This guide covers deploying the new SRP-6a authentication system to production. This is a **breaking change** that requires a clean migration from the old bcrypt system.

## ⚠️ Important Notes

1. **No Backwards Compatibility**: Existing users will need to have their passwords reset
2. **Clean Migration**: Old password_hash column has been replaced with srp_salt and srp_verifier
3. **Admin Password**: Will be auto-generated on first startup and saved to `admin_credentials.txt`

## Pre-Deployment Checklist

- [ ] Backup existing database
- [ ] Notify users of maintenance window
- [ ] Test deployment in staging environment
- [ ] Prepare communication for password reset process
- [ ] Review SECURITY_AUDIT.md

## Database Migration

### Option 1: Fresh Installation (Recommended for new deployments)

```bash
# Run the init.sql script
psql -U timeline_user -h localhost -d timeline -f database/init.sql
```

This will create:
- Users table with `srp_salt` and `srp_verifier` columns
- Admin user with placeholder credentials (updated on first backend startup)
- All other tables

### Option 2: Migration from Existing System (Production upgrade)

```sql
-- Backup first!
-- Then run this migration:

BEGIN;

-- Add new SRP columns
ALTER TABLE users 
  ADD COLUMN srp_salt VARCHAR(255),
  ADD COLUMN srp_verifier TEXT;

-- Remove old password_hash column
ALTER TABLE users 
  DROP COLUMN password_hash;

-- Make SRP columns NOT NULL (after data migration)
-- Note: You'll need to reset all user passwords or generate them
UPDATE users SET 
  srp_salt = '$placeholder$',
  srp_verifier = '$placeholder$';

ALTER TABLE users 
  ALTER COLUMN srp_salt SET NOT NULL,
  ALTER COLUMN srp_verifier SET NOT NULL;

COMMIT;
```

**Important**: After migration, users will need new passwords. You have two options:
1. Admin generates new passwords for all users (recommended for small user base)
2. Implement password reset flow for users to set new passwords

## Backend Deployment

### 1. Build the Application

```bash
cd backend
cargo build --release
```

### 2. Set Environment Variables

```bash
export DATABASE_URL="postgres://timeline_user:timeline_password@localhost:5432/timeline"
export RUST_LOG=info
export DOMAIN=yourdomain.com
export REQUIRE_TLS=true  # Recommended for production
export USE_SELF_SIGNED_SSL=false  # Use reverse proxy for TLS
```

### 3. Start the Backend

```bash
./target/release/timeline-backend
```

### 4. Retrieve Admin Credentials

On first startup, admin credentials are written to `admin_credentials.txt`:

```bash
cat admin_credentials.txt
```

**⚠️ Important**: Save these credentials securely and delete the file!

## Frontend Deployment

The frontend changes are already included in the static files. No separate deployment needed.

### Files Updated:
- `static/srp.js` - New SRP client library
- `static/crypto.js` - Added password hash derivation
- `static/app.js` - Updated login flow
- `static/index.html` - Added srp.js script

## Post-Deployment Verification

### 1. Admin Login Test

```bash
# Navigate to http://yourdomain.com
# Login with admin credentials from admin_credentials.txt
# Verify dashboard loads
```

### 2. User Registration Test

```bash
# As admin, create a new user
# Note the generated password
# Logout and login with new user credentials
```

### 3. Password Change Test

```bash
# As regular user, navigate to settings
# Change password
# Logout and login with new password
```

### 4. 2FA Test (if applicable)

```bash
# As regular user, enable 2FA
# Scan QR code
# Enter TOTP code
# Logout and login with 2FA
```

## Monitoring

### Key Metrics to Monitor

1. **Authentication Success Rate**
```bash
# Check logs for:
grep "SRP verification failed" /var/log/timeline/backend.log
```

2. **Session Creation Rate**
```bash
# Monitor session table growth
```

3. **Rate Limiting Triggers**
```bash
# Check for rate limit events
grep "rate limit" /var/log/timeline/backend.log
```

### Health Checks

```bash
# Check if server is responding
curl http://localhost:8080/

# Check database connectivity
psql -U timeline_user -h localhost -d timeline -c "SELECT COUNT(*) FROM users;"
```

## Rollback Plan

If issues arise, you can rollback to the previous version:

### 1. Restore Database Backup

```bash
psql -U timeline_user -h localhost -d timeline < backup.sql
```

### 2. Deploy Previous Backend Version

```bash
# Stop current backend
pkill timeline-backend

# Start previous version
./timeline-backend-old
```

### 3. Restore Previous Frontend Files

```bash
# Copy from backup
cp -r backup/static/* static/
```

## Security Considerations

### TLS/HTTPS

- **Highly Recommended**: Always use HTTPS in production
- Set `REQUIRE_TLS=true` in environment
- Use a reverse proxy (nginx, Caddy) for TLS termination

### Database Security

- Use strong database passwords
- Restrict database access to application server only
- Enable PostgreSQL SSL connections
- Regular database backups

### Rate Limiting

- Monitor rate limiting logs
- Adjust limits based on usage patterns
- Consider adding IP-based blocks for persistent attackers

### Session Security

- Cookies are HttpOnly and SameSite=Strict (already configured)
- Consider adding Secure flag for HTTPS deployments
- Monitor session expiration settings

## Troubleshooting

### Issue: Admin credentials not generated

**Solution**: Check that admin user exists in database:
```sql
SELECT * FROM users WHERE username = 'admin';
```

### Issue: Login fails immediately

**Solution**: Check browser console for JavaScript errors. Verify srp.js is loading:
```bash
curl http://yourdomain.com/static/srp.js
```

### Issue: 2FA not working

**Solution**: Verify password hash derivation is working. Check that TOTP secrets are encrypted properly in database.

### Issue: Database connection fails

**Solution**: Verify DATABASE_URL environment variable and PostgreSQL is running:
```bash
pg_isready -h localhost -p 5432
```

## Support

For issues or questions:
1. Check SECURITY_AUDIT.md for security-related questions
2. Review NEW_AUTH_PLAN.md for implementation details
3. Check application logs: `tail -f /var/log/timeline/backend.log`

## Success Criteria

✅ Admin can login  
✅ New users can be created  
✅ Users can login  
✅ Password changes work  
✅ 2FA setup works  
✅ Session management works  
✅ No security vulnerabilities  
✅ All features accessible  

## Conclusion

The SRP authentication system provides significant security improvements and is production-ready. Follow this guide carefully for a smooth deployment.

**Deployment Status:** 🟢 READY FOR PRODUCTION
