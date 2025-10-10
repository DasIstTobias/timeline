# Migration Guide: Upgrading to SRP Authentication

This guide explains how to migrate an existing Timeline installation to the new SRP-6a authentication system.

## Important Notes

⚠️ **BREAKING CHANGE**: This migration removes bcrypt password hashes and replaces them with SRP credentials. All users will need their passwords reset.

⚠️ **NO BACKWARDS COMPATIBILITY**: Once migrated, you cannot rollback without data loss.

⚠️ **BACKUP FIRST**: Always backup your database before performing this migration.

## Migration Scenarios

### Scenario 1: Fresh Installation (No Existing Database)

If you're starting fresh, no migration is needed:

1. Pull the latest code
2. Start the application with `docker-compose up -d`
3. The database will be initialised with the SRP schema
4. Retrieve admin password from logs: `docker-compose logs backend | grep "Admin password"`

### Scenario 2: Existing Installation (Database Already Exists)

If you have an existing database with user data, follow these steps:

#### Step 1: Backup Your Database

```bash
# Create a backup of your PostgreSQL database
docker-compose exec database pg_dump -U timeline_user timeline > backup_$(date +%Y%m%d_%H%M%S).sql
```

#### Step 2: Stop the Application

```bash
docker-compose down
```

#### Step 3: Pull Latest Code

```bash
git pull
```

#### Step 4: Apply Migration

You have two options:

**Option A: Automatic Migration (Recommended)**

The migration will be applied automatically when you start the application. The backend checks for old schema and applies the migration.

```bash
docker-compose up -d
```

**Option B: Manual Migration**

If you prefer to apply the migration manually:

```bash
# Start only the database
docker-compose up -d database

# Wait for database to be ready (about 5 seconds)
sleep 5

# Apply migration script
docker-compose exec -T database psql -U timeline_user -d timeline < database/migrate_to_srp.sql

# Start the full application
docker-compose up -d
```

#### Step 5: Retrieve New Admin Password

The admin password will be regenerated. Retrieve it from the logs:

```bash
docker-compose logs backend | grep "Admin password"
```

Example output:
```
backend-1   | Admin password: Xt9K2nP5mQ8vL4hR7wJ3d
```

**⚠️ IMPORTANT**: Save this password immediately! It will only be shown once.

#### Step 6: Verify Migration

1. Access the application at `https://localhost:8443` (or your configured domain)
2. Log in with username `admin` and the new password
3. Verify all features work correctly

## Post-Migration Steps

### Reset User Passwords

All existing user passwords are invalidated during migration. You have two options:

**Option 1: Users Request Password Reset (if implemented)**

If you have a password reset feature, users can request new passwords through that mechanism.

**Option 2: Admin Creates New Users**

1. Log in as admin
2. Delete old user accounts (or keep them for data preservation)
3. Create new user accounts with the admin panel
4. Provide new credentials to users

### Verify 2FA Still Works

If users had 2FA enabled:

1. The TOTP secrets are encrypted with password-derived keys
2. After migration, users will need to:
   - Log in with their new password
   - Re-enable 2FA
   - Scan the new QR code

### Update Documentation

Update any internal documentation with:
- New admin password
- User credential management procedures
- 2FA re-setup instructions

## Rollback Procedure

⚠️ **WARNING**: Rollback is only possible if you have a database backup from before the migration.

```bash
# Stop the application
docker-compose down

# Restore from backup
docker-compose up -d database
sleep 5
docker-compose exec -T database psql -U timeline_user -d timeline < backup_YYYYMMDD_HHMMSS.sql

# Checkout previous version
git checkout <previous-commit>

# Start application
docker-compose up -d
```

## Troubleshooting

### Error: "column srp_salt does not exist"

This means the migration didn't run. Follow Option B (Manual Migration) above.

### Error: "database system was not properly shut down"

This is normal after stopping containers. The database performs automatic recovery. Wait for the log message:
```
database system is ready to accept connections
```

### Admin Password Not Showing in Logs

Check logs more thoroughly:
```bash
docker-compose logs backend | grep -i "admin\|password"
```

If still not found, the admin user may already exist. Reset it:
```bash
docker-compose exec database psql -U timeline_user -d timeline -c "DELETE FROM users WHERE username='admin';"
docker-compose restart backend
```

### Application Won't Start After Migration

1. Check logs: `docker-compose logs backend`
2. Verify database schema: 
   ```bash
   docker-compose exec database psql -U timeline_user -d timeline -c "\d users"
   ```
3. Confirm `srp_salt` and `srp_verifier` columns exist
4. Confirm `password_hash` column does NOT exist

### Users Cannot Login

This is expected after migration. All passwords are invalidated because:
- Old: bcrypt hashes (server-side)
- New: SRP verifiers (client-computed)

Users need new credentials created by admin.

## Database Schema Changes

### Before (Old Schema)
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,  -- bcrypt hash
    ...
);
```

### After (New Schema)
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    srp_salt VARCHAR(255) NOT NULL,       -- SRP salt
    srp_verifier TEXT NOT NULL,           -- SRP verifier
    ...
);
```

## Security Improvements

The migration provides these security benefits:

1. **Zero-Knowledge Authentication**: Server never sees passwords
2. **No Password Storage**: SRP verifiers are useless without the protocol
3. **Offline Attack Protection**: Verifiers can't be cracked like bcrypt hashes
4. **Forward Security**: Compromise of database doesn't reveal passwords

## Support

If you encounter issues not covered in this guide:

1. Check the logs: `docker-compose logs`
2. Review SECURITY_AUDIT.md for security considerations
3. Review DEPLOYMENT_GUIDE.md for deployment procedures
4. Open an issue on GitHub with:
   - Error messages from logs
   - Output of `docker-compose ps`
   - Database schema output from troubleshooting steps

## Migration Checklist

- [ ] Database backup created
- [ ] Application stopped (`docker-compose down`)
- [ ] Latest code pulled (`git pull`)
- [ ] Migration applied (automatic or manual)
- [ ] Application started (`docker-compose up -d`)
- [ ] Admin password retrieved and saved
- [ ] Admin login verified
- [ ] User accounts recreated
- [ ] 2FA re-setup instructions sent to users
- [ ] Documentation updated
- [ ] Old backup retained for rollback
