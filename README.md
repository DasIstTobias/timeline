# <img src="backend/static/favicon.ico" alt="Timeline Logo" width="32" height="32" style="vertical-align: middle;"> Timeline

This is a secure personal timeline application for documenting and managing life events with client-side zero-knowledge encryption.

## Features

### Security
- **SRP-6a Authentication**: Zero-knowledge password authentication - server never sees passwords
- Client-side zero-knowledge encryption with AES-GCM-256
- All data encrypted in the browser before transmission
- Session-based authentication with secure session management
- Optional two-factor authentication (2FA) with TOTP
- Cryptographically secure random number generation
- Protection against timing attacks and offline brute-force
- TLS/HTTPS support with automatic certificate generation

### Event Management
- Create events with title, description, and timestamp
- Live timers show how much time passed since each event
- Custom or current timestamps for events
- USe labels for organisation and filtering

### Timeline Interface
- Chronological vertical timeline display
- Real-time search across event content
- Time separators (daily, weekly, monthly, yearly)
- Responsive design for all devices

### Personalisation
- Display custom name and profile picture
- Set a display-name which is zero-knowledge encrypted next to your login-name
- Theme selection (light, dark, system preference)
- Customisable accent colour
- Time format (12-hour or 24-hour)
- Date format preferences

### Data Management
- Export timeline data as JSON
- Export filtered events as PDF
- Import events from JSON files

### Notes
- Personal notes feature with autosave
- Write down stuff that does not fit in a timeline
- All notes are zero-knowledge encrypted

### Administration
- Admin dashboard for user management
- Create user accounts with secure password generation
- Easy to use

## Getting Started

### Requirements
- Docker and Docker Compose
- Git

### Installation

1. Clone the repository:
```bash
git clone https://github.com/DasIstTobias/timeline.git
cd timeline
```

2. Use the settings (DOMAIN, REQUIRE_TLS, USE_SELF_SIGNED_SSL) in the "docker-compose.yml" to configure the application.

3. Start the application:
```bash
docker compose up --build -d
```

4. Retrieve admin credentials:
```bash
cat admin_credentials.txt
```

5. Access the application at `http://localhost:8080` or `https://localhost:8443` and login with username "admin" and the password from step 4.

### Initial Configuration

1. Log in with the admin credentials
2. Create user accounts through the admin dashboard
3. Users should change their password after first login
4. Configure personal settings (theme, formats, display name)

### Administrative Tasks

Administrators can:
- Create new user accounts (passwords auto-generated)
- Delete user accounts (requires confirmation)
- Change their own password
- View existing users

Note: Administrators cannot access user data due to zero-knowledge encryption.

## Technical Information

### Stack
- Backend: Rust (Axum framework)
- Database: PostgreSQL
- Frontend: HTML, CSS, JavaScript
- Deployment: Docker

### Architecture
Timeline uses a zero-knowledge architecture with SRP-6a authentication where:
- **Authentication**: Server never sees passwords (SRP-6a protocol with zero-knowledge proof)
- **Data Encryption**: All user data is encrypted in the browser before transmission (AES-GCM-256)
- **Key Derivation**: Encryption keys are derived from user passwords using PBKDF2
- **2FA Protection**: TOTP secrets are encrypted with password-derived keys
- **Privacy**: User data remains private and inaccessible to server administrators

### Migration from Older Versions

If upgrading from a version using bcrypt authentication, see **MIGRATION_GUIDE.md** for detailed instructions.

**Quick Migration Steps:**
1. Backup your database: `docker-compose exec database pg_dump -U timeline_user timeline > backup.sql`
2. Pull latest code: `git pull`
3. Start application: `docker-compose up -d` (migration runs automatically)
4. Retrieve new admin password: `cat admin_credentials.txt`

⚠️ **Note**: All user passwords will be reset during migration. See MIGRATION_GUIDE.md for details.

### Ports
- HTTP: 8080
- HTTPS: 8443 (when configured)

## Licence

This software is licensed under the GNU General Public Licence Version 3.
Refer to the LICENCE file for more information.
