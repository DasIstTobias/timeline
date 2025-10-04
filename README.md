# Timeline

A secure personal timeline application for documenting and managing life events. Built with Rust backend, PostgreSQL database, and vanilla HTML/CSS/JavaScript frontend, all containerised with Docker for streamlined deployment.

## Overview

Timeline enables users to create, manage, and visualise personal events in a chronological format. The application prioritises security through zero-knowledge encryption, ensuring all user data remains private and accessible only to the account holder.

## Key Features

### Security and Privacy
- **Zero-knowledge encryption**: All user data is encrypted client-side before transmission
- **Secure authentication**: Session-based authentication with server-side validation
- **Password protection**: All passwords are hashed using bcrypt
- **Client-side data processing**: Decryption and encryption occur exclusively in the browser
- **No persistent sessions**: Session data is stored in memory and cleared on server restart

### User Experience
- **Timeline visualisation**: Vertical timeline interface with chronological event display
- **Live timers**: Real-time countdown showing elapsed time since each event
- **Event management**: Create, view, and delete events with title, description, timestamp, and tags
- **Search and filtering**: Search events by content and filter by tags
- **Customisable settings**: Personalise display name, theme, time format, and date format
- **Data portability**: Export and import timeline data as JSON files
- **Time separators**: Configurable visual separators (daily, weekly, monthly, yearly) between timeline periods

### Administrative Features
- **User management**: Admin dashboard for creating and removing user accounts
- **Secure user creation**: Automatic password generation with one-time display
- **Account security**: Multi-step confirmation process for user deletion

### Technical Capabilities
- **Responsive design**: Optimised for all device sizes and screen orientations
- **Theme support**: Light, dark, and system preference themes
- **Flexible formatting**: Multiple time and date format options
- **Tag system**: Colour-coded tags for event categorisation and filtering
- **Containerised deployment**: Complete Docker-based setup for easy installation

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Git
- sudo privileges (for Docker commands)

### Installation

1. Clone the repository:
```bash
git clone [repository url]
cd timeline
```

2. Start the application:
```bash
sudo docker compose up -d
```

3. Access admin credentials:
```bash
cat admin_credentials.txt
```

The application will be available at `http://localhost:8080`

### Initial Setup

1. Access the application using the admin credentials from `admin_credentials.txt`
2. Create user accounts through the admin dashboard
3. Users should change their passwords after first login
4. Configure user settings including display name, theme, and date/time preferences

## Usage Guide

### For Users

#### Creating Events
1. Click "Add Event" in the bottom toolbar
2. Enter event title and description (required fields)
3. Set timestamp using "Now" or "Custom" time selection
4. Add optional tags for categorisation
5. Click "Create" to add the event to your timeline

#### Managing Events
- **View**: Events appear chronologically on the timeline with live timers
- **Search**: Use the search bar to find events by title or description
- **Filter**: Use tag filters to display specific event categories
- **Delete**: Click the delete button on any event (requires confirmation)

#### Personalisation
- **Display name**: Set a custom display name separate from username
- **Theme**: Choose between light, dark, or system preference themes
- **Time format**: Select 24-hour or 12-hour (AM/PM) display
- **Date format**: Choose from multiple date representation formats
- **Time separators**: Configure visual separators between timeline periods

#### Data Management
- **Export**: Download all timeline data as unencrypted JSON
- **Import**: Upload JSON files to add events to existing timeline
- **Backup**: Regular exports recommended for data preservation

### For Administrators

#### User Management
- **Create users**: Generate accounts with automatic password creation
- **Delete users**: Multi-step verification process for account removal
- **Monitor accounts**: View user creation dates and account status

#### Security Management
- **Password changes**: Administrative password updates
- **Session management**: User sessions automatically expire on server restart
- **Data oversight**: All user data remains encrypted and inaccessible to administrators

## Architecture

### Technology Stack
- **Backend**: Rust with Axum web framework
- **Database**: PostgreSQL 17
- **Frontend**: Vanilla HTML5, CSS3, and JavaScript (ES6+)
- **Encryption**: AES-GCM with PBKDF2 key derivation using Web Crypto API
- **Containerisation**: Docker and Docker Compose
- **Authentication**: HTTP cookies with server-side session storage

### Security Implementation
- **Client-side encryption**: All sensitive data encrypted before leaving the browser
- **Zero-knowledge architecture**: Server cannot access user data in plain text
- **Secure key derivation**: User passwords derive encryption keys via PBKDF2
- **Session isolation**: Each user session is independent and secure
- **CSRF protection**: Cookie-based authentication prevents cross-site attacks

### Database Design
- **User management**: Secure storage of user credentials and metadata
- **Encrypted storage**: All user data stored in encrypted format
- **Tag management**: Automatic tag lifecycle management
- **Event storage**: Chronological event data with associated metadata

## Configuration

### Environment Variables
- `DATABASE_URL`: PostgreSQL connection string
- `RUST_LOG`: Logging level configuration
- `DOMAIN`: Comma-separated list of allowed domains with strict enforcement (see Domain Configuration below)
- `REQUIRE_TLS`: Set to `true` to enforce HTTPS
- `USE_SELF_SIGNED_SSL`: Set to `true` to use self-signed SSL certificates (default: `true`)

### Domain Configuration

The `DOMAIN` environment variable enforces strict domain access control. Only requests from specified domains will be accepted.

**Important:** This replaces the previous `CORS_DOMAIN` variable and provides stricter security by rejecting requests from unauthorised domains at the application level, not just via browser CORS policies.

Accepted formats:
- `localhost` (default): Allows localhost and 127.0.0.1 on any port
- Single domain/IP: `example.com` or `192.168.1.100`
- Multiple comma-separated domains: `example.com,192.168.1.100,timeline.local`

When a bare hostname is provided (without port), the application automatically allows both port 8080 and 8443.

Examples:
```bash
# Allow localhost only (default - for development)
DOMAIN=localhost

# Allow a specific domain
DOMAIN=timeline.example.com

# Allow local network access from specific IP
DOMAIN=192.168.178.172

# Allow multiple domains
DOMAIN=timeline.example.com,192.168.1.100,timeline.local
```

**Security Note:** Unlike browser-only CORS restrictions, `DOMAIN` enforcement blocks unauthorised requests at the server level, preventing access from any domain not explicitly listed.

### SSL/TLS Configuration

Timeline includes built-in support for HTTPS using self-signed SSL certificates, enabled by default.

#### Self-Signed SSL (Default)

By default, Timeline generates self-signed SSL certificates automatically:
- **HTTPS server**: Runs on port 8443
- **HTTP server**: Runs on port 8080 (redirects to HTTPS when `REQUIRE_TLS=true`)
- **Configuration**: `USE_SELF_SIGNED_SSL=true` (default)

To access the application:
```
https://localhost:8443
https://your-ip:8443
```

**TLS Enforcement Behaviour:**
- When `REQUIRE_TLS=true` (default): HTTP requests are redirected to HTTPS
- When `REQUIRE_TLS=false`: Both HTTP and HTTPS work independently (for development/testing)

**Note**: Browsers will show a security warning for self-signed certificates. This is expected. Click "Advanced" and "Proceed" to continue.

#### Using External Reverse Proxy

If you prefer to use an external reverse proxy (nginx, Caddy, Traefik) with valid SSL certificates:

1. Set `USE_SELF_SIGNED_SSL=false` in `docker-compose.yml`
2. Configure your reverse proxy to forward to port 8080
3. Set `REQUIRE_TLS=true` to enforce HTTPS
4. Ensure reverse proxy sets `X-Forwarded-Proto: https` header

Example docker-compose.yml configuration:
```yaml
environment:
  REQUIRE_TLS: "true"
  USE_SELF_SIGNED_SSL: "false"
  DOMAIN: your-domain.com
```

#### HTTP Warning Banner

When accessing the application over HTTP (insecure connection), a red warning banner will appear:

⚠️ **WARNING: Unencrypted HTTP Connection** ⚠️
*This connection is not secure. Please use HTTPS for encrypted communication.*

This ensures users are aware they are using an insecure connection.

### Container Configuration
- Database: PostgreSQL 17 with persistent volume storage
- Backend: Rust application with automated dependency management
- Network: Isolated Docker network for service communication

## Development

### Building from Source
```bash
cd backend
cargo build --release
```

### Database Migrations
Database schema is automatically initialised on first startup via Docker entrypoint scripts.

### Logs and Debugging
```bash
sudo docker compose logs -f backend
sudo docker compose logs -f database
```

## Security Considerations

### Data Protection
- All user data undergoes client-side encryption before transmission
- Encryption keys are derived from user passwords and never transmitted
- Server-side data storage maintains no access to plain text user information
- Session management prevents unauthorised access to user accounts

### Best Practices
- Regular password updates recommended
- Secure storage of admin credentials
- Regular data exports for backup purposes
- Monitor application logs for security events

## Support and Maintenance

### Backup Procedures
1. Export user data regularly through the application interface
2. Database backups can be performed via Docker volume management
3. Container persistence ensures data survival across restarts

### Updates and Maintenance
- Application updates require container rebuild
- Database migrations are handled automatically
- User sessions reset on application restart for security

### Troubleshooting
- Check container logs for error messages
- Verify Docker network connectivity
- Ensure proper file permissions for admin credentials
- Confirm database connectivity and schema initialisation

## Licence

This project is licensed under the terms specified in the LICENCE file.

## Technical Requirements

### Minimum System Requirements
- 1GB RAM
- 2GB available disk space
- Docker 20.10 or later
- Docker Compose 2.0 or later

### Supported Browsers
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

### Network Requirements
- Port 8080 available for application access
- Outbound internet access for Docker image downloads (initial setup only)