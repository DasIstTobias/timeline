# Timeline

A personal timeline application built with Rust backend, PostgreSQL database, and vanilla HTML/CSS/JS frontend. All containerised with Docker for easy deployment.

## Setup

```bash
git clone [repository url]
cd timeline
sudo docker compose up -d
```

After startup, admin credentials will be available in `admin_credentials.txt`.

## Features

- **Zero-knowledge encryption** - All user data is encrypted on the client-side
- **Admin dashboard** - User management and administration
- **Timeline interface** - Vertical timeline with events, tags, and live timers
- **Settings** - Theme, time format, date format, display name, password changes
- **Backup/Restore** - Export/import timeline data as JSON
- **Search & filtering** - Search events and filter by tags
- **Responsive design** - Works on all device sizes

## Required Icons

| Icon Description | File Path |
|------------------|-----------|
| Burger menu (three horizontal lines) | `/backend/static/icons/burger-menu.png` |
| Close/X button | `/backend/static/icons/close.png` |
| Search icon | `/backend/static/icons/search.png` |
| Add/Plus icon | `/backend/static/icons/add.png` |
| Delete/Trash icon | `/backend/static/icons/delete.png` |
| Settings/Gear icon | `/backend/static/icons/settings.png` |
| Backup/Download icon | `/backend/static/icons/backup.png` |
| Import/Upload icon | `/backend/static/icons/import.png` |
| Tag/Label icon | `/backend/static/icons/tag.png` |

## Technology Stack

- **Backend**: Rust with Axum web framework
- **Database**: PostgreSQL 13
- **Frontend**: Vanilla HTML/CSS/JavaScript
- **Encryption**: AES-GCM with PBKDF2 key derivation
- **Authentication**: HTTP cookies with server-side session management
- **Containerisation**: Docker and Docker Compose

## Security Features

- Password hashing with bcrypt
- Zero-knowledge client-side encryption using Web Crypto API
- Session-based authentication with in-memory session storage
- CSRF protection through cookie-based authentication
- All user data encrypted before storage