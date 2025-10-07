# <img src="backend/static/favicon.ico" alt="Timeline Logo" width="32" height="32" style="vertical-align: middle;"> Timeline

Timeline is a secure personal timeline application for documenting and managing life events with client-side encryption.

## Features

### Security
- Client-side zero-knowledge encryption
- All data encrypted in the browser before transmission
- Passwords hashed with bcrypt
- Session-based authentication
- Optional two-factor authentication (2FA)

### Event Management
- Create events with title, description, and timestamp
- Live timers showing elapsed time since each event
- Custom or current timestamps for events
- Delete individual events
- Colour-coded tags for organisation and filtering

### Timeline Interface
- Chronological vertical timeline display
- Real-time search across event content
- Filter events by tags
- Time separators (daily, weekly, monthly, yearly)
- Responsive design for all devices

### Personalisation
- Display name and profile picture
- Theme selection (light, dark, system preference)
- Customisable accent colour
- Time format (12-hour or 24-hour)
- Date format preferences

### Data Management
- Export timeline data as JSON
- Import events from JSON files
- Export filtered events as PDF
- Personal notes feature with autosave

### Administration
- Admin dashboard for user management
- Create user accounts with secure password generation
- Multi-step user deletion process
- Admin password management

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

2. Start the application:
```bash
docker compose up -d
```

3. Retrieve admin credentials:
```bash
cat admin_credentials.txt
```

4. Access the application at `http://localhost:8080`

### Initial Configuration

1. Log in with the admin credentials
2. Create user accounts through the admin dashboard
3. Users should change their password after first login
4. Configure personal settings (theme, formats, display name)

## Usage

### Creating Events

1. Click the "Add Event" button
2. Enter event details:
   - Title and description
   - Choose current time or specify custom date/time
   - Add optional tags for categorisation
3. Save the event

### Managing Your Timeline

- Use the search bar to find specific events
- Click tag filters to view events by category
- Export your data regularly as backup
- Access settings to customise your experience

### Administrative Tasks

Administrators can:
- Create new user accounts (passwords auto-generated)
- Delete user accounts (requires confirmation)
- Change their own password
- View existing users

Note: Administrators cannot access user data due to client-side encryption.

## Technical Information

### Stack
- Backend: Rust (Axum framework)
- Database: PostgreSQL
- Frontend: HTML, CSS, JavaScript
- Deployment: Docker

### Architecture
Timeline uses a zero-knowledge architecture where all user data is encrypted in the browser before being sent to the server. Encryption keys are derived from user passwords and never leave the client. This ensures that user data remains private and inaccessible to server administrators.

### Ports
- HTTP: 8080
- HTTPS: 8443 (when configured)

## Licence

Refer to the LICENCE file for terms and conditions.
