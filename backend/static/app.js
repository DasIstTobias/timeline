// Timeline Application
class TimelineApp {
    constructor() {
        this.currentUser = null;
        this.userPassword = null;
        this.csrfToken = null; // CSRF token for state-changing requests
        this.events = [];
        this.tags = [];
        this.filteredEvents = [];
        this.notes = '';
        this.profilePicture = null; // Decrypted profile picture data URL
        this.settings = {
            theme: 'device',
            timeFormat: '24h',
            dateFormat: 'dd/mm/yyyy',
            displayName: '',
            timeSeparator: 'weekly',
            accentColor: '#710193'
        };
        this.eventTimers = new Map();
        this.notesAutosaveTimer = null;
        this.temp2FASessionId = null; // For 2FA login flow
        this.temp2FASecret = null; // Temporarily store TOTP secret during setup
        this.temp2FAPassword = null; // Temporarily store password during 2FA setup
        
        this.init();
    }

    async init() {
        this.setupEventListeners();
        this.applyTheme();
        this.checkAuthStatus();
        this.checkHttpWarning();
        
        // Update timers every second
        setInterval(() => this.updateEventTimers(), 1000);
    }
    
    checkHttpWarning() {
        // Show warning if using HTTP instead of HTTPS
        const httpWarning = document.getElementById('http-warning');
        if (httpWarning && window.location.protocol === 'http:') {
            httpWarning.style.display = 'block';
        }
    }

    setupEventListeners() {
        // Login form
        document.getElementById('login-form').addEventListener('submit', (e) => this.handleLogin(e));
        
        // Admin functions
        document.getElementById('admin-logout-btn').addEventListener('click', () => this.logout());
        document.getElementById('admin-change-password-btn').addEventListener('click', () => this.showAdminPasswordOverlay());
        document.getElementById('add-user-form').addEventListener('submit', (e) => this.handleAddUser(e));
        
        // User functions
        document.getElementById('user-logout-btn').addEventListener('click', () => this.logout());
        document.getElementById('burger-btn').addEventListener('click', () => this.toggleBurgerMenu());
        document.getElementById('notes-btn').addEventListener('click', () => this.showNotesOverlay());
        document.getElementById('settings-btn').addEventListener('click', () => this.showSettingsOverlay());
        document.getElementById('backup-btn').addEventListener('click', () => this.showBackupOverlay());
        document.getElementById('add-event-btn').addEventListener('click', () => this.showAddEventOverlay());
        document.getElementById('empty-add-events-btn').addEventListener('click', () => this.showAddEventOverlay());
        
        // Search and filter
        document.getElementById('search-btn').addEventListener('click', () => this.performSearch());
        document.getElementById('search-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.performSearch();
        });
        document.getElementById('tag-filter-btn').addEventListener('click', () => this.toggleTagFilter());
        
        // Overlay closers
        document.querySelectorAll('.close-overlay').forEach(btn => {
            btn.addEventListener('click', (e) => this.closeOverlay(e.target.closest('.overlay')));
        });
        
        // Settings tabs
        document.querySelectorAll('.settings-tab').forEach(tab => {
            tab.addEventListener('click', (e) => this.switchSettingsTab(e.target.dataset.tab));
        });
        
        // Settings
        document.getElementById('save-display-name').addEventListener('click', () => this.saveDisplayName());
        document.getElementById('upload-profile-picture-btn').addEventListener('click', () => this.showProfilePictureUploadOverlay());
        document.getElementById('remove-profile-picture-btn').addEventListener('click', () => this.removeProfilePicture());
        document.getElementById('change-password').addEventListener('click', () => this.changePassword());
        document.getElementById('save-theme').addEventListener('click', () => this.saveTheme());
        document.getElementById('save-time-format').addEventListener('click', () => this.saveTimeFormat());
        document.getElementById('save-date-format').addEventListener('click', () => this.saveDateFormat());
        document.getElementById('save-time-separator').addEventListener('click', () => this.saveTimeSeparator());
        document.getElementById('save-accent-color').addEventListener('click', () => this.saveAccentColor());
        
        // Password change overlays
        document.getElementById('confirm-password-change').addEventListener('click', () => this.confirmPasswordChange());
        document.getElementById('cancel-password-change').addEventListener('click', () => this.closeOverlay(document.getElementById('password-confirm-overlay')));
        
        // Admin password change overlays
        document.getElementById('confirm-admin-password-change').addEventListener('click', () => this.confirmAdminPasswordChange());
        document.getElementById('cancel-admin-password-change').addEventListener('click', () => this.closeOverlay(document.getElementById('admin-password-confirm-overlay')));
        
        // Delete confirmation overlay
        document.getElementById('cancel-delete').addEventListener('click', () => this.closeOverlay(document.getElementById('delete-confirmation-overlay')));
        
        // Backup
        document.getElementById('export-btn').addEventListener('click', () => this.exportEvents());
        document.getElementById('import-btn').addEventListener('click', () => this.importEvents());
        document.getElementById('import-file').addEventListener('change', (e) => this.handleImportFile(e));
        
        // PDF Export
        document.getElementById('export-pdf-btn').addEventListener('click', () => this.showPdfExportOverlay());
        document.getElementById('generate-pdf-btn').addEventListener('click', () => this.generatePdf());
        document.getElementById('pdf-error-ok').addEventListener('click', () => this.closeOverlay(document.getElementById('pdf-export-error-overlay')));
        
        // Add event
        document.getElementById('add-event-form').addEventListener('submit', (e) => this.handleAddEvent(e));
        document.getElementById('time-toggle').addEventListener('change', () => this.toggleCustomTime());
        document.getElementById('add-tag-btn').addEventListener('click', () => this.addNewTag());
        
        // Admin password change
        document.getElementById('admin-password-form').addEventListener('submit', (e) => this.handleAdminPasswordChange(e));
        
        // Profile picture upload
        document.getElementById('profile-picture-file-input').addEventListener('change', (e) => this.handleProfilePictureFileSelect(e));
        document.getElementById('cancel-profile-picture-upload').addEventListener('click', () => this.closeProfilePictureUpload());
        document.getElementById('set-profile-picture-btn').addEventListener('click', () => this.setNewProfilePicture());
        
        // 2FA functionality
        document.getElementById('twofa-login-form').addEventListener('submit', (e) => this.handle2FALogin(e));
        document.getElementById('abort-2fa-login').addEventListener('click', () => this.abort2FALogin());
        document.getElementById('enable-2fa-btn').addEventListener('click', () => this.startEnable2FA());
        document.getElementById('disable-2fa-btn').addEventListener('click', () => this.startDisable2FA());
        document.getElementById('enable-2fa-step1-form').addEventListener('submit', (e) => this.continueEnable2FAStep1(e));
        document.getElementById('enable-2fa-step2-form').addEventListener('submit', (e) => this.finishEnable2FA(e));
        document.getElementById('disable-2fa-form').addEventListener('submit', (e) => this.finishDisable2FA(e));
        
        // Click outside to close menus
        document.addEventListener('click', (e) => this.handleOutsideClick(e));
    }

    async checkAuthStatus() {
        // Check if user is already logged in via cookie
        try {
            const response = await fetch('/api/user-info', {
                credentials: 'include'
            });
            
            if (response.ok) {
                const data = await response.json();
                this.currentUser = data;
                
                // Fetch CSRF token for authenticated users
                await this.fetchCsrfToken();
                
                if (data.is_admin) {
                    this.showAdminDashboard();
                } else {
                    this.showUserTimeline();
                }
            } else {
                this.showLoginScreen();
            }
        } catch (error) {
            this.showLoginScreen();
        }
    }

    async handleLogin(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const totpCode = document.getElementById('totp-code-login').value.trim();
        const rememberMe = document.getElementById('remember-me').checked;
        
        try {
            // Step 1: Initialize SRP authentication
            const initResponse = await fetch('/api/login/init', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username }),
                credentials: 'include'
            });
            
            if (!initResponse.ok) {
                this.showElementError('login-error', 'Login failed');
                return;
            }
            
            const initData = await initResponse.json();
            const { salt, b_pub, session_id } = initData;
            
            // Step 2: Compute SRP client values
            const srpResult = await window.srpClient.startAuthentication(username, password, salt, b_pub);
            
            // Step 3: Verify with server
            const verifyResponse = await fetch('/api/login/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    session_id: session_id,
                    a_pub: srpResult.A,
                    m1: srpResult.M1,
                    remember_me: rememberMe
                }),
                credentials: 'include'
            });
            
            const verifyData = await verifyResponse.json();
            
            // Step 4: Verify server's proof (M2)
            if (verifyData.m2) {
                try {
                    await window.srpClient.verifyServerProof(verifyData.m2);
                } catch (err) {
                    this.showElementError('login-error', 'Server authentication failed');
                    return;
                }
            }
            
            // Check if 2FA is required
            if (verifyData.requires_2fa && verifyData.temp_2fa_session_id) {
                if (totpCode) {
                    // User provided 2FA code - verify it now
                    const passwordHash = await window.cryptoUtils.derivePasswordHash(password);
                    
                    const verify2FAResponse = await fetch('/api/verify-2fa', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            temp_session_id: verifyData.temp_2fa_session_id,
                            totp_code: totpCode,
                            password_hash: passwordHash
                        }),
                        credentials: 'include'
                    });
                    
                    const verify2FAData = await verify2FAResponse.json();
                    
                    if (verify2FAData.success) {
                        // 2FA verification successful
                        localStorage.setItem('rememberMe', rememberMe.toString());
                        this.userPassword = password;
                        this.currentUser = { username, is_admin: false };
                        
                        // Fetch CSRF token for state-changing requests
                        await this.fetchCsrfToken();
                        
                        await this.loadUserData();
                        this.showUserTimeline();
                    } else {
                        this.showElementError('login-error', verify2FAData.message || '2FA verification failed');
                    }
                } else {
                    // Show error - user must provide 2FA code
                    this.showElementError('login-error', '2FA verification required. Please enter your 6-digit code.');
                }
            } else if (verifyData.success) {
                // No 2FA required - login successful
                localStorage.setItem('rememberMe', rememberMe.toString());
                this.userPassword = password;
                this.currentUser = { username, is_admin: verifyData.user_type === 'admin' };
                
                // Fetch CSRF token for state-changing requests
                await this.fetchCsrfToken();
                
                if (verifyData.user_type === 'admin') {
                    this.showAdminDashboard();
                } else {
                    await this.loadUserData();
                    this.showUserTimeline();
                }
            } else {
                this.showElementError('login-error', verifyData.message || 'Login failed');
            }
        } catch (error) {
            console.error('Login error:', error);
            this.showElementError('login-error', 'Network error. Please try again.');
        }
    }

    async logout() {
        try {
            await fetch('/api/logout', {
                method: 'POST',
                credentials: 'include'
            });
        } catch (error) {
            console.error('Logout error:', error);
        }
        
        // Aggressively clear all sensitive data from memory
        this.clearSensitiveData();
        location.reload();
    }
    
    // Clear all sensitive data from memory
    clearSensitiveData() {
        // Overwrite sensitive strings before nullifying
        if (this.userPassword) {
            this.userPassword = '\0'.repeat(this.userPassword.length);
        }
        if (this.temp2FASecret) {
            this.temp2FASecret = '\0'.repeat(this.temp2FASecret.length);
        }
        if (this.temp2FAPassword) {
            this.temp2FAPassword = '\0'.repeat(this.temp2FAPassword.length);
        }
        
        // Null out all sensitive properties
        this.currentUser = null;
        this.userPassword = null;
        this.csrfToken = null;
        this.temp2FASecret = null;
        this.temp2FAPassword = null;
        this.temp2FASessionId = null;
        this.events = [];
        this.tags = [];
        this.notes = '';
        
        // Clear local storage
        localStorage.removeItem('rememberMe');
    }
    
    async fetchCsrfToken() {
        try {
            const response = await fetch('/api/csrf-token', {
                credentials: 'include'
            });
            if (response.ok) {
                const data = await response.json();
                this.csrfToken = data.csrf_token;
            }
        } catch (error) {
            console.error('Failed to fetch CSRF token:', error);
        }
    }
    
    // Helper to get headers with CSRF token for POST/DELETE requests
    getCsrfHeaders() {
        const headers = {
            'Content-Type': 'application/json'
        };
        if (this.csrfToken) {
            headers['X-CSRF-Token'] = this.csrfToken;
        }
        return headers;
    }

    showLoginScreen() {
        this.hideAllScreens();
        document.getElementById('login-screen').style.display = 'flex';
    }

    async showAdminDashboard() {
        this.hideAllScreens();
        document.getElementById('admin-screen').style.display = 'flex';
        await this.loadUsers();
    }

    async showUserTimeline() {
        this.hideAllScreens();
        document.getElementById('user-screen').style.display = 'flex';
        
        // If we don't have the user password (e.g., after page refresh), check remember me preference
        if (!this.userPassword) {
            const rememberMe = localStorage.getItem('rememberMe') === 'true';
            if (rememberMe) {
                await this.promptForPassword();
            } else {
                // If remember me was not checked, log out completely
                this.logout();
                return;
            }
        }
        
        await this.loadUserData();
        this.updateUserDisplayName();
        this.renderTimeline();
        this.updateEventCounts();
    }

    async promptForPassword() {
        return new Promise((resolve, reject) => {
            const overlay = document.getElementById('password-prompt-overlay');
            const form = document.getElementById('password-prompt-form');
            const passwordInput = document.getElementById('password-prompt-input');
            const closeBtn = document.getElementById('password-prompt-close');
            
            // Clear previous input
            passwordInput.value = '';
            
            // Show overlay
            overlay.style.display = 'flex';
            passwordInput.focus();
            
            const handleSubmit = async (e) => {
                e.preventDefault();
                const password = passwordInput.value;
                
                if (!password) {
                    this.showError('Password is required', 'Password Required');
                    return;
                }
                
                // Verify password by attempting to load settings (simplest encrypted data)
                try {
                    this.userPassword = password;
                    await this.loadSettings();
                    
                    // If successful, hide overlay and resolve
                    overlay.style.display = 'none';
                    form.removeEventListener('submit', handleSubmit);
                    closeBtn.removeEventListener('click', handleClose);
                    resolve();
                } catch (error) {
                    this.userPassword = null;
                    this.showError('Incorrect password. Please try again.', 'Authentication Failed');
                    passwordInput.value = '';
                    passwordInput.focus();
                }
            };
            
            const handleClose = () => {
                // If user cancels, log them out
                overlay.style.display = 'none';
                form.removeEventListener('submit', handleSubmit);
                closeBtn.removeEventListener('click', handleClose);
                this.logout();
                reject(new Error('Password prompt cancelled'));
            };
            
            form.addEventListener('submit', handleSubmit);
            closeBtn.addEventListener('click', handleClose);
        });
    }

    hideAllScreens() {
        document.querySelectorAll('.screen').forEach(screen => {
            screen.style.display = 'none';
        });
    }

    async loadUserData() {
        await Promise.all([
            this.loadEvents(),
            this.loadTags(),
            this.loadSettings(),
            this.loadNotes()
        ]);
    }

    async loadEvents() {
        try {
            const response = await fetch('/api/events', {
                credentials: 'include'
            });
            
            if (response.ok) {
                const encryptedEvents = await response.json();
                this.events = [];
                
                for (const event of encryptedEvents) {
                    try {
                        const tags = [];
                        for (const tagEncrypted of event.tag_names_encrypted || []) {
                            if (tagEncrypted) {
                                tags.push(await cryptoUtils.decrypt(tagEncrypted, this.userPassword));
                            }
                        }
                        
                        const decryptedEvent = {
                            id: event.id,
                            title: await cryptoUtils.decrypt(event.title_encrypted, this.userPassword),
                            description: await cryptoUtils.decrypt(event.description_encrypted, this.userPassword),
                            timestamp: new Date(event.event_timestamp),
                            tags: tags
                        };
                        this.events.push(decryptedEvent);
                    } catch (error) {
                        console.error('Failed to decrypt event:', error);
                    }
                }
                
                this.filteredEvents = [...this.events];
            }
        } catch (error) {
            console.error('Failed to load events:', error);
        }
    }

    async loadTags() {
        try {
            const response = await fetch('/api/tags', {
                credentials: 'include'
            });
            
            if (response.ok) {
                const encryptedTags = await response.json();
                this.tags = [];
                const seenTagNames = new Set(); // Track seen tag names to avoid duplicates
                
                for (const tag of encryptedTags) {
                    try {
                        const decryptedTagName = await cryptoUtils.decrypt(tag.name_encrypted, this.userPassword);
                        
                        // Only add if we haven't seen this tag name before
                        if (!seenTagNames.has(decryptedTagName)) {
                            const decryptedTag = {
                                id: tag.id,
                                name: decryptedTagName
                            };
                            this.tags.push(decryptedTag);
                            seenTagNames.add(decryptedTagName);
                        }
                    } catch (error) {
                        console.error('Failed to decrypt tag:', error);
                    }
                }
            }
        } catch (error) {
            console.error('Failed to load tags:', error);
        }
    }

    async loadSettings() {
        try {
            const response = await fetch('/api/settings', {
                credentials: 'include'
            });
            
            if (response.ok) {
                const data = await response.json();
                if (data.settings_encrypted) {
                    try {
                        const decryptedSettings = await cryptoUtils.decrypt(data.settings_encrypted, this.userPassword);
                        this.settings = { ...this.settings, ...JSON.parse(decryptedSettings) };
                    } catch (error) {
                        console.error('Failed to decrypt settings:', error);
                    }
                }
                
                // Load profile picture
                if (data.profile_picture_encrypted) {
                    try {
                        const decryptedPicture = await cryptoUtils.decrypt(data.profile_picture_encrypted, this.userPassword);
                        this.profilePicture = decryptedPicture;
                    } catch (error) {
                        console.error('Failed to decrypt profile picture:', error);
                        this.profilePicture = null;
                    }
                } else {
                    this.profilePicture = null;
                }
                
                this.applySettings();
                this.updateProfilePictureDisplay();
            }
        } catch (error) {
            console.error('Failed to load settings:', error);
        }
    }

    applySettings() {
        // Apply theme
        document.getElementById('theme-select').value = this.settings.theme;
        this.applyTheme();
        
        // Apply other settings
        document.getElementById('time-format-select').value = this.settings.timeFormat;
        document.getElementById('date-format-select').value = this.settings.dateFormat;
        document.getElementById('time-separator-select').value = this.settings.timeSeparator;
        document.getElementById('accent-color').value = this.settings.accentColor || '';
        
        if (this.settings.displayName) {
            document.getElementById('display-name').value = this.settings.displayName;
        }
        
        this.updateUserDisplayName();
        this.applyAccentColor();
    }

    updateUserDisplayName() {
        const displayNameEl = document.getElementById('user-display-name');
        if (displayNameEl) {
            const displayName = this.settings.displayName || (this.currentUser ? this.currentUser.username : '');
            displayNameEl.textContent = displayName;
        }
    }

    applyTheme() {
        const theme = this.settings.theme;
        
        if (theme === 'device') {
            // Use system preference
            if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
                document.documentElement.setAttribute('data-theme', 'dark');
            } else {
                document.documentElement.removeAttribute('data-theme');
            }
        } else if (theme === 'dark') {
            document.documentElement.setAttribute('data-theme', 'dark');
        } else {
            document.documentElement.removeAttribute('data-theme');
        }
    }

    renderTimeline() {
        const container = document.getElementById('events-container');
        const emptyState = document.getElementById('empty-state');
        const timelineLine = document.querySelector('.timeline-line');
        
        container.innerHTML = '';
        
        // Check if there are any events to display
        if (this.filteredEvents.length === 0) {
            // Show empty state, hide timeline elements
            emptyState.style.display = 'flex';
            timelineLine.style.display = 'none';
            return;
        }
        
        // Hide empty state, show timeline elements
        emptyState.style.display = 'none';
        timelineLine.style.display = 'block';
        
        // Sort events by timestamp (oldest first as per requirements)
        const sortedEvents = [...this.filteredEvents].sort((a, b) => a.timestamp - b.timestamp);
        
        let lastSeparatorDate = null;
        
        sortedEvents.forEach(event => {
            // Check if we need to add a separator before this event
            if (this.settings.timeSeparator !== 'disabled') {
                const separatorDate = this.getSeparatorDate(event.timestamp, lastSeparatorDate);
                if (separatorDate) {
                    const separatorElement = this.createTimeSeparatorElement(separatorDate);
                    container.appendChild(separatorElement);
                    lastSeparatorDate = separatorDate;
                }
            }
            
            const eventElement = this.createEventElement(event);
            container.appendChild(eventElement);
        });
        
        // Scroll to bottom (newest events)
        const timelineContent = document.querySelector('.timeline-content');
        timelineContent.scrollTop = timelineContent.scrollHeight;
    }

    createEventElement(event) {
        const eventDiv = document.createElement('div');
        eventDiv.className = 'event-item';
        eventDiv.dataset.eventId = event.id;
        
        const formattedTime = this.formatDateTime(event.timestamp);
        const timer = this.calculateTimer(event.timestamp);
        
        eventDiv.innerHTML = `
            <div class="event-header">
                <div class="event-title">${this.escapeHtml(event.title)}</div>
                <div class="event-timestamp">${formattedTime}</div>
            </div>
            <div class="event-description">${this.escapeHtml(event.description)}</div>
            <div class="event-timer" data-timestamp="${event.timestamp.getTime()}">${timer}</div>
            <div class="event-tags">
                ${event.tags.map(tag => `<span class="event-tag">${this.escapeHtml(tag)}</span>`).join('')}
            </div>
            <div class="event-footer">
                <button class="delete-event-btn" data-event-id="${event.id}" data-event-title="${this.escapeHtml(event.title)}">Delete</button>
            </div>
        `;
        
        // Add event listener for delete button
        const deleteBtn = eventDiv.querySelector('.delete-event-btn');
        deleteBtn.addEventListener('click', () => {
            this.deleteEvent(event.id, event.title);
        });
        
        return eventDiv;
    }

    calculateTimer(timestamp) {
        const now = new Date();
        const diff = now - timestamp;
        
        const seconds = Math.floor(diff / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);
        const months = Math.floor(days / 30);
        const years = Math.floor(days / 365);
        
        // Always show all time units, even if they're 0
        const yearValue = years;
        const monthValue = months % 12;
        const dayValue = days % 30;
        const hourValue = hours % 24;
        const minuteValue = minutes % 60;
        const secondValue = seconds % 60;
        
        // First row: Years, Months, Days
        const firstRow = [
            `<span class="time-value">${yearValue}</span> Year${yearValue !== 1 ? 's' : ''}`,
            `<span class="time-value">${monthValue}</span> Month${monthValue !== 1 ? 's' : ''}`,
            `<span class="time-value">${dayValue}</span> Day${dayValue !== 1 ? 's' : ''}`
        ].join(' ');
        
        // Second row: Hours, Minutes, Seconds
        const secondRow = [
            `<span class="time-value">${hourValue}</span> Hour${hourValue !== 1 ? 's' : ''}`,
            `<span class="time-value">${minuteValue}</span> Minute${minuteValue !== 1 ? 's' : ''}`,
            `<span class="time-value">${secondValue}</span> Second${secondValue !== 1 ? 's' : ''}`
        ].join(' ');
        
        return `<div class="time-row">${firstRow}</div><div class="time-row">${secondRow}</div><div>ago</div>`;
    }

    updateEventTimers() {
        document.querySelectorAll('.event-timer').forEach(timerEl => {
            const timestamp = parseInt(timerEl.dataset.timestamp);
            const timer = this.calculateTimer(new Date(timestamp));
            timerEl.innerHTML = timer;
        });
    }

    getSeparatorDate(eventTimestamp, lastSeparatorDate) {
        const eventDate = new Date(eventTimestamp);
        
        switch (this.settings.timeSeparator) {
            case 'daily':
                // Normalize to start of day for comparison
                const dayStart = new Date(eventDate.getFullYear(), eventDate.getMonth(), eventDate.getDate());
                const lastDayStart = lastSeparatorDate ? new Date(lastSeparatorDate.getFullYear(), lastSeparatorDate.getMonth(), lastSeparatorDate.getDate()) : null;
                if (!lastDayStart || dayStart.getTime() !== lastDayStart.getTime()) {
                    return dayStart;
                }
                break;
                
            case 'weekly':
                const weekStart = this.getWeekStart(eventDate);
                if (!lastSeparatorDate || weekStart.getTime() !== lastSeparatorDate.getTime()) {
                    return weekStart;
                }
                break;
                
            case 'monthly':
                const monthStart = new Date(eventDate.getFullYear(), eventDate.getMonth(), 1);
                if (!lastSeparatorDate || monthStart.getTime() !== lastSeparatorDate.getTime()) {
                    return monthStart;
                }
                break;
                
            case 'yearly':
                const yearStart = new Date(eventDate.getFullYear(), 0, 1);
                if (!lastSeparatorDate || yearStart.getTime() !== lastSeparatorDate.getTime()) {
                    return yearStart;
                }
                break;
        }
        
        return null;
    }

    getWeekStart(date) {
        const d = new Date(date);
        const day = d.getDay();
        const diff = d.getDate() - day + (day === 0 ? -6 : 1); // Adjust when day is Sunday
        d.setDate(diff);
        // Reset time to start of day for consistent comparison
        d.setHours(0, 0, 0, 0);
        return d;
    }

    createTimeSeparatorElement(separatorDate) {
        const separatorDiv = document.createElement('div');
        separatorDiv.className = 'timeline-separator';
        
        const formattedDate = this.formatSeparatorDate(separatorDate);
        
        separatorDiv.innerHTML = `
            <div class="separator-line"></div>
            <div class="separator-date">${formattedDate}</div>
        `;
        
        return separatorDiv;
    }

    formatSeparatorDate(date) {
        const dateFormat = this.settings.dateFormat;
        
        switch (dateFormat) {
            case 'dd/mm/yyyy':
                return date.toLocaleDateString('en-GB');
            case 'mm/dd/yyyy':
                return date.toLocaleDateString('en-US');
            case 'yyyy-mm-dd':
                return date.toISOString().split('T')[0];
            case 'dd mmm yyyy':
                return date.toLocaleDateString('en-GB', {
                    day: 'numeric',
                    month: 'long',
                    year: 'numeric'
                });
            default:
                return date.toLocaleDateString('en-GB');
        }
    }

    formatDateTime(date) {
        const timeFormat = this.settings.timeFormat;
        const dateFormat = this.settings.dateFormat;
        
        let timeStr;
        if (timeFormat === '12h') {
            timeStr = date.toLocaleTimeString('en-GB', { 
                hour12: true,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
        } else {
            timeStr = date.toLocaleTimeString('en-GB', {
                hour12: false,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
        }
        
        let dateStr;
        const day = date.getDate().toString().padStart(2, '0');
        const month = (date.getMonth() + 1).toString().padStart(2, '0');
        const year = date.getFullYear();
        
        switch (dateFormat) {
            case 'mm/dd/yyyy':
                dateStr = `${month}/${day}/${year}`;
                break;
            case 'yyyy-mm-dd':
                dateStr = `${year}-${month}-${day}`;
                break;
            case 'dd mmm yyyy':
                const monthNames = ['January', 'February', 'March', 'April', 'May', 'June',
                    'July', 'August', 'September', 'October', 'November', 'December'];
                dateStr = `${date.getDate()} ${monthNames[date.getMonth()]} ${year}`;
                break;
            default: // dd/mm/yyyy
                dateStr = `${day}/${month}/${year}`;
        }
        
        return `${timeStr} ${dateStr}`;
    }

    updateEventCounts() {
        document.getElementById('total-event-count').textContent = `${this.events.length} Events in the list`;
        document.getElementById('filtered-event-count').textContent = `${this.filteredEvents.length} Events`;
    }

    performSearch() {
        const query = document.getElementById('search-input').value.toLowerCase().trim();
        
        if (!query) {
            this.filteredEvents = [...this.events];
        } else {
            this.filteredEvents = this.events.filter(event => 
                event.title.toLowerCase().includes(query) ||
                event.description.toLowerCase().includes(query)
            );
        }
        
        this.renderTimeline();
        this.updateEventCounts();
    }

    toggleBurgerMenu() {
        const menu = document.getElementById('burger-menu-content');
        menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
    }

    toggleTagFilter() {
        const menu = document.getElementById('tag-filter-menu');
        menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
        
        if (menu.style.display === 'block') {
            this.renderTagFilter();
        }
    }

    renderTagFilter() {
        const container = document.getElementById('tag-filter-list');
        container.innerHTML = '';
        
        this.tags.forEach(tag => {
            const div = document.createElement('div');
            div.className = 'tag-filter-item';
            div.innerHTML = `
                <input type="checkbox" id="tag-${tag.id}" value="${tag.name}">
                <label for="tag-${tag.id}">${this.escapeHtml(tag.name)}</label>
            `;
            
            const checkbox = div.querySelector('input');
            checkbox.addEventListener('change', () => this.applyTagFilter());
            
            container.appendChild(div);
        });
    }

    applyTagFilter() {
        const selectedTags = Array.from(document.querySelectorAll('#tag-filter-list input:checked'))
            .map(input => input.value);
        
        if (selectedTags.length === 0) {
            this.filteredEvents = [...this.events];
        } else {
            this.filteredEvents = this.events.filter(event => 
                selectedTags.every(tag => event.tags.includes(tag))
            );
        }
        
        this.renderTimeline();
        this.updateEventCounts();
    }

    // Admin functions
    async loadUsers() {
        try {
            const response = await fetch('/api/users', {
                credentials: 'include'
            });
            
            if (response.ok) {
                const users = await response.json();
                this.renderUserList(users);
            }
        } catch (error) {
            console.error('Failed to load users:', error);
        }
    }

    renderUserList(users) {
        const container = document.getElementById('user-list');
        container.innerHTML = '';
        
        users.forEach(user => {
            const userDiv = document.createElement('div');
            userDiv.className = 'user-item';
            userDiv.innerHTML = `
                <div class="user-info">
                    <div class="user-username">${this.escapeHtml(user.username)}</div>
                    <div class="user-created">Created: ${new Date(user.created_at).toLocaleDateString('en-GB')}</div>
                </div>
                <button class="delete-user-btn" data-user-id="${user.id}" data-username="${this.escapeHtml(user.username)}">Delete</button>
            `;
            container.appendChild(userDiv);
            
            // Add event listener for delete button
            const deleteBtn = userDiv.querySelector('.delete-user-btn');
            deleteBtn.addEventListener('click', () => {
                this.deleteUser(user.id, user.username);
            });
        });
    }

    async handleAddUser(e) {
        e.preventDefault();
        
        const username = document.getElementById('new-username').value;
        
        try {
            const response = await fetch('/api/users', {
                method: 'POST',
                headers: this.getCsrfHeaders(),
                body: JSON.stringify({ username }),
                credentials: 'include'
            });
            
            const data = await response.json();
            
            if (data.success) {
                document.getElementById('success-username').textContent = username;
                document.getElementById('success-password').textContent = data.password;
                this.showOverlay('user-add-success-overlay');
                document.getElementById('new-username').value = '';
                await this.loadUsers();
            } else {
                this.showError('User Creation Failed', data.message || 'Failed to create user');
            }
        } catch (error) {
            this.showError('Network Error', 'Network error. Please try again.');
        }
    }

    async deleteUser(userId, username) {
        this.showDeleteConfirmation(
            'Delete User',
            `Are you sure you want to delete user "${username}"? This action cannot be undone.`,
            username,
            async () => {
                try {
                    const confirmationUsername = document.getElementById('confirmation-input').value;
                    
                    const response = await fetch(`/api/users/${userId}`, {
                        method: 'POST',
                        headers: this.getCsrfHeaders(),
                        body: JSON.stringify({ confirmation_username: confirmationUsername }),
                        credentials: 'include'
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        await this.loadUsers();
                        this.closeOverlay(document.getElementById('delete-confirmation-overlay'));
                    } else {
                        this.showError('User Deletion Failed', data.message || 'Failed to delete user');
                    }
                } catch (error) {
                    this.showError('Network Error', 'Network error. Please try again.');
                }
            }
        );
    }

    // Event management
    async handleAddEvent(e) {
        e.preventDefault();
        
        const title = document.getElementById('event-title').value;
        const description = document.getElementById('event-description').value;
        
        let timestamp;
        const isCustomTime = document.getElementById('time-toggle').checked;
        
        if (!isCustomTime) {
            timestamp = new Date();
        } else {
            const day = parseInt(document.getElementById('day').value);
            const month = parseInt(document.getElementById('month').value) - 1; // JS months are 0-indexed
            const year = parseInt(document.getElementById('year').value);
            const hour = parseInt(document.getElementById('hour').value) || 0;
            const minute = parseInt(document.getElementById('minute').value) || 0;
            const second = parseInt(document.getElementById('second').value) || 0;
            
            timestamp = new Date(year, month, day, hour, minute, second);
        }
        
        // Get selected tags
        const selectedTags = Array.from(document.querySelectorAll('#available-tags input:checked'))
            .map(input => input.value);
        
        try {
            // Encrypt data
            const titleEncrypted = await cryptoUtils.encrypt(title, this.userPassword);
            const descriptionEncrypted = await cryptoUtils.encrypt(description, this.userPassword);
            const tagsEncrypted = [];
            
            for (const tag of selectedTags) {
                tagsEncrypted.push(await cryptoUtils.encrypt(tag, this.userPassword));
            }
            
            const response = await fetch('/api/events', {
                method: 'POST',
                headers: this.getCsrfHeaders(),
                body: JSON.stringify({
                    title_encrypted: titleEncrypted,
                    description_encrypted: descriptionEncrypted,
                    event_timestamp: timestamp.toISOString(),
                    tag_names_encrypted: tagsEncrypted
                }),
                credentials: 'include'
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.closeOverlay(document.getElementById('add-event-overlay'));
                document.getElementById('add-event-form').reset();
                await this.loadUserData();
                this.renderTimeline();
                this.updateEventCounts();
            } else {
                this.showError('Event Creation Failed', 'Failed to create event');
            }
        } catch (error) {
            this.showError('Network Error', 'Network error. Please try again.');
        }
    }

    toggleCustomTime() {
        const customInputs = document.getElementById('custom-time-inputs');
        const isCustom = document.getElementById('time-toggle').checked;
        customInputs.style.display = isCustom ? 'grid' : 'none';
        
        if (isCustom) {
            // Pre-fill with current date/time
            const now = new Date();
            document.getElementById('day').value = now.getDate();
            document.getElementById('month').value = now.getMonth() + 1;
            document.getElementById('year').value = now.getFullYear();
            document.getElementById('hour').value = now.getHours();
            document.getElementById('minute').value = now.getMinutes();
            document.getElementById('second').value = now.getSeconds();
        }
    }

    addNewTag() {
        const tagName = document.getElementById('new-tag-name').value.trim();
        if (!tagName) return;
        
        // Add to available tags if not already present
        if (!this.tags.find(tag => tag.name === tagName)) {
            this.tags.push({ id: 'temp-' + Date.now(), name: tagName });
            this.renderAvailableTags();
        }
        
        document.getElementById('new-tag-name').value = '';
    }

    renderAvailableTags() {
        const container = document.getElementById('available-tags');
        container.innerHTML = '';
        
        this.tags.forEach(tag => {
            const div = document.createElement('div');
            div.className = 'tag-checkbox-item';
            div.innerHTML = `
                <input type="checkbox" id="event-tag-${tag.id}" value="${tag.name}">
                <label for="event-tag-${tag.id}">${this.escapeHtml(tag.name)}</label>
            `;
            container.appendChild(div);
        });
    }

    async deleteEvent(eventId, eventTitle) {
        this.showDeleteConfirmation(
            'Delete Event',
            `Are you sure you want to delete the event "${eventTitle}"? This action cannot be undone.`,
            eventTitle,
            async () => {
                const confirmationTitle = document.getElementById('confirmation-input').value;
                
                if (confirmationTitle !== eventTitle) {
                    this.showError('Title Mismatch', 'Event title does not match. Please enter the exact title.');
                    return;
                }
                
                try {
                    const response = await fetch(`/api/events/${eventId}`, {
                        method: 'POST',
                        headers: this.getCsrfHeaders(),
                        body: JSON.stringify({ confirmation_title: confirmationTitle }),
                        credentials: 'include'
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        await this.loadUserData();
                        this.renderTimeline();
                        this.updateEventCounts();
                        this.closeOverlay(document.getElementById('delete-confirmation-overlay'));
                    } else {
                        this.showError('Event Deletion Failed', data.message || 'Failed to delete event');
                    }
                } catch (error) {
                    this.showError('Network Error', 'Network error. Please try again.');
                }
            }
        );
    }

    // Settings functions
    async saveDisplayName() {
        const displayName = document.getElementById('display-name').value;
        this.settings.displayName = displayName;
        await this.saveSettingsToServer();
        this.updateUserDisplayName();
    }

    updateProfilePictureDisplay() {
        const previewImg = document.getElementById('profile-picture-preview');
        const noProfileText = document.getElementById('no-profile-picture-text');
        const removeBtn = document.getElementById('remove-profile-picture-btn');
        const topBarImg = document.getElementById('user-profile-picture');
        
        if (this.profilePicture) {
            previewImg.src = this.profilePicture;
            previewImg.style.display = 'block';
            noProfileText.style.display = 'none';
            removeBtn.style.display = 'inline-block';
            topBarImg.src = this.profilePicture;
            topBarImg.style.display = 'inline';
        } else {
            previewImg.style.display = 'none';
            noProfileText.style.display = 'block';
            removeBtn.style.display = 'none';
            topBarImg.style.display = 'none';
        }
    }

    showProfilePictureUploadOverlay() {
        this.showOverlay('profile-picture-upload-overlay');
        // Reset file input
        document.getElementById('profile-picture-file-input').value = '';
        document.getElementById('profile-picture-crop-container').style.display = 'none';
        document.getElementById('set-profile-picture-btn').style.display = 'none';
        if (this.cropper) {
            this.cropper.destroy();
            this.cropper = null;
        }
    }

    closeProfilePictureUpload() {
        if (this.cropper) {
            this.cropper.destroy();
            this.cropper = null;
        }
        this.closeOverlay(document.getElementById('profile-picture-upload-overlay'));
    }

    async handleProfilePictureFileSelect(event) {
        const file = event.target.files[0];
        if (!file) return;

        // Validate file type
        const validTypes = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'];
        if (!validTypes.includes(file.type)) {
            this.showError('Invalid File Type', 'Please select a PNG, JPG, JPEG, or WEBP image.');
            event.target.value = '';
            return;
        }

        // Validate file size (max 1MB)
        if (file.size > 1024 * 1024) {
            this.showError('File Too Large', 'Please select an image smaller than 1MB.');
            event.target.value = '';
            return;
        }

        // Load image for cropping
        const reader = new FileReader();
        reader.onload = (e) => {
            const cropImage = document.getElementById('profile-picture-crop-image');
            
            // Destroy previous cropper if exists
            if (this.cropper) {
                this.cropper.destroy();
                this.cropper = null;
            }

            cropImage.src = e.target.result;
            document.getElementById('profile-picture-crop-container').style.display = 'block';
            document.getElementById('set-profile-picture-btn').style.display = 'inline-block';

            // Wait for image to load before initializing cropper
            cropImage.onload = () => {
                // Initialize Cropper.js after image is loaded
                this.cropper = new Cropper(cropImage, {
                    aspectRatio: 1,
                    viewMode: 1,
                    minCropBoxWidth: 100,
                    minCropBoxHeight: 100,
                    autoCropArea: 1,
                    responsive: true,
                });
            };
        };
        reader.readAsDataURL(file);
    }

    async setNewProfilePicture() {
        if (!this.cropper) {
            this.showError('No Image Selected', 'Please select an image first.');
            return;
        }

        try {
            // Get cropped canvas at 300x300
            const canvas = this.cropper.getCroppedCanvas({
                width: 300,
                height: 300,
                imageSmoothingEnabled: true,
                imageSmoothingQuality: 'high'
            });

            if (!canvas) {
                this.showError('Crop Failed', 'Failed to process the image. Please try again.');
                return;
            }

            // Convert to PNG data URL
            const dataURL = canvas.toDataURL('image/png');

            // Encrypt and save
            const encrypted = await cryptoUtils.encrypt(dataURL, this.userPassword);
            
            const response = await fetch('/api/profile-picture', {
                method: 'POST',
                headers: this.getCsrfHeaders(),
                body: JSON.stringify({
                    profile_picture_encrypted: encrypted
                }),
                credentials: 'include'
            });

            const data = await response.json();

            if (data.success) {
                this.profilePicture = dataURL;
                this.updateProfilePictureDisplay();
                this.closeProfilePictureUpload();
                this.showSuccess('Profile Picture Updated', 'Your profile picture has been updated successfully.');
            } else {
                this.showError('Upload Failed', data.message || 'Failed to upload profile picture.');
            }
        } catch (error) {
            console.error('Failed to set profile picture:', error);
            this.showError('Upload Failed', 'Failed to upload profile picture. Please try again.');
        }
    }

    async removeProfilePicture() {
        try {
            const response = await fetch('/api/profile-picture', {
                method: 'DELETE',
                headers: this.getCsrfHeaders(),
                credentials: 'include'
            });

            const data = await response.json();

            if (data.success) {
                this.profilePicture = null;
                this.updateProfilePictureDisplay();
                this.showSuccess('Profile Picture Removed', 'Your profile picture has been removed.');
            } else {
                this.showError('Remove Failed', data.message || 'Failed to remove profile picture.');
            }
        } catch (error) {
            console.error('Failed to remove profile picture:', error);
            this.showError('Remove Failed', 'Failed to remove profile picture. Please try again.');
        }
    }

    async changePassword() {
        const oldPassword = document.getElementById('old-password').value;
        const newPassword = document.getElementById('new-password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        
        if (newPassword !== confirmPassword) {
            this.showPasswordError('New passwords do not match');
            return;
        }
        
        // SECURITY FIX: For SRP, we cannot compare plaintext passwords client-side
        // Instead, we'll validate during the password change process on the server
        // by attempting to re-encrypt TOTP secrets with the old password hash
        
        // Show confirmation overlay
        this.showPasswordConfirmation();
    }

    async confirmPasswordChange() {
        // Close confirmation overlay
        this.closeOverlay(document.getElementById('password-confirm-overlay'));
        
        const oldPassword = document.getElementById('old-password').value;
        const newPassword = document.getElementById('new-password').value;
        
        try {
            // Step 1: Initialize password change with SRP verification
            const initResponse = await fetch('/api/change-password/init', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({}),
                credentials: 'include'
            });
            
            if (!initResponse.ok) {
                throw new Error('Failed to initialize password change');
            }
            
            const initData = await initResponse.json();
            
            // Step 2: Perform SRP authentication with old password to verify it
            const srpAuth = await window.srpClient.startAuthentication(
                this.currentUser.username,
                oldPassword,
                initData.salt,
                initData.b_pub
            );
            
            // Step 3: Generate new SRP credentials
            const newCredentials = await window.srpClient.generateCredentials(this.currentUser.username, newPassword);
            
            // Step 4: Derive password hashes for TOTP re-encryption
            const oldPasswordHash = await window.cryptoUtils.derivePasswordHash(oldPassword);
            const newPasswordHash = await window.cryptoUtils.derivePasswordHash(newPassword);
            
            // Step 5: Verify old password and change to new password in backend
            const passwordResponse = await fetch('/api/change-password/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    session_id: initData.session_id,
                    a_pub: srpAuth.A,
                    m1: srpAuth.M1,
                    new_salt: newCredentials.salt,
                    new_verifier: newCredentials.verifier,
                    old_password_hash: oldPasswordHash,
                    new_password_hash: newPasswordHash
                }),
                credentials: 'include'
            });
            
            const passwordData = await passwordResponse.json();
            
            if (!passwordData.success) {
                throw new Error(passwordData.message || 'Failed to change password');
            }
            
            // Password verification successful! Now handle data re-encryption
            
            // Step 6: Create temporary unencrypted backup of all data
            const backupData = {
                events: this.events.map(event => ({
                    title: event.title,
                    description: event.description,
                    timestamp: event.timestamp.toISOString(),
                    tags: event.tags
                })),
                settings: this.settings,
                notes: this.notes,
                profilePicture: this.profilePicture,
                exported_at: new Date().toISOString()
            };
            
            // Step 7: Clear all user data from backend
            const clearResponse = await fetch('/api/user-data', {
                method: 'POST',
                headers: this.getCsrfHeaders(),
                credentials: 'include'
            });
            
            if (!clearResponse.ok) {
                throw new Error('Failed to clear user data');
            }
            
            // Step 8: Update local password for encryption
            this.userPassword = newPassword;
            
            // Step 9: Re-import all data with new encryption
            for (const event of backupData.events) {
                try {
                    const titleEncrypted = await cryptoUtils.encrypt(event.title, this.userPassword);
                    const descriptionEncrypted = await cryptoUtils.encrypt(event.description, this.userPassword);
                    const tagsEncrypted = [];
                    
                    for (const tag of event.tags || []) {
                        tagsEncrypted.push(await cryptoUtils.encrypt(tag, this.userPassword));
                    }
                    
                    await fetch('/api/events', {
                        method: 'POST',
                        headers: app.getCsrfHeaders(),
                        body: JSON.stringify({
                            title_encrypted: titleEncrypted,
                            description_encrypted: descriptionEncrypted,
                            event_timestamp: event.timestamp,
                            tag_names_encrypted: tagsEncrypted
                        }),
                        credentials: 'include'
                    });
                } catch (error) {
                    console.error('Failed to re-import event:', event.title, error);
                }
            }
            
            // Step 10: Re-save settings with new encryption
            if (backupData.settings) {
                this.settings = backupData.settings;
                await this.saveSettingsToServer();
            }
            
            // Step 11: Re-save notes with new encryption
            if (backupData.notes !== undefined) {
                this.notes = backupData.notes;
                await this.saveNotes();
            }
            
            // Step 12: Re-save profile picture with new encryption
            if (backupData.profilePicture) {
                this.profilePicture = backupData.profilePicture;
                const encrypted = await cryptoUtils.encrypt(this.profilePicture, this.userPassword);
                await fetch('/api/profile-picture', {
                    method: 'POST',
                    headers: app.getCsrfHeaders(),
                    body: JSON.stringify({
                        profile_picture_encrypted: encrypted
                    }),
                    credentials: 'include'
                });
            }
            
            // Step 13: Clear the temporary backup data from memory
            // (JavaScript garbage collector will handle this)
            
            // Reload data to reflect changes
            await this.loadUserData();
            this.renderTimeline();
            this.updateEventCounts();
            
            // Show success message
            this.showPasswordSuccess();
            
            // Clear form fields
            document.getElementById('old-password').value = '';
            document.getElementById('new-password').value = '';
            document.getElementById('confirm-password').value = '';
            
        } catch (error) {
            this.showPasswordError(`Password change failed: ${error.message}. Your data remains unchanged.`);
            console.error('Password change error:', error);
        }
    }

    async saveTheme() {
        const theme = document.getElementById('theme-select').value;
        this.settings.theme = theme;
        this.applyTheme();
        await this.saveSettingsToServer();
    }

    async saveTimeFormat() {
        const timeFormat = document.getElementById('time-format-select').value;
        this.settings.timeFormat = timeFormat;
        await this.saveSettingsToServer();
        this.renderTimeline(); // Re-render to apply new format
    }

    async saveDateFormat() {
        const dateFormat = document.getElementById('date-format-select').value;
        this.settings.dateFormat = dateFormat;
        await this.saveSettingsToServer();
        this.renderTimeline(); // Re-render to apply new format
    }

    async saveTimeSeparator() {
        const timeSeparator = document.getElementById('time-separator-select').value;
        this.settings.timeSeparator = timeSeparator;
        await this.saveSettingsToServer();
        this.renderTimeline(); // Re-render to apply new separators
    }

    async saveAccentColor() {
        const accentColor = document.getElementById('accent-color').value.trim();
        
        // If field is empty, use default color
        if (accentColor === '') {
            this.settings.accentColor = '#710193';
            this.applyAccentColor();
            await this.saveSettingsToServer();
            return;
        }
        
        // Validate hex color format for non-empty values
        const hexColorRegex = /^#[0-9A-Fa-f]{6}$/;
        if (!hexColorRegex.test(accentColor)) {
            // Reset field to current valid value instead of showing alert
            document.getElementById('accent-color').value = this.settings.accentColor;
            return;
        }
        
        this.settings.accentColor = accentColor;
        this.applyAccentColor();
        await this.saveSettingsToServer();
    }

    applyAccentColor() {
        const color = this.settings.accentColor || '#710193';
        document.documentElement.style.setProperty('--accent-color', color);
    }

    async saveSettingsToServer() {
        try {
            const settingsEncrypted = await cryptoUtils.encrypt(JSON.stringify(this.settings), this.userPassword);
            const displayNameEncrypted = this.settings.displayName ? 
                await cryptoUtils.encrypt(this.settings.displayName, this.userPassword) : null;
            
            const response = await fetch('/api/settings', {
                method: 'POST',
                headers: this.getCsrfHeaders(),
                body: JSON.stringify({
                    settings_encrypted: settingsEncrypted,
                    display_name_encrypted: displayNameEncrypted
                }),
                credentials: 'include'
            });
            
            const data = await response.json();
            
            if (!data.success) {
                this.showError('Settings Error', 'Failed to save settings');
            }
        } catch (error) {
            this.showError('Network Error', 'Network error. Please try again.');
        }
    }

    // Notes functions
    async loadNotes() {
        try {
            const response = await fetch('/api/notes', {
                credentials: 'include'
            });
            
            if (response.ok) {
                const data = await response.json();
                if (data.content_encrypted) {
                    try {
                        this.notes = await cryptoUtils.decrypt(data.content_encrypted, this.userPassword);
                    } catch (error) {
                        console.error('Failed to decrypt notes:', error);
                        this.notes = '';
                    }
                } else {
                    this.notes = '';
                }
            }
        } catch (error) {
            console.error('Failed to load notes:', error);
            this.notes = '';
        }
    }

    async saveNotes() {
        try {
            this.updateNotesStatus('saving');
            const notesEncrypted = await cryptoUtils.encrypt(this.notes, this.userPassword);
            
            const response = await fetch('/api/notes', {
                method: 'POST',
                headers: this.getCsrfHeaders(),
                body: JSON.stringify({
                    content_encrypted: notesEncrypted
                }),
                credentials: 'include'
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.updateNotesStatus('saved');
            } else {
                this.updateNotesStatus('unsaved');
                console.error('Failed to save notes');
            }
        } catch (error) {
            this.updateNotesStatus('unsaved');
            console.error('Failed to save notes:', error);
        }
    }

    updateNotesStatus(status) {
        const statusElement = document.getElementById('notes-status-text');
        if (!statusElement) return;
        
        switch (status) {
            case 'unsaved':
                statusElement.textContent = 'Your notes are unsaved!';
                statusElement.style.color = 'var(--error-color)';
                break;
            case 'saving':
                statusElement.textContent = 'Saving notes...';
                statusElement.style.color = 'var(--text-secondary)';
                break;
            case 'saved':
                statusElement.textContent = 'Your notes are saved.';
                statusElement.style.color = 'var(--success-color)';
                break;
        }
    }

    showNotesOverlay() {
        // Load current notes into textarea
        document.getElementById('notes-textarea').value = this.notes;
        this.showOverlay('notes-overlay');
        
        // Set initial status
        this.updateNotesStatus('saved');
        
        // Setup autosave
        this.setupNotesAutosave();
    }

    setupNotesAutosave() {
        const textarea = document.getElementById('notes-textarea');
        
        // Clear existing timer
        if (this.notesAutosaveTimer) {
            clearTimeout(this.notesAutosaveTimer);
        }
        
        // Remove existing event listener to avoid duplicates
        textarea.removeEventListener('input', this.handleNotesInput);
        
        // Bind the handler to maintain context
        this.handleNotesInput = this.handleNotesInput.bind(this);
        
        // Add event listener for input changes
        textarea.addEventListener('input', this.handleNotesInput);
    }

    handleNotesInput() {
        // Update local notes
        this.notes = document.getElementById('notes-textarea').value;
        
        // Show unsaved status immediately
        this.updateNotesStatus('unsaved');
        
        // Clear existing timer
        if (this.notesAutosaveTimer) {
            clearTimeout(this.notesAutosaveTimer);
        }
        
        // Set timer to save after 1 second of no input
        this.notesAutosaveTimer = setTimeout(() => {
            this.saveNotes();
        }, 1000);
    }

    // Backup functions
    async exportEvents() {
        const exportData = {
            events: this.events.map(event => ({
                title: event.title,
                description: event.description,
                timestamp: event.timestamp.toISOString(),
                tags: event.tags
            })),
            exported_at: new Date().toISOString()
        };
        
        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `timeline_backup_${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        
        URL.revokeObjectURL(url);
    }

    importEvents() {
        document.getElementById('import-file').click();
    }

    async handleImportFile(e) {
        const file = e.target.files[0];
        if (!file) return;
        
        try {
            const text = await file.text();
            const importData = JSON.parse(text);
            
            if (!importData.events || !Array.isArray(importData.events)) {
                this.showError('Import Error', 'Invalid backup file format');
                return;
            }
            
            // Import events
            for (const event of importData.events) {
                try {
                    const titleEncrypted = await cryptoUtils.encrypt(event.title, this.userPassword);
                    const descriptionEncrypted = await cryptoUtils.encrypt(event.description, this.userPassword);
                    const tagsEncrypted = [];
                    
                    for (const tag of event.tags || []) {
                        tagsEncrypted.push(await cryptoUtils.encrypt(tag, this.userPassword));
                    }
                    
                    await fetch('/api/events', {
                        method: 'POST',
                        headers: app.getCsrfHeaders(),
                        body: JSON.stringify({
                            title_encrypted: titleEncrypted,
                            description_encrypted: descriptionEncrypted,
                            event_timestamp: event.timestamp,
                            tag_names_encrypted: tagsEncrypted
                        }),
                        credentials: 'include'
                    });
                } catch (error) {
                    console.error('Failed to import event:', event.title, error);
                }
            }
            
            this.showSuccess('Import Complete', `Successfully imported ${importData.events.length} events`);
            await this.loadUserData();
            this.renderTimeline();
            this.updateEventCounts();
            this.closeOverlay(document.getElementById('backup-overlay'));
            
        } catch (error) {
            this.showError('Import Error', 'Failed to import backup file');
        }
        
        // Reset file input
        e.target.value = '';
    }

    // PDF Export functions
    showPdfExportOverlay() {
        this.populatePdfLabels();
        this.showOverlay('pdf-export-overlay');
    }

    populatePdfLabels() {
        const labelList = document.getElementById('pdf-label-list');
        labelList.innerHTML = '';
        
        if (this.tags.length === 0) {
            labelList.innerHTML = '<p style="text-align: center; color: var(--text-secondary);">No labels available</p>';
            return;
        }
        
        this.tags.forEach(tag => {
            const labelItem = document.createElement('div');
            labelItem.className = 'pdf-label-item';
            
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'pdf-label-checkbox';
            checkbox.id = `pdf-label-${tag.name}`;
            checkbox.value = tag.name;
            
            const label = document.createElement('label');
            label.setAttribute('for', `pdf-label-${tag.name}`);
            label.style.cursor = 'pointer';
            label.style.display = 'flex';
            label.style.alignItems = 'center';
            
            const labelName = document.createElement('span');
            labelName.className = 'pdf-label-name';
            labelName.textContent = tag.name;
            
            label.appendChild(labelName);
            labelItem.appendChild(checkbox);
            labelItem.appendChild(label);
            labelList.appendChild(labelItem);
        });
    }

    async generatePdf() {
        // Get selected labels
        const selectedLabels = [];
        const checkboxes = document.querySelectorAll('.pdf-label-checkbox:checked');
        checkboxes.forEach(cb => {
            selectedLabels.push(cb.value);
        });
        
        // Validate that at least one label is selected
        if (selectedLabels.length === 0) {
            this.showOverlay('pdf-export-error-overlay');
            return;
        }
        
        // Get filename
        let filename = document.getElementById('pdf-filename').value.trim();
        if (!filename) {
            filename = 'export';
        }
        
        // Filter events by selected labels
        const filteredEvents = this.events.filter(event => {
            return event.tags && event.tags.some(tag => selectedLabels.includes(tag));
        });
        
        if (filteredEvents.length === 0) {
            this.showError('Export Error', 'No events found with the selected labels');
            return;
        }
        
        // Generate PDF
        try {
            await this.createPdfDocument(filteredEvents, filename);
            this.closeOverlay(document.getElementById('pdf-export-overlay'));
        } catch (error) {
            console.error('PDF generation failed:', error);
            this.showError('Export Error', 'Failed to generate PDF document');
        }
    }

    async createPdfDocument(events, filename) {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        // Set document properties
        doc.setProperties({
            title: 'Timeline Export',
            subject: 'Timeline Events',
            author: 'Timeline App',
            keywords: 'timeline, events',
            creator: 'Timeline App'
        });
        
        // Set font and colors for black/white theme
        doc.setFont('helvetica');
        doc.setTextColor(0, 0, 0); // Black text
        
        // Convert accent color from hex to RGB
        const hexToRgb = (hex) => {
            const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
            return result ? {
                r: parseInt(result[1], 16),
                g: parseInt(result[2], 16),
                b: parseInt(result[3], 16)
            } : { r: 113, g: 1, b: 147 }; // Default color if parsing fails
        };
        
        const accentColor = this.settings.accentColor || '#710193';
        const rgb = hexToRgb(accentColor);
        
        // Helper function to add page numbers
        const addPageNumber = (pageNum) => {
            const pageWidth = doc.internal.pageSize.width;
            const pageHeight = doc.internal.pageSize.height;
            doc.setFontSize(10);
            doc.setFont('helvetica', 'normal');
            doc.text(`${pageNum}`, pageWidth - 20, pageHeight - 10);
        };
        
        // Add title
        doc.setFontSize(20);
        doc.text('Timeline Export', 20, 20);
        
        // Add export date
        doc.setFontSize(10);
        const exportDate = new Date().toLocaleDateString('en-GB', {
            day: '2-digit',
            month: '2-digit', 
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
        doc.text(`Exported on: ${exportDate}`, 20, 30);
        
        // Sort events by timestamp (oldest first)
        const sortedEvents = [...events].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        
        let yPosition = 50;
        const pageHeight = doc.internal.pageSize.height;
        const lineHeight = 6;
        const marginBottom = 20;
        let currentPageNumber = 1;
        
        // Add page number to first page
        addPageNumber(currentPageNumber);
        
        for (let i = 0; i < sortedEvents.length; i++) {
            const event = sortedEvents[i];
            
            // Check if we need a new page
            if (yPosition > pageHeight - marginBottom - 40) {
                doc.addPage();
                currentPageNumber++;
                addPageNumber(currentPageNumber);
                yPosition = 20;
            }
            
            // Draw timeline line (vertical line on the left)
            doc.setDrawColor(rgb.r, rgb.g, rgb.b);
            doc.setLineWidth(2);
            doc.line(15, yPosition - 5, 15, yPosition + 25);
            
            // Draw timeline dot
            doc.setFillColor(rgb.r, rgb.g, rgb.b);
            doc.circle(15, yPosition + 5, 2, 'F');
            
            // Event title
            doc.setFontSize(14);
            doc.setFont('helvetica', 'bold');
            doc.text(event.title, 25, yPosition);
            
            // Event timestamp
            const timestamp = new Date(event.timestamp).toLocaleString('en-GB', {
                day: '2-digit',
                month: '2-digit',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
            doc.setFontSize(10);
            doc.setFont('helvetica', 'normal');
            const timestampWidth = doc.getStringUnitWidth(timestamp) * 10;
            doc.text(timestamp, doc.internal.pageSize.width - 20 - timestampWidth, yPosition);
            
            yPosition += 8;
            
            // Event description
            doc.setFontSize(11);
            const description = event.description;
            const maxWidth = doc.internal.pageSize.width - 45;
            const descriptionLines = doc.splitTextToSize(description, maxWidth);
            
            for (const line of descriptionLines) {
                if (yPosition > pageHeight - marginBottom - 10) {
                    doc.addPage();
                    currentPageNumber++;
                    addPageNumber(currentPageNumber);
                    yPosition = 20;
                }
                doc.text(line, 25, yPosition);
                yPosition += lineHeight;
            }
            
            // Event tags
            if (event.tags && event.tags.length > 0) {
                yPosition += 2;
                doc.setFontSize(9);
                doc.setFont('helvetica', 'italic');
                const tagsText = `Tags: ${event.tags.join(', ')}`;
                doc.text(tagsText, 25, yPosition);
                yPosition += 6;
            }
            
            yPosition += 10; // Space between events
        }
        
        // Save the PDF
        doc.save(`${filename}.pdf`);
    }

    // Admin password change
    async handleAdminPasswordChange(e) {
        e.preventDefault();
        
        const oldPassword = document.getElementById('admin-old-password').value;
        const newPassword = document.getElementById('admin-new-password').value;
        const confirmPassword = document.getElementById('admin-confirm-password').value;
        
        if (newPassword !== confirmPassword) {
            this.showError('Password Mismatch', 'New passwords do not match');
            return;
        }
        
        // Show confirmation overlay
        this.showAdminPasswordConfirmation();
    }

    async confirmAdminPasswordChange() {
        // Close confirmation overlay
        this.closeOverlay(document.getElementById('admin-password-confirm-overlay'));
        
        const oldPassword = document.getElementById('admin-old-password').value;
        const newPassword = document.getElementById('admin-new-password').value;
        
        try {
            // Step 1: Initialize password change with SRP verification
            const initResponse = await fetch('/api/admin/change-password/init', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({}),
                credentials: 'include'
            });
            
            if (!initResponse.ok) {
                throw new Error('Failed to initialize password change');
            }
            
            const initData = await initResponse.json();
            
            // Step 2: Perform SRP authentication with old password to verify it
            const srpAuth = await window.srpClient.startAuthentication(
                this.currentUser.username,
                oldPassword,
                initData.salt,
                initData.b_pub
            );
            
            // Step 3: Generate new SRP credentials for the new password
            const newCredentials = await window.srpClient.generateCredentials(this.currentUser.username, newPassword);
            
            // Step 4: Verify old password and change to new password
            const response = await fetch('/api/admin/change-password/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    session_id: initData.session_id,
                    a_pub: srpAuth.A,
                    m1: srpAuth.M1,
                    new_salt: newCredentials.salt,
                    new_verifier: newCredentials.verifier
                }),
                credentials: 'include'
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.showSuccess('Password Changed', 'Admin password changed successfully. Please log in again with your new password.');
                this.closeOverlay(document.getElementById('admin-password-overlay'));
                document.getElementById('admin-password-form').reset();
                
                // Log out after password change
                setTimeout(() => {
                    window.location.href = '/';
                }, 2000);
            } else {
                this.showError('Password Change Failed', data.message || 'Failed to change password');
            }
        } catch (error) {
            console.error('Admin password change error:', error);
            this.showError('Network Error', 'Network error. Please try again.');
        }
    }

    // Utility functions
    showOverlay(overlayId) {
        document.getElementById(overlayId).style.display = 'flex';
        
        if (overlayId === 'add-event-overlay') {
            this.renderAvailableTags();
        }
    }

    closeOverlay(overlay) {
        overlay.style.display = 'none';
    }

    showSettingsOverlay() {
        this.showOverlay('settings-overlay');
        // Load 2FA status when opening settings (only for non-admin users)
        if (this.currentUser && !this.currentUser.is_admin) {
            this.load2FAStatus();
        }
        // Update profile picture display
        this.updateProfilePictureDisplay();
        // Show profile tab by default
        this.switchSettingsTab('profile');
    }

    switchSettingsTab(tabName) {
        // Hide all tab contents
        document.querySelectorAll('.settings-tab-content').forEach(content => {
            content.style.display = 'none';
        });
        
        // Remove active class from all tabs
        document.querySelectorAll('.settings-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        
        // Show selected tab content
        const selectedContent = document.getElementById(`settings-${tabName}`);
        if (selectedContent) {
            selectedContent.style.display = 'block';
        }
        
        // Add active class to selected tab
        const selectedTab = document.querySelector(`.settings-tab[data-tab="${tabName}"]`);
        if (selectedTab) {
            selectedTab.classList.add('active');
        }
    }

    showBackupOverlay() {
        this.showOverlay('backup-overlay');
    }

    showAddEventOverlay() {
        this.showOverlay('add-event-overlay');
    }

    showAdminPasswordOverlay() {
        this.showOverlay('admin-password-overlay');
    }

    showPasswordError(message) {
        document.getElementById('password-error-message').textContent = message;
        this.showOverlay('password-error-overlay');
    }

    showPasswordSuccess() {
        this.showOverlay('password-success-overlay');
    }

    showPasswordConfirmation() {
        this.showOverlay('password-confirm-overlay');
    }

    showInfo(title, message) {
        document.getElementById('info-title').textContent = title;
        document.getElementById('info-message').textContent = message;
        this.showOverlay('info-overlay');
    }

    showError(title, message) {
        document.getElementById('error-title').textContent = title;
        document.getElementById('error-message').textContent = message;
        this.showOverlay('error-overlay');
    }

    showSuccess(title, message) {
        document.getElementById('success-title').textContent = title;
        document.getElementById('success-message').textContent = message;
        this.showOverlay('success-overlay');
    }

    showAdminPasswordConfirmation() {
        this.showOverlay('admin-password-confirm-overlay');
    }

    showDeleteConfirmation(title, message, confirmationText, onConfirm) {
        document.getElementById('delete-title').textContent = title;
        document.getElementById('delete-message').textContent = message;
        
        const inputGroup = document.getElementById('confirmation-input-group');
        const confirmationInput = document.getElementById('confirmation-input');
        const confirmationLabel = document.getElementById('confirmation-label');
        
        if (confirmationText) {
            inputGroup.style.display = 'block';
            confirmationLabel.textContent = `Enter "${confirmationText}" to confirm:`;
            confirmationInput.value = '';
        } else {
            inputGroup.style.display = 'none';
        }
        
        // Remove any existing event listener and set up new one
        const confirmBtn = document.getElementById('confirm-delete');
        const newConfirmBtn = confirmBtn.cloneNode(true);
        confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);
        newConfirmBtn.addEventListener('click', onConfirm);
        
        this.showOverlay('delete-confirmation-overlay');
    }

    showElementError(elementId, message) {
        const errorEl = document.getElementById(elementId);
        errorEl.textContent = message;
        errorEl.style.display = 'block';
        
        setTimeout(() => {
            errorEl.style.display = 'none';
        }, 5000);
    }

    handleOutsideClick(e) {
        // Close burger menu if clicking outside
        const burgerMenu = document.getElementById('burger-menu-content');
        const burgerBtn = document.getElementById('burger-btn');
        
        if (burgerMenu.style.display === 'block' && 
            !burgerMenu.contains(e.target) && 
            !burgerBtn.contains(e.target)) {
            burgerMenu.style.display = 'none';
        }
        
        // Close tag filter menu if clicking outside
        const tagFilterMenu = document.getElementById('tag-filter-menu');
        const tagFilterBtn = document.getElementById('tag-filter-btn');
        
        if (tagFilterMenu.style.display === 'block' && 
            !tagFilterMenu.contains(e.target) && 
            !tagFilterBtn.contains(e.target)) {
            tagFilterMenu.style.display = 'none';
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // 2FA Functions
    
    show2FALoginScreen() {
        this.hideAllScreens();
        document.getElementById('twofa-login-screen').style.display = 'flex';
        document.getElementById('twofa-code').value = '';
        document.getElementById('twofa-code').focus();
    }

    abort2FALogin() {
        this.temp2FASessionId = null;
        this.userPassword = null;
        this.currentUser = null;
        this.showLoginScreen();
    }

    async handle2FALogin(e) {
        e.preventDefault();
        
        const totpCode = document.getElementById('twofa-code').value;
        
        if (!this.temp2FASessionId) {
            this.showElementError('twofa-login-error', 'Session expired. Please log in again.');
            setTimeout(() => this.showLoginScreen(), 2000);
            return;
        }
        
        try {
            const response = await fetch('/api/verify-2fa', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    temp_session_id: this.temp2FASessionId,
                    totp_code: totpCode
                }),
                credentials: 'include'
            });
            
            const data = await response.json();
            
            if (data.success) {
                // 2FA verification successful
                this.temp2FASessionId = null;
                // rememberMe was already set in handleLogin, don't override it
                await this.loadUserData();
                this.showUserTimeline();
            } else {
                this.showElementError('twofa-login-error', data.message || '2FA verification failed');
            }
        } catch (error) {
            this.showElementError('twofa-login-error', 'Network error. Please try again.');
        }
    }

    async load2FAStatus() {
        const statusText = document.getElementById('twofa-status-text');
        const enableBtn = document.getElementById('enable-2fa-btn');
        const disableBtn = document.getElementById('disable-2fa-btn');
        
        try {
            const response = await fetch('/api/2fa/status', {
                method: 'GET',
                credentials: 'include'
            });
            
            if (response.ok) {
                try {
                    const data = await response.json();
                    
                    if (data.enabled) {
                        const enabledDate = new Date(data.enabled_at);
                        const formattedDateTime = this.formatDateTime(enabledDate);
                        statusText.textContent = `2FA is enabled. Activated on ${formattedDateTime}.`;
                        enableBtn.style.display = 'none';
                        disableBtn.style.display = 'inline-block';
                    } else {
                        statusText.textContent = '2FA is currently disabled.';
                        enableBtn.style.display = 'inline-block';
                        disableBtn.style.display = 'none';
                    }
                } catch (jsonError) {
                    console.error('Error parsing 2FA status JSON:', jsonError);
                    // Failed to parse JSON, default to disabled
                    statusText.textContent = '2FA is currently disabled.';
                    enableBtn.style.display = 'inline-block';
                    disableBtn.style.display = 'none';
                }
            } else {
                // If the request failed, show an error but still show the enable button
                console.error('2FA status request failed with status:', response.status);
                statusText.textContent = '2FA is currently disabled.';
                enableBtn.style.display = 'inline-block';
                disableBtn.style.display = 'none';
            }
        } catch (error) {
            console.error('Error loading 2FA status:', error);
            // On network error, default to showing the enable button
            statusText.textContent = '2FA is currently disabled.';
            enableBtn.style.display = 'inline-block';
            disableBtn.style.display = 'none';
        }
    }

    startEnable2FA() {
        // Close settings overlay
        this.closeOverlay(document.getElementById('settings-overlay'));
        // Clear previous inputs and errors
        document.getElementById('enable-2fa-step1-password').value = '';
        document.getElementById('enable-2fa-step1-error').style.display = 'none';
        // Show step 1: warning with password input
        this.showOverlay('enable-2fa-step1-overlay');
    }

    async continueEnable2FAStep1(e) {
        e.preventDefault();
        
        // Get password from form
        const password = document.getElementById('enable-2fa-step1-password').value;
        if (!password) {
            this.showElementError('enable-2fa-step1-error', 'Password is required.');
            return;
        }
        
        try {
            // SECURITY FIX: Verify password using SRP authentication
            // Step 1: Initialize SRP authentication for 2FA password verification
            const initResponse = await fetch('/api/2fa/verify-password/init', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({}),
                credentials: 'include'
            });
            
            if (!initResponse.ok) {
                this.showElementError('enable-2fa-step1-error', 'Password verification failed. Please try again.');
                return;
            }
            
            const initData = await initResponse.json();
            const { salt, b_pub, session_id } = initData;
            
            // Step 2: Compute SRP client values
            const srpResult = await window.srpClient.startAuthentication(this.currentUser.username, password, salt, b_pub);
            
            // Step 3: Verify password with server
            const verifyResponse = await fetch('/api/2fa/verify-password/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    session_id: session_id,
                    a_pub: srpResult.A,
                    m1: srpResult.M1
                }),
                credentials: 'include'
            });
            
            const verifyData = await verifyResponse.json();
            
            if (!verifyData.success) {
                this.showElementError('enable-2fa-step1-error', verifyData.message || 'Invalid password');
                return;
            }
            
            // Step 4: Verify server's proof (M2)
            if (verifyData.m2) {
                try {
                    await window.srpClient.verifyServerProof(verifyData.m2);
                } catch (err) {
                    this.showElementError('enable-2fa-step1-error', 'Server authentication failed');
                    return;
                }
            }
            
            // Password verified successfully! Close step 1 and proceed to step 2
            this.closeOverlay(document.getElementById('enable-2fa-step1-overlay'));
            this.setupEnable2FAStep2(password);
        } catch (error) {
            console.error('Password verification error:', error);
            this.showElementError('enable-2fa-step1-error', 'Network error. Please try again.');
        }
    }

    async setupEnable2FAStep2(password) {
        // Store password for use in finishEnable2FA
        this.temp2FAPassword = password;
        
        try {
            // Call setup endpoint to generate 2FA secret
            // Password has already been verified via SRP in continueEnable2FAStep1
            const response = await fetch('/api/2fa/setup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({}),
                credentials: 'include'
            });
            
            const data = await response.json();
            
            if (data.success && data.secret && data.qr_uri) {
                // Store secret temporarily
                this.temp2FASecret = data.secret;
                
                // Display secret
                document.getElementById('totp-secret-display').textContent = data.secret;
                
                // Generate QR code
                const canvas = document.getElementById('twofa-qr-code');
                const qr = new QRious({
                    element: canvas,
                    value: data.qr_uri,
                    size: 250
                });
                
                // Clear secret from local variable immediately after QR generation
                const secretCopy = data.secret;
                data.secret = null;
                
                // Show step 2 overlay
                document.getElementById('verify-totp-code').value = '';
                document.getElementById('enable-2fa-step2-error').style.display = 'none';
                this.showOverlay('enable-2fa-step2-overlay');
            } else {
                this.showError('2FA Setup Error', data.message || 'Failed to generate 2FA secret');
            }
        } catch (error) {
            this.showError('2FA Setup Error', 'Network error. Please try again.');
        }
    }

    async finishEnable2FA(e) {
        e.preventDefault();
        
        const totpCode = document.getElementById('verify-totp-code').value;
        
        if (!this.temp2FASecret) {
            this.showElementError('enable-2fa-step2-error', 'Session expired. Please try again.');
            return;
        }
        
        if (!this.temp2FAPassword) {
            this.showElementError('enable-2fa-step2-error', 'Password not found. Please try again.');
            return;
        }
        
        // Validate TOTP code
        if (totpCode.length !== 6 || !/^\d{6}$/.test(totpCode)) {
            this.showElementError('enable-2fa-step2-error', 'Please enter a valid 6-digit code.');
            return;
        }
        
        try {
            // Derive password hash for TOTP encryption
            const passwordHash = await window.cryptoUtils.derivePasswordHash(this.temp2FAPassword);
            
            const response = await fetch('/api/2fa/enable', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    totp_code: totpCode,
                    password_hash: passwordHash
                }),
                credentials: 'include'
            });
            
            const data = await response.json();
            
            if (data.success) {
                // Aggressively clear temporary data
                if (this.temp2FASecret) {
                    this.temp2FASecret = '\0'.repeat(this.temp2FASecret.length);
                    this.temp2FASecret = null;
                }
                if (this.temp2FAPassword) {
                    this.temp2FAPassword = '\0'.repeat(this.temp2FAPassword.length);
                    this.temp2FAPassword = null;
                }
                
                // Clear QR code
                const canvas = document.getElementById('twofa-qr-code');
                const ctx = canvas.getContext('2d');
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                
                // Clear displayed secret
                document.getElementById('totp-secret-display').textContent = '';
                
                // Close overlay
                this.closeOverlay(document.getElementById('enable-2fa-step2-overlay'));
                
                // Show success message
                this.showSuccess('2FA Enabled', 'Two-Factor Authentication has been successfully enabled for your account.');
                
                // Reload 2FA status in settings (will update when settings is reopened)
                await this.load2FAStatus();
            } else {
                this.showElementError('enable-2fa-step2-error', data.message || 'Failed to enable 2FA');
            }
        } catch (error) {
            this.showElementError('enable-2fa-step2-error', 'Network error. Please try again.');
        }
    }

    startDisable2FA() {
        // Close settings overlay
        this.closeOverlay(document.getElementById('settings-overlay'));
        // Show disable overlay
        document.getElementById('disable-verify-totp-code').value = '';
        document.getElementById('disable-2fa-password').value = '';
        document.getElementById('disable-2fa-error').style.display = 'none';
        this.showOverlay('disable-2fa-overlay');
    }

    async finishDisable2FA(e) {
        e.preventDefault();
        
        const totpCode = document.getElementById('disable-verify-totp-code').value;
        const password = document.getElementById('disable-2fa-password').value;
        
        // Validate TOTP code
        if (totpCode.length !== 6 || !/^\d{6}$/.test(totpCode)) {
            this.showElementError('disable-2fa-error', 'Please enter a valid 6-digit code.');
            return;
        }
        
        try {
            // Derive password hash for TOTP decryption
            const passwordHash = await window.cryptoUtils.derivePasswordHash(password);
            
            const response = await fetch('/api/2fa/disable', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    totp_code: totpCode,
                    password_hash: passwordHash
                }),
                credentials: 'include'
            });
            
            const data = await response.json();
            
            if (data.success) {
                // Close overlay
                this.closeOverlay(document.getElementById('disable-2fa-overlay'));
                
                // Show success message
                this.showSuccess('2FA Disabled', 'Two-Factor Authentication has been disabled for your account.');
                
                // Reload 2FA status in settings
                await this.load2FAStatus();
            } else {
                this.showElementError('disable-2fa-error', data.message || 'Failed to disable 2FA');
            }
        } catch (error) {
            this.showElementError('disable-2fa-error', 'Network error. Please try again.');
        }
    }
}

// Initialize app when page loads
let app;
document.addEventListener('DOMContentLoaded', () => {
    app = new TimelineApp();
});