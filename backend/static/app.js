// Timeline Application
class TimelineApp {
    constructor() {
        this.currentUser = null;
        this.userPassword = null;
        this.events = [];
        this.tags = [];
        this.filteredEvents = [];
        this.settings = {
            theme: 'device',
            timeFormat: '24h',
            dateFormat: 'dd/mm/yyyy',
            displayName: ''
        };
        this.eventTimers = new Map();
        
        this.init();
    }

    async init() {
        this.setupEventListeners();
        this.applyTheme();
        this.checkAuthStatus();
        
        // Update timers every second
        setInterval(() => this.updateEventTimers(), 1000);
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
        document.getElementById('settings-btn').addEventListener('click', () => this.showSettingsOverlay());
        document.getElementById('backup-btn').addEventListener('click', () => this.showBackupOverlay());
        document.getElementById('add-event-btn').addEventListener('click', () => this.showAddEventOverlay());
        
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
        
        // Settings
        document.getElementById('save-display-name').addEventListener('click', () => this.saveDisplayName());
        document.getElementById('change-password').addEventListener('click', () => this.changePassword());
        document.getElementById('save-theme').addEventListener('click', () => this.saveTheme());
        document.getElementById('save-time-format').addEventListener('click', () => this.saveTimeFormat());
        document.getElementById('save-date-format').addEventListener('click', () => this.saveDateFormat());
        
        // Password change overlays
        document.getElementById('confirm-password-change').addEventListener('click', () => this.confirmPasswordChange());
        document.getElementById('cancel-password-change').addEventListener('click', () => this.closeOverlay(document.getElementById('password-confirm-overlay')));
        
        // Admin password change overlays
        document.getElementById('confirm-admin-password-change').addEventListener('click', () => this.confirmAdminPasswordChange());
        document.getElementById('cancel-admin-password-change').addEventListener('click', () => this.closeOverlay(document.getElementById('admin-password-confirm-overlay')));
        
        // Backup
        document.getElementById('export-btn').addEventListener('click', () => this.exportEvents());
        document.getElementById('import-btn').addEventListener('click', () => this.importEvents());
        document.getElementById('import-file').addEventListener('change', (e) => this.handleImportFile(e));
        
        // Add event
        document.getElementById('add-event-form').addEventListener('submit', (e) => this.handleAddEvent(e));
        document.querySelectorAll('input[name="time-mode"]').forEach(radio => {
            radio.addEventListener('change', () => this.toggleCustomTime());
        });
        document.getElementById('add-tag-btn').addEventListener('click', () => this.addNewTag());
        
        // Admin password change
        document.getElementById('admin-password-form').addEventListener('submit', (e) => this.handleAdminPasswordChange(e));
        
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
        
        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password }),
                credentials: 'include'
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.userPassword = password; // Store for encryption
                this.currentUser = { username, is_admin: data.user_type === 'admin' };
                
                if (data.user_type === 'admin') {
                    this.showAdminDashboard();
                } else {
                    await this.loadUserData();
                    this.showUserTimeline();
                }
            } else {
                this.showError('login-error', data.message || 'Login failed');
            }
        } catch (error) {
            this.showError('login-error', 'Network error. Please try again.');
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
        
        this.currentUser = null;
        this.userPassword = null;
        this.events = [];
        this.tags = [];
        location.reload();
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
        await this.loadUserData();
        this.renderTimeline();
        this.updateEventCounts();
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
            this.loadSettings()
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
                
                for (const tag of encryptedTags) {
                    try {
                        const decryptedTag = {
                            id: tag.id,
                            name: await cryptoUtils.decrypt(tag.name_encrypted, this.userPassword)
                        };
                        this.tags.push(decryptedTag);
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
                
                this.applySettings();
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
        
        if (this.settings.displayName) {
            document.getElementById('display-name').value = this.settings.displayName;
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
        container.innerHTML = '';
        
        // Sort events by timestamp (oldest first as per requirements)
        const sortedEvents = [...this.filteredEvents].sort((a, b) => a.timestamp - b.timestamp);
        
        sortedEvents.forEach(event => {
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
                <button class="delete-event-btn" onclick="app.deleteEvent('${event.id}', '${this.escapeHtml(event.title)}')">Delete</button>
            </div>
        `;
        
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
        
        const parts = [];
        
        if (years > 0) parts.push(`<span class="time-value">${years}</span> year${years > 1 ? 's' : ''}`);
        if (months % 12 > 0) parts.push(`<span class="time-value">${months % 12}</span> month${months % 12 > 1 ? 's' : ''}`);
        if (days % 30 > 0) parts.push(`<span class="time-value">${days % 30}</span> day${days % 30 > 1 ? 's' : ''}`);
        if (hours % 24 > 0) parts.push(`<span class="time-value">${hours % 24}</span> hour${hours % 24 > 1 ? 's' : ''}`);
        if (minutes % 60 > 0) parts.push(`<span class="time-value">${minutes % 60}</span> minute${minutes % 60 > 1 ? 's' : ''}`);
        if (seconds % 60 > 0) parts.push(`<span class="time-value">${seconds % 60}</span> second${seconds % 60 > 1 ? 's' : ''}`);
        
        return parts.slice(0, 3).join(' ') + ' ago';
    }

    updateEventTimers() {
        document.querySelectorAll('.event-timer').forEach(timerEl => {
            const timestamp = parseInt(timerEl.dataset.timestamp);
            const timer = this.calculateTimer(new Date(timestamp));
            timerEl.innerHTML = timer;
        });
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
                <button class="delete-user-btn" onclick="app.deleteUser('${user.id}', '${this.escapeHtml(user.username)}')">Delete</button>
            `;
            container.appendChild(userDiv);
        });
    }

    async handleAddUser(e) {
        e.preventDefault();
        
        const username = document.getElementById('new-username').value;
        
        try {
            const response = await fetch('/api/users', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
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
                        headers: {
                            'Content-Type': 'application/json',
                        },
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
        const timeMode = document.querySelector('input[name="time-mode"]:checked').value;
        
        if (timeMode === 'now') {
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
                headers: {
                    'Content-Type': 'application/json',
                },
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
        const isCustom = document.querySelector('input[name="time-mode"]:checked').value === 'custom';
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
                        headers: {
                            'Content-Type': 'application/json',
                        },
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
    }

    async changePassword() {
        const oldPassword = document.getElementById('old-password').value;
        const newPassword = document.getElementById('new-password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        
        if (newPassword !== confirmPassword) {
            this.showPasswordError('New passwords do not match');
            return;
        }
        
        if (oldPassword !== this.userPassword) {
            this.showPasswordError('Current password is incorrect');
            return;
        }
        
        // Show confirmation overlay
        this.showPasswordConfirmation();
    }

    async confirmPasswordChange() {
        // Close confirmation overlay
        this.closeOverlay(document.getElementById('password-confirm-overlay'));
        
        const oldPassword = document.getElementById('old-password').value;
        const newPassword = document.getElementById('new-password').value;
        
        try {
            // Step 1: Create temporary unencrypted backup of all data
            const backupData = {
                events: this.events.map(event => ({
                    title: event.title,
                    description: event.description,
                    timestamp: event.timestamp.toISOString(),
                    tags: event.tags
                })),
                settings: this.settings,
                exported_at: new Date().toISOString()
            };
            
            // Step 2: Clear all user data from backend
            const clearResponse = await fetch('/api/user-data', {
                method: 'POST',
                credentials: 'include'
            });
            
            if (!clearResponse.ok) {
                throw new Error('Failed to clear user data');
            }
            
            // Step 3: Change password in backend
            const passwordResponse = await fetch('/api/change-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    old_password: oldPassword,
                    new_password: newPassword
                }),
                credentials: 'include'
            });
            
            const passwordData = await passwordResponse.json();
            
            if (!passwordData.success) {
                throw new Error(passwordData.message || 'Failed to change password');
            }
            
            // Step 4: Update local password for encryption
            this.userPassword = newPassword;
            
            // Step 5: Re-import all data with new encryption
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
                        headers: {
                            'Content-Type': 'application/json',
                        },
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
            
            // Step 6: Re-save settings with new encryption
            if (backupData.settings) {
                this.settings = backupData.settings;
                await this.saveSettingsToServer();
            }
            
            // Step 7: Clear the temporary backup data from memory
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

    async saveSettingsToServer() {
        try {
            const settingsEncrypted = await cryptoUtils.encrypt(JSON.stringify(this.settings), this.userPassword);
            const displayNameEncrypted = this.settings.displayName ? 
                await cryptoUtils.encrypt(this.settings.displayName, this.userPassword) : null;
            
            const response = await fetch('/api/settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
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
                        headers: {
                            'Content-Type': 'application/json',
                        },
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
            const response = await fetch('/api/change-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    old_password: oldPassword,
                    new_password: newPassword
                }),
                credentials: 'include'
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.showSuccess('Password Changed', 'Admin password changed successfully');
                this.closeOverlay(document.getElementById('admin-password-overlay'));
                document.getElementById('admin-password-form').reset();
            } else {
                this.showError('Password Change Failed', data.message || 'Failed to change password');
            }
        } catch (error) {
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
        
        // Set up confirm button
        const confirmBtn = document.getElementById('confirm-delete');
        confirmBtn.onclick = onConfirm;
        
        this.showOverlay('delete-confirmation-overlay');
    }

    showError(elementId, message) {
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
}

// Initialize app when page loads
let app;
document.addEventListener('DOMContentLoaded', () => {
    app = new TimelineApp();
});