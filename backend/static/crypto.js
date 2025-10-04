// Client-side encryption utilities for zero-knowledge encryption

class CryptoUtils {
    constructor() {
        this.encoder = new TextEncoder();
        this.decoder = new TextDecoder();
        this.available = !!(window.isSecureContext && window.crypto && window.crypto.subtle);
        
        if (!this.available) {
            console.error('Warning: Unencrypted HTTP connection detected. This connection is not secure.');
            try {
                const banner = document.createElement('div');
                banner.id = 'http-warning';
                banner.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9999;padding:12px;background:#dc3545;color:#fff;text-align:center;font-family:sans-serif;font-weight:bold;box-shadow:0 2px 8px rgba(0,0,0,0.3);';
                banner.innerHTML = '⚠️ WARNING: Unencrypted HTTP Connection ⚠️<br><small style="font-weight:normal;">This connection is not secure. Please use HTTPS for encrypted communication.</small>';
                if (document.readyState === 'loading') {
                    document.addEventListener('DOMContentLoaded', () => {
                        if (document.body) document.body.prepend(banner);
                    });
                } else {
                    if (document.body) document.body.prepend(banner);
                }
            } catch (e) {
                console.error('Failed to show HTTP warning banner:', e);
            }
        }
    }
    
    ensureAvailable() {
        if (!this.available) {
            throw new Error('Web Crypto unavailable: use HTTPS or localhost.');
        }
    }

    // Generate a key from password using PBKDF2
    async generateKey(password, salt) {
        this.ensureAvailable();
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            this.encoder.encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveBits', 'deriveKey']
        );

        return window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    // Generate random salt
    generateSalt() {
        this.ensureAvailable();
        return window.crypto.getRandomValues(new Uint8Array(16));
    }

    // Generate random IV
    generateIV() {
        this.ensureAvailable();
        return window.crypto.getRandomValues(new Uint8Array(12));
    }

    // Encrypt text with password
    async encrypt(text, password) {
        this.ensureAvailable();
        const salt = this.generateSalt();
        const iv = this.generateIV();
        const key = await this.generateKey(password, salt);

        const encrypted = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            this.encoder.encode(text)
        );

        // Combine salt + iv + encrypted data
        const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
        combined.set(salt, 0);
        combined.set(iv, salt.length);
        combined.set(new Uint8Array(encrypted), salt.length + iv.length);

        return btoa(String.fromCharCode(...combined));
    }

    // Decrypt text with password
    async decrypt(encryptedData, password) {
        this.ensureAvailable();
        try {
            const combined = new Uint8Array(atob(encryptedData).split('').map(c => c.charCodeAt(0)));
            
            const salt = combined.slice(0, 16);
            const iv = combined.slice(16, 28);
            const encrypted = combined.slice(28);

            const key = await this.generateKey(password, salt);

            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                key,
                encrypted
            );

            return this.decoder.decode(decrypted);
        } catch (error) {
            console.error('Decryption failed:', error);
            throw new Error('Failed to decrypt data');
        }
    }

    // Generate a random encryption key for new users
    generateRandomKey() {
        this.ensureAvailable();
        const array = new Uint8Array(32);
        window.crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }
}

// Global instance
window.cryptoUtils = new CryptoUtils();