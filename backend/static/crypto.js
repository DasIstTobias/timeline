// Client-side encryption utilities for zero-knowledge encryption

class CryptoUtils {
    constructor() {
        this.encoder = new TextEncoder();
        this.decoder = new TextDecoder();
    }

    // Generate a key from password using PBKDF2
    async generateKey(password, salt) {
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
        return window.crypto.getRandomValues(new Uint8Array(16));
    }

    // Generate random IV
    generateIV() {
        return window.crypto.getRandomValues(new Uint8Array(12));
    }

    // Encrypt text with password
    async encrypt(text, password) {
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
        const array = new Uint8Array(32);
        window.crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    // Derive a consistent password hash for TOTP encryption and authentication
    // Uses PBKDF2 with a fixed salt to derive a deterministic hash from password
    async derivePasswordHash(password) {
        const encoder = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveBits']
        );
        
        const salt = encoder.encode('timeline_auth_hash'); // Fixed salt for auth hash derivation
        const bits = await window.crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            256
        );
        
        return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
    }
}

// Global instance
window.cryptoUtils = new CryptoUtils();