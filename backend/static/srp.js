// Minimal SRP-6a client implementation for browser
// Based on RFC 5054 (SRP for TLS Authentication)

class SRPClient {
    constructor() {
        // SRP Group parameters (2048-bit MODP Group from RFC 5054)
        // N = 2^2048 - 2^1984 - 1 + 2^64 * floor(2^1918 π + 124476)
        this.N_hex = 'AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73';
        this.g = 2; // Generator
        
        // k = H(N || PAD(g))
        this.k_hex = '5b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300';
    }

    // Convert hex string to byte array
    hexToBytes(hex) {
        const bytes = [];
        for (let i = 0; i < hex.length; i += 2) {
            bytes.push(parseInt(hex.substr(i, 2), 16));
        }
        return new Uint8Array(bytes);
    }

    // Convert byte array to hex string
    bytesToHex(bytes) {
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Generate random bytes
    randomBytes(length) {
        return crypto.getRandomValues(new Uint8Array(length));
    }

    // SHA-256 hash
    async sha256(data) {
        const buffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
        const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
        return new Uint8Array(hashBuffer);
    }

    // Compute identity hash H(username || ':' || password)
    async computeIdentityHash(username, password) {
        const combined = username + ':' + password;
        return await this.sha256(combined);
    }

    // Compute x = H(salt || identity_hash)
    async computeX(salt, identityHash) {
        const saltBytes = this.hexToBytes(salt);
        const combined = new Uint8Array(saltBytes.length + identityHash.length);
        combined.set(saltBytes);
        combined.set(identityHash, saltBytes.length);
        return await this.sha256(combined);
    }

    // Big integer operations using native BigInt
    // Modular exponentiation: base^exp mod modulus
    modPow(base, exp, modulus) {
        if (typeof base === 'string') base = BigInt('0x' + base);
        if (typeof exp === 'string') exp = BigInt('0x' + exp);
        if (typeof modulus === 'string') modulus = BigInt('0x' + modulus);
        
        let result = 1n;
        base = base % modulus;
        
        while (exp > 0n) {
            if (exp % 2n === 1n) {
                result = (result * base) % modulus;
            }
            exp = exp >> 1n;
            base = (base * base) % modulus;
        }
        
        return result;
    }

    // Convert BigInt to hex string with padding
    bigIntToHex(value, minLength = 0) {
        let hex = value.toString(16);
        if (hex.length % 2 === 1) hex = '0' + hex;
        while (hex.length < minLength * 2) hex = '00' + hex;
        return hex;
    }

    // Generate client credentials (for registration)
    async generateCredentials(username, password) {
        // Generate random salt
        const saltBytes = this.randomBytes(32);
        const salt = this.bytesToHex(saltBytes);
        
        // Compute identity hash
        const identityHash = await this.computeIdentityHash(username, password);
        
        // Compute x
        const xBytes = await this.computeX(salt, identityHash);
        const x = BigInt('0x' + this.bytesToHex(xBytes));
        
        // Compute verifier v = g^x mod N
        const N = BigInt('0x' + this.N_hex);
        const g = BigInt(this.g);
        const v = this.modPow(g, x, N);
        
        return {
            salt: salt,
            verifier: this.bigIntToHex(v)
        };
    }

    // Start authentication (client step 1)
    async startAuthentication(username, password, serverSalt, serverBPub) {
        // Parse server values
        const N = BigInt('0x' + this.N_hex);
        const g = BigInt(this.g);
        const k = BigInt('0x' + this.k_hex);
        const B = BigInt('0x' + serverBPub);
        
        // Compute identity hash
        const identityHash = await this.computeIdentityHash(username, password);
        
        // Compute x
        const xBytes = await this.computeX(serverSalt, identityHash);
        const x = BigInt('0x' + this.bytesToHex(xBytes));
        
        // Generate random a (256 bits)
        const aBytes = this.randomBytes(32);
        const a = BigInt('0x' + this.bytesToHex(aBytes));
        
        // Compute A = g^a mod N
        const A = this.modPow(g, a, N);
        const A_hex = this.bigIntToHex(A);
        
        // Compute u = H(A || B)
        const A_bytes = this.hexToBytes(A_hex);
        const B_bytes = this.hexToBytes(serverBPub);
        const u_input = new Uint8Array(A_bytes.length + B_bytes.length);
        u_input.set(A_bytes);
        u_input.set(B_bytes, A_bytes.length);
        const u_hash = await this.sha256(u_input);
        const u = BigInt('0x' + this.bytesToHex(u_hash));
        
        // Compute client premaster secret: S = (B - kg^x)^(a + ux) mod N
        const gx = this.modPow(g, x, N);
        const kgx = (k * gx) % N;
        let base = (B - kgx) % N;
        if (base < 0n) base += N;
        
        const exp = (a + u * x) % (N - 1n);
        const S = this.modPow(base, exp, N);
        
        // Compute session key K = H(S)
        const S_hex = this.bigIntToHex(S);
        const S_bytes = this.hexToBytes(S_hex);
        const K = await this.sha256(S_bytes);
        
        // Compute M1 = H(A || B || K)
        const m1_input = new Uint8Array(A_bytes.length + B_bytes.length + K.length);
        m1_input.set(A_bytes);
        m1_input.set(B_bytes, A_bytes.length);
        m1_input.set(K, A_bytes.length + B_bytes.length);
        const M1 = await this.sha256(m1_input);
        
        // Store for M2 verification
        this.sessionKey = K;
        this.A_bytes = A_bytes;
        this.M1 = M1;
        
        return {
            A: A_hex,
            M1: this.bytesToHex(M1)
        };
    }

    // Verify server response (client step 2)
    async verifyServerProof(serverM2) {
        const M2_bytes = this.hexToBytes(serverM2);
        
        // Compute expected M2 = H(A || M1 || K)
        const m2_input = new Uint8Array(this.A_bytes.length + this.M1.length + this.sessionKey.length);
        m2_input.set(this.A_bytes);
        m2_input.set(this.M1, this.A_bytes.length);
        m2_input.set(this.sessionKey, this.A_bytes.length + this.M1.length);
        const expectedM2 = await this.sha256(m2_input);
        
        // Compare
        if (this.bytesToHex(expectedM2) !== serverM2) {
            throw new Error('Server authentication failed');
        }
        
        return true;
    }
}

// Export as global
window.srpClient = new SRPClient();
