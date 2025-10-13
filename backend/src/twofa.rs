use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use totp_lite::{totp, Sha256};

// Brute-force protection: track failed attempts per identifier (IP or session)
pub struct TwoFABruteForceProtection {
    failed_attempts: Arc<RwLock<HashMap<String, FailedAttemptInfo>>>,
}

struct FailedAttemptInfo {
    count: u32,
    lockout_until: Option<SystemTime>,
}

impl TwoFABruteForceProtection {
    pub fn new() -> Self {
        Self {
            failed_attempts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn check_and_update(&self, identifier: &str, success: bool) -> Result<(), String> {
        let mut attempts = self.failed_attempts.write().await;
        let now = SystemTime::now();

        let info = attempts.entry(identifier.to_string()).or_insert(FailedAttemptInfo {
            count: 0,
            lockout_until: None,
        });

        // Check if currently locked out
        if let Some(lockout_until) = info.lockout_until {
            if now < lockout_until {
                let remaining = lockout_until.duration_since(now).unwrap_or(Duration::from_secs(0));
                return Err(format!("Too many failed attempts. Try again in {} seconds.", remaining.as_secs()));
            } else {
                // Lockout expired, reset
                info.count = 0;
                info.lockout_until = None;
            }
        }

        if success {
            // Reset on success
            info.count = 0;
            info.lockout_until = None;
        } else {
            // Increment failed attempts
            info.count += 1;

            // Apply progressive lockout
            if info.count >= 10 {
                // 10+ attempts: 1 hour lockout
                info.lockout_until = Some(now + Duration::from_secs(3600));
                return Err("Too many failed attempts. Try again in 3600 seconds.".to_string());
            } else if info.count >= 5 {
                // 5-9 attempts: 5 minutes lockout
                info.lockout_until = Some(now + Duration::from_secs(300));
                return Err("Too many failed attempts. Try again in 300 seconds.".to_string());
            } else if info.count >= 3 {
                // 3-4 attempts: 30 seconds lockout
                info.lockout_until = Some(now + Duration::from_secs(30));
                return Err("Too many failed attempts. Try again in 30 seconds.".to_string());
            }
        }

        Ok(())
    }

    // Clean up old entries periodically (can be called from a background task)
    #[allow(dead_code)]
    pub async fn cleanup_old_entries(&self) {
        let mut attempts = self.failed_attempts.write().await;
        let now = SystemTime::now();
        
        attempts.retain(|_, info| {
            if let Some(lockout_until) = info.lockout_until {
                // Keep entries that are still in lockout or have recent activity
                now < lockout_until + Duration::from_secs(3600)
            } else {
                // Keep entries with failed attempts from the last hour
                info.count > 0
            }
        });
    }
}

/// Generate a random TOTP secret (base32 encoded)
pub fn generate_totp_secret() -> String {
    const BASE32_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut rng = rand::thread_rng();
    
    // Generate 20 random bytes (160 bits, standard for TOTP)
    let secret: String = (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..BASE32_CHARS.len());
            BASE32_CHARS[idx] as char
        })
        .collect();
    
    secret
}

/// Verify a TOTP code against a secret using constant-time comparison
pub fn verify_totp_code(secret: &str, code: &str) -> bool {
    // Decode base32 secret
    let secret_bytes = match base32_decode(secret) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    // Get current timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Check current time, 30 seconds before AND after to account for clock skew (90s total window)
    // This provides better tolerance for devices with clock drift
    for offset in [-30i64, 0, 30] {
        let test_timestamp = (timestamp as i64 + offset) as u64;
        let generated_code = totp::<Sha256>(&secret_bytes, test_timestamp);
        
        // totp() returns a String, but it may not always be 6 digits
        // Extract the last 6 digits
        let code_num: u64 = generated_code.parse().unwrap_or(0);
        let code_6_digit = format!("{:06}", code_num % 1000000);
        
        // Use constant-time comparison to prevent timing attacks
        if constant_time_compare(&code_6_digit, code) {
            return true;
        }
    }

    false
}

/// Constant-time string comparison to prevent timing attacks
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

/// Generate the TOTP provisioning URI for QR codes
/// Now uses SHA-256 algorithm (more secure than SHA-1)
pub fn generate_totp_uri(secret: &str, username: &str, issuer: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA256&digits=6&period=30",
        urlencoding::encode(issuer),
        urlencoding::encode(username),
        secret,
        urlencoding::encode(issuer)
    )
}

/// Decode base32 string to bytes
fn base32_decode(input: &str) -> Result<Vec<u8>, String> {
    const BASE32_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    
    let input = input.to_uppercase().replace('=', "");
    let mut bits = 0u64;
    let mut bit_count = 0;
    let mut output = Vec::new();

    for ch in input.chars() {
        let value = BASE32_CHARS
            .find(ch)
            .ok_or_else(|| format!("Invalid base32 character: {}", ch))? as u64;

        bits = (bits << 5) | value;
        bit_count += 5;

        if bit_count >= 8 {
            output.push((bits >> (bit_count - 8)) as u8);
            bit_count -= 8;
            bits &= (1 << bit_count) - 1;
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secret() {
        let secret = generate_totp_secret();
        assert_eq!(secret.len(), 32);
        assert!(secret.chars().all(|c| "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".contains(c)));
    }

    #[test]
    fn test_base32_decode() {
        let decoded = base32_decode("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(decoded, b"Hello!");
    }

    #[test]
    fn test_totp_uri_generation() {
        let uri = generate_totp_uri("JBSWY3DPEHPK3PXP", "user@example.com", "Timeline");
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(uri.contains("issuer=Timeline"));
    }
}
