use num_bigint::BigUint;
use rand::Rng;
use sha2::{Digest, Sha256};
use srp::client::SrpClient;
use srp::groups::G_2048;
use srp::server::SrpServer;
use srp::utils::compute_k;

/// Generate SRP credentials for registration
/// Returns (salt, verifier) as hex strings
pub fn generate_srp_credentials(username: &str, password: &str) -> (String, String) {
    // Generate random salt (32 bytes = 64 hex chars)
    let salt_bytes: [u8; 32] = rand::thread_rng().gen();
    let salt = hex::encode(&salt_bytes);
    
    // Compute verifier using SRP client
    let client = SrpClient::<Sha256>::new(&G_2048);
    
    // Compute identity hash
    let identity_hash = SrpClient::<Sha256>::compute_identity_hash(username.as_bytes(), password.as_bytes());
    
    // Compute x from identity hash and salt
    let x = SrpClient::<Sha256>::compute_x(identity_hash.as_slice(), &salt_bytes);
    
    // Compute verifier
    let verifier = client.compute_v(&x);
    
    (salt, hex::encode(&verifier.to_bytes_be()))
}

/// Represents server's ephemeral data during SRP authentication
pub struct SrpServerEphemeral {
    pub b_pub: Vec<u8>,
    pub b_priv: BigUint,
}

/// Begin SRP authentication (server generates B)
/// Returns server's ephemeral public/private values
pub fn srp_begin_authentication(
    _username: &str,
    _salt: &[u8],
    verifier: &[u8],
) -> Result<SrpServerEphemeral, String> {
    let server = SrpServer::<Sha256>::new(&G_2048);
    
    // Generate server's private ephemeral (b) - random 256-bit number
    let mut b_bytes = [0u8; 32];
    rand::thread_rng().fill(&mut b_bytes);
    let b_priv = BigUint::from_bytes_be(&b_bytes);
    
    // Compute k
    let k = compute_k::<Sha256>(&G_2048);
    
    // Parse verifier
    let v = BigUint::from_bytes_be(verifier);
    
    // Compute server's public ephemeral (B = kv + g^b mod N)
    let b_pub = server.compute_b_pub(&b_priv, &k, &v);
    
    Ok(SrpServerEphemeral {
        b_pub: b_pub.to_bytes_be(),
        b_priv,
    })
}

/// Verify SRP session and compute server proof M2
/// Returns M2 if verification succeeds
pub fn srp_verify_session(
    username: &str,
    salt: &[u8],
    verifier: &[u8],
    a_pub: &[u8],
    b_priv: &BigUint,
    m1_client: &[u8],
) -> Result<Vec<u8>, String> {
    let server = SrpServer::<Sha256>::new(&G_2048);
    
    // Parse values
    let a_pub_big = BigUint::from_bytes_be(a_pub);
    let v = BigUint::from_bytes_be(verifier);
    
    // Compute u
    let b_pub = {
        let k = compute_k::<Sha256>(&G_2048);
        server.compute_b_pub(b_priv, &k, &v)
    };
    let u = srp::utils::compute_u::<Sha256>(&a_pub, &b_pub.to_bytes_be());
    
    // Compute premaster secret (server side)
    let premaster = server.compute_premaster_secret(&a_pub_big, &v, &u, b_priv);
    
    // Compute session key
    let session_key = sha2::Sha256::digest(&premaster.to_bytes_be());
    
    // Verify M1
    let m1_expected = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(a_pub);
        hasher.update(&b_pub.to_bytes_be());
        hasher.update(&session_key);
        hasher.finalize()
    };
    
    if m1_client != m1_expected.as_slice() {
        return Err("M1 verification failed".to_string());
    }
    
    // Compute M2
    let m2 = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(a_pub);
        hasher.update(&m1_expected);
        hasher.update(&session_key);
        hasher.finalize()
    };
    
    Ok(m2.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_credentials() {
        let (salt, verifier) = generate_srp_credentials("testuser", "testpassword");
        assert!(!salt.is_empty());
        assert!(!verifier.is_empty());
        assert_eq!(salt.len(), 64); // 32 bytes = 64 hex chars
    }
    
    #[test]
    fn test_srp_flow() {
        let username = "testuser";
        let password = "testpassword";
        
        // Registration
        let (salt_hex, verifier_hex) = generate_srp_credentials(username, password);
        let salt = hex::decode(&salt_hex).unwrap();
        let verifier = hex::decode(&verifier_hex).unwrap();
        
        // Server side: begin authentication
        let server_eph = srp_begin_authentication(username, &salt, &verifier).unwrap();
        
        // Client side: compute A and M1
        let client = SrpClient::<Sha256>::new(&G_2048);
        
        // Generate a
        let mut a_bytes = [0u8; 32];
        rand::thread_rng().fill(&mut a_bytes);
        let a_priv = BigUint::from_bytes_be(&a_bytes);
        let a_pub = client.compute_a_pub(&a_priv);
        
        // Compute identity hash and x
        let identity_hash = SrpClient::<Sha256>::compute_identity_hash(username.as_bytes(), password.as_bytes());
        let x = SrpClient::<Sha256>::compute_x(identity_hash.as_slice(), &salt);
        
        // Compute k and u
        let k = compute_k::<Sha256>(&G_2048);
        let b_pub_big = BigUint::from_bytes_be(&server_eph.b_pub);
        let u = srp::utils::compute_u::<Sha256>(&a_pub.to_bytes_be(), &server_eph.b_pub);
        
        // Compute premaster secret (client side)
        let premaster = client.compute_premaster_secret(&b_pub_big, &k, &x, &a_priv, &u);
        
        // Compute session key
        use sha2::Digest;
        let session_key = sha2::Sha256::digest(&premaster.to_bytes_be());
        
        // Compute M1
        let m1 = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(&a_pub.to_bytes_be());
            hasher.update(&server_eph.b_pub);
            hasher.update(&session_key);
            hasher.finalize()
        };
        
        // Server side: verify M1 and get M2
        let m2 = srp_verify_session(
            username,
            &salt,
            &verifier,
            &a_pub.to_bytes_be(),
            &server_eph.b_priv,
            m1.as_slice(),
        ).unwrap();
        
        // Client side: verify M2
        let m2_expected = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(&a_pub.to_bytes_be());
            hasher.update(&m1);
            hasher.update(&session_key);
            hasher.finalize()
        };
        
        assert_eq!(m2, m2_expected.as_slice());
    }
}
