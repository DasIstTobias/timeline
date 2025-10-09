use rand::Rng;
use sha2::Sha256;
use srp::groups::G_2048;
use srp::client::SrpClient;
use srp::server::{SrpServer, UserRecord};

/// Generate SRP credentials for registration
/// Returns (salt, verifier) as hex strings
pub fn generate_srp_credentials(username: &str, password: &str) -> (String, String) {
    // Generate random salt (32 bytes = 64 hex chars)
    let salt_bytes: [u8; 32] = rand::thread_rng().gen();
    let salt = hex::encode(&salt_bytes);
    
    // Compute verifier using SRP
    let client = SrpClient::<Sha256>::new(&G_2048);
    let verifier = client.compute_verifier(username.as_bytes(), password.as_bytes(), &salt_bytes);
    
    (salt, hex::encode(&verifier))
}

/// Represents server's ephemeral data during SRP authentication
pub struct SrpServerEphemeral {
    pub b_pub: Vec<u8>,
    pub b_priv: Vec<u8>,
}

/// Begin SRP authentication (server generates B)
/// Returns server's ephemeral public/private values
pub fn srp_begin_authentication(
    username: &str,
    salt: &[u8],
    verifier: &[u8],
) -> Result<SrpServerEphemeral, String> {
    let server = SrpServer::<Sha256>::new(&G_2048);
    
    // Generate server's private ephemeral (b)
    let b_priv = server.generate_b();
    
    // Compute server's public ephemeral (B)
    let user_record = UserRecord {
        username: username.as_bytes(),
        salt,
        verifier,
    };
    
    let b_pub = server.compute_b(&b_priv, &user_record)
        .map_err(|e| format!("Failed to compute B: {:?}", e))?;
    
    Ok(SrpServerEphemeral {
        b_pub,
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
    b_priv: &[u8],
    m1_client: &[u8],
) -> Result<Vec<u8>, String> {
    let server = SrpServer::<Sha256>::new(&G_2048);
    
    let user_record = UserRecord {
        username: username.as_bytes(),
        salt,
        verifier,
    };
    
    // Verify M1 and get session proof
    let proof = server.verify_a_and_m1(&user_record, a_pub, b_priv, m1_client)
        .map_err(|e| format!("SRP verification failed: {:?}", e))?;
    
    Ok(proof.m2().to_vec())
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
        let a_priv = client.generate_a();
        let a_pub = client.compute_a(&a_priv);
        
        let client_proof = client.process_b(username.as_bytes(), password.as_bytes(), &salt, &a_priv, &server_eph.b_pub)
            .unwrap();
        
        // Server side: verify M1 and get M2
        let m2 = srp_verify_session(
            username,
            &salt,
            &verifier,
            &a_pub,
            &server_eph.b_priv,
            client_proof.m1(),
        ).unwrap();
        
        // Client side: verify M2
        client_proof.verify_m2(&m2).unwrap();
    }
}
