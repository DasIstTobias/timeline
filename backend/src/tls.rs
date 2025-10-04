use axum_server::tls_rustls::RustlsConfig;
use rcgen::generate_simple_self_signed;

pub async fn generate_self_signed_cert() -> Result<RustlsConfig, Box<dyn std::error::Error>> {
    log::info!("Generating self-signed SSL certificate...");
    
    let subject_alt_names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    
    let cert = generate_simple_self_signed(subject_alt_names)?;
    
    let cert_pem = cert.serialize_pem()?;
    let key_pem = cert.serialize_private_key_pem();
    
    // Write certificate and key to temporary files for RustlsConfig
    tokio::fs::write("/tmp/cert.pem", &cert_pem).await?;
    tokio::fs::write("/tmp/key.pem", &key_pem).await?;
    
    log::info!("Self-signed SSL certificate generated successfully");
    
    let config = RustlsConfig::from_pem_file("/tmp/cert.pem", "/tmp/key.pem").await?;
    
    Ok(config)
}
