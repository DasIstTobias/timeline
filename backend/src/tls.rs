use axum::{
    http::{HeaderMap, StatusCode, HeaderValue, Method, header},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;

#[derive(Clone)]
pub struct TlsConfig {
    pub use_self_signed_ssl: bool,
    pub require_tls: bool,
    pub domains: Vec<String>,
}

impl TlsConfig {
    pub fn from_env() -> Self {
        let use_self_signed_ssl = std::env::var("USE_SELF_SIGNED_SSL")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase() == "true";
        
        let require_tls = std::env::var("REQUIRE_TLS")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase() == "true";
        
        let domain_str = std::env::var("DOMAIN")
            .unwrap_or_else(|_| "localhost".to_string());
        
        let domains = domain_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        
        Self {
            use_self_signed_ssl,
            require_tls,
            domains,
        }
    }
    
    pub fn log_configuration(&self) {
        log::info!("TLS Configuration:");
        log::info!("  USE_SELF_SIGNED_SSL: {}", self.use_self_signed_ssl);
        log::info!("  REQUIRE_TLS: {}", self.require_tls);
        log::info!("  DOMAIN: {}", self.domains.join(", "));
        
        if self.require_tls && self.use_self_signed_ssl {
            log::info!("  Mode: Auto-redirect HTTP to HTTPS with self-signed certificates");
        } else if self.require_tls && !self.use_self_signed_ssl {
            log::info!("  Mode: TLS required (reverse proxy expected)");
        } else if !self.require_tls && self.use_self_signed_ssl {
            log::info!("  Mode: HTTP and self-signed HTTPS both available");
        } else {
            log::info!("  Mode: HTTP and HTTPS (via proxy) both allowed");
        }
    }
}

/// Generate self-signed TLS certificate
pub async fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    log::info!("Generating self-signed TLS certificate...");
    
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, "Timeline Application");
    params.distinguished_name.push(DnType::OrganizationName, "Timeline");
    
    // Add Subject Alternative Names for common localhost variants
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".to_string()),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        rcgen::SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
    ];
    
    let cert = Certificate::from_params(params)?;
    let cert_pem = cert.serialize_pem()?.into_bytes();
    let key_pem = cert.serialize_private_key_pem().into_bytes();
    
    log::info!("Self-signed certificate generated successfully");
    Ok((cert_pem, key_pem))
}

/// Create CORS layer based on configured domains
pub fn create_cors_layer(domains: &[String]) -> CorsLayer {
    let mut origins = Vec::new();
    
    // Handle localhost specially
    if domains.iter().any(|d| d == "localhost") {
        origins.push("http://localhost:8080".parse::<HeaderValue>().unwrap());
        origins.push("http://127.0.0.1:8080".parse::<HeaderValue>().unwrap());
        origins.push("https://localhost:8443".parse::<HeaderValue>().unwrap());
        origins.push("https://127.0.0.1:8443".parse::<HeaderValue>().unwrap());
        log::info!("CORS: Added localhost origins (8080 HTTP, 8443 HTTPS)");
    }
    
    // Add all other domains
    for domain in domains {
        if domain != "localhost" && domain != "127.0.0.1" {
            origins.push(format!("http://{}:8080", domain).parse::<HeaderValue>().unwrap());
            origins.push(format!("https://{}:8443", domain).parse::<HeaderValue>().unwrap());
            log::info!("CORS: Added domain '{}' (8080 HTTP, 8443 HTTPS)", domain);
        }
    }
    
    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST])
        .allow_credentials(true)
        .allow_headers([header::CONTENT_TYPE, header::COOKIE])
}

/// Check if request is over TLS (either direct or via proxy)
pub fn check_tls_requirement(
    headers: &HeaderMap,
    require_tls: bool,
    is_https_port: bool,
) -> Result<(), StatusCode> {
    if !require_tls {
        return Ok(());
    }
    
    // If this is the HTTPS port (8443), TLS is definitely present
    if is_https_port {
        return Ok(());
    }
    
    // Check X-Forwarded-Proto header set by reverse proxy
    if let Some(proto) = headers.get("x-forwarded-proto") {
        if proto.to_str().unwrap_or("") == "https" {
            return Ok(());
        }
    }
    
    log::warn!("TLS required but request not over HTTPS");
    Err(StatusCode::FORBIDDEN)
}

/// Check if domain is allowed based on Host header
pub fn check_domain_allowed(headers: &HeaderMap, allowed_domains: &[String]) -> Result<(), StatusCode> {
    // Try multiple headers to find the host information
    // HTTP/1.1 uses "host", HTTP/2 uses ":authority" pseudo-header
    let host_header = headers.get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| {
            // Try :authority for HTTP/2
            headers.iter()
                .find(|(name, _)| name.as_str() == ":authority")
                .and_then(|(_, value)| value.to_str().ok())
        })
        .unwrap_or("");
    
    // Debug: log all headers if Host is missing
    if host_header.is_empty() {
        log::warn!("Host/:authority header missing. Available headers:");
        for (name, value) in headers.iter() {
            log::warn!("  {}: {:?}", name, value);
        }
        log::warn!("No Host or :authority header provided, blocking request");
        return Err(StatusCode::FORBIDDEN);
    }
    
    log::info!("Domain check: Host header = '{}', Allowed domains = {:?}", host_header, allowed_domains);
    
    // Extract hostname without port
    // Handle IPv6 addresses in brackets like [::1]:8080
    let hostname = if host_header.starts_with('[') {
        // IPv6 address in brackets - extract content between brackets
        host_header.split(']').next()
            .and_then(|s| s.strip_prefix('['))
            .unwrap_or(host_header)
    } else {
        // Regular hostname or IPv4 - split by : and take first part
        host_header.split(':').next().unwrap_or(host_header)
    };
    
    log::info!("Extracted hostname: '{}'", hostname);
    
    // Check if hostname matches any allowed domain (case-insensitive for domain names)
    let hostname_lower = hostname.to_lowercase();
    let is_allowed = allowed_domains.iter().any(|domain| {
        let domain_lower = domain.to_lowercase();
        let matches = if domain_lower == "localhost" {
            hostname_lower == "localhost" || hostname == "127.0.0.1" || hostname == "::1"
        } else {
            hostname_lower == domain_lower
        };
        log::info!("Checking '{}' against '{}': {}", hostname, domain, matches);
        matches
    });
    
    if !is_allowed {
        log::warn!("Domain '{}' not in allowed list {:?}, blocking request", hostname, allowed_domains);
        return Err(StatusCode::FORBIDDEN);
    }
    
    log::info!("Domain '{}' allowed", hostname);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn test_check_domain_allowed_with_localhost() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("localhost:8080"));
        
        let allowed_domains = vec!["localhost".to_string()];
        let result = check_domain_allowed(&headers, &allowed_domains);
        
        assert!(result.is_ok(), "localhost should be allowed");
    }

    #[test]
    fn test_check_domain_allowed_with_localhost_ip() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("127.0.0.1:8080"));
        
        let allowed_domains = vec!["localhost".to_string()];
        let result = check_domain_allowed(&headers, &allowed_domains);
        
        assert!(result.is_ok(), "127.0.0.1 should be allowed when localhost is configured");
    }

    #[test]
    fn test_check_domain_allowed_with_ipv6_localhost() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("[::1]:8080"));
        
        let allowed_domains = vec!["localhost".to_string()];
        let result = check_domain_allowed(&headers, &allowed_domains);
        
        assert!(result.is_ok(), "::1 should be allowed when localhost is configured");
    }

    #[test]
    fn test_check_domain_allowed_with_custom_domain() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("example.com:8080"));
        
        let allowed_domains = vec!["example.com".to_string()];
        let result = check_domain_allowed(&headers, &allowed_domains);
        
        assert!(result.is_ok(), "example.com should be allowed");
    }

    #[test]
    fn test_check_domain_allowed_with_ip_address() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("192.168.1.10:8080"));
        
        let allowed_domains = vec!["192.168.1.10".to_string()];
        let result = check_domain_allowed(&headers, &allowed_domains);
        
        assert!(result.is_ok(), "IP address should be allowed when explicitly configured");
    }

    #[test]
    fn test_check_domain_allowed_blocks_unknown_domain() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("evil.com:8080"));
        
        let allowed_domains = vec!["localhost".to_string()];
        let result = check_domain_allowed(&headers, &allowed_domains);
        
        assert!(result.is_err(), "evil.com should be blocked");
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_check_domain_allowed_blocks_unknown_ip() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("192.168.1.100:8080"));
        
        let allowed_domains = vec!["localhost".to_string()];
        let result = check_domain_allowed(&headers, &allowed_domains);
        
        assert!(result.is_err(), "Unknown IP should be blocked");
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_check_domain_allowed_blocks_missing_host_header() {
        let headers = HeaderMap::new();
        
        let allowed_domains = vec!["localhost".to_string()];
        let result = check_domain_allowed(&headers, &allowed_domains);
        
        assert!(result.is_err(), "Missing Host header should be blocked");
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_check_domain_allowed_with_multiple_domains() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("example.com:8080"));
        
        let allowed_domains = vec!["localhost".to_string(), "example.com".to_string(), "test.com".to_string()];
        let result = check_domain_allowed(&headers, &allowed_domains);
        
        assert!(result.is_ok(), "example.com should be allowed in multi-domain list");
    }

    #[test]
    fn test_check_domain_allowed_without_port() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("localhost"));
        
        let allowed_domains = vec!["localhost".to_string()];
        let result = check_domain_allowed(&headers, &allowed_domains);
        
        assert!(result.is_ok(), "localhost without port should be allowed");
    }

    #[test]
    fn test_check_domain_allowed_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("EXAMPLE.COM:8443"));
        
        let allowed_domains = vec!["example.com".to_string()];
        let result = check_domain_allowed(&headers, &allowed_domains);
        
        assert!(result.is_ok(), "Domain matching should be case-insensitive");
    }

    #[test]
    fn test_check_domain_allowed_localhost_uppercase() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("LOCALHOST:8443"));
        
        let allowed_domains = vec!["localhost".to_string()];
        let result = check_domain_allowed(&headers, &allowed_domains);
        
        assert!(result.is_ok(), "Localhost should be case-insensitive");
    }
}

/// Start HTTP server on port 8080
pub async fn start_http_server(
    app: Router,
    tls_config: Arc<RwLock<TlsConfig>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = tls_config.read().await.clone();
    
    // If both REQUIRE_TLS and USE_SELF_SIGNED_SSL are true, redirect HTTP to HTTPS
    let final_app = if config.require_tls && config.use_self_signed_ssl {
        log::info!("HTTP server will redirect all traffic to HTTPS");
        Router::new().fallback(|uri: axum::http::Uri, headers: HeaderMap| async move {
            let host = headers.get(header::HOST)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("localhost");
            
            // Replace port in host if present
            let host_without_port = host.split(':').next().unwrap_or(host);
            let new_location = format!("https://{}:8443{}", host_without_port, uri.path());
            
            (
                StatusCode::MOVED_PERMANENTLY,
                [(header::LOCATION, new_location)],
                "Redirecting to HTTPS"
            )
        })
    } else {
        app
    };
    
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    log::info!("HTTP server starting on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, final_app).await?;
    
    Ok(())
}

/// Start HTTPS server on port 8443 with self-signed certificate
pub async fn start_https_server(
    app: Router,
) -> Result<(), Box<dyn std::error::Error>> {
    let (cert_pem, key_pem) = generate_self_signed_cert().await?;
    
    // Write to temporary files for RustlsConfig
    let cert_path = "/tmp/timeline_cert.pem";
    let key_path = "/tmp/timeline_key.pem";
    
    tokio::fs::write(cert_path, &cert_pem).await?;
    tokio::fs::write(key_path, &key_pem).await?;
    
    let tls_config = RustlsConfig::from_pem_file(cert_path, key_path).await?;
    
    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    log::info!("HTTPS server starting on {}", addr);
    
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await?;
    
    Ok(())
}
