use crate::error::{Result, TangError};
use std::time::Duration;

/// Security configuration for the Tang server
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Maximum request body size (bytes)
    pub max_body_size: usize,
    /// Request timeout
    pub request_timeout: Duration,
    /// Rate limit: requests per second per IP
    pub rate_limit_per_second: u32,
    /// Rate limit burst size
    pub rate_limit_burst: u32,
    /// Enable HTTPS/TLS
    pub enable_tls: bool,
    /// TLS certificate path
    pub tls_cert_path: Option<String>,
    /// TLS key path
    pub tls_key_path: Option<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_body_size: 16 * 1024, // 16KB - reasonable for JWK
            request_timeout: Duration::from_secs(10),
            rate_limit_per_second: 100,
            rate_limit_burst: 200,
            enable_tls: false,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

impl SecurityConfig {
    /// Create a secure production configuration
    pub fn secure() -> Self {
        Self {
            max_body_size: 8 * 1024, // 8KB - stricter limit
            request_timeout: Duration::from_secs(5),
            rate_limit_per_second: 50,
            rate_limit_burst: 100,
            enable_tls: true,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }

    /// Validate the security configuration
    pub fn validate(&self) -> Result<()> {
        if self.max_body_size == 0 {
            return Err(TangError::ServerError(
                "max_body_size must be greater than 0".to_string(),
            ));
        }

        if self.max_body_size > 1024 * 1024 {
            return Err(TangError::ServerError(
                "max_body_size too large (max 1MB)".to_string(),
            ));
        }

        if self.rate_limit_per_second == 0 {
            return Err(TangError::ServerError(
                "rate_limit_per_second must be greater than 0".to_string(),
            ));
        }

        if self.enable_tls {
            if self.tls_cert_path.is_none() {
                return Err(TangError::ServerError(
                    "TLS enabled but no certificate path provided".to_string(),
                ));
            }
            if self.tls_key_path.is_none() {
                return Err(TangError::ServerError(
                    "TLS enabled but no key path provided".to_string(),
                ));
            }
        }

        Ok(())
    }
}

/// Validate key ID format to prevent path traversal and injection attacks
pub fn validate_kid(kid: &str) -> Result<()> {
    // Check length
    if kid.is_empty() {
        return Err(TangError::InvalidKeyFormat("Key ID is empty".to_string()));
    }

    if kid.len() > 256 {
        return Err(TangError::InvalidKeyFormat(
            "Key ID too long".to_string(),
        ));
    }

    // Check for path traversal attempts
    if kid.contains("..") || kid.contains('/') || kid.contains('\\') {
        return Err(TangError::InvalidKeyFormat(
            "Key ID contains invalid characters".to_string(),
        ));
    }

    // Check for control characters
    if kid.chars().any(|c| c.is_control()) {
        return Err(TangError::InvalidKeyFormat(
            "Key ID contains control characters".to_string(),
        ));
    }

    // Ensure it's valid base64url characters
    let valid_chars = kid
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');

    if !valid_chars {
        return Err(TangError::InvalidKeyFormat(
            "Key ID contains invalid characters for base64url".to_string(),
        ));
    }

    Ok(())
}

/// Sanitize error messages to prevent information disclosure
pub fn sanitize_error_message(error: &str, detailed: bool) -> String {
    if detailed {
        error.to_string()
    } else {
        // In production, don't reveal internal details
        match error {
            e if e.contains("Key not found") => "Key not found".to_string(),
            e if e.contains("Invalid") => "Invalid request".to_string(),
            _ => "Internal server error".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_kid_valid() {
        assert!(validate_kid("abc123-_").is_ok());
        assert!(validate_kid("5vxI4stGNSe4fzQOny2x9Ac_1Ny-psdXBLWsasSNw2U").is_ok());
    }

    #[test]
    fn test_validate_kid_invalid() {
        assert!(validate_kid("").is_err());
        assert!(validate_kid("../etc/passwd").is_err());
        assert!(validate_kid("key/id").is_err());
        assert!(validate_kid("key\\id").is_err());
        assert!(validate_kid("key\x00id").is_err());
        assert!(validate_kid("key id").is_err()); // space is invalid
    }

    #[test]
    fn test_security_config_validation() {
        let mut config = SecurityConfig::default();
        assert!(config.validate().is_ok());

        config.max_body_size = 0;
        assert!(config.validate().is_err());

        config.max_body_size = 10 * 1024 * 1024; // 10MB
        assert!(config.validate().is_err());
    }
}
