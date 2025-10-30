use crate::error::{Result, TangError};
use crate::jwk::{Jwk, JwkSet};
use crate::security::validate_kid;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use walkdir::WalkDir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Key manager for Tang server
pub struct KeyManager {
    db_path: PathBuf,
}

impl KeyManager {
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let db_path = db_path.as_ref().to_path_buf();

        // Create directory if it doesn't exist
        if !db_path.exists() {
            fs::create_dir_all(&db_path)?;

            // Set restrictive permissions on Unix systems (0700 = rwx------)
            #[cfg(unix)]
            {
                let metadata = fs::metadata(&db_path)?;
                let mut permissions = metadata.permissions();
                permissions.set_mode(0o700);
                fs::set_permissions(&db_path, permissions)?;
                info!("Set key directory permissions to 0700");
            }
        } else {
            // Verify existing directory permissions
            Self::verify_directory_permissions(&db_path)?;
        }

        Ok(Self { db_path })
    }

    /// Verify that the key directory has secure permissions
    #[cfg(unix)]
    fn verify_directory_permissions(path: &Path) -> Result<()> {
        let metadata = fs::metadata(path)?;
        let permissions = metadata.permissions();
        let mode = permissions.mode();

        // Check if directory is readable/writable by others (world permissions)
        if mode & 0o007 != 0 {
            warn!("Key directory has world-accessible permissions: {:o}", mode);
            return Err(TangError::ServerError(
                "Key directory has insecure permissions. Should be 0700 or stricter".to_string(),
            ));
        }

        // Check if directory is readable/writable by group
        if mode & 0o070 != 0 {
            warn!("Key directory has group-accessible permissions: {:o}", mode);
        }

        Ok(())
    }

    #[cfg(not(unix))]
    fn verify_directory_permissions(_path: &Path) -> Result<()> {
        // On non-Unix systems, skip permission checks
        Ok(())
    }

    /// Generate a new signing/verification key pair
    pub fn generate_signing_key(&self) -> Result<String> {
        let (mut jwk, _) = Jwk::generate_ec_p256()?;

        // Add key operations
        jwk.other.insert("use".to_string(), json!("sig"));
        jwk.other.insert("alg".to_string(), json!("ES256"));

        let kid = jwk.thumbprint()?;
        jwk.other.insert("kid".to_string(), json!(kid.clone()));

        self.save_key(&kid, &jwk)?;
        Ok(kid)
    }

    /// Generate a new exchange key pair
    pub fn generate_exchange_key(&self) -> Result<String> {
        let (mut jwk, _) = Jwk::generate_ec_p256()?;

        // Add key operations
        jwk.other.insert("use".to_string(), json!("enc"));
        jwk.other.insert("key_ops".to_string(), json!(["deriveKey"]));

        let kid = jwk.thumbprint()?;
        jwk.other.insert("kid".to_string(), json!(kid.clone()));

        self.save_key(&kid, &jwk)?;
        Ok(kid)
    }

    /// Save a key to the database with secure permissions
    fn save_key(&self, kid: &str, jwk: &Jwk) -> Result<()> {
        // Validate kid to prevent path traversal
        validate_kid(kid)?;

        let key_path = self.db_path.join(format!("{}.jwk", kid));
        let json = serde_json::to_string_pretty(jwk)?;

        // Write atomically by writing to temp file first
        let temp_path = key_path.with_extension("jwk.tmp");
        fs::write(&temp_path, json)?;

        // Set restrictive permissions on Unix systems (0600 = rw-------)
        #[cfg(unix)]
        {
            let metadata = fs::metadata(&temp_path)?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(&temp_path, permissions)?;
        }

        // Atomic rename
        fs::rename(temp_path, key_path)?;

        Ok(())
    }

    /// Load a specific key by ID with validation
    pub fn load_key(&self, kid: &str) -> Result<Jwk> {
        // Validate kid to prevent path traversal attacks
        validate_kid(kid)?;

        let key_path = self.db_path.join(format!("{}.jwk", kid));

        // Ensure the path is within the database directory
        if !key_path.starts_with(&self.db_path) {
            return Err(TangError::InvalidKeyFormat(
                "Invalid key path".to_string(),
            ));
        }

        if !key_path.exists() {
            return Err(TangError::KeyNotFound(kid.to_string()));
        }

        let contents = fs::read_to_string(key_path)?;
        let jwk: Jwk = serde_json::from_str(&contents)?;

        // Validate the JWK structure
        jwk.validate()?;

        Ok(jwk)
    }

    /// Load all active (non-hidden) keys
    pub fn load_active_keys(&self) -> Result<JwkSet> {
        let mut jwk_set = JwkSet::new();

        for entry in WalkDir::new(&self.db_path)
            .max_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();

            // Skip hidden files (those starting with '.')
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with('.') || !name.ends_with(".jwk") {
                    continue;
                }
            } else {
                continue;
            }

            if path.is_file() {
                let contents = fs::read_to_string(path)?;
                if let Ok(jwk) = serde_json::from_str::<Jwk>(&contents) {
                    jwk_set.add_key(jwk);
                }
            }
        }

        Ok(jwk_set)
    }

    /// Get signing keys (for advertisement)
    pub fn get_signing_keys(&self) -> Result<Vec<Jwk>> {
        let all_keys = self.load_active_keys()?;
        Ok(all_keys
            .keys
            .into_iter()
            .filter(|k| {
                k.other
                    .get("use")
                    .and_then(|v| v.as_str())
                    .map(|u| u == "sig")
                    .unwrap_or(false)
            })
            .collect())
    }

    /// Get exchange keys (for recovery)
    pub fn get_exchange_keys(&self) -> Result<Vec<Jwk>> {
        let all_keys = self.load_active_keys()?;
        Ok(all_keys
            .keys
            .into_iter()
            .filter(|k| {
                k.other
                    .get("use")
                    .and_then(|v| v.as_str())
                    .map(|u| u == "enc")
                    .unwrap_or(false)
            })
            .collect())
    }

    /// Hide a key (rename to start with '.')
    pub fn hide_key(&self, kid: &str) -> Result<()> {
        let old_path = self.db_path.join(format!("{}.jwk", kid));
        let new_path = self.db_path.join(format!(".{}.jwk", kid));

        if !old_path.exists() {
            return Err(TangError::KeyNotFound(kid.to_string()));
        }

        fs::rename(old_path, new_path)?;
        Ok(())
    }

    /// Get database path
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }
}
