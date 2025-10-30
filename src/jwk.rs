use crate::error::{Result, TangError};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use p256::{
    ecdh::EphemeralSecret,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    EncodedPoint, PublicKey,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
    pub d: Option<String>,
    #[serde(flatten)]
    pub other: HashMap<String, Value>,
}

impl Jwk {
    /// Generate a new EC P-256 key pair
    pub fn generate_ec_p256() -> Result<(Jwk, EphemeralSecret)> {
        let secret = EphemeralSecret::random(&mut OsRng);
        let public_key = PublicKey::from(&secret);
        let encoded = public_key.to_encoded_point(false);

        let x = BASE64_URL_SAFE_NO_PAD.encode(encoded.x().unwrap());
        let y = BASE64_URL_SAFE_NO_PAD.encode(encoded.y().unwrap());

        let jwk = Jwk {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some(x),
            y: Some(y),
            d: None,
            other: HashMap::new(),
        };

        Ok((jwk, secret))
    }

    /// Calculate the key ID (thumbprint) for this JWK
    pub fn thumbprint(&self) -> Result<String> {
        // JWK thumbprint as per RFC 7638
        let canonical = json!({
            "crv": self.crv.as_ref().unwrap_or(&String::new()),
            "kty": &self.kty,
            "x": self.x.as_ref().unwrap_or(&String::new()),
            "y": self.y.as_ref().unwrap_or(&String::new()),
        });

        let canonical_str = serde_json::to_string(&canonical)?;
        let mut hasher = Sha256::new();
        hasher.update(canonical_str.as_bytes());
        let hash = hasher.finalize();

        Ok(BASE64_URL_SAFE_NO_PAD.encode(hash))
    }

    /// Convert JWK to P-256 public key
    pub fn to_public_key(&self) -> Result<PublicKey> {
        if self.kty != "EC" || self.crv.as_deref() != Some("P-256") {
            return Err(TangError::InvalidJwk("Expected EC P-256 key".to_string()));
        }

        let x = self
            .x
            .as_ref()
            .ok_or_else(|| TangError::InvalidJwk("Missing x coordinate".to_string()))?;
        let y = self
            .y
            .as_ref()
            .ok_or_else(|| TangError::InvalidJwk("Missing y coordinate".to_string()))?;

        let x_bytes = BASE64_URL_SAFE_NO_PAD.decode(x)
            .map_err(|e| TangError::InvalidJwk(format!("Invalid x coordinate: {}", e)))?;
        let y_bytes = BASE64_URL_SAFE_NO_PAD.decode(y)
            .map_err(|e| TangError::InvalidJwk(format!("Invalid y coordinate: {}", e)))?;

        let encoded = EncodedPoint::from_affine_coordinates(
            x_bytes.as_slice().into(),
            y_bytes.as_slice().into(),
            false,
        );

        Option::from(PublicKey::from_encoded_point(&encoded))
            .ok_or_else(|| TangError::InvalidJwk("Invalid public key".to_string()))
    }

    /// Validate JWK structure and parameters
    pub fn validate(&self) -> Result<()> {
        // Check key type
        if self.kty.is_empty() {
            return Err(TangError::InvalidJwk("Missing key type".to_string()));
        }

        // Ensure key type is supported
        if self.kty != "EC" {
            return Err(TangError::InvalidJwk(format!(
                "Unsupported key type: {}",
                self.kty
            )));
        }

        // Check curve
        if self.crv.as_deref() != Some("P-256") {
            return Err(TangError::InvalidJwk("Only P-256 curve is supported".to_string()));
        }

        // Validate coordinates exist
        if self.x.is_none() || self.y.is_none() {
            return Err(TangError::InvalidJwk("Missing coordinates".to_string()));
        }

        // Validate coordinate encoding
        if let Some(x) = &self.x {
            BASE64_URL_SAFE_NO_PAD.decode(x)
                .map_err(|_| TangError::InvalidJwk("Invalid x coordinate encoding".to_string()))?;
        }

        if let Some(y) = &self.y {
            BASE64_URL_SAFE_NO_PAD.decode(y)
                .map_err(|_| TangError::InvalidJwk("Invalid y coordinate encoding".to_string()))?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    pub fn add_key(&mut self, key: Jwk) {
        self.keys.push(key);
    }

    /// Find key by ID using constant-time comparison to prevent timing attacks
    pub fn find_by_kid(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| {
            k.other
                .get("kid")
                .and_then(|v| v.as_str())
                .map(|k| {
                    // Use constant-time comparison for key IDs
                    k.as_bytes().ct_eq(kid.as_bytes()).into()
                })
                .unwrap_or(false)
        })
    }
}

impl Default for JwkSet {
    fn default() -> Self {
        Self::new()
    }
}
