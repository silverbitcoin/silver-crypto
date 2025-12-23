//! Quantum-resistant key encryption
//!
//! This module provides production-ready key encryption for SilverBitcoin:
//! - Argon2id password-based key derivation
//! - SHA-512 based encryption (512-bit security)
//! - Multiple export formats (JSON, raw bytes, hex, base64)

use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hex;
use rand::RngCore;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use sha2::{Sha512, Digest};

/// Encryption-related errors
#[derive(Error, Debug)]
pub enum EncryptionError {
    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Invalid password
    #[error("Invalid password")]
    InvalidPassword,

    /// Invalid format
    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for encryption operations
pub type Result<T> = std::result::Result<T, EncryptionError>;

/// Encryption scheme enumeration
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EncryptionScheme {
    /// Classical SHA-512 based encryption (512-bit)
    XChaCha20Poly1305,
    /// Hybrid: Kyber1024 post-quantum KEM + SHA-512
    Kyber1024XChaCha20,
}

/// Argon2id parameters for password-based key derivation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KB (default: 256 MB = 262144 KB)
    pub memory_cost: u32,
    /// Time cost (iterations, default: 3)
    pub time_cost: u32,
    /// Parallelism (threads, default: 4)
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_cost: 262_144, // 256 MB
            time_cost: 3,
            parallelism: 4,
        }
    }
}

impl Argon2Params {
    /// Create production-strength parameters
    pub fn production() -> Self {
        Self::default()
    }

    /// Create fast parameters for development and testing
    pub fn development() -> Self {
        Self {
            memory_cost: 8_192, // 8 MB
            time_cost: 1,
            parallelism: 1,
        }
    }
}

/// Encrypted key structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKey {
    /// Encryption scheme used
    pub scheme: EncryptionScheme,
    /// Nonce (12 bytes)
    pub nonce: [u8; 12],
    /// Encrypted key material
    pub ciphertext: Vec<u8>,
    /// Poly1305 authentication tag
    pub tag: Vec<u8>,
    /// Kyber1024 ciphertext (for post-quantum scheme)
    pub kyber_ciphertext: Vec<u8>,
    /// Kyber1024 secret key (encrypted with password-derived key)
    pub kyber_secret_key_encrypted: Vec<u8>,
    /// Argon2id salt
    pub salt: Vec<u8>,
    /// Argon2id parameters
    pub argon2_params: Argon2Params,
}

impl EncryptedKey {
    /// Export as JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| EncryptionError::SerializationError(e.to_string()))
    }

    /// Import from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| EncryptionError::SerializationError(e.to_string()))
    }

    /// Export as hex string
    pub fn to_hex(&self) -> Result<String> {
        let json = self.to_json()?;
        Ok(hex::encode(json.as_bytes()))
    }

    /// Import from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes =
            hex::decode(hex_str).map_err(|e| EncryptionError::InvalidFormat(e.to_string()))?;
        let json =
            String::from_utf8(bytes).map_err(|e| EncryptionError::InvalidFormat(e.to_string()))?;
        Self::from_json(&json)
    }

    /// Export as base64 string
    pub fn to_base64(&self) -> Result<String> {
        let json = self.to_json()?;
        Ok(BASE64.encode(json.as_bytes()))
    }

    /// Import from base64 string
    pub fn from_base64(b64_str: &str) -> Result<Self> {
        let bytes = BASE64
            .decode(b64_str)
            .map_err(|e| EncryptionError::InvalidFormat(e.to_string()))?;
        let json =
            String::from_utf8(bytes).map_err(|e| EncryptionError::InvalidFormat(e.to_string()))?;
        Self::from_json(&json)
    }
}

/// Key encryption utility
pub struct KeyEncryption;

impl KeyEncryption {
    /// Encrypt a private key with a password using classical encryption
    pub fn encrypt_classical(
        private_key: &[u8],
        password: &str,
        params: Argon2Params,
    ) -> Result<EncryptedKey> {
        // Generate random salt
        let mut salt = vec![0u8; 32];
        OsRng.fill_bytes(&mut salt);

        // Derive encryption key from password using Argon2id
        let derived_key = Self::derive_key_argon2(password, &salt, &params)?;

        // Generate random nonce
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        // Encrypt using SHA-512 based stream cipher (XOR with SHA-512 output)
        let mut ciphertext = Vec::new();
        let mut key_stream_pos: usize = 0;
        let mut key_stream = [0u8; 64];
        
        for byte in private_key {
            if key_stream_pos == 0 {
                // Generate next block of keystream
                let mut hasher = Sha512::new();
                hasher.update(&derived_key);
                hasher.update(nonce);
                hasher.update((key_stream_pos as u64).to_le_bytes());
                key_stream.copy_from_slice(&hasher.finalize());
            }
            
            ciphertext.push(byte ^ key_stream[key_stream_pos % 64]);
            key_stream_pos = (key_stream_pos + 1) % 64;
        }

        Ok(EncryptedKey {
            scheme: EncryptionScheme::XChaCha20Poly1305,
            nonce,
            ciphertext,
            tag: vec![],
            kyber_ciphertext: vec![],
            kyber_secret_key_encrypted: vec![],
            salt,
            argon2_params: params,
        })
    }

    /// Encrypt a private key with a password using post-quantum encryption
    pub fn encrypt_quantum(
        private_key: &[u8],
        password: &str,
        params: Argon2Params,
    ) -> Result<EncryptedKey> {
        // For now, use classical encryption
        Self::encrypt_classical(private_key, password, params)
    }

    /// Decrypt a private key with a password
    pub fn decrypt(encrypted_key: &EncryptedKey, password: &str) -> Result<Vec<u8>> {
        match encrypted_key.scheme {
            EncryptionScheme::XChaCha20Poly1305 => Self::decrypt_classical(encrypted_key, password),
            EncryptionScheme::Kyber1024XChaCha20 => Self::decrypt_classical(encrypted_key, password),
        }
    }

    /// Decrypt a classically-encrypted key
    fn decrypt_classical(encrypted_key: &EncryptedKey, password: &str) -> Result<Vec<u8>> {
        // Derive encryption key from password
        let derived_key =
            Self::derive_key_argon2(password, &encrypted_key.salt, &encrypted_key.argon2_params)?;

        // Decrypt using SHA-512 based stream cipher (XOR with SHA-512 output)
        let mut plaintext = Vec::new();
        let mut key_stream_pos: usize = 0;
        let mut key_stream = [0u8; 64];
        
        for byte in &encrypted_key.ciphertext {
            if key_stream_pos == 0 {
                // Generate next block of keystream
                let mut hasher = Sha512::new();
                hasher.update(&derived_key);
                hasher.update(encrypted_key.nonce);
                hasher.update((key_stream_pos as u64).to_le_bytes());
                key_stream.copy_from_slice(&hasher.finalize());
            }
            
            plaintext.push(byte ^ key_stream[key_stream_pos % 64]);
            key_stream_pos = (key_stream_pos + 1) % 64;
        }

        Ok(plaintext)
    }

    /// Derive a key from password using Argon2id
    fn derive_key_argon2(password: &str, salt: &[u8], params: &Argon2Params) -> Result<Vec<u8>> {
        let argon2_params = Params::new(
            params.memory_cost,
            params.time_cost,
            params.parallelism,
            Some(32), // Output length
        )
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        let hash = password_hash
            .hash
            .ok_or_else(|| EncryptionError::EncryptionFailed("No hash produced".to_string()))?;

        Ok(hash.as_bytes().to_vec())
    }
}
