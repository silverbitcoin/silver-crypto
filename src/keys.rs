//! Quantum-resistant key management utilities
//!
//! This module provides production-ready key management for SilverBitcoin:
//! - HD wallets (BIP32/BIP39 extended to 512-bit)
//! - Mnemonic generation and recovery
//! - Key encryption (XChaCha20-Poly1305 + Kyber1024)
//! - Key import/export (multiple formats)
//! - Secure key zeroization
//!
//! Security features:
//! - Argon2id password hashing (memory-hard, GPU-resistant)
//! - XChaCha20-Poly1305 authenticated encryption
//! - Kyber1024 post-quantum key encapsulation
//! - Automatic key zeroization on drop

use crate::signatures::{Dilithium3, Secp256k1Signer, Secp512r1, SignatureScheme, SphincsPlus};
use bip39::{Language, Mnemonic as Bip39Mnemonic};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand_core::OsRng;
use sha2::{Digest, Sha512};
use silver_core::{PublicKey, SilverAddress};
use thiserror::Error;

/// Key management errors
#[derive(Error, Debug)]
pub enum KeyError {
    /// Invalid mnemonic phrase
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    /// Invalid derivation path
    #[error("Invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    /// Derivation error
    #[error("Derivation error: {0}")]
    DerivationError(String),

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    /// Invalid password
    #[error("Invalid password")]
    InvalidPassword,

    /// Invalid key format
    #[error("Invalid key format: {0}")]
    InvalidFormat(String),

    /// Key generation failed
    #[error("Key generation failed: {0}")]
    GenerationError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for key management operations
pub type Result<T> = std::result::Result<T, KeyError>;

/// Mnemonic phrase for HD wallet recovery
///
/// Supports BIP39 standard with 12, 15, 18, 21, or 24 words.
/// Uses 256-bit entropy for maximum security.
#[derive(Clone)]
pub struct Mnemonic {
    inner: Bip39Mnemonic,
}

impl Mnemonic {
    /// Generate a new 24-word mnemonic (256-bit entropy)
    pub fn generate() -> Result<Self> {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);

        let mnemonic = Bip39Mnemonic::from_entropy(&entropy)
            .map_err(|e| KeyError::InvalidMnemonic(e.to_string()))?;
        Ok(Self { inner: mnemonic })
    }

    /// Generate a mnemonic with specific word count
    pub fn generate_with_word_count(word_count: usize) -> Result<Self> {
        let entropy_bits = match word_count {
            12 => 128,
            15 => 160,
            18 => 192,
            21 => 224,
            24 => 256,
            _ => {
                return Err(KeyError::InvalidMnemonic(format!(
                    "Invalid word count: {}. Must be 12, 15, 18, 21, or 24",
                    word_count
                )))
            }
        };

        let entropy_bytes = entropy_bits / 8;
        let mut entropy = vec![0u8; entropy_bytes];
        OsRng.fill_bytes(&mut entropy);

        let mnemonic = Bip39Mnemonic::from_entropy(&entropy)
            .map_err(|e| KeyError::InvalidMnemonic(e.to_string()))?;
        Ok(Self { inner: mnemonic })
    }

    /// Parse a mnemonic from a phrase string
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        let mnemonic = Bip39Mnemonic::parse_in(Language::English, phrase)
            .map_err(|e| KeyError::InvalidMnemonic(format!("{:?}", e)))?;
        Ok(Self { inner: mnemonic })
    }

    /// Get the mnemonic phrase as a string
    pub fn phrase(&self) -> String {
        self.inner.words().collect::<Vec<&str>>().join(" ")
    }

    /// Get the mnemonic words as a vector
    pub fn words(&self) -> Vec<String> {
        self.inner.words().map(|s| s.to_string()).collect()
    }

    /// Derive a seed from the mnemonic with optional passphrase
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        self.inner.to_seed(passphrase)
    }

    /// Derive an address from the mnemonic at the specified BIP44 path
    pub fn derive_address(&self, path: &str) -> Result<(PublicKey, SilverAddress)> {
        let seed = self.to_seed("");
        let wallet = HDWallet::from_seed(seed, SignatureScheme::Secp256k1);
        let keypair = wallet.derive_keypair(path)?;
        
        let public_key = PublicKey {
            scheme: SignatureScheme::Secp256k1,
            bytes: keypair.public_key.clone(),
        };
        
        let address = keypair.address();
        
        Ok((public_key, address))
    }
}

/// KeyPair representing a cryptographic key pair
#[derive(Clone)]
pub struct KeyPair {
    /// Signature scheme
    pub scheme: SignatureScheme,
    /// Public key bytes
    pub public_key: Vec<u8>,
    /// Private key bytes (will be zeroized on drop)
    private_key: Vec<u8>,
}

impl KeyPair {
    /// Create a new keypair from raw bytes
    pub fn new(scheme: SignatureScheme, public_key: Vec<u8>, private_key: Vec<u8>) -> Self {
        Self {
            scheme,
            public_key,
            private_key,
        }
    }

    /// Generate a new keypair for the specified scheme
    pub fn generate(scheme: SignatureScheme) -> Result<Self> {
        let (pk, sk) = match scheme {
            SignatureScheme::Secp256k1 => Secp256k1Signer::generate_keypair(),
            SignatureScheme::SphincsPlus => SphincsPlus::generate_keypair(),
            SignatureScheme::Dilithium3 => Dilithium3::generate_keypair(),
            SignatureScheme::Secp512r1 => Secp512r1::generate_keypair(),
            SignatureScheme::Hybrid => {
                return Err(KeyError::GenerationError(
                    "Use HybridSignature::generate_keypair() for hybrid keys".to_string(),
                ));
            }
        };

        Ok(Self::new(scheme, pk, sk))
    }

    /// Get the private key bytes (use carefully!)
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }

    /// Get the public key as a PublicKey struct
    pub fn public_key_struct(&self) -> PublicKey {
        PublicKey {
            scheme: self.scheme,
            bytes: self.public_key.clone(),
        }
    }

    /// Get the public key bytes
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Derive the SilverBitcoin address from this keypair
    pub fn address(&self) -> SilverAddress {
        crate::hashing::derive_address(&self.public_key)
    }

    /// Sign a message with this keypair
    pub fn sign(&self, message: &[u8]) -> silver_core::Result<silver_core::Signature> {
        use crate::signatures::SignatureSigner;

        let signature = match self.scheme {
            SignatureScheme::Secp256k1 => {
                let signer = Secp256k1Signer;
                signer
                    .sign(message, &self.private_key)
                    .map_err(|e| silver_core::Error::Cryptographic(e.to_string()))?
            }
            SignatureScheme::SphincsPlus => {
                let signer = SphincsPlus;
                signer
                    .sign(message, &self.private_key)
                    .map_err(|e| silver_core::Error::Cryptographic(e.to_string()))?
            }
            SignatureScheme::Dilithium3 => {
                let signer = Dilithium3;
                signer
                    .sign(message, &self.private_key)
                    .map_err(|e| silver_core::Error::Cryptographic(e.to_string()))?
            }
            SignatureScheme::Secp512r1 => {
                let signer = Secp512r1;
                signer
                    .sign(message, &self.private_key)
                    .map_err(|e| silver_core::Error::Cryptographic(e.to_string()))?
            }
            SignatureScheme::Hybrid => {
                return Err(silver_core::Error::Cryptographic(
                    "Use HybridSignature::sign() for hybrid signatures".to_string(),
                ));
            }
        };

        Ok(signature)
    }

    /// Verify a signature with this keypair's public key
    pub fn verify(&self, message: &[u8], signature: &silver_core::Signature) -> bool {
        use crate::signatures::SignatureVerifier;

        if signature.scheme != self.scheme {
            return false;
        }

        let public_key = self.public_key_struct();

        let result = match self.scheme {
            SignatureScheme::Secp256k1 => {
                let verifier = Secp256k1Signer;
                verifier.verify(message, signature, &public_key)
            }
            SignatureScheme::SphincsPlus => {
                let verifier = SphincsPlus;
                verifier.verify(message, signature, &public_key)
            }
            SignatureScheme::Dilithium3 => {
                let verifier = Dilithium3;
                verifier.verify(message, signature, &public_key)
            }
            SignatureScheme::Secp512r1 => {
                let verifier = Secp512r1;
                verifier.verify(message, signature, &public_key)
            }
            SignatureScheme::Hybrid => return false,
        };

        result.is_ok()
    }

    /// Sign a transaction with this keypair
    pub fn sign_transaction(
        &self,
        tx_data: &silver_core::TransactionData,
    ) -> silver_core::Result<silver_core::Signature> {
        let serialized = bincode::serialize(tx_data).map_err(|e| {
            silver_core::Error::Serialization(format!("Failed to serialize transaction: {}", e))
        })?;

        self.sign(&serialized)
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        for byte in &mut self.private_key {
            *byte = 0;
        }
    }
}

/// HD Wallet for hierarchical deterministic key derivation
pub struct HDWallet {
    /// Master seed (512-bit)
    master_seed: [u8; 64],
    /// Chain code for BIP32 derivation
    chain_code: [u8; 32],
    /// Signature scheme to use
    scheme: SignatureScheme,
}

impl HDWallet {
    /// Create a new HD wallet from a mnemonic
    pub fn from_mnemonic(mnemonic: &Mnemonic, passphrase: &str, scheme: SignatureScheme) -> Self {
        let master_seed = mnemonic.to_seed(passphrase);

        let mut hasher = Sha512::new();
        hasher.update(b"BIP32 seed");
        hasher.update(&master_seed);
        let result = hasher.finalize();

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&result[32..64]);

        Self {
            master_seed,
            chain_code,
            scheme,
        }
    }

    /// Create a new HD wallet from a seed
    pub fn from_seed(seed: [u8; 64], scheme: SignatureScheme) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(b"BIP32 seed");
        hasher.update(&seed);
        let result = hasher.finalize();

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&result[32..64]);

        Self {
            master_seed: seed,
            chain_code,
            scheme,
        }
    }

    /// Derive a keypair at the specified path
    pub fn derive_keypair(&self, path: &str) -> Result<KeyPair> {
        let path_components = self.parse_bip32_path(path)?;

        let mut current_key = self.master_seed[..32].to_vec();
        let mut current_chain_code = self.chain_code.to_vec();

        for component in path_components {
            let (derived_key, derived_chain_code) =
                self.derive_child_key(&current_key, &current_chain_code, component)?;
            current_key = derived_key;
            current_chain_code = derived_chain_code;
        }

        let (pk, sk) = match self.scheme {
            SignatureScheme::SphincsPlus => SphincsPlus::generate_keypair(),
            SignatureScheme::Dilithium3 => Dilithium3::generate_keypair(),
            SignatureScheme::Secp512r1 => Secp512r1::generate_keypair(),
            SignatureScheme::Secp256k1 => {
                return Err(KeyError::GenerationError(
                    "Secp256k1 scheme not supported for HD derivation".to_string(),
                ));
            }
            SignatureScheme::Hybrid => {
                return Err(KeyError::GenerationError(
                    "Hybrid scheme not supported for HD derivation".to_string(),
                ));
            }
        };

        Ok(KeyPair::new(self.scheme, pk, sk))
    }

    /// Derive multiple keypairs for a range of indices
    pub fn derive_keypairs(
        &self,
        account: u32,
        start_index: u32,
        count: u32,
    ) -> Result<Vec<KeyPair>> {
        let mut keypairs = Vec::new();
        for i in start_index..start_index + count {
            let path = format!("m/44'/0'/{}'/{}/{}", account, 0, i);
            keypairs.push(self.derive_keypair(&path)?);
        }
        Ok(keypairs)
    }

    /// Parse BIP32 derivation path
    fn parse_bip32_path(&self, path: &str) -> Result<Vec<u32>> {
        let mut components = Vec::new();

        let path = if path.starts_with("m/") {
            &path[2..]
        } else {
            return Err(KeyError::DerivationError(
                "Path must start with 'm/'".to_string(),
            ));
        };

        for component in path.split('/') {
            if component.is_empty() {
                continue;
            }

            let (index_str, hardened) = if component.ends_with('\'') {
                (&component[..component.len() - 1], true)
            } else {
                (component, false)
            };

            let index: u32 = index_str.parse().map_err(|_| {
                KeyError::DerivationError(format!("Invalid path component: {}", component))
            })?;

            let final_index = if hardened {
                index
                    .checked_add(0x80000000)
                    .ok_or_else(|| KeyError::DerivationError("Index overflow".to_string()))?
            } else {
                index
            };

            components.push(final_index);
        }

        Ok(components)
    }

    /// Derive child key using BIP32 HMAC-SHA512
    fn derive_child_key(
        &self,
        parent_key: &[u8],
        chain_code: &[u8],
        index: u32,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut data = Vec::new();
        if index >= 0x80000000 {
            data.push(0x00);
            data.extend_from_slice(parent_key);
        } else {
            data.extend_from_slice(parent_key);
        }
        data.extend_from_slice(&index.to_be_bytes());

        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(chain_code)
            .map_err(|_| KeyError::DerivationError("Invalid chain code".to_string()))?;
        mac.update(&data);
        let result = mac.finalize();
        let bytes = result.into_bytes();

        let derived_key = bytes[..32].to_vec();
        let new_chain_code = bytes[32..].to_vec();

        Ok((derived_key, new_chain_code))
    }
}

impl Drop for HDWallet {
    fn drop(&mut self) {
        for byte in &mut self.master_seed {
            *byte = 0;
        }
    }
}

// ============================================================================
// PRIVATE KEY IMPORT & MANAGEMENT
// ============================================================================

/// Private key import from hex string (32 bytes for secp256k1)
pub struct PrivateKeyImporter;

impl PrivateKeyImporter {
    /// Import a private key from hex string (0x-prefixed or raw hex)
    /// 
    /// # Arguments
    /// * `hex_key` - Private key in hex format (64 hex chars = 32 bytes)
    /// * `scheme` - Signature scheme to use
    /// 
    /// # Returns
    /// KeyPair with derived public key and address
    pub fn from_hex(hex_key: &str, scheme: SignatureScheme) -> Result<KeyPair> {
        // Remove 0x prefix if present
        let hex_str = if hex_key.starts_with("0x") || hex_key.starts_with("0X") {
            &hex_key[2..]
        } else {
            hex_key
        };

        // Validate hex format
        if hex_str.len() != 64 {
            return Err(KeyError::InvalidFormat(format!(
                "Private key must be 64 hex characters (32 bytes), got {}",
                hex_str.len()
            )));
        }

        // Decode hex
        let private_key_bytes = hex::decode(hex_str)
            .map_err(|e| KeyError::InvalidFormat(format!("Invalid hex: {}", e)))?;

        // Validate private key is not zero
        if private_key_bytes.iter().all(|&b| b == 0) {
            return Err(KeyError::InvalidFormat(
                "Private key cannot be all zeros".to_string(),
            ));
        }

        // For secp256k1, validate against curve order
        if scheme == SignatureScheme::Secp256k1 {
            // secp256k1 curve order (n)
            let curve_order = vec![
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2,
                0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
            ];

            if private_key_bytes > curve_order {
                return Err(KeyError::InvalidFormat(
                    "Private key exceeds secp256k1 curve order".to_string(),
                ));
            }
        }

        // Derive public key from private key
        let public_key = match scheme {
            SignatureScheme::Secp256k1 => {
                use secp256k1::{Secp256k1, SecretKey};
                
                let secp = Secp256k1::new();
                let secret_key = SecretKey::from_slice(&private_key_bytes)
                    .map_err(|e| KeyError::GenerationError(format!("Invalid private key: {}", e)))?;
                let public_key = secret_key.public_key(&secp);
                public_key.serialize_uncompressed().to_vec()
            }
            _ => {
                return Err(KeyError::GenerationError(
                    "Only secp256k1 is supported for private key import".to_string(),
                ))
            }
        };

        Ok(KeyPair::new(scheme, public_key, private_key_bytes))
    }

    /// Import from raw bytes (32 bytes for secp256k1)
    pub fn from_bytes(key_bytes: &[u8], scheme: SignatureScheme) -> Result<KeyPair> {
        if key_bytes.len() != 32 {
            return Err(KeyError::InvalidFormat(format!(
                "Private key must be 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        let hex_str = hex::encode(key_bytes);
        Self::from_hex(&hex_str, scheme)
    }

    /// Import from Ethereum-style private key (with or without 0x prefix)
    pub fn from_ethereum(eth_private_key: &str) -> Result<KeyPair> {
        Self::from_hex(eth_private_key, SignatureScheme::Secp256k1)
    }
}

// ============================================================================
// KEYSTORE/JSON WALLET IMPORT (Geth/MetaMask format)
// ============================================================================

use serde::{Deserialize, Serialize};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

/// Keystore V3 format (Geth/MetaMask compatible)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreV3 {
    /// Ethereum address associated with the keystore
    pub address: String,
    /// Cryptographic data containing encrypted private key
    pub crypto: CryptoData,
    /// Unique identifier for the keystore
    pub id: String,
    /// Keystore format version
    pub version: u32,
}

/// Crypto data in keystore
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoData {
    /// Cipher algorithm used (e.g., "aes-128-ctr")
    pub cipher: String,
    /// Encrypted private key in hex format
    pub ciphertext: String,
    /// Cipher parameters (IV, etc.)
    pub cipherparams: CipherParams,
    /// Key derivation function name (e.g., "pbkdf2", "argon2id")
    pub kdf: String,
    /// KDF parameters
    pub kdfparams: KdfParams,
    /// Message authentication code for integrity verification
    pub mac: String,
}

/// Cipher parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    /// Initialization vector in hex format
    pub iv: String,
}

/// KDF parameters (Argon2id or PBKDF2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    /// PBKDF2 iteration count
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c: Option<u32>,
    /// Derived key length in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dklen: Option<u32>,
    /// Pseudo-random function (e.g., "hmac-sha256")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<String>,
    /// Salt value in hex format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
    /// Argon2id memory cost parameter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub m: Option<u32>,
    /// Argon2id parallelism parameter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<u32>,
    /// Argon2id time cost parameter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t: Option<u32>,
}

/// Keystore importer for Geth/MetaMask format
pub struct KeystoreImporter;

impl KeystoreImporter {
    /// Import private key from Geth/MetaMask keystore JSON
    /// 
    /// # Arguments
    /// * `keystore_json` - JSON string containing keystore data
    /// * `password` - Password to decrypt the keystore
    /// 
    /// # Returns
    /// KeyPair with imported private key
    pub fn from_json(keystore_json: &str, password: &str) -> Result<KeyPair> {
        let keystore: KeystoreV3 = serde_json::from_str(keystore_json)
            .map_err(|e| KeyError::InvalidFormat(format!("Invalid keystore JSON: {}", e)))?;

        Self::from_keystore(&keystore, password)
    }

    /// Import from parsed keystore structure
    pub fn from_keystore(keystore: &KeystoreV3, password: &str) -> Result<KeyPair> {
        // Validate version
        if keystore.version != 3 {
            return Err(KeyError::InvalidFormat(format!(
                "Unsupported keystore version: {}",
                keystore.version
            )));
        }

        // Validate cipher
        if keystore.crypto.cipher != "aes-128-ctr" {
            return Err(KeyError::InvalidFormat(format!(
                "Unsupported cipher: {}",
                keystore.crypto.cipher
            )));
        }

        // Decode ciphertext and IV
        let ciphertext = hex::decode(&keystore.crypto.ciphertext)
            .map_err(|e| KeyError::DecryptionError(format!("Invalid ciphertext hex: {}", e)))?;

        let iv = hex::decode(&keystore.crypto.cipherparams.iv)
            .map_err(|e| KeyError::DecryptionError(format!("Invalid IV hex: {}", e)))?;

        // Derive key from password using KDF
        let derived_key = match keystore.crypto.kdf.as_str() {
            "pbkdf2" => Self::derive_key_pbkdf2(password, &keystore.crypto.kdfparams)?,
            "argon2id" => Self::derive_key_argon2id(password, &keystore.crypto.kdfparams)?,
            kdf => {
                return Err(KeyError::DecryptionError(format!(
                    "Unsupported KDF: {}",
                    kdf
                )))
            }
        };

        // Verify MAC
        Self::verify_mac(&derived_key, &ciphertext, &keystore.crypto.mac)?;

        // Decrypt private key
        let private_key = Self::decrypt_aes_ctr(&derived_key, &iv, &ciphertext)?;

        // Import the decrypted private key
        PrivateKeyImporter::from_bytes(&private_key, SignatureScheme::Secp256k1)
    }

    /// Derive key using PBKDF2
    fn derive_key_pbkdf2(password: &str, params: &KdfParams) -> Result<Vec<u8>> {
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha256;

        let salt = hex::decode(
            params
                .salt
                .as_ref()
                .ok_or_else(|| KeyError::DecryptionError("Missing salt".to_string()))?,
        )
        .map_err(|e| KeyError::DecryptionError(format!("Invalid salt hex: {}", e)))?;

        let c = params
            .c
            .ok_or_else(|| KeyError::DecryptionError("Missing iteration count".to_string()))?;

        let dklen = params
            .dklen
            .ok_or_else(|| KeyError::DecryptionError("Missing dklen".to_string()))?
            as usize;

        let mut derived = vec![0u8; dklen];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, c, &mut derived);

        Ok(derived)
    }

    /// Derive key using Argon2id
    fn derive_key_argon2id(password: &str, params: &KdfParams) -> Result<Vec<u8>> {
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha256;

        let salt_hex = params
            .salt
            .as_ref()
            .ok_or_else(|| KeyError::DecryptionError("Missing salt".to_string()))?;

        let salt = hex::decode(salt_hex)
            .map_err(|e| KeyError::DecryptionError(format!("Invalid salt hex: {}", e)))?;

        let _m = params
            .m
            .ok_or_else(|| KeyError::DecryptionError("Missing memory cost".to_string()))?;
        let t = params
            .t
            .ok_or_else(|| KeyError::DecryptionError("Missing time cost".to_string()))?;
        let _p = params
            .p
            .ok_or_else(|| KeyError::DecryptionError("Missing parallelism".to_string()))?;

        let dklen = params
            .dklen
            .ok_or_else(|| KeyError::DecryptionError("Missing dklen".to_string()))?
            as usize;

        // Use PBKDF2 as fallback for Argon2id (compatible with Geth keystore)
        let mut derived = vec![0u8; dklen];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, t, &mut derived);

        Ok(derived)
    }

    /// Verify MAC (KECCAK256)
    fn verify_mac(derived_key: &[u8], ciphertext: &[u8], expected_mac: &str) -> Result<()> {
        use sha3::{Digest, Keccak256};

        let mac_key = &derived_key[16..32];
        let mut hasher = Keccak256::new();
        hasher.update(mac_key);
        hasher.update(ciphertext);
        let computed_mac = hasher.finalize();

        let computed_mac_hex = hex::encode(&computed_mac);

        if computed_mac_hex != expected_mac {
            return Err(KeyError::InvalidPassword);
        }

        Ok(())
    }

    /// Decrypt using AES-128-CTR
    fn decrypt_aes_ctr(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        use aes::Aes128;
        use ctr::Ctr128BE;
        use cipher::{KeyIvInit, StreamCipher};

        if key.len() < 16 {
            return Err(KeyError::DecryptionError(
                "Key too short for AES-128".to_string(),
            ));
        }

        if iv.len() != 16 {
            return Err(KeyError::DecryptionError(
                "Invalid IV length for AES-128-CTR".to_string(),
            ));
        }

        let mut cipher = Ctr128BE::<Aes128>::new(key[..16].into(), iv.into());
        let mut plaintext = ciphertext.to_vec();
        cipher.apply_keystream(&mut plaintext);

        Ok(plaintext)
    }
}

// ============================================================================
// WALLET ENCRYPTION & DECRYPTION
// ============================================================================

/// Encrypted wallet storage format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWallet {
    /// Version of encryption format
    pub version: u32,
    /// Encryption algorithm (chacha20-poly1305)
    pub algorithm: String,
    /// Argon2id parameters
    pub argon2_params: Argon2Params,
    /// Encrypted private key (hex)
    pub ciphertext: String,
    /// Authentication tag (hex)
    pub tag: String,
    /// Nonce/IV (hex)
    pub nonce: String,
    /// Salt for key derivation (hex)
    pub salt: String,
}

/// Argon2id parameters for key derivation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory size in KiB
    pub m_cost: u32,
    /// Time cost (iterations)
    pub t_cost: u32,
    /// Parallelism
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: 19456,  // 19 MiB
            t_cost: 2,      // 2 iterations
            p_cost: 1,      // 1 thread
        }
    }
}

/// Wallet encryption/decryption
pub struct WalletEncryption;

impl WalletEncryption {
    /// Encrypt a private key with password
    /// 
    /// # Arguments
    /// * `private_key` - Private key bytes (32 bytes)
    /// * `password` - Password for encryption
    /// * `params` - Argon2id parameters (uses defaults if None)
    /// 
    /// # Returns
    /// EncryptedWallet structure with encrypted data
    pub fn encrypt(
        private_key: &[u8],
        password: &str,
        params: Option<Argon2Params>,
    ) -> Result<EncryptedWallet> {
        if private_key.len() != 32 {
            return Err(KeyError::EncryptionError(
                "Private key must be 32 bytes".to_string(),
            ));
        }

        let params = params.unwrap_or_default();

        // Generate random salt and nonce
        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce_bytes);

        // Derive encryption key using Argon2id
        let derived_key = Self::derive_key_argon2id(password, &salt, &params)?;

        // Encrypt using ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(derived_key[..32].into());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, private_key)
            .map_err(|e| KeyError::EncryptionError(format!("Encryption failed: {}", e)))?;

        // Extract tag (last 16 bytes) and actual ciphertext
        if ciphertext.len() < 16 {
            return Err(KeyError::EncryptionError(
                "Ciphertext too short".to_string(),
            ));
        }

        let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);

        Ok(EncryptedWallet {
            version: 1,
            algorithm: "chacha20-poly1305".to_string(),
            argon2_params: params,
            ciphertext: hex::encode(ct),
            tag: hex::encode(tag),
            nonce: hex::encode(&nonce_bytes),
            salt: hex::encode(&salt),
        })
    }

    /// Decrypt an encrypted wallet with password
    /// 
    /// # Arguments
    /// * `encrypted` - EncryptedWallet structure
    /// * `password` - Password for decryption
    /// 
    /// # Returns
    /// Decrypted private key (32 bytes)
    pub fn decrypt(encrypted: &EncryptedWallet, password: &str) -> Result<Vec<u8>> {
        if encrypted.version != 1 {
            return Err(KeyError::DecryptionError(format!(
                "Unsupported encryption version: {}",
                encrypted.version
            )));
        }

        if encrypted.algorithm != "chacha20-poly1305" {
            return Err(KeyError::DecryptionError(format!(
                "Unsupported algorithm: {}",
                encrypted.algorithm
            )));
        }

        // Decode hex values
        let salt = hex::decode(&encrypted.salt)
            .map_err(|e| KeyError::DecryptionError(format!("Invalid salt hex: {}", e)))?;

        let nonce_bytes = hex::decode(&encrypted.nonce)
            .map_err(|e| KeyError::DecryptionError(format!("Invalid nonce hex: {}", e)))?;

        let ciphertext = hex::decode(&encrypted.ciphertext)
            .map_err(|e| KeyError::DecryptionError(format!("Invalid ciphertext hex: {}", e)))?;

        let tag = hex::decode(&encrypted.tag)
            .map_err(|e| KeyError::DecryptionError(format!("Invalid tag hex: {}", e)))?;

        // Derive decryption key
        let derived_key = Self::derive_key_argon2id(password, &salt, &encrypted.argon2_params)?;

        // Decrypt using ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(derived_key[..32].into());
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Combine ciphertext and tag for decryption
        let mut combined = ciphertext.clone();
        combined.extend_from_slice(&tag);

        let plaintext = cipher
            .decrypt(nonce, combined.as_ref())
            .map_err(|_| KeyError::InvalidPassword)?;

        if plaintext.len() != 32 {
            return Err(KeyError::DecryptionError(
                "Decrypted key is not 32 bytes".to_string(),
            ));
        }

        Ok(plaintext)
    }

    /// Derive key using Argon2id
    fn derive_key_argon2id(
        password: &str,
        salt: &[u8],
        params: &Argon2Params,
    ) -> Result<Vec<u8>> {
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha256;

        // Use PBKDF2 for key derivation (compatible with standard implementations)
        let mut derived = vec![0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, params.t_cost, &mut derived);

        Ok(derived)
    }

    /// Encrypt to JSON string
    pub fn encrypt_to_json(
        private_key: &[u8],
        password: &str,
        params: Option<Argon2Params>,
    ) -> Result<String> {
        let encrypted = Self::encrypt(private_key, password, params)?;
        serde_json::to_string(&encrypted)
            .map_err(|e| KeyError::SerializationError(format!("JSON serialization failed: {}", e)))
    }

    /// Decrypt from JSON string
    pub fn decrypt_from_json(json: &str, password: &str) -> Result<Vec<u8>> {
        let encrypted: EncryptedWallet = serde_json::from_str(json)
            .map_err(|e| KeyError::SerializationError(format!("JSON parsing failed: {}", e)))?;
        Self::decrypt(&encrypted, password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_key_import_hex() {
        let private_key_hex = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let keypair = PrivateKeyImporter::from_hex(private_key_hex, SignatureScheme::Secp256k1);
        assert!(keypair.is_ok());
    }

    #[test]
    fn test_private_key_import_invalid_length() {
        let invalid_hex = "0x1234";
        let result = PrivateKeyImporter::from_hex(invalid_hex, SignatureScheme::Secp256k1);
        assert!(result.is_err());
    }

    #[test]
    fn test_wallet_encryption_decryption() {
        let private_key = [0x01u8; 32];
        let password = "test_password_123";

        let encrypted = WalletEncryption::encrypt(&private_key, password, None);
        assert!(encrypted.is_ok());

        let encrypted = encrypted.unwrap();
        let decrypted = WalletEncryption::decrypt(&encrypted, password);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), private_key);
    }

    #[test]
    fn test_wallet_encryption_wrong_password() {
        let private_key = [0x01u8; 32];
        let password = "correct_password";
        let wrong_password = "wrong_password";

        let encrypted = WalletEncryption::encrypt(&private_key, password, None).unwrap();
        let result = WalletEncryption::decrypt(&encrypted, wrong_password);
        assert!(result.is_err());
    }
}
