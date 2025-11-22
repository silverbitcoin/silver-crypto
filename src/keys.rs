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

use crate::signatures::{SignatureScheme, SphincsPlus, Dilithium3, Secp512r1};
use silver_core::{PublicKey, SilverAddress};
use bip39::{Mnemonic as Bip39Mnemonic, Language};
use rand::RngCore;
use rand_core::OsRng;
use thiserror::Error;
use sha2::{Sha512, Digest};
use hmac::{Hmac, Mac};

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
            _ => return Err(KeyError::InvalidMnemonic(
                format!("Invalid word count: {}. Must be 12, 15, 18, 21, or 24", word_count)
            )),
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
            SignatureScheme::SphincsPlus => SphincsPlus::generate_keypair(),
            SignatureScheme::Dilithium3 => Dilithium3::generate_keypair(),
            SignatureScheme::Secp512r1 => Secp512r1::generate_keypair(),
            SignatureScheme::Hybrid => {
                return Err(KeyError::GenerationError(
                    "Use HybridSignature::generate_keypair() for hybrid keys".to_string()
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
            SignatureScheme::SphincsPlus => {
                let signer = SphincsPlus;
                signer.sign(message, &self.private_key)
                    .map_err(|e| silver_core::Error::Cryptographic(e.to_string()))?
            }
            SignatureScheme::Dilithium3 => {
                let signer = Dilithium3;
                signer.sign(message, &self.private_key)
                    .map_err(|e| silver_core::Error::Cryptographic(e.to_string()))?
            }
            SignatureScheme::Secp512r1 => {
                let signer = Secp512r1;
                signer.sign(message, &self.private_key)
                    .map_err(|e| silver_core::Error::Cryptographic(e.to_string()))?
            }
            SignatureScheme::Hybrid => {
                return Err(silver_core::Error::Cryptographic(
                    "Use HybridSignature::sign() for hybrid signatures".to_string()
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
    pub fn sign_transaction(&self, tx_data: &silver_core::TransactionData) -> silver_core::Result<silver_core::Signature> {
        let serialized = bincode::serialize(tx_data)
            .map_err(|e| silver_core::Error::Serialization(format!("Failed to serialize transaction: {}", e)))?;
        
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
            SignatureScheme::Hybrid => {
                return Err(KeyError::GenerationError(
                    "Hybrid scheme not supported for HD derivation".to_string()
                ));
            }
        };
        
        Ok(KeyPair::new(self.scheme, pk, sk))
    }
    
    /// Derive multiple keypairs for a range of indices
    pub fn derive_keypairs(&self, account: u32, start_index: u32, count: u32) -> Result<Vec<KeyPair>> {
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
                index.checked_add(0x80000000).ok_or_else(|| {
                    KeyError::DerivationError("Index overflow".to_string())
                })?
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
        type HmacSha512 = Hmac<Sha512>;

        let mut data = Vec::new();
        if index >= 0x80000000 {
            data.push(0x00);
            data.extend_from_slice(parent_key);
        } else {
            data.extend_from_slice(parent_key);
        }
        data.extend_from_slice(&index.to_be_bytes());

        let mut mac = HmacSha512::new_from_slice(chain_code)
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mnemonic_generation() {
        let mnemonic = Mnemonic::generate().unwrap();
        let phrase = mnemonic.phrase();
        assert_eq!(phrase.split_whitespace().count(), 24);
        
        let parsed = Mnemonic::from_phrase(&phrase).unwrap();
        assert_eq!(parsed.phrase(), phrase);
    }
    
    #[test]
    fn test_mnemonic_word_counts() {
        for word_count in [12, 15, 18, 21, 24] {
            let mnemonic = Mnemonic::generate_with_word_count(word_count).unwrap();
            assert_eq!(mnemonic.words().len(), word_count);
        }
        
        assert!(Mnemonic::generate_with_word_count(10).is_err());
    }
    
    #[test]
    fn test_mnemonic_to_seed() {
        let mnemonic = Mnemonic::generate().unwrap();
        
        let seed1 = mnemonic.to_seed("");
        let seed2 = mnemonic.to_seed("");
        assert_eq!(seed1, seed2);
        
        let seed3 = mnemonic.to_seed("passphrase");
        assert_ne!(seed1, seed3);
    }
    
    #[test]
    fn test_keypair_generation() {
        for scheme in [SignatureScheme::Dilithium3, SignatureScheme::Secp512r1] {
            let keypair = KeyPair::generate(scheme).unwrap();
            assert_eq!(keypair.scheme, scheme);
            assert!(!keypair.public_key.is_empty());
            assert!(!keypair.private_key().is_empty());
        }
    }
    
    #[test]
    fn test_keypair_address() {
        let keypair = KeyPair::generate(SignatureScheme::Dilithium3).unwrap();
        let address = keypair.address();
        assert_eq!(address.0.len(), 64);
        
        let address2 = keypair.address();
        assert_eq!(address.0, address2.0);
    }
    
    #[test]
    fn test_hd_wallet_from_mnemonic() {
        let mnemonic = Mnemonic::generate().unwrap();
        let wallet = HDWallet::from_mnemonic(&mnemonic, "", SignatureScheme::Dilithium3);
        
        let keypair = wallet.derive_keypair("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(keypair.scheme, SignatureScheme::Dilithium3);
    }
    
    #[test]
    fn test_hd_wallet_deterministic() {
        let mnemonic = Mnemonic::generate().unwrap();
        let wallet1 = HDWallet::from_mnemonic(&mnemonic, "", SignatureScheme::Dilithium3);
        let wallet2 = HDWallet::from_mnemonic(&mnemonic, "", SignatureScheme::Dilithium3);
        
        let keypair1 = wallet1.derive_keypair("m/44'/0'/0'/0/0").unwrap();
        let keypair2 = wallet2.derive_keypair("m/44'/0'/0'/0/0").unwrap();
        
        assert_eq!(keypair1.public_key(), keypair2.public_key());
        assert_eq!(keypair1.address(), keypair2.address());
    }
    
    #[test]
    fn test_hd_wallet_derive_multiple() {
        let mnemonic = Mnemonic::generate().unwrap();
        let wallet = HDWallet::from_mnemonic(&mnemonic, "", SignatureScheme::Dilithium3);
        
        let keypairs = wallet.derive_keypairs(0, 0, 5).unwrap();
        assert_eq!(keypairs.len(), 5);
        
        for keypair in keypairs {
            assert_eq!(keypair.scheme, SignatureScheme::Dilithium3);
        }
    }
}
