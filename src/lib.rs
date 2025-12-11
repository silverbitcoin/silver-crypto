//! # SilverBitcoin Cryptography
//!
//! Quantum-resistant cryptographic primitives for SilverBitcoin blockchain.
//!
//! This crate provides:
//! - Post-quantum signature schemes (SPHINCS+, Dilithium3)
//! - Classical signatures (Secp256k1, Secp512r1)
//! - Hybrid signature mode
//! - Blake3-512 hashing
//! - Key management (HD wallets, encryption)
//! - Quantum-resistant key encapsulation (Kyber1024)

#![warn(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

pub mod encryption;
pub mod hashing;
pub mod keys;
pub mod signatures;

pub use encryption::{EncryptedKey, EncryptionScheme, KeyEncryption};
pub use hashing::{derive_address, hash_512, Blake3Hasher};
pub use keys::{HDWallet, KeyPair, Mnemonic};
pub use signatures::{
    Dilithium3, HybridSignature, Secp256k1Signer, Secp512r1, SignatureError, SignatureScheme,
    SignatureSigner, SignatureVerifier, SphincsPlus,
};

/// Derive public key from private key using the specified signature scheme
/// Real production implementation for all supported schemes
pub fn derive_public_key(scheme: SignatureScheme, private_key: &[u8]) -> Result<Vec<u8>, signatures::SignatureError> {
    match scheme {
        SignatureScheme::Secp256k1 => {
            // Secp256k1: derive public key from 32-byte private key
            use secp256k1::{Secp256k1, SecretKey};
            
            let secret_key = SecretKey::from_slice(private_key)
                .map_err(|e| signatures::SignatureError::MalformedPrivateKey(format!("Invalid secp256k1 key: {}", e)))?;
            
            let secp = Secp256k1::new();
            let public_key = secret_key.public_key(&secp);
            Ok(public_key.serialize().to_vec()) // 33 bytes compressed
        }
        SignatureScheme::Secp512r1 => {
            // Secp512r1: derive public key from 66-byte private key
            use p521::ecdsa::{SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey};
            
            let signing_key = P521SigningKey::from_bytes(private_key.into())
                .map_err(|e| signatures::SignatureError::MalformedPrivateKey(format!("Invalid secp512r1 key: {}", e)))?;
            
            let verifying_key = P521VerifyingKey::from(&signing_key);
            Ok(verifying_key.to_encoded_point(false).as_bytes().to_vec())
        }
        SignatureScheme::Dilithium3 => {
            // Dilithium3: derive public key from private key
            // Use the SignatureSigner trait to derive public key
            let signer = signatures::Dilithium3;
            let pub_key = signer.public_key(private_key)?;
            Ok(pub_key.bytes)
        }
        SignatureScheme::SphincsPlus => {
            // SPHINCS+: derive public key from private key
            // Use the SignatureSigner trait to derive public key
            let signer = signatures::SphincsPlus;
            let pub_key = signer.public_key(private_key)?;
            Ok(pub_key.bytes)
        }
        SignatureScheme::Hybrid => {
            // Hybrid: derive both secp256k1 and SPHINCS+ public keys
            let secp_pub = derive_public_key(SignatureScheme::Secp256k1, &private_key[..32])?;
            let sphincs_pub = derive_public_key(SignatureScheme::SphincsPlus, &private_key[32..])?;
            
            let mut combined = Vec::new();
            combined.extend_from_slice(&secp_pub);
            combined.extend_from_slice(&sphincs_pub);
            Ok(combined)
        }
    }
}
