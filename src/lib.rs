//! # SilverBitcoin Cryptography
//!
//! Quantum-resistant cryptographic primitives for SilverBitcoin 512-bit blockchain.
//!
//! This crate provides:
//! - Post-quantum signature schemes (SPHINCS+, Dilithium3)
//! - Classical signatures (Secp512r1 - NIST P-521)
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
pub mod mining;

pub use encryption::{EncryptedKey, EncryptionScheme, KeyEncryption};
pub use hashing::{derive_address, hash_512, Blake3Hasher};
pub use keys::{HDWallet, KeyPair, Mnemonic};
pub use signatures::{
    Dilithium3, HybridSignature, Secp512r1, SignatureError, SignatureScheme,
    SignatureSigner, SignatureVerifier, SphincsPlus,
};
pub use mining::{
    compute_sha512, compute_sha512_with_nonce, meets_difficulty, mine_block, DifficultyAdjuster,
    MiningError, WorkProof,
};

/// Derive public key from private key using the specified signature scheme
/// Real production implementation for all supported 512-bit schemes
pub fn derive_public_key(scheme: SignatureScheme, private_key: &[u8]) -> Result<Vec<u8>, signatures::SignatureError> {
    match scheme {
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
            // Hybrid: derive both secp512r1 and SPHINCS+ public keys
            let secp_pub = derive_public_key(SignatureScheme::Secp512r1, &private_key[..66])?;
            let sphincs_pub = derive_public_key(SignatureScheme::SphincsPlus, &private_key[66..])?;
            
            let mut combined = Vec::new();
            combined.extend_from_slice(&(secp_pub.len() as u32).to_le_bytes());
            combined.extend_from_slice(&secp_pub);
            combined.extend_from_slice(&sphincs_pub);
            Ok(combined)
        }
    }
}
