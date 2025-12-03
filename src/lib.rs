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
