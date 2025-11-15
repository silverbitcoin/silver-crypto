//! # SilverBitcoin Cryptography
//!
//! Quantum-resistant cryptographic primitives for SilverBitcoin blockchain.
//!
//! This crate provides:
//! - Post-quantum signature schemes (SPHINCS+, Dilithium3)
//! - Classical signatures (Secp512r1)
//! - Hybrid signature mode
//! - Blake3-512 hashing
//! - Key management (HD wallets, encryption)
//! - Quantum-resistant key encapsulation (Kyber1024)

#![warn(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

pub mod signatures;
pub mod hashing;
pub mod encryption;
pub mod keys;

pub use signatures::{
    SignatureScheme, SignatureVerifier, SignatureSigner,
    SphincsPlus, Dilithium3, Secp512r1, HybridSignature,
    SignatureError,
};
pub use hashing::{Blake3Hasher, hash_512, derive_address};
pub use encryption::{KeyEncryption, EncryptedKey, EncryptionScheme};
pub use keys::{KeyPair, HDWallet, Mnemonic};
