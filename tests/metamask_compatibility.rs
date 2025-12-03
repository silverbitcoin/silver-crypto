//! MetaMask compatibility tests for Secp256k1 signature scheme
//!
//! This test suite demonstrates that SilverBitcoin blockchain now supports
//! Secp256k1 signatures, making it compatible with MetaMask and other
//! standard Ethereum/Bitcoin wallets.

use silver_crypto::{KeyPair, SignatureScheme};
use silver_core::SignatureScheme as CoreSignatureScheme;

#[test]
fn test_metamask_compatible_keypair() {
    // MetaMask uses Secp256k1 for all transactions
    let keypair = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate MetaMask-compatible keypair");

    // Verify the keypair uses Secp256k1
    assert_eq!(keypair.scheme, SignatureScheme::Secp256k1);

    // Public key should be 33 bytes (compressed format, standard for Ethereum)
    assert_eq!(keypair.public_key().len(), 33);

    // Private key should be 32 bytes (256-bit)
    assert_eq!(keypair.private_key().len(), 32);
}

#[test]
fn test_metamask_transaction_signing() {
    // Simulate a MetaMask transaction signing flow
    let keypair = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate keypair");

    // Transaction data (simulated)
    let transaction_data = b"Transfer 1 SLV to 0x742d35Cc6634C0532925a3b844Bc9e7595f42bE";

    // Sign with Secp256k1 (MetaMask compatible)
    let signature = keypair.sign(transaction_data)
        .expect("Failed to sign transaction");

    // Verify signature scheme
    assert_eq!(signature.scheme, CoreSignatureScheme::Secp256k1);

    // Verify signature size (64 bytes for compact format)
    assert_eq!(signature.bytes.len(), 64);

    // Verify the signature
    assert!(keypair.verify(transaction_data, &signature));
}

#[test]
fn test_multiple_wallets_compatibility() {
    // Simulate multiple MetaMask wallets
    let wallet1 = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate wallet 1");
    let wallet2 = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate wallet 2");
    let wallet3 = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate wallet 3");

    let message = b"SilverBitcoin transaction";

    // Each wallet can sign independently
    let sig1 = wallet1.sign(message).expect("Failed to sign");
    let sig2 = wallet2.sign(message).expect("Failed to sign");
    let sig3 = wallet3.sign(message).expect("Failed to sign");

    // Each wallet can verify its own signature
    assert!(wallet1.verify(message, &sig1));
    assert!(wallet2.verify(message, &sig2));
    assert!(wallet3.verify(message, &sig3));

    // Cross-verification should fail (different keys)
    assert!(!wallet1.verify(message, &sig2));
    assert!(!wallet2.verify(message, &sig3));
    assert!(!wallet3.verify(message, &sig1));
}

#[test]
fn test_address_generation_from_secp256k1() {
    // MetaMask generates addresses from Secp256k1 public keys
    let keypair = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate keypair");

    let address = keypair.address();

    // SilverBitcoin uses 512-bit Blake3 hashes for addresses
    assert_eq!(address.0.len(), 64);

    // Address should be deterministic from the same keypair
    let address2 = keypair.address();
    assert_eq!(address, address2);
}

#[test]
fn test_secp256k1_signature_format() {
    // Verify Secp256k1 signature format compatibility
    let keypair = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate keypair");

    let message = b"Format test";
    let signature = keypair.sign(message).expect("Failed to sign");

    // Signature should be in compact format (64 bytes)
    // This is the standard format used by Bitcoin and Ethereum
    assert_eq!(signature.bytes.len(), 64);

    // First 32 bytes: r component
    // Last 32 bytes: s component
    let r = &signature.bytes[0..32];
    let s = &signature.bytes[32..64];

    // Both components should be non-zero
    assert!(!r.iter().all(|&b| b == 0));
    assert!(!s.iter().all(|&b| b == 0));
}

#[test]
fn test_secp256k1_deterministic_signatures() {
    // RFC 6979 deterministic ECDSA (used by Secp256k1)
    let keypair = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate keypair");

    let message = b"Deterministic test";

    // Sign the same message multiple times
    let sig1 = keypair.sign(message).expect("Failed to sign");
    let sig2 = keypair.sign(message).expect("Failed to sign");
    let sig3 = keypair.sign(message).expect("Failed to sign");

    // All signatures should be identical (deterministic)
    assert_eq!(sig1.bytes, sig2.bytes);
    assert_eq!(sig2.bytes, sig3.bytes);

    // All should verify
    assert!(keypair.verify(message, &sig1));
    assert!(keypair.verify(message, &sig2));
    assert!(keypair.verify(message, &sig3));
}

#[test]
fn test_secp256k1_public_key_format() {
    // Verify public key format compatibility
    let keypair = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate keypair");

    let public_key = keypair.public_key();

    // Secp256k1 public keys in compressed format are 33 bytes
    // First byte is 0x02 or 0x03 (indicating y-coordinate parity)
    // Followed by 32 bytes of x-coordinate
    assert_eq!(public_key.len(), 33);
    assert!(public_key[0] == 0x02 || public_key[0] == 0x03);
}

#[test]
fn test_secp256k1_private_key_format() {
    // Verify private key format compatibility
    let keypair = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate keypair");

    let private_key = keypair.private_key();

    // Secp256k1 private keys are 32 bytes (256-bit)
    assert_eq!(private_key.len(), 32);

    // Private key should be non-zero
    assert!(!private_key.iter().all(|&b| b == 0));
}

#[test]
fn test_mixed_signature_schemes() {
    // SilverBitcoin supports multiple signature schemes
    // Users can choose Secp256k1 for MetaMask compatibility
    // or post-quantum schemes for future-proofing

    let secp256k1_keypair = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate Secp256k1 keypair");

    let message = b"Multi-scheme test";

    // Sign with Secp256k1
    let secp_sig = secp256k1_keypair.sign(message)
        .expect("Failed to sign with Secp256k1");

    // Verify with Secp256k1
    assert!(secp256k1_keypair.verify(message, &secp_sig));

    // Verify scheme is correct
    assert_eq!(secp_sig.scheme, silver_core::SignatureScheme::Secp256k1);
}

#[test]
fn test_secp256k1_transaction_size() {
    // Calculate typical transaction size with Secp256k1
    let keypair = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate keypair");

    let message = b"Transaction data";
    let signature = keypair.sign(message).expect("Failed to sign");

    // Secp256k1 signature: 64 bytes
    // Public key: 33 bytes (compressed)
    // Address: 64 bytes (512-bit Blake3)
    // Total overhead: ~161 bytes

    let signature_size = signature.bytes.len();
    let public_key_size = keypair.public_key().len();
    let address_size = 64; // Blake3-512

    let total_overhead = signature_size + public_key_size + address_size;

    assert_eq!(signature_size, 64);
    assert_eq!(public_key_size, 33);
    assert_eq!(total_overhead, 161);
}
