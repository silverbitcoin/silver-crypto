//! Secp256k1 signature scheme tests

use silver_crypto::{KeyPair, SignatureScheme, SignatureSigner, SignatureVerifier};
use silver_core::SignatureScheme as CoreSignatureScheme;

#[test]
fn test_secp256k1_keypair_generation() {
    let keypair = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate Secp256k1 keypair");

    assert_eq!(keypair.scheme, SignatureScheme::Secp256k1);
    assert_eq!(keypair.public_key().len(), 33); // Compressed public key
    assert_eq!(keypair.private_key().len(), 32); // 256-bit private key
}

#[test]
fn test_secp256k1_sign_and_verify() {
    let keypair = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate Secp256k1 keypair");

    let message = b"Hello, SilverBitcoin!";

    // Sign the message
    let signature = keypair.sign(message).expect("Failed to sign message");

    assert_eq!(signature.scheme, CoreSignatureScheme::Secp256k1);
    assert_eq!(signature.bytes.len(), 64); // Compact signature format

    // Verify the signature
    let is_valid = keypair.verify(message, &signature);
    assert!(is_valid, "Signature verification failed");
}

#[test]
fn test_secp256k1_signature_verification_fails_with_wrong_message() {
    let keypair = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate Secp256k1 keypair");

    let message = b"Hello, SilverBitcoin!";
    let wrong_message = b"Wrong message";

    let signature = keypair.sign(message).expect("Failed to sign message");

    // Verification should fail with wrong message
    let is_valid = keypair.verify(wrong_message, &signature);
    assert!(!is_valid, "Signature should not verify with wrong message");
}

#[test]
fn test_secp256k1_signature_verification_fails_with_wrong_key() {
    let keypair1 = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate first Secp256k1 keypair");
    let keypair2 = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate second Secp256k1 keypair");

    let message = b"Hello, SilverBitcoin!";

    let signature = keypair1.sign(message).expect("Failed to sign message");

    // Verification should fail with different keypair
    let is_valid = keypair2.verify(message, &signature);
    assert!(!is_valid, "Signature should not verify with different keypair");
}

#[test]
fn test_secp256k1_multiple_signatures() {
    let keypair = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate Secp256k1 keypair");

    let messages = vec![
        b"Message 1".as_slice(),
        b"Message 2".as_slice(),
        b"Message 3".as_slice(),
    ];

    for message in messages {
        let signature = keypair.sign(message).expect("Failed to sign message");
        let is_valid = keypair.verify(message, &signature);
        assert!(is_valid, "Signature verification failed for message: {:?}", message);
    }
}

#[test]
fn test_secp256k1_address_derivation() {
    let keypair = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate Secp256k1 keypair");

    let address = keypair.address();

    // Address should be 64 bytes (512-bit Blake3 hash)
    assert_eq!(address.0.len(), 64);
}

#[test]
fn test_secp256k1_deterministic_signing() {
    let keypair = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate Secp256k1 keypair");

    let message = b"Deterministic test";

    let sig1 = keypair.sign(message).expect("Failed to sign message");
    let sig2 = keypair.sign(message).expect("Failed to sign message");

    // Secp256k1 signatures are deterministic (RFC 6979)
    assert_eq!(sig1.bytes, sig2.bytes, "Signatures should be deterministic");
}

#[test]
fn test_secp256k1_public_key_derivation() {
    use silver_crypto::Secp256k1Signer;

    let (pk, sk) = Secp256k1Signer::generate_keypair();

    // Derive public key from private key
    let derived_pk = Secp256k1Signer.public_key(&sk)
        .expect("Failed to derive public key");

    assert_eq!(derived_pk.bytes, pk, "Derived public key should match generated public key");
}

#[test]
fn test_secp256k1_signature_size() {
    let keypair = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate Secp256k1 keypair");

    let message = b"Size test";
    let signature = keypair.sign(message).expect("Failed to sign message");

    // Secp256k1 compact signature is always 64 bytes
    assert_eq!(signature.bytes.len(), 64);
}

#[test]
fn test_secp256k1_transaction_signing() {
    use silver_core::{ObjectID, ObjectRef, TransactionData, TransactionExpiration, TransactionKind, Command, SilverAddress, TransactionDigest};

    let keypair = KeyPair::generate(SignatureScheme::Secp256k1)
        .expect("Failed to generate Secp256k1 keypair");

    // Create a simple transaction
    let sender = keypair.address();
    let recipient = SilverAddress::new([1u8; 64]);

    let object_id = ObjectID::new([2u8; 64]);
    let tx_digest = TransactionDigest::new([3u8; 64]);
    let fuel_payment = ObjectRef::new(object_id, 1, tx_digest);

    let tx_data = TransactionData::new(
        sender,
        fuel_payment,
        1000,
        1000,
        TransactionKind::CompositeChain(vec![
            Command::TransferObjects {
                objects: vec![fuel_payment],
                recipient,
            },
        ]),
        TransactionExpiration::None,
    );

    // Sign the transaction
    let signature = keypair.sign_transaction(&tx_data)
        .expect("Failed to sign transaction");

    assert_eq!(signature.scheme, CoreSignatureScheme::Secp256k1);
    assert_eq!(signature.bytes.len(), 64);
}
