//! Blake3-512 hashing functions
//!
//! This module provides production-ready Blake3-512 hashing for SilverBitcoin.
//! Blake3 is a cryptographic hash function that is:
//! - Extremely fast (faster than SHA-2, SHA-3, and BLAKE2)
//! - Secure (based on BLAKE2 which is based on ChaCha)
//! - Parallelizable (SIMD optimizations built-in)
//! - Supports extended output (XOF) for arbitrary-length hashes
//!
//! We use 512-bit (64-byte) output for quantum resistance:
//! - 256-bit collision resistance (quantum-safe)
//! - 512-bit preimage resistance
//! - Provides safety margin for future cryptanalysis

use blake3::Hasher as Blake3Core;
use silver_core::SilverAddress;
use thiserror::Error;

/// Hashing-related errors
#[derive(Error, Debug)]
pub enum HashError {
    /// Invalid input data
    #[error("Invalid input data: {0}")]
    InvalidInput(String),

    /// Hash computation failed
    #[error("Hash computation failed: {0}")]
    ComputationError(String),
}

/// Result type for hashing operations
pub type Result<T> = std::result::Result<T, HashError>;

/// Domain separation tags for different hash use cases
#[derive(Debug, Clone, Copy)]
pub enum HashDomain {
    /// Address derivation from public keys
    Address,
    /// Transaction digests
    Transaction,
    /// Object IDs
    Object,
    /// State roots
    State,
    /// Snapshot digests
    Snapshot,
    /// Generic hashing
    Generic,
}

impl HashDomain {
    /// Get the domain separation prefix
    fn prefix(&self) -> &'static [u8] {
        match self {
            HashDomain::Address => b"SILVERBITCOIN_ADDRESS_V1",
            HashDomain::Transaction => b"SILVERBITCOIN_TX_V1",
            HashDomain::Object => b"SILVERBITCOIN_OBJ_V1",
            HashDomain::State => b"SILVERBITCOIN_STATE_V1",
            HashDomain::Snapshot => b"SILVERBITCOIN_SNAP_V1",
            HashDomain::Generic => b"SILVERBITCOIN_HASH_V1",
        }
    }
}

/// Blake3-512 hasher with domain separation
pub struct Blake3Hasher {
    hasher: Blake3Core,
    domain: HashDomain,
}

impl Blake3Hasher {
    /// Create a new hasher with domain separation
    pub fn new(domain: HashDomain) -> Self {
        let mut hasher = Blake3Core::new();
        hasher.update(domain.prefix());
        Self { hasher, domain }
    }

    /// Create a new hasher for generic hashing
    pub fn new_generic() -> Self {
        Self::new(HashDomain::Generic)
    }

    /// Update the hasher with data (incremental hashing)
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.hasher.update(data);
        self
    }

    /// Finalize the hash and return 512-bit output
    pub fn finalize(&self) -> [u8; 64] {
        let mut output = [0u8; 64];
        let mut reader = self.hasher.finalize_xof();
        reader.fill(&mut output);
        output
    }

    /// Finalize the hash and return arbitrary-length output
    pub fn finalize_variable(&self, output: &mut [u8]) {
        let mut reader = self.hasher.finalize_xof();
        reader.fill(output);
    }

    /// Get the domain of this hasher
    pub fn domain(&self) -> HashDomain {
        self.domain
    }
}

/// Compute Blake3-512 hash of data with domain separation
pub fn hash_512_domain(data: &[u8], domain: HashDomain) -> [u8; 64] {
    let mut hasher = Blake3Hasher::new(domain);
    hasher.update(data);
    hasher.finalize()
}

/// Compute Blake3-512 hash of data (generic domain)
pub fn hash_512(data: &[u8]) -> [u8; 64] {
    hash_512_domain(data, HashDomain::Generic)
}

/// Compute Blake3-512 hash of multiple data chunks
pub fn hash_512_multi(chunks: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Blake3Hasher::new_generic();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize()
}

/// Derive a SilverBitcoin address from a public key
///
/// Address derivation uses Blake3-512 with domain separation:
/// 1. Hash the public key with ADDRESS domain
/// 2. Return the 512-bit hash as the address
///
/// This provides:
/// - 256-bit collision resistance (quantum-safe)
/// - 512-bit preimage resistance
/// - Domain separation prevents cross-protocol attacks
pub fn derive_address(public_key: &[u8]) -> SilverAddress {
    let hash = hash_512_domain(public_key, HashDomain::Address);
    SilverAddress(hash)
}

/// Derive a SilverBitcoin address from a public key with canonical serialization
///
/// This ensures consistent address derivation regardless of public key encoding.
/// Canonical serialization follows these rules:
/// 1. Validate public key format (must be 33 or 65 bytes for compressed/uncompressed)
/// 2. Normalize to compressed format (33 bytes)
/// 3. Hash the canonical form
pub fn derive_address_canonical(public_key: &[u8]) -> Result<SilverAddress> {
    if public_key.is_empty() {
        return Err(HashError::InvalidInput(
            "Public key cannot be empty".to_string(),
        ));
    }

    // Validate and normalize public key to canonical form
    let canonical_key = normalize_public_key(public_key)?;
    
    // Hash the canonical form with domain separation
    let hash = hash_512_domain(&canonical_key, HashDomain::Address);
    Ok(SilverAddress(hash))
}

/// Normalize a public key to canonical compressed format (33 bytes)
///
/// Supports:
/// - Compressed format (33 bytes): 02/03 prefix + 32-byte X coordinate
/// - Uncompressed format (65 bytes): 04 prefix + 32-byte X + 32-byte Y
/// - Raw format (64 bytes): 32-byte X + 32-byte Y (assumes uncompressed)
fn normalize_public_key(public_key: &[u8]) -> Result<Vec<u8>> {
    match public_key.len() {
        // Already compressed format
        33 => {
            // Validate prefix (02 or 03 for compressed)
            match public_key[0] {
                0x02 | 0x03 => Ok(public_key.to_vec()),
                _ => Err(HashError::InvalidInput(
                    "Invalid compressed public key prefix".to_string(),
                )),
            }
        }
        // Uncompressed format (04 prefix + X + Y)
        65 => {
            if public_key[0] != 0x04 {
                return Err(HashError::InvalidInput(
                    "Invalid uncompressed public key prefix".to_string(),
                ));
            }
            // Compress: use 02/03 prefix based on Y coordinate parity
            let y_last_byte = public_key[64];
            let prefix = if y_last_byte & 1 == 0 { 0x02 } else { 0x03 };
            
            let mut compressed = vec![prefix];
            compressed.extend_from_slice(&public_key[1..33]); // X coordinate
            Ok(compressed)
        }
        // Raw format (X + Y, no prefix)
        64 => {
            // Compress: use 02/03 prefix based on Y coordinate parity
            let y_last_byte = public_key[63];
            let prefix = if y_last_byte & 1 == 0 { 0x02 } else { 0x03 };
            
            let mut compressed = vec![prefix];
            compressed.extend_from_slice(&public_key[0..32]); // X coordinate
            Ok(compressed)
        }
        _ => Err(HashError::InvalidInput(
            format!(
                "Invalid public key length: {}. Expected 33, 64, or 65 bytes",
                public_key.len()
            ),
        )),
    }
}

/// Incremental hasher for large data
///
/// Useful for hashing large files or streaming data without loading
/// everything into memory at once.
pub struct IncrementalHasher {
    hasher: Blake3Hasher,
}

impl IncrementalHasher {
    /// Create a new incremental hasher
    pub fn new(domain: HashDomain) -> Self {
        Self {
            hasher: Blake3Hasher::new(domain),
        }
    }

    /// Update with a chunk of data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize and return the hash
    pub fn finalize(self) -> [u8; 64] {
        self.hasher.finalize()
    }
}

/// SIMD-optimized batch hashing
///
/// Blake3 automatically uses SIMD instructions (AVX2, AVX-512, NEON)
/// when available for maximum performance.
pub fn hash_512_batch(inputs: &[&[u8]]) -> Vec<[u8; 64]> {
    inputs.iter().map(|data| hash_512(data)).collect()
}

/// Compute a keyed hash (HMAC-like construction)
pub fn hash_512_keyed(key: &[u8; 32], data: &[u8]) -> [u8; 64] {
    let mut hasher = Blake3Core::new_keyed(key);
    hasher.update(data);
    let mut output = [0u8; 64];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut output);
    output
}

/// Compute a derived key using Blake3 key derivation
pub fn derive_key(context: &str, key_material: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Blake3Core::new_derive_key(context);
    hasher.update(key_material);
    let mut output = vec![0u8; output_len];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut output);
    output
}
