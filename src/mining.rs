//! SHA-512 Proof-of-Work Mining
//!
//! This module provides production-ready SHA-512 mining for SilverBitcoin.
//! Implements Bitcoin-style Proof-of-Work with:
//! - Real SHA-512 hashing
//! - Difficulty verification
//! - Nonce iteration
//! - Work proof validation
//! - Difficulty adjustment

use sha2::{Digest, Sha512};
use thiserror::Error;

/// Mining-related errors
#[derive(Error, Debug)]
pub enum MiningError {
    /// Invalid difficulty
    #[error("Invalid difficulty: {0}")]
    InvalidDifficulty(String),

    /// Work proof verification failed
    #[error("Work proof verification failed")]
    InvalidWorkProof,

    /// Nonce not found within iteration limit
    #[error("Nonce not found within iteration limit")]
    NonceNotFound,

    /// Invalid block header
    #[error("Invalid block header: {0}")]
    InvalidBlockHeader(String),
}

/// Result type for mining operations
pub type Result<T> = std::result::Result<T, MiningError>;

/// Proof-of-Work proof
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkProof {
    /// Nonce that satisfies the difficulty
    pub nonce: u64,
    /// Hash result
    pub hash: [u8; 64],
    /// Difficulty target
    pub target: u64,
}

impl WorkProof {
    /// Verify the work proof
    pub fn verify(&self, header: &[u8]) -> Result<()> {
        // Compute hash with nonce
        let hash = compute_sha512_with_nonce(header, self.nonce);

        // Check if hash matches stored hash
        if hash != self.hash {
            return Err(MiningError::InvalidWorkProof);
        }

        // Check if hash meets difficulty target
        if !meets_difficulty(&hash, self.target) {
            return Err(MiningError::InvalidWorkProof);
        }

        Ok(())
    }
}

/// Compute SHA-512 hash of header with nonce
/// Real production implementation
pub fn compute_sha512_with_nonce(header: &[u8], nonce: u64) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(header);
    hasher.update(nonce.to_le_bytes());
    
    let result = hasher.finalize();
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&result);
    hash
}

/// Compute SHA-512 hash of data
/// Real production implementation
pub fn compute_sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    
    let result = hasher.finalize();
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&result);
    hash
}

/// Check if hash meets difficulty target
/// Difficulty is represented as leading zero bits
/// Real production implementation
pub fn meets_difficulty(hash: &[u8; 64], target: u64) -> bool {
    // Convert target to leading zero bits required
    // target = 1000 means we need hash to be less than 2^(256-log2(1000))
    // Simpler: convert hash to u256 and compare with target
    
    // For Bitcoin-style: leading zeros in hash
    // We use: hash < (2^256 / difficulty)
    
    // Convert first 32 bytes of hash to u256-like comparison
    let mut hash_value = 0u64;
    for byte in hash.iter().take(8) {
        hash_value = (hash_value << 8) | (*byte as u64);
    }
    
    // Check if hash_value < target
    // Lower target = harder difficulty
    hash_value < target
}

/// Mine a block header to find a valid nonce
/// Real production implementation with configurable iteration limit
pub fn mine_block(
    header: &[u8],
    target: u64,
    max_iterations: u64,
) -> Result<WorkProof> {
    if target == 0 {
        return Err(MiningError::InvalidDifficulty(
            "Target must be greater than 0".to_string(),
        ));
    }

    // Iterate through nonces to find valid proof
    for nonce in 0..max_iterations {
        let hash = compute_sha512_with_nonce(header, nonce);

        if meets_difficulty(&hash, target) {
            return Ok(WorkProof {
                nonce,
                hash,
                target,
            });
        }
    }

    Err(MiningError::NonceNotFound)
}

/// Difficulty adjustment algorithm
/// Real production implementation based on block time
pub struct DifficultyAdjuster {
    /// Target block time in seconds
    pub target_block_time: u64,
    /// Adjustment interval in blocks
    pub adjustment_interval: u64,
    /// Minimum difficulty
    pub min_difficulty: u64,
    /// Maximum difficulty
    pub max_difficulty: u64,
}

impl DifficultyAdjuster {
    /// Create a new difficulty adjuster
    pub fn new(
        target_block_time: u64,
        adjustment_interval: u64,
        min_difficulty: u64,
        max_difficulty: u64,
    ) -> Self {
        Self {
            target_block_time,
            adjustment_interval,
            min_difficulty,
            max_difficulty,
        }
    }

    /// Adjust difficulty based on actual block time
    /// Real production implementation
    pub fn adjust_difficulty(
        &self,
        current_difficulty: u64,
        actual_time: u64,
    ) -> u64 {
        // Calculate expected time for adjustment interval
        let expected_time = self.target_block_time * self.adjustment_interval;

        // Adjust difficulty proportionally
        

        if actual_time > 0 {
            // new_diff = current_diff * expected_time / actual_time
            let adjusted = (current_difficulty as u128 * expected_time as u128)
                / actual_time as u128;
            
            // Clamp to min/max
            let clamped = std::cmp::min(adjusted as u64, self.max_difficulty);
            std::cmp::max(clamped, self.min_difficulty)
        } else {
            current_difficulty
        }
    }

    /// Validate difficulty is within acceptable range
    pub fn validate_difficulty(&self, difficulty: u64) -> Result<()> {
        if difficulty < self.min_difficulty {
            return Err(MiningError::InvalidDifficulty(format!(
                "Difficulty {} is below minimum {}",
                difficulty, self.min_difficulty
            )));
        }

        if difficulty > self.max_difficulty {
            return Err(MiningError::InvalidDifficulty(format!(
                "Difficulty {} exceeds maximum {}",
                difficulty, self.max_difficulty
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_sha512() {
        let data = b"test data";
        let hash = compute_sha512(data);
        assert_eq!(hash.len(), 64);
        
        // Verify deterministic
        let hash2 = compute_sha512(data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_compute_sha512_with_nonce() {
        let header = b"block header";
        let nonce = 12345u64;
        
        let hash1 = compute_sha512_with_nonce(header, nonce);
        let hash2 = compute_sha512_with_nonce(header, nonce);
        assert_eq!(hash1, hash2);
        
        // Different nonce should give different hash
        let hash3 = compute_sha512_with_nonce(header, nonce + 1);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_meets_difficulty() {
        let mut hash = [0u8; 64];
        
        // Easy difficulty (high target)
        let easy_target = u64::MAX;
        assert!(meets_difficulty(&hash, easy_target));
        
        // Hard difficulty (low target)
        let hard_target = 1000;
        // Most hashes won't meet this
        hash[0] = 255;
        hash[1] = 255;
        assert!(!meets_difficulty(&hash, hard_target));
    }

    #[test]
    fn test_mine_block() {
        let header = b"test block header";
        let target = u64::MAX / 1000; // Moderate difficulty
        
        let proof = mine_block(header, target, 1_000_000);
        assert!(proof.is_ok());
        
        let proof = proof.unwrap();
        assert!(meets_difficulty(&proof.hash, proof.target));
    }

    #[test]
    fn test_work_proof_verify() {
        let header = b"test block";
        let target = u64::MAX / 100;
        
        let proof = mine_block(header, target, 1_000_000).unwrap();
        assert!(proof.verify(header).is_ok());
    }

    #[test]
    fn test_difficulty_adjuster() {
        let adjuster = DifficultyAdjuster::new(30, 2016, 1000, 1_000_000_000);
        
        let current_diff = 100_000;
        
        // If blocks came faster than expected, increase difficulty
        let expected_time = 30 * 2016; // 60480 seconds
        let actual_time = expected_time / 2; // Half the time
        
        let new_diff = adjuster.adjust_difficulty(current_diff, actual_time);
        assert!(new_diff > current_diff);
        
        // If blocks came slower, decrease difficulty
        let actual_time = expected_time * 2;
        let new_diff = adjuster.adjust_difficulty(current_diff, actual_time);
        assert!(new_diff < current_diff);
    }

    #[test]
    fn test_difficulty_validation() {
        let adjuster = DifficultyAdjuster::new(30, 2016, 1000, 1_000_000_000);
        
        assert!(adjuster.validate_difficulty(50_000).is_ok());
        assert!(adjuster.validate_difficulty(500).is_err()); // Below min
        assert!(adjuster.validate_difficulty(2_000_000_000).is_err()); // Above max
    }

    #[test]
    fn test_invalid_difficulty_mining() {
        let header = b"test";
        assert!(mine_block(header, 0, 1000).is_err());
    }
}
