//! Core cryptographic engine and network message types.
//!
//! This module provides:
//! - [`TrxCrypto`]: Main cryptographic engine wrapping Tess
//! - [`TrxMessage`]: Network protocol message types
//!
//! # TrxCrypto
//!
//! The [`TrxCrypto`] struct is the primary interface to the cryptographic operations:
//! - Owns Tess threshold encryption scheme and parameters
//! - Implements [`TransactionEncryption`] and [`BatchDecryption`] traits
//! - Implements [`SetupManager`] for DKG and trusted setup
//!
//! # TrxMessage Protocol
//!
//! Network messages flow through the consensus protocol:
//!
//! 1. **SubmitEncryptedTx**: Client → Network
//! 2. **ProposeBlock**: Proposer → Validators (contains encrypted batch)
//! 3. **VoteWithDecryption**: Validator → Network (vote + optional partial decryption)
//! 4. **RequestDecryptionShares**: Collector → Validators (request shares for finalized batch)
//! 5. **DecryptionShare**: Validator → Collector (partial decryption share)
//!
//! # Example
//!
//! ```rust,no_run
//! # use trx::*;
//! # fn example() -> Result<(), TrxError> {
//! let mut rng = rand::thread_rng();
//!
//! // Initialize crypto engine
//! let crypto = TrxCrypto::<tess::PairingEngine>::new(&mut rng, 5, 3)?;
//!
//! // Crypto engine implements all traits
//! // - TransactionEncryption: for client operations
//! // - BatchDecryption: for consensus operations
//! // - SetupManager: for setup and DKG
//! # Ok(())
//! # }
//! ```

use rand_core::RngCore;
use tess::{Fr, PairingBackend, Params, SilentThresholdScheme, ThresholdEncryption};

use crate::{
    DecryptionContext, EncryptedTransaction, PartialDecryption, TrxError, ValidatorSignature,
    ValidatorVerifyKey,
};

/// Validator identifier (u32 index).
pub type ValidatorId = u32;

/// Primary cryptographic engine for TrX protocol.
///
/// Wraps the Tess threshold encryption library and provides implementations
/// of all TrX cryptographic traits. Each instance is configured with fixed
/// threshold parameters (parties, threshold) that determine the security level.
///
/// # Threshold Parameters
///
/// - `parties`: Total number of validators
/// - `threshold`: Minimum validators needed to decrypt (must be ≤ parties)
///
/// Security increases with threshold, but availability decreases. Typical choice:
/// `threshold = ⌊2*parties/3⌋ + 1` for Byzantine fault tolerance.
///
/// # Thread Safety
///
/// Not thread-safe. Create separate instances for concurrent operations or
/// wrap in appropriate synchronization primitives.
#[derive(Debug)]
pub struct TrxCrypto<B: PairingBackend<Scalar = Fr>> {
    /// Tess threshold encryption scheme
    pub(crate) scheme: SilentThresholdScheme<B>,
    /// Tess cryptographic parameters (SRS, Lagrange powers)
    pub(crate) params: Params<B>,
    /// Total number of parties (validators)
    pub(crate) parties: usize,
    /// Minimum shares needed for decryption
    pub(crate) threshold: usize,
}

impl<B: PairingBackend<Scalar = Fr>> TrxCrypto<B> {
    /// Creates a new TrX cryptographic engine.
    ///
    /// Initializes the Tess threshold encryption scheme with the specified
    /// parameters and generates fresh cryptographic parameters.
    ///
    /// # Arguments
    ///
    /// * `rng` - Cryptographically secure random number generator
    /// * `parties` - Total number of validators participating
    /// * `threshold` - Minimum validators needed to decrypt
    ///
    /// # Returns
    ///
    /// A configured [`TrxCrypto`] instance ready for encryption/decryption.
    ///
    /// # Errors
    ///
    /// Returns [`TrxError::InvalidConfig`] if:
    /// - `threshold` is zero
    /// - `threshold >= parties` (must leave at least one validator redundant)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use trx::*;
    /// # fn example() -> Result<(), TrxError> {
    /// let mut rng = rand::thread_rng();
    ///
    /// // 5 validators, need 3 to decrypt (60% threshold)
    /// let crypto = TrxCrypto::<tess::PairingEngine>::new(&mut rng, 5, 3)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(rng: &mut impl RngCore, parties: usize, threshold: usize) -> Result<Self, TrxError> {
        if threshold == 0 || threshold >= parties {
            return Err(TrxError::InvalidConfig(
                "threshold must be in 1..parties".into(),
            ));
        }
        let scheme = SilentThresholdScheme::<B>::new();
        let params = scheme.param_gen(rng, parties, threshold)?;
        Ok(Self {
            scheme,
            params,
            parties,
            threshold,
        })
    }
}

/// Network protocol messages for TrX.
///
/// Defines the complete set of messages exchanged between clients, validators,
/// and proposers during the encrypted transaction lifecycle.
///
/// # Message Flow
///
/// ```text
/// Client                Proposer              Validators
///   │                      │                       │
///   ├─SubmitEncryptedTx──→│                       │
///   │                      ├─ProposeBlock────────→│
///   │                      │                       ├─VoteWithDecryption→
///   │                      │←─────────────────────┤
///   │                      ├─RequestDecryptionShares→│
///   │                      │←DecryptionShare──────┤
///   │                      │                       │
/// ```
#[derive(Clone, Debug)]
pub enum TrxMessage<B: PairingBackend> {
    /// Client submits an encrypted transaction to the network.
    ///
    /// The transaction includes ciphertext, associated data, and client signature.
    SubmitEncryptedTx(EncryptedTransaction<B>),

    /// Proposer proposes a block containing encrypted transactions.
    ///
    /// Validators will vote on this block and optionally include partial decryptions.
    ProposeBlock {
        /// Hash of the proposed block
        block_hash: Vec<u8>,
        /// Batch of encrypted transactions in the block
        encrypted_txs: Vec<EncryptedTransaction<B>>,
    },

    /// Validator votes on a block, optionally including a partial decryption.
    ///
    /// Used in optimistic protocols where decryption happens during voting.
    VoteWithDecryption {
        /// Vote message (e.g., block hash, approval)
        vote: Vec<u8>,
        /// Optional partial decryption share for the batch
        partial_decryption: Option<PartialDecryption<B>>,
        /// BLS signature over (vote || partial_decryption)
        validator_sig: ValidatorSignature,
        /// Validator's BLS public key
        validator_vk: ValidatorVerifyKey,
    },

    /// Request validators to produce decryption shares for a finalized batch.
    ///
    /// Used in pessimistic protocols where decryption happens after finality.
    RequestDecryptionShares {
        /// Hash of the finalized block
        block_hash: Vec<u8>,
        /// Decryption context for the batch
        context: DecryptionContext,
    },

    /// Validator provides a decryption share for a specific block.
    ///
    /// Response to RequestDecryptionShares or sent proactively after finality.
    DecryptionShare {
        /// Hash of the block being decrypted
        block_hash: Vec<u8>,
        /// Partial decryption share
        share: PartialDecryption<B>,
        /// BLS signature over (block_hash || share)
        validator_sig: ValidatorSignature,
        /// Validator's BLS public key
        validator_vk: ValidatorVerifyKey,
    },
}
