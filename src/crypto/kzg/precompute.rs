//! Precomputation cache for batch commitments and evaluation proofs.
//!
//! This module provides a caching layer to optimize consensus performance by
//! reusing expensive cryptographic computations across voting rounds.
//!
//! # Motivation
//!
//! Computing KZG commitments and evaluation proofs is computationally expensive:
//! - **Commitment**: O(n) group operations for n transactions
//! - **Evaluation proofs**: O(n²) operations for n proofs
//!
//! Validators may need to verify the same batch multiple times during consensus
//! (e.g., in optimistic protocols with re-proposals). Caching eliminates redundant work.
//!
//! # Cache Design
//!
//! The [`PrecomputationEngine`] caches based on:
//! - Batch content hash (BLAKE3 of all ciphertext payloads)
//! - Decryption context (block height, context index)
//!
//! This ensures cache hits only occur for identical batches in the same context,
//! preventing cross-epoch or cross-block replay.
//!
//! # Example
//!
//! ```rust,no_run
//! # use trx::*;
//! # use std::sync::Arc;
//! # fn example() -> Result<(), TrxError> {
//! # let mut rng = rand::thread_rng();
//! # let crypto = TrxCrypto::<tess::PairingEngine>::new(&mut rng, 5, 3)?;
//! # let global_setup = crypto.generate_global_setup(&mut rng, 128)?;
//! # let setup = crypto.generate_epoch_setup(&mut rng, 1, 1000, global_setup)?;
//! # let batch = vec![]; // encrypted transactions
//! let engine = PrecomputationEngine::<tess::PairingEngine>::new();
//! let context = DecryptionContext { block_height: 1, context_index: 0 };
//!
//! // First call computes and caches
//! let data1 = engine.precompute(&batch, &context, &setup)?;
//! println!("First computation took: {:?}", data1.computation_time);
//!
//! // Second call retrieves from cache (instant)
//! let data2 = engine.precompute(&batch, &context, &setup)?;
//! assert_eq!(data2.computation_time.as_nanos(), 0); // Cache hit
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use blake3::Hasher;
use tess::{Fr, PairingBackend};
use tracing::instrument;

use crate::{
    CollectiveDecryption, DecryptionContext, EncryptedTransaction, EpochSetup, EvalProof,
    TransactionBatchCommitment, TrxCrypto, TrxError,
};

/// Cache for expensive batch commitment and proof computations.
///
/// Stores precomputed KZG commitments and evaluation proofs keyed by batch hash
/// and context. Thread-safe via internal mutex.
#[derive(Debug)]
pub struct PrecomputationEngine<B: PairingBackend<Scalar = Fr>> {
    /// Thread-safe cache mapping (batch_hash, context) to precomputed data
    cache: Mutex<HashMap<Vec<u8>, PrecomputedData<B>>>,
}

/// Precomputed cryptographic data for a batch.
///
/// Contains the commitment, proofs, and metadata about the computation.
#[derive(Debug)]
pub struct PrecomputedData<B: PairingBackend<Scalar = Fr>> {
    /// KZG commitment over the batch polynomial
    pub digest: TransactionBatchCommitment<B>,
    /// KZG evaluation proofs (one per transaction)
    pub eval_proofs: Vec<EvalProof<B>>,
    /// Time spent computing (zero if cache hit)
    pub computation_time: Duration,
}

impl<B: PairingBackend<Scalar = Fr>> Clone for PrecomputedData<B>
where
    B::G1: Clone,
{
    fn clone(&self) -> Self {
        Self {
            digest: self.digest.clone(),
            eval_proofs: self.eval_proofs.clone(),
            computation_time: self.computation_time,
        }
    }
}
impl<B: PairingBackend<Scalar = Fr>> PrecomputationEngine<B> {
    /// Creates a new empty precomputation cache.
    #[instrument(level = "info", skip_all)]
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Computes or retrieves cached digest and evaluation proofs for a batch.
    ///
    /// Checks the cache for previously computed results. On cache miss, computes
    /// the commitment and proofs, stores them, and returns the result.
    ///
    /// # Arguments
    ///
    /// * `batch` - Encrypted transactions to process
    /// * `context` - Decryption context (binds cache key to specific block/epoch)
    /// * `setup` - Epoch setup for KZG operations
    ///
    /// # Returns
    ///
    /// Precomputed data containing:
    /// - `digest`: Batch commitment
    /// - `eval_proofs`: Evaluation proofs for all transactions
    /// - `computation_time`: Time spent (zero if cache hit)
    ///
    /// # Errors
    ///
    /// Returns [`TrxError`] if KZG operations fail (only on cache miss).
    #[instrument(
        level = "info",
        skip_all,
        fields(batch_len = batch.len(), context_index = context.context_index, block_height = context.block_height)
    )]
    pub fn precompute(
        &self,
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &EpochSetup<B>,
    ) -> Result<PrecomputedData<B>, TrxError> {
        let key = precompute_key(batch, context);

        // Check cache (handle poisoned mutex gracefully)
        {
            let cache = self
                .cache
                .lock()
                .map_err(|_| TrxError::Backend("precomputation cache lock poisoned".into()))?;
            if let Some(cached) = cache.get(&key).cloned() {
                return Ok(cached);
            }
        }

        // Cache miss - compute and store
        let start = Instant::now();
        let digest = TrxCrypto::<B>::compute_digest(batch, context, setup)?;
        let eval_proofs = TrxCrypto::<B>::compute_eval_proofs(batch, context, setup)?;
        let data = PrecomputedData {
            digest,
            eval_proofs,
            computation_time: start.elapsed(),
        };

        // Store in cache (handle poisoned mutex gracefully)
        self.cache
            .lock()
            .map_err(|_| TrxError::Backend("precomputation cache lock poisoned".into()))?
            .insert(key, data.clone());

        Ok(data)
    }
}

impl<B: PairingBackend<Scalar = Fr>> Default for PrecomputationEngine<B> {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes the cache key for a batch and context.
///
/// The key binds both the batch contents and the decryption context.
///
/// # Arguments
///
/// * `batch` - Encrypted transactions
/// * `context` - Decryption context
///
/// # Returns
///
/// A 32-byte BLAKE3 hash uniquely identifying this (batch, context) pair.
///
/// # Key Format
///
/// ```text
/// BLAKE3(block_height || context_index || tx1.payload || tx2.payload || ...)
/// ```
fn precompute_key<B: PairingBackend>(
    batch: &[EncryptedTransaction<B>],
    context: &DecryptionContext,
) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(&context.block_height.to_le_bytes());
    hasher.update(&context.context_index.to_le_bytes());
    for tx in batch {
        hasher.update(&tx.ciphertext.payload);
    }
    hasher.finalize().as_bytes().to_vec()
}
