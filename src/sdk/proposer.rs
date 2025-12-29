//! Proposer Phase API - Batch commitment and KZG proof generation.
//!
//! This phase handles block proposer operations for committing to batches
//! of encrypted transactions using KZG commitments.

use crate::{
    verify_eval_proofs, BatchCommitment, BatchDecryption, DecryptionContext, EncryptedTransaction,
    EpochSetup, EvalProof, TrxCrypto, TrxError,
};
use tess::{Fr, PairingBackend};

/// Proposer Phase API for batch commitment operations.
///
/// This phase handles:
/// - Computing KZG commitments over transaction batches
/// - Generating evaluation proofs for batch integrity
/// - Verifying evaluation proofs
///
/// # Example
///
/// ```no_run
/// use trx::TrxMinion;
/// use tess::PairingEngine;
/// use trx::DecryptionContext;
/// use rand::thread_rng;
/// use std::sync::Arc;
///
/// let mut rng = thread_rng();
/// let client = TrxMinion::<PairingEngine>::new(&mut rng, 5, 3)?;
///
/// # let setup = Arc::new(todo!());
/// # let batch = vec![];
/// let context = DecryptionContext {
///     block_height: 100,
///     context_index: 0,
/// };
///
/// // Proposer commits to the batch
/// let commitment = client.proposer().compute_digest(&batch, &context, &setup)?;
/// let proofs = client.proposer().compute_eval_proofs(&batch, &context, &setup)?;
/// # Ok::<(), trx::TrxError>(())
/// ```
pub struct ProposerPhase<B: PairingBackend<Scalar = Fr>> {
    _phantom: std::marker::PhantomData<B>,
}

impl<B: PairingBackend<Scalar = Fr>> ProposerPhase<B>
where
    B::G1: PartialEq,
{
    pub(crate) fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Compute a KZG commitment (digest) over a batch of encrypted transactions.
    ///
    /// The commitment binds the entire batch to a specific decryption context,
    /// creating a succinct cryptographic commitment that can be verified
    /// against individual transaction proofs.
    ///
    /// # Process
    ///
    /// 1. Construct polynomial from `H(tx_i || context)` for each transaction
    /// 2. Compute KZG commitment `C = [p(τ)]₁` where τ is from the global setup
    /// 3. Return commitment with polynomial degree
    ///
    /// # Arguments
    ///
    /// * `batch` - Slice of encrypted transactions to commit to
    /// * `context` - Decryption context binding (block height + context index)
    /// * `setup` - The epoch setup containing SRS parameters
    ///
    /// # Errors
    ///
    /// Returns `TrxError::InvalidInput` if:
    /// - Batch is empty
    /// - Batch size exceeds setup's max batch size
    ///
    /// Returns `TrxError::Backend` if KZG computation fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use trx::TrxMinion;
    /// use tess::PairingEngine;
    /// use trx::DecryptionContext;
    /// use rand::thread_rng;
    /// use std::sync::Arc;
    ///
    /// let mut rng = thread_rng();
    /// let client = TrxMinion::<PairingEngine>::new(&mut rng, 5, 3)?;
    ///
    /// # let setup = Arc::new(todo!());
    /// # let batch = vec![];
    /// let context = DecryptionContext {
    ///     block_height: 100,
    ///     context_index: 0,
    /// };
    ///
    /// // Proposer computes commitment for inclusion in block header
    /// let commitment = client.proposer().compute_digest(&batch, &context, &setup)?;
    ///
    /// // Commitment is constant size regardless of batch size
    /// println!("Committed to batch of {} transactions", batch.len());
    /// # Ok::<(), trx::TrxError>(())
    /// ```
    pub fn compute_digest(
        &self,
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &EpochSetup<B>,
    ) -> Result<BatchCommitment<B>, TrxError> {
        TrxCrypto::<B>::compute_digest(batch, context, setup)
    }

    /// Compute KZG evaluation proofs for each transaction in the batch.
    ///
    /// Each proof demonstrates that a specific transaction's hash evaluates
    /// correctly at its position in the committed polynomial. Validators
    /// verify these proofs before generating partial decryptions.
    ///
    /// # Process
    ///
    /// For each transaction at index i:
    /// 1. Compute evaluation point: `x = i + 1`
    /// 2. Compute expected value: `y = H(tx_i || context)`
    /// 3. Generate proof: `π = [(p(x) - y) / (x - ω)]₁`
    ///
    /// # Arguments
    ///
    /// * `batch` - Slice of encrypted transactions
    /// * `context` - Decryption context (must match `compute_digest`)
    /// * `setup` - The epoch setup containing SRS parameters
    ///
    /// # Errors
    ///
    /// Returns `TrxError::InvalidInput` if:
    /// - Batch is empty
    /// - Batch size exceeds setup's max batch size
    ///
    /// Returns `TrxError::Backend` if proof computation fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use trx::TrxMinion;
    /// use tess::PairingEngine;
    /// use trx::DecryptionContext;
    /// use rand::thread_rng;
    /// use std::sync::Arc;
    ///
    /// let mut rng = thread_rng();
    /// let client = TrxMinion::<PairingEngine>::new(&mut rng, 5, 3)?;
    ///
    /// # let setup = Arc::new(todo!());
    /// # let batch = vec![];
    /// let context = DecryptionContext {
    ///     block_height: 100,
    ///     context_index: 0,
    /// };
    ///
    /// // Generate commitment
    /// let commitment = client.proposer().compute_digest(&batch, &context, &setup)?;
    ///
    /// // Generate proofs for each transaction
    /// let proofs = client.proposer().compute_eval_proofs(&batch, &context, &setup)?;
    ///
    /// assert_eq!(proofs.len(), batch.len());
    /// println!("Generated {} proofs", proofs.len());
    /// # Ok::<(), trx::TrxError>(())
    /// ```
    pub fn compute_eval_proofs(
        &self,
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &EpochSetup<B>,
    ) -> Result<Vec<EvalProof<B>>, TrxError> {
        TrxCrypto::<B>::compute_eval_proofs(batch, context, setup)
    }

    /// Verify KZG evaluation proofs for an entire batch.
    ///
    /// Validators should call this before generating partial decryptions
    /// to ensure the batch commitment is valid.
    ///
    /// # Verification Process
    ///
    /// For each transaction:
    /// 1. Recompute `y = H(tx_i || context)`
    /// 2. Verify pairing equation: `e(proof, [τ - (i+1)]₂) = e(C - [y]₁, H)`
    ///
    /// # Arguments
    ///
    /// * `setup` - The epoch setup containing SRS and pairing parameters
    /// * `commitment` - The batch commitment to verify against
    /// * `batch` - The batch of encrypted transactions
    /// * `context` - Decryption context (must match commitment)
    /// * `proofs` - Evaluation proofs (one per transaction)
    ///
    /// # Errors
    ///
    /// Returns `TrxError::InvalidInput` if:
    /// - Proofs length doesn't match batch length
    /// - Any proof fails verification
    /// - Batch is empty
    ///
    /// # Example
    ///
    /// ```no_run
    /// use trx::TrxMinion;
    /// use tess::PairingEngine;
    /// use trx::DecryptionContext;
    /// use rand::thread_rng;
    /// use std::sync::Arc;
    ///
    /// let mut rng = thread_rng();
    /// let client = TrxMinion::<PairingEngine>::new(&mut rng, 5, 3)?;
    ///
    /// # let setup = Arc::new(todo!());
    /// # let batch = vec![];
    /// # let commitment = todo!();
    /// # let proofs = vec![];
    /// let context = DecryptionContext {
    ///     block_height: 100,
    ///     context_index: 0,
    /// };
    ///
    /// // Validator verifies batch before decrypting
    /// match client.proposer().verify_eval_proofs(
    ///     &setup,
    ///     &commitment,
    ///     &batch,
    ///     &context,
    ///     &proofs,
    /// ) {
    ///     Ok(_) => println!("Batch verified, safe to decrypt"),
    ///     Err(e) => println!("Invalid batch: {}", e),
    /// }
    /// # Ok::<(), trx::TrxError>(())
    /// ```
    pub fn verify_eval_proofs(
        &self,
        setup: &EpochSetup<B>,
        commitment: &BatchCommitment<B>,
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        proofs: &[EvalProof<B>],
    ) -> Result<(), TrxError> {
        verify_eval_proofs(setup, commitment, batch, context, proofs)
    }
}
