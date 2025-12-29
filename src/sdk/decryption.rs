//! Decryption Phase API - Combining partial decryptions into plaintexts.
//!
//! This phase handles the final step of threshold decryption where
//! partial decryptions from validators are aggregated to recover plaintexts.

use crate::{
    BatchContext, BatchDecryption, DecryptionResult, PartialDecryption, PublicKey, TrustedSetup,
    TrxCrypto, TrxError,
};
use tess::{Fr, PairingBackend};

/// Decryption Phase API for combining threshold shares.
///
/// This phase handles:
/// - Combining partial decryptions from validators
/// - Verifying batch integrity via KZG proofs
/// - Recovering transaction plaintexts
///
/// # Example
///
/// ```no_run
/// use trx::TrxMinion;
/// use tess::PairingEngine;
/// use trx::BatchContext;
/// use rand::thread_rng;
/// use std::sync::Arc;
///
/// let mut rng = thread_rng();
/// let client = TrxMinion::<PairingEngine>::new(&mut rng, 5, 3)?;
///
/// # let partial_decryptions = vec![];
/// # let batch_ctx = todo!();
/// # let setup = Arc::new(todo!());
/// # let agg_key = todo!();
///
/// // Combine threshold+1 partial decryptions
/// let results = client.decryption().combine_and_decrypt(
///     partial_decryptions,
///     batch_ctx,
///     3,  // threshold
///     &setup,
///     &agg_key,
/// )?;
/// # Ok::<(), trx::TrxError>(())
/// ```
pub struct DecryptionPhase<'a, B: PairingBackend<Scalar = Fr>> {
    crypto: &'a TrxCrypto<B>,
}

impl<'a, B: PairingBackend<Scalar = Fr>> DecryptionPhase<'a, B>
where
    B::G1: PartialEq,
{
    pub(crate) fn new(crypto: &'a TrxCrypto<B>) -> Self {
        Self { crypto }
    }

    /// Combine partial decryptions and recover transaction plaintexts.
    ///
    /// This is the final step of threshold decryption, performed after:
    /// 1. Batch has been committed (KZG commitment + eval proofs)
    /// 2. Validators have generated partial decryptions
    /// 3. At least `threshold + 1` partial decryptions have been collected
    ///
    /// # Process
    ///
    /// For each transaction in the batch:
    /// 1. Verify KZG eval proof for batch integrity
    /// 2. Collect `threshold + 1` partial decryptions for the transaction
    /// 3. Use Lagrange interpolation to combine shares in G2
    /// 4. Apply combined key to TESS ciphertext to recover plaintext
    ///
    /// # Arguments
    ///
    /// * `partial_decryptions` - Vec of partial decryptions from validators
    ///   (must have at least `threshold + 1` shares per transaction)
    /// * `batch_ctx` - Batch context containing batch, context, commitment, and proofs
    /// * `threshold` - Minimum number of shares required (t in t-of-n threshold)
    /// * `setup` - The trusted setup used for the epoch
    /// * `agg_key` - The aggregate public key from the epoch
    ///
    /// # Security Considerations
    ///
    /// - KZG proofs are verified before decryption to prevent batch manipulation
    /// - Lagrange interpolation uses validator IDs as evaluation points
    /// - Requires exactly `threshold + 1` shares (not more, not less per transaction)
    ///
    /// # Errors
    ///
    /// Returns `TrxError::NotEnoughShares` if fewer than `threshold + 1` shares
    /// are provided for any transaction.
    ///
    /// Returns `TrxError::InvalidInput` if:
    /// - KZG proof verification fails
    /// - Partial decryptions are malformed
    /// - Batch context is inconsistent
    ///
    /// Returns `TrxError::Backend` if cryptographic operations fail.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use trx::TrxMinion;
    /// use tess::PairingEngine;
    /// use trx::{BatchContext, DecryptionContext};
    /// use rand::thread_rng;
    /// use std::sync::Arc;
    ///
    /// let mut rng = thread_rng();
    /// let client = TrxMinion::<PairingEngine>::new(&mut rng, 5, 3)?;
    ///
    /// # let setup = Arc::new(todo!());
    /// # let batch = vec![];
    /// # let commitment = todo!();
    /// # let eval_proofs = vec![];
    /// # let epoch_key = todo!();
    ///
    /// let context = DecryptionContext {
    ///     block_height: 100,
    ///     context_index: 0,
    /// };
    ///
    /// let batch_ctx = BatchContext {
    ///     batch: &batch,
    ///     context: &context,
    ///     commitment: &commitment,
    ///     eval_proofs: &eval_proofs,
    /// };
    ///
    /// // Collect partial decryptions from validators
    /// let mut partial_decryptions = vec![];
    ///
    /// # let validator_secret_shares = vec![];
    /// // For each transaction, collect threshold+1 shares
    /// for (tx_index, tx) in batch.iter().enumerate() {
    ///     // Get shares from first threshold+1 validators
    ///     for share in validator_secret_shares.iter().take(4) {  // threshold + 1 = 3 + 1
    ///         let pd = client.validator().generate_partial_decryption(
    ///             share,
    ///             &commitment,
    ///             &context,
    ///             tx_index,
    ///             &tx.ciphertext,
    ///         )?;
    ///         partial_decryptions.push(pd);
    ///     }
    /// }
    ///
    /// // Combine and decrypt
    /// let results = client.decryption().combine_and_decrypt(
    ///     partial_decryptions,
    ///     batch_ctx,
    ///     3,
    ///     &setup,
    ///     &epoch_key,
    /// )?;
    ///
    /// // Process decrypted transactions
    /// for (i, result) in results.iter().enumerate() {
    ///     if let Some(plaintext) = &result.plaintext {
    ///         println!("Transaction {}: {:?}", i, String::from_utf8_lossy(plaintext));
    ///     } else {
    ///         println!("Transaction {} decryption failed", i);
    ///     }
    /// }
    /// # Ok::<(), trx::TrxError>(())
    /// ```
    pub fn combine_and_decrypt<'b>(
        &self,
        partial_decryptions: Vec<PartialDecryption<B>>,
        batch_ctx: BatchContext<'b, B>,
        threshold: u32,
        setup: &TrustedSetup<B>,
        agg_key: &PublicKey<B>,
    ) -> Result<Vec<DecryptionResult>, TrxError> {
        self.crypto.combine_and_decrypt(
            partial_decryptions,
            batch_ctx,
            threshold,
            setup,
            &agg_key.agg_key,
        )
    }
}
