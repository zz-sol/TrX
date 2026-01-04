//! Decryption Phase API - Combining partial decryptions into plaintexts.
//!
//! This phase handles the final step of threshold decryption where
//! partial decryptions from validators are aggregated to recover plaintexts.

use crate::{
    verify_validator_share_bound, BatchContext, BatchDecryption, DecryptionResult, EpochSetup,
    PartialDecryption, SignedPartialDecryption, ThresholdEncryptionPublicKey, TrxCrypto, TrxError,
};
use tess::{Fr, PairingBackend};

/// Decryption Phase API for combining threshold shares.
///
/// This phase handles:
/// - Combining partial decryptions from validators
/// - Verifying batch integrity via KZG proofs
/// - Recovering transaction plaintexts
/// - Optionally verifying commitment-bound share signatures
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
/// // Combine threshold partial decryptions
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
    /// 3. At least `threshold` partial decryptions have been collected
    ///
    /// # Process
    ///
    /// For each transaction in the batch:
    /// 1. Verify KZG eval proof for batch integrity
    /// 2. Collect `threshold` partial decryptions for the transaction
    /// 3. Use Lagrange interpolation to combine shares in G2
    /// 4. Apply combined key to TESS ciphertext to recover plaintext
    ///
    /// # Arguments
    ///
    /// * `partial_decryptions` - Vec of partial decryptions from validators
    ///   (must have at least `threshold` shares per transaction)
    /// * `batch_ctx` - Batch context containing batch, context, commitment, and proofs
    /// * `threshold` - Minimum number of shares required (t in t-of-n threshold)
    /// * `setup` - The epoch setup used for the epoch
    /// * `agg_key` - The aggregate public key from the epoch
    ///
    /// # Security Considerations
    ///
    /// - KZG proofs are verified before decryption to prevent batch manipulation
    /// - Lagrange interpolation uses validator IDs as evaluation points
    /// - Requires exactly `threshold` shares (not more, not less per transaction)
    ///
    /// # Errors
    ///
    /// Returns `TrxError::NotEnoughShares` if fewer than `threshold` shares
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
    /// let batch_ctx = BatchContext::new(batch, context, commitment, eval_proofs);
    ///
    /// // Collect partial decryptions from validators
    /// let mut partial_decryptions = vec![];
    ///
    /// # let validator_secret_shares = vec![];
    /// // For each transaction, collect threshold shares
    /// for (tx_index, tx) in batch_ctx.transactions.iter().enumerate() {
    ///     // Get shares from first threshold validators
    ///     for share in validator_secret_shares.iter().take(3) {  // threshold = 3
    ///         let pd = client.validator().generate_partial_decryption(
    ///             share,
    ///             &batch_ctx.commitment,
    ///             &batch_ctx.context,
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
    ///     &batch_ctx,
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
    pub fn combine_and_decrypt(
        &self,
        partial_decryptions: Vec<PartialDecryption<B>>,
        batch_ctx: &BatchContext<B>,
        threshold: u32,
        setup: &EpochSetup<B>,
        agg_key: &ThresholdEncryptionPublicKey<B>,
    ) -> Result<Vec<DecryptionResult>, TrxError> {
        self.crypto.combine_and_decrypt(
            partial_decryptions,
            batch_ctx,
            threshold,
            setup,
            &agg_key.agg_key,
        )
    }

    /// Combine and decrypt with signed, commitment-bound shares.
    pub fn combine_and_decrypt_signed(
        &self,
        signed_partial_decryptions: Vec<SignedPartialDecryption<B>>,
        batch_ctx: &BatchContext<B>,
        threshold: u32,
        setup: &EpochSetup<B>,
        agg_key: &ThresholdEncryptionPublicKey<B>,
    ) -> Result<Vec<DecryptionResult>, TrxError> {
        let commitment_hash = crate::utils::hash_commitment_for_signature(&batch_ctx.commitment);
        for signed in &signed_partial_decryptions {
            let share = &signed.share;
            if share.context.block_height != batch_ctx.context.block_height
                || share.context.context_index != batch_ctx.context.context_index
            {
                return Err(TrxError::InvalidInput(
                    "partial decryptions have mismatched contexts".into(),
                ));
            }
            let tx = batch_ctx
                .transactions
                .get(share.tx_index)
                .ok_or_else(|| TrxError::InvalidInput("invalid tx index".into()))?;
            let ciphertext_hash = crate::utils::hash_ciphertext_for_share_signature(
                &tx.ciphertext,
                &tx.associated_data,
            );
            verify_validator_share_bound(
                &signed.validator_vk,
                &signed.signature,
                &commitment_hash,
                &ciphertext_hash,
                share,
            )?;
            TrxCrypto::<B>::verify_partial_decryption(
                share,
                &batch_ctx.commitment,
                &tx.ciphertext,
                &agg_key.agg_key,
            )?;
        }

        let shares = signed_partial_decryptions
            .into_iter()
            .map(|signed| signed.share)
            .collect();
        self.combine_and_decrypt(shares, batch_ctx, threshold, setup, agg_key)
    }
}
