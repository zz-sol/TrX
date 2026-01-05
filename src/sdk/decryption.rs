//! Decryption Phase API - Combining partial decryptions into plaintexts.
//!
//! This phase handles the final step of threshold decryption where
//! partial decryptions from validators are aggregated to recover plaintexts.

use crate::{
    verify_validator_share_bound, BatchContext, CollectiveDecryption, DecryptionResult, EpochSetup,
    PartialDecryption, ThresholdEncryptionPublicKey, TrxCrypto, TrxError,
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
/// # let signed_partial_decryptions = vec![];
/// # let batch_ctx = todo!();
/// # let setup = Arc::new(todo!());
/// # let agg_key = todo!();
///
/// // Combine signed, commitment-bound shares
/// let results = client.decryption().combine_and_decrypt_signed(
///     signed_partial_decryptions,
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
    /// This is an internal helper for unsigned shares.
    pub(crate) fn combine_and_decrypt(
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
        signed_partial_decryptions: Vec<PartialDecryption<B>>,
        batch_ctx: &BatchContext<B>,
        threshold: u32,
        setup: &EpochSetup<B>,
        agg_key: &ThresholdEncryptionPublicKey<B>,
    ) -> Result<Vec<DecryptionResult>, TrxError> {
        let commitment_hash =
            crate::utils::hash_commitment_for_signature(&batch_ctx.batch_proofs.commitment);
        for share in &signed_partial_decryptions {
            if share.context.block_height != batch_ctx.context.block_height
                || share.context.context_index != batch_ctx.context.context_index
            {
                return Err(TrxError::InvalidInput(
                    "partial decryptions have mismatched contexts".into(),
                ));
            }
            let signature = share
                .signature
                .as_ref()
                .ok_or_else(|| TrxError::InvalidInput("missing share signature".into()))?;
            let validator_vk = share.validator_vk.as_ref().ok_or_else(|| {
                TrxError::InvalidInput("missing validator verification key".into())
            })?;
            let tx = batch_ctx
                .transactions
                .get(share.tx_index)
                .ok_or_else(|| TrxError::InvalidInput("invalid tx index".into()))?;
            let ciphertext_hash = crate::utils::hash_ciphertext_for_share_signature(
                &tx.ciphertext,
                &tx.associated_data,
            );
            verify_validator_share_bound(
                validator_vk,
                signature,
                &commitment_hash,
                &ciphertext_hash,
                share,
            )?;
            TrxCrypto::<B>::verify_partial_decryption(
                share,
                &batch_ctx.batch_proofs.commitment,
                &tx.ciphertext,
                &agg_key.agg_key,
            )?;
        }

        self.combine_and_decrypt(
            signed_partial_decryptions,
            batch_ctx,
            threshold,
            setup,
            agg_key,
        )
    }
}
