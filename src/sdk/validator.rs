//! Validator Phase API - Key generation and partial decryption.
//!
//! This phase handles validator-side operations including non-interactive
//! key generation and creating partial decryptions for batches.

use crate::{
    sign_validator_share_bound, validator_verify_key, CollectiveDecryption, DecryptionContext,
    PartialDecryption, ThresholdEncryptionSecretKeyShare, TransactionBatchCommitment, TrxCrypto,
    TrxError, ValidatorKeyPair, ValidatorSigningKey,
};
use tess::{Ciphertext as TessCiphertext, Fr, PairingBackend};

/// Validator Phase API for key generation and decryption operations.
///
/// This phase handles:
/// - Silent (non-interactive) key generation per validator
/// - Generating partial decryptions for transaction batches
/// - Verifying partial decryptions from other validators
///
/// # Example
///
/// ```no_run
/// use trx::TrxMinion;
/// use tess::PairingEngine;
/// use rand::thread_rng;
///
/// let mut rng = thread_rng();
/// let client = TrxMinion::<PairingEngine>::new(&mut rng, 5, 3)?;
///
/// // Validator 0 generates their keypair independently
/// let validator_keypair = client.validator().keygen_single_validator(&mut rng, 0)?;
///
/// // Keep the secret key share private!
/// // Share the public key with coordinator for aggregation
/// # Ok::<(), trx::TrxError>(())
/// ```
pub struct ValidatorPhase<'a, B: PairingBackend<Scalar = Fr>> {
    crypto: &'a TrxCrypto<B>,
}

impl<'a, B: PairingBackend<Scalar = Fr>> ValidatorPhase<'a, B> {
    pub(crate) fn new(crypto: &'a TrxCrypto<B>) -> Self {
        Self { crypto }
    }

    /// Generate a keypair for a single validator (silent setup).
    ///
    /// This is a **non-interactive** operation - each validator can independently
    /// generate their keypair without coordinating with other validators.
    ///
    /// After generation:
    /// 1. The validator keeps `ValidatorKeyPair.secret_share` private
    /// 2. The validator publishes `ValidatorKeyPair.public_key` to a coordinator
    /// 3. The coordinator aggregates all public keys (see `SetupPhase::aggregate_epoch_keys`)
    ///
    /// # Arguments
    ///
    /// * `rng` - Cryptographically secure random number generator
    /// * `validator_id` - Unique identifier for this validator (0-indexed)
    ///
    /// # Security Considerations
    ///
    /// - **CRITICAL**: Never share or serialize the secret key share
    /// - Each validator must use a unique `validator_id`
    /// - The RNG must be cryptographically secure (not a test RNG)
    ///
    /// # Errors
    ///
    /// Returns `TrxError::Backend` if key generation fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use trx::TrxMinion;
    /// use tess::PairingEngine;
    /// use rand::thread_rng;
    ///
    /// let mut rng = thread_rng();
    /// let client = TrxMinion::<PairingEngine>::new(&mut rng, 100, 67)?;
    ///
    /// // Each validator runs this independently
    /// let validator_0_keypair = client.validator().keygen_single_validator(&mut rng, 0)?;
    /// let validator_1_keypair = client.validator().keygen_single_validator(&mut rng, 1)?;
    /// // ... (all 100 validators)
    ///
    /// // Validators publish their public keys for aggregation
    /// // They NEVER share their secret_share!
    /// # Ok::<(), trx::TrxError>(())
    /// ```
    pub fn keygen_single_validator(
        &self,
        rng: &mut impl rand_core::RngCore,
        validator_id: u32,
    ) -> Result<ValidatorKeyPair<B>, TrxError> {
        self.crypto.keygen_single_validator(rng, validator_id)
    }

    /// Generate a partial decryption for a specific transaction in a batch.
    ///
    /// Validators generate partial decryptions after a batch has been committed
    /// (via KZG commitment). Each validator contributes one partial decryption
    /// per transaction in the batch.
    ///
    /// # Arguments
    ///
    /// * `secret_share` - This validator's secret key share (from `keygen_single_validator`)
    /// * `commitment` - The KZG commitment binding the batch
    /// * `context` - The decryption context (block height + context index)
    /// * `tx_index` - Index of the transaction within the batch (0-indexed)
    /// * `ciphertext` - The TESS ciphertext to decrypt
    ///
    /// # Security Considerations
    ///
    /// - Validators should verify the batch commitment before generating shares
    /// - The context binds decryption to a specific block (prevents replay attacks)
    /// - Partial decryptions can be safely shared publicly
    ///
    /// # Errors
    ///
    /// Returns `TrxError::Backend` if partial decryption computation fails.
    ///
    /// Internal helper for unsigned shares.
    pub(crate) fn generate_partial_decryption(
        &self,
        secret_share: &ThresholdEncryptionSecretKeyShare<B>,
        commitment: &TransactionBatchCommitment<B>,
        context: &DecryptionContext,
        tx_index: usize,
        ciphertext: &TessCiphertext<B>,
    ) -> Result<PartialDecryption<B>, TrxError> {
        TrxCrypto::<B>::generate_partial_decryption(
            secret_share,
            commitment,
            context,
            tx_index,
            ciphertext,
        )
    }

    /// Generate a signed partial decryption bound to batch commitment and context.
    ///
    /// The signature covers commitment hash, context, tx index, and ciphertext hash.
    #[allow(clippy::too_many_arguments)]
    pub fn generate_signed_partial_decryption(
        &self,
        signing_key: &ValidatorSigningKey,
        secret_share: &ThresholdEncryptionSecretKeyShare<B>,
        commitment: &TransactionBatchCommitment<B>,
        context: &DecryptionContext,
        tx_index: usize,
        ciphertext: &TessCiphertext<B>,
        associated_data: &[u8],
    ) -> Result<PartialDecryption<B>, TrxError> {
        let mut share = self.generate_partial_decryption(
            secret_share,
            commitment,
            context,
            tx_index,
            ciphertext,
        )?;
        let commitment_hash = crate::utils::hash_commitment_for_signature(commitment);
        let ciphertext_hash =
            crate::utils::hash_ciphertext_for_share_signature(ciphertext, associated_data);
        let signature =
            sign_validator_share_bound(signing_key, &commitment_hash, &ciphertext_hash, &share);
        share.signature = Some(signature);
        share.validator_vk = Some(validator_verify_key(signing_key));
        Ok(share)
    }
}
