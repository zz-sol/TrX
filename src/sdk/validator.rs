//! Validator Phase API - Key generation and partial decryption.
//!
//! This phase handles validator-side operations including non-interactive
//! key generation and creating partial decryptions for batches.

use crate::{
    BatchCommitment, BatchDecryption, DecryptionContext, PartialDecryption,
    ThresholdEncryptionPublicKey, ThresholdEncryptionSecretKeyShare, TrxCrypto, TrxError,
    ValidatorKeyPair,
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
    /// # Example
    ///
    /// ```no_run
    /// use trx::TrxMinion;
    /// use tess::PairingEngine;
    /// use trx::DecryptionContext;
    /// use rand::thread_rng;
    ///
    /// let mut rng = thread_rng();
    /// let client = TrxMinion::<PairingEngine>::new(&mut rng, 5, 3)?;
    ///
    /// # let secret_share = todo!();
    /// # let commitment = todo!();
    /// # let ciphertext = todo!();
    /// let context = DecryptionContext {
    ///     block_height: 100,
    ///     context_index: 0,
    /// };
    ///
    /// // Validator generates partial decryption for tx 0 in the batch
    /// let partial_decryption = client.validator().generate_partial_decryption(
    ///     &secret_share,
    ///     &commitment,
    ///     &context,
    ///     0,  // tx_index
    ///     &ciphertext,
    /// )?;
    ///
    /// // Broadcast partial_decryption to other validators
    /// # Ok::<(), trx::TrxError>(())
    /// ```
    pub fn generate_partial_decryption(
        &self,
        secret_share: &ThresholdEncryptionSecretKeyShare<B>,
        commitment: &BatchCommitment<B>,
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

    /// Verify a partial decryption from another validator.
    ///
    /// This checks that the partial decryption was correctly computed
    /// using the validator's public key and the batch commitment.
    ///
    /// # Arguments
    ///
    /// * `partial_decryption` - The partial decryption to verify
    /// * `commitment` - The batch commitment
    /// * `public_keys` - Map of validator ID -> public key for all validators
    ///
    /// # Errors
    ///
    /// Returns `TrxError::InvalidInput` if:
    /// - The partial decryption doesn't match the commitment
    /// - The validator ID is not in the public keys map
    /// - The cryptographic verification fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use trx::TrxMinion;
    /// use tess::PairingEngine;
    /// use std::collections::HashMap;
    /// use rand::thread_rng;
    ///
    /// let mut rng = thread_rng();
    /// let client = TrxMinion::<PairingEngine>::new(&mut rng, 5, 3)?;
    ///
    /// # let partial_decryption = todo!();
    /// # let commitment = todo!();
    /// # let public_keys: HashMap<u32, _> = HashMap::new();
    ///
    /// // Verify partial decryption from validator before accepting
    /// match client.validator().verify_partial_decryption(
    ///     &partial_decryption,
    ///     &commitment,
    ///     &public_keys,
    /// ) {
    ///     Ok(_) => println!("Valid partial decryption"),
    ///     Err(e) => println!("Invalid partial decryption: {}", e),
    /// }
    /// # Ok::<(), trx::TrxError>(())
    /// ```
    pub fn verify_partial_decryption(
        &self,
        partial_decryption: &PartialDecryption<B>,
        commitment: &BatchCommitment<B>,
        public_keys: &std::collections::HashMap<u32, ThresholdEncryptionPublicKey<B>>,
    ) -> Result<(), TrxError> {
        TrxCrypto::<B>::verify_partial_decryption(partial_decryption, commitment, public_keys)
    }
}
