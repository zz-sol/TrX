//! Setup Phase API - System bootstrapping and setup generation.
//!
//! This phase is performed during system initialization and at each epoch
//! to create the cryptographic parameters required for threshold encryption.

use crate::{EpochKeys, EpochSetup, GlobalSetup, SetupManager, TrxCrypto, TrxError};
use std::sync::Arc;
use tess::{Fr, PairingBackend};

/// Setup Phase API for system initialization.
///
/// This phase handles:
/// - Generating global setup (SRS)
/// - Generating epoch setup (randomized kappa contexts)
/// - Aggregating validator public keys
/// - Verifying setup integrity
///
/// # Example
///
/// ```no_run
/// use trx::TrxMinion;
/// use tess::PairingEngine;
/// use rand::thread_rng;
/// let mut rng = thread_rng();
/// let client = TrxMinion::<PairingEngine>::new(&mut rng, 100, 67)?;
///
/// // Generate global setup (SRS)
/// let global_setup = client.setup().generate_global_setup(&mut rng, 1000)?;
///
/// // Generate epoch setup for batches up to 1000 transactions
/// let setup = client
///     .setup()
///     .generate_epoch_setup(&mut rng, 1, 100, global_setup.clone())?;
///
/// // Verify setup integrity
/// client.setup().verify_epoch_setup(&setup)?;
/// # Ok::<(), trx::TrxError>(())
/// ```
pub struct SetupPhase<'a, B: PairingBackend<Scalar = Fr>> {
    crypto: &'a TrxCrypto<B>,
}

impl<'a, B: PairingBackend<Scalar = Fr>> SetupPhase<'a, B> {
    pub(crate) fn new(crypto: &'a TrxCrypto<B>) -> Self {
        Self { crypto }
    }

    /// Generate a new global setup.
    ///
    /// This is a one-time operation that creates the SRS (Structured Reference String)
    /// used for KZG commitments. The resulting `GlobalSetup` can be reused across
    /// all epochs and should be distributed to participants.
    pub fn generate_global_setup(
        &self,
        rng: &mut impl rand_core::RngCore,
        max_batch_size: usize,
    ) -> Result<Arc<GlobalSetup<B>>, TrxError> {
        self.crypto.generate_global_setup(rng, max_batch_size)
    }

    /// Generate a new epoch setup.
    ///
    /// This derives randomized kappa contexts from the global setup for a specific epoch.
    /// Each kappa context is single-use and should be discarded after being consumed.
    pub fn generate_epoch_setup(
        &self,
        rng: &mut impl rand_core::RngCore,
        epoch_id: u64,
        max_contexts: usize,
        global_setup: Arc<GlobalSetup<B>>,
    ) -> Result<Arc<EpochSetup<B>>, TrxError> {
        self.crypto
            .generate_epoch_setup(rng, epoch_id, max_contexts, global_setup)
    }

    /// Aggregate validator public keys into an epoch key.
    ///
    /// This function takes individual validator public keys and combines them
    /// into a single aggregate key used for encryption during the epoch.
    ///
    /// This operation is **non-interactive** - validators generate keys independently,
    /// then a coordinator (or any party) can aggregate the public keys without
    /// needing access to any secret key shares.
    ///
    /// # Arguments
    ///
    /// * `validator_public_keys` - Public keys from all validators
    /// * `threshold` - Minimum number of validators needed for decryption
    /// * `setup` - The epoch setup to bind this epoch to
    ///
    /// # Security Considerations
    ///
    /// - Only public keys are needed for aggregation (secret shares remain private)
    /// - Public keys can be safely shared over insecure channels
    /// - The aggregate key is deterministic (same inputs = same output)
    ///
    /// # Errors
    ///
    /// Returns `TrxError::InvalidConfig` if:
    /// - `threshold >= validator_public_keys.len()`
    /// - Number of public keys doesn't match configured parties
    ///
    /// # Example
    ///
    /// ```no_run
    /// use trx::TrxMinion;
    /// use tess::PairingEngine;
    /// use rand::thread_rng;
    /// use std::sync::Arc;
    ///
    /// let mut rng = thread_rng();
    /// let client = TrxMinion::<PairingEngine>::new(&mut rng, 3, 2)?;
    /// let global_setup = client.setup().generate_global_setup(&mut rng, 100)?;
    /// let setup = client
    ///     .setup()
    ///     .generate_epoch_setup(&mut rng, 1, 10, global_setup.clone())?;
    ///
    /// // Each validator generates their keypair independently
    /// let kp0 = client.validator().keygen_single_validator(&mut rng, 0)?;
    /// let kp1 = client.validator().keygen_single_validator(&mut rng, 1)?;
    /// let kp2 = client.validator().keygen_single_validator(&mut rng, 2)?;
    ///
    /// // Coordinator aggregates ONLY the public keys (validators keep secret shares private)
    /// let epoch_keys = client.setup().aggregate_epoch_keys(
    ///     vec![kp0.public_key, kp1.public_key, kp2.public_key],
    ///     2,
    ///     setup.clone(),
    /// )?;
    ///
    /// // epoch_keys.public_key is now ready for client encryption
    /// # Ok::<(), trx::TrxError>(())
    /// ```
    pub fn aggregate_epoch_keys(
        &self,
        validator_public_keys: Vec<tess::PublicKey<B>>,
        threshold: u32,
        setup: Arc<EpochSetup<B>>,
    ) -> Result<EpochKeys<B>, TrxError> {
        self.crypto
            .aggregate_epoch_keys(validator_public_keys, threshold, setup)
    }

    /// Verify the integrity of a global setup.
    pub fn verify_global_setup(&self, setup: &GlobalSetup<B>) -> Result<(), TrxError> {
        self.crypto.verify_global_setup(setup)
    }

    /// Verify the integrity of an epoch setup.
    pub fn verify_epoch_setup(&self, setup: &EpochSetup<B>) -> Result<(), TrxError> {
        self.crypto.verify_epoch_setup(setup)
    }
}
