//! Setup Phase API - System bootstrapping and trusted setup generation.
//!
//! This phase is performed once during system initialization to create the
//! cryptographic parameters required for threshold encryption.

use crate::{EpochKeys, SetupManager, TrustedSetup, TrxCrypto, TrxError, ValidatorKeyPair};
use std::sync::Arc;
use tess::{Fr, PairingBackend};

/// Setup Phase API for system initialization.
///
/// This phase handles:
/// - Generating trusted setup (SRS and kappa contexts)
/// - Aggregating validator public keys
/// - Verifying setup integrity
///
/// # Example
///
/// ```no_run
/// use trx::TrxClient;
/// use tess::PairingEngine;
/// use rand::thread_rng;
/// use std::sync::Arc;
///
/// let mut rng = thread_rng();
/// let client = TrxClient::<PairingEngine>::new(&mut rng, 100, 67)?;
///
/// // Generate trusted setup for batches up to 1000 transactions
/// let setup = Arc::new(
///     client.setup().generate_trusted_setup(&mut rng, 1000, 100)?
/// );
///
/// // Verify setup integrity
/// client.setup().verify_setup(&setup)?;
/// # Ok::<(), trx::TrxError>(())
/// ```
pub struct SetupPhase<'a, B: PairingBackend<Scalar = Fr>> {
    crypto: &'a TrxCrypto<B>,
}

impl<'a, B: PairingBackend<Scalar = Fr>> SetupPhase<'a, B> {
    pub(crate) fn new(crypto: &'a TrxCrypto<B>) -> Self {
        Self { crypto }
    }

    /// Generate a new trusted setup.
    ///
    /// This is a one-time operation that creates:
    /// - **SRS (Structured Reference String)**: Powers of tau for KZG commitments
    /// - **Kappa Contexts**: Randomized, single-use contexts for decryption blocks
    ///
    /// The resulting `TrustedSetup` should be:
    /// 1. Verified using `verify_setup()`
    /// 2. Securely archived/distributed to all participants
    /// 3. Used for the lifetime of the system (or until a new epoch)
    ///
    /// # Arguments
    ///
    /// * `rng` - Cryptographically secure random number generator
    /// * `max_batch_size` - Maximum number of transactions per batch
    /// * `max_contexts` - Maximum number of decryption contexts (typically = max blocks)
    ///
    /// # Security Considerations
    ///
    /// - The randomness used in setup generation should be sourced from a trusted process
    /// - For production systems, consider using a distributed setup ceremony (MPC)
    /// - The toxic waste (random scalars) must be destroyed after generation
    ///
    /// # Errors
    ///
    /// Returns `TrxError::Backend` if cryptographic operations fail.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use trx::TrxClient;
    /// use tess::PairingEngine;
    /// use rand::thread_rng;
    /// use std::sync::Arc;
    ///
    /// let mut rng = thread_rng();
    /// let client = TrxClient::<PairingEngine>::new(&mut rng, 100, 67)?;
    ///
    /// // Setup for batches of up to 1000 txs, 100 blocks
    /// let setup = Arc::new(
    ///     client.setup().generate_trusted_setup(&mut rng, 1000, 100)?
    /// );
    ///
    /// // TODO: Securely archive this setup for disaster recovery
    /// # Ok::<(), trx::TrxError>(())
    /// ```
    pub fn generate_trusted_setup(
        &self,
        rng: &mut impl rand_core::RngCore,
        max_batch_size: usize,
        max_contexts: usize,
    ) -> Result<TrustedSetup<B>, TrxError> {
        self.crypto
            .generate_trusted_setup(rng, max_batch_size, max_contexts)
    }

    /// Aggregate validator public keys into an epoch key.
    ///
    /// This function takes individual validator key pairs and combines their
    /// public keys into a single aggregate key used for encryption during the epoch.
    ///
    /// This operation is **non-interactive** - validators generate keys independently,
    /// then a coordinator (or any party) can aggregate the public keys.
    ///
    /// # Arguments
    ///
    /// * `validator_keypairs` - Public and secret key pairs from all validators
    /// * `threshold` - Minimum number of validators needed for decryption
    /// * `setup` - The trusted setup to bind this epoch to
    ///
    /// # Security Considerations
    ///
    /// - Each validator must keep their `SecretKeyShare` private
    /// - Public keys can be safely shared over insecure channels
    /// - The aggregate key is deterministic (same inputs = same output)
    ///
    /// # Errors
    ///
    /// Returns `TrxError::InvalidConfig` if:
    /// - `threshold >= validator_keypairs.len()`
    /// - Validator IDs are not unique
    ///
    /// # Example
    ///
    /// ```no_run
    /// use trx::TrxClient;
    /// use tess::PairingEngine;
    /// use rand::thread_rng;
    /// use std::sync::Arc;
    ///
    /// let mut rng = thread_rng();
    /// let client = TrxClient::<PairingEngine>::new(&mut rng, 3, 2)?;
    /// let setup = Arc::new(client.setup().generate_trusted_setup(&mut rng, 100, 10)?);
    ///
    /// // Each validator generates their keypair independently
    /// let kp0 = client.validator().keygen_single_validator(&mut rng, 0)?;
    /// let kp1 = client.validator().keygen_single_validator(&mut rng, 1)?;
    /// let kp2 = client.validator().keygen_single_validator(&mut rng, 2)?;
    ///
    /// // Coordinator aggregates public keys
    /// let epoch_keys = client.setup().aggregate_epoch_keys(
    ///     vec![kp0, kp1, kp2],
    ///     2,
    ///     setup.clone(),
    /// )?;
    ///
    /// // epoch_keys.public_key is now ready for client encryption
    /// # Ok::<(), trx::TrxError>(())
    /// ```
    pub fn aggregate_epoch_keys(
        &self,
        validator_keypairs: Vec<ValidatorKeyPair<B>>,
        threshold: u32,
        setup: Arc<TrustedSetup<B>>,
    ) -> Result<EpochKeys<B>, TrxError> {
        self.crypto
            .aggregate_epoch_keys(validator_keypairs, threshold, setup)
    }

    /// Verify the integrity of a trusted setup.
    ///
    /// This performs basic structural validation:
    /// - SRS has correct degree for the configured max batch size
    /// - Kappa contexts are present and properly initialized
    ///
    /// # Note
    ///
    /// This does NOT verify the setup was generated honestly (that would require
    /// verifying the MPC transcript in a production setup ceremony).
    ///
    /// # Errors
    ///
    /// Returns `TrxError::InvalidInput` if the setup structure is invalid.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use trx::TrxClient;
    /// use tess::PairingEngine;
    /// use rand::thread_rng;
    /// use std::sync::Arc;
    ///
    /// let mut rng = thread_rng();
    /// let client = TrxClient::<PairingEngine>::new(&mut rng, 100, 67)?;
    /// let setup = Arc::new(client.setup().generate_trusted_setup(&mut rng, 1000, 100)?);
    ///
    /// // Verify before using
    /// client.setup().verify_setup(&setup)?;
    /// println!("Setup verified successfully!");
    /// # Ok::<(), trx::TrxError>(())
    /// ```
    pub fn verify_setup(&self, setup: &TrustedSetup<B>) -> Result<(), TrxError> {
        self.crypto.verify_setup(setup)
    }
}
