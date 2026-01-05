//! Setup types and key aggregation logic.

use core::sync::atomic::AtomicBool;
use std::sync::Arc;

use rand_core::RngCore;
use tess::{CurvePoint, FieldElement, Fr, PairingBackend, Params, ThresholdEncryption, SRS};
use tracing::instrument;

use super::engine::TrxCrypto;
use crate::{
    ThresholdEncryptionPublicKey, ThresholdEncryptionSecretKeyShare, TrxError, ValidatorId,
};

/// Global setup parameters (one-time, reusable across epochs).
///
/// This bundles:
/// - Tess params for threshold key generation (includes lagrange powers)
/// - An independent SRS for KZG commitments sized to the max batch size
///
/// From the global setup, epoch-specific randomized kappa contexts can be derived.
#[derive(Clone, Debug)]
pub struct GlobalSetup<B: PairingBackend<Scalar = Fr>> {
    /// Tess parameters for key generation and aggregation.
    pub params: Params<B>,
    /// KZG structured reference string for batch commitments.
    pub srs: SRS<B>,
}

/// Epoch-specific setup with randomized kappa contexts.
///
/// This is derived from the GlobalSetup for each epoch and contains:
/// - Randomized kappa contexts for batch decryption
/// - Reference to the global setup
///
/// Each kappa context is computed as κ·[τ⁰G, τ¹G, τ²G, ...] where κ is a
/// random scalar specific to this epoch, and the SRS elements come from the global setup.
#[derive(Debug)]
pub struct EpochSetup<B: PairingBackend<Scalar = Fr>> {
    /// Epoch identifier
    pub epoch_id: u64,
    /// Randomized kappa contexts (one per potential decryption context/block)
    pub kappa_setups: Vec<KappaSetup<B>>,
    /// Reference to the global setup
    pub global_setup: Arc<GlobalSetup<B>>,
}

impl<B: PairingBackend<Scalar = Fr>> EpochSetup<B> {
    /// Validates that a context index is within bounds.
    #[instrument(
        level = "info",
        skip_all,
        fields(context_index, max_contexts = self.kappa_setups.len())
    )]
    pub fn validate_context_index(&self, context_index: u32) -> Result<(), TrxError> {
        if context_index as usize >= self.kappa_setups.len() {
            let max_msg = if self.kappa_setups.is_empty() {
                "no kappa contexts available".to_string()
            } else {
                format!("exceeds maximum {}", self.kappa_setups.len() - 1)
            };
            return Err(TrxError::InvalidInput(format!(
                "context_index {} {} (from epoch setup)",
                context_index, max_msg
            )));
        }
        Ok(())
    }

    /// Get the SRS from the global setup.
    pub fn srs(&self) -> &SRS<B> {
        &self.global_setup.srs
    }
}

/// Single-use randomized context for batch decryption.
#[derive(Debug)]
pub struct KappaSetup<B: PairingBackend> {
    /// Sequential index of this kappa context
    pub index: u32,
    /// Randomized SRS elements: [κτ⁰G, κτ¹G, κτ²G, ...]
    pub elements: Vec<B::G1>,
    /// Atomic flag indicating if this context has been consumed
    pub used: AtomicBool,
}

impl<B: PairingBackend> KappaSetup<B> {
    /// Atomically marks this context as used.
    #[instrument(level = "info", skip_all, fields(index = self.index))]
    pub fn try_use(&self) -> Result<(), TrxError> {
        use core::sync::atomic::Ordering;
        if self.used.swap(true, Ordering::SeqCst) {
            return Err(TrxError::InvalidInput(format!(
                "kappa context {} already used",
                self.index
            )));
        }
        Ok(())
    }

    /// Checks if this context has been used.
    #[instrument(level = "info", skip_all, fields(index = self.index))]
    pub fn is_used(&self) -> bool {
        use core::sync::atomic::Ordering;
        self.used.load(Ordering::SeqCst)
    }
}

/// Cryptographic material for a single epoch.
#[derive(Clone, Debug)]
pub struct EpochKeys<B: PairingBackend<Scalar = Fr>> {
    /// Unique identifier for this epoch
    ///
    /// Placeholder field: callers should supply their own epoch ID scheme.
    pub epoch_id: u64,
    /// Aggregate threshold public key for encryption
    pub public_key: ThresholdEncryptionPublicKey<B>,
    /// Shared reference to the epoch setup (contains kappa contexts and global setup)
    pub epoch_setup: Arc<EpochSetup<B>>,
}

/// Individual validator's key pair for threshold encryption.
#[derive(Clone, Debug)]
pub struct ValidatorKeyPair<B: PairingBackend<Scalar = Fr>> {
    /// Validator's unique ID
    pub validator_id: ValidatorId,
    /// Public key (can be shared publicly)
    pub public_key: tess::PublicKey<B>,
    /// Secret key share (kept private)
    pub secret_share: ThresholdEncryptionSecretKeyShare<B>,
}

/// Setup and key generation interface for TrX.
pub trait SetupManager<B: PairingBackend<Scalar = Fr>> {
    /// Generates a global setup (one-time, reusable across epochs).
    ///
    /// This generates the universal parameters (SRS and Lagrange points) that can be
    /// reused across all epochs. The global setup is the Tess `Params`.
    ///
    /// # Arguments
    ///
    /// * `rng` - Random number generator
    /// * `max_batch_size` - Maximum number of transactions per batch
    ///
    /// # Returns
    ///
    /// A `GlobalSetup` (Tess `Params`) containing the SRS.
    fn generate_global_setup(
        &self,
        rng: &mut impl RngCore,
        max_batch_size: usize,
    ) -> Result<Arc<GlobalSetup<B>>, TrxError>;

    /// Generates an epoch-specific setup from the global setup.
    ///
    /// This derives randomized kappa contexts from the global setup for a specific epoch.
    /// Each kappa context is computed as κ·SRS where κ is a random scalar.
    ///
    /// # Arguments
    ///
    /// * `rng` - Random number generator
    /// * `epoch_id` - Unique identifier for this epoch
    /// * `max_contexts` - Maximum number of decryption contexts (blocks) in this epoch
    /// * `global_setup` - Reference to the global setup
    ///
    /// # Returns
    ///
    /// An `EpochSetup` containing randomized kappa contexts.
    fn generate_epoch_setup(
        &self,
        rng: &mut impl RngCore,
        epoch_id: u64,
        max_contexts: usize,
        global_setup: Arc<GlobalSetup<B>>,
    ) -> Result<Arc<EpochSetup<B>>, TrxError>;

    /// Verifies the integrity of a global setup.
    fn verify_global_setup(&self, setup: &GlobalSetup<B>) -> Result<(), TrxError>;

    /// Verifies the integrity of an epoch setup.
    fn verify_epoch_setup(&self, setup: &EpochSetup<B>) -> Result<(), TrxError>;

    /// Aggregates public keys from all validators to create epoch keys.
    /// This is the "DKG" step but it's non-interactive - just aggregation of published keys.
    fn aggregate_epoch_keys(
        &self,
        validator_public_keys: &[tess::PublicKey<B>],
        threshold: u32,
        epoch_setup: Arc<EpochSetup<B>>,
    ) -> Result<EpochKeys<B>, TrxError>;
}

impl<B: PairingBackend<Scalar = Fr>> SetupManager<B> for TrxCrypto<B> {
    #[instrument(level = "info", skip_all, fields(max_batch_size))]
    fn generate_global_setup(
        &self,
        rng: &mut impl RngCore,
        max_batch_size: usize,
    ) -> Result<Arc<GlobalSetup<B>>, TrxError> {
        if max_batch_size == 0 {
            return Err(TrxError::InvalidConfig("max_batch_size must be > 0".into()));
        }

        // Generate seed for SRS
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        // Reuse the crypto instance params so keygen/aggregate/encrypt stay consistent.
        let params = self.params.clone();

        // Generate KZG SRS sized for batch commitments.
        let srs = <tess::KZG as tess::PolynomialCommitment<B>>::setup(max_batch_size, &seed)
            .map_err(|e| TrxError::Backend(e.to_string()))?;

        Ok(Arc::new(GlobalSetup { params, srs }))
    }

    #[instrument(level = "info", skip_all, fields(epoch_id, max_contexts))]
    fn generate_epoch_setup(
        &self,
        rng: &mut impl RngCore,
        epoch_id: u64,
        max_contexts: usize,
        global_setup: Arc<GlobalSetup<B>>,
    ) -> Result<Arc<EpochSetup<B>>, TrxError> {
        // Generate randomized kappa contexts from the global SRS
        let mut kappa_setups = Vec::with_capacity(max_contexts);
        for idx in 0..max_contexts {
            let kappa = B::Scalar::random(rng);
            let elements = global_setup
                .srs
                .powers_of_g
                .iter()
                .map(|g| g.mul_scalar(&kappa))
                .collect::<Vec<_>>();
            kappa_setups.push(KappaSetup {
                index: idx as u32,
                elements,
                used: AtomicBool::new(false),
            });
        }

        Ok(Arc::new(EpochSetup {
            epoch_id,
            kappa_setups,
            global_setup,
        }))
    }

    #[instrument(level = "info", skip_all)]
    fn verify_global_setup(&self, setup: &GlobalSetup<B>) -> Result<(), TrxError> {
        if setup.srs.powers_of_g.is_empty() || setup.srs.powers_of_h.is_empty() {
            return Err(TrxError::InvalidInput("global setup missing powers".into()));
        }
        if setup.params.srs.powers_of_g.is_empty() || setup.params.srs.powers_of_h.is_empty() {
            return Err(TrxError::InvalidInput(
                "global setup params missing powers".into(),
            ));
        }
        Ok(())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(kappa_len = setup.kappa_setups.len())
    )]
    fn verify_epoch_setup(&self, setup: &EpochSetup<B>) -> Result<(), TrxError> {
        self.verify_global_setup(&setup.global_setup)?;
        if setup.kappa_setups.is_empty() {
            return Err(TrxError::InvalidInput(
                "epoch setup missing kappa contexts".into(),
            ));
        }
        Ok(())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(num_validators = validator_public_keys.len(), threshold)
    )]
    fn aggregate_epoch_keys(
        &self,
        validator_public_keys: &[tess::PublicKey<B>],
        threshold: u32,
        epoch_setup: Arc<EpochSetup<B>>,
    ) -> Result<EpochKeys<B>, TrxError> {
        let parties = validator_public_keys.len();
        if parties == 0 {
            return Err(TrxError::InvalidConfig("validators cannot be empty".into()));
        }
        if parties != self.parties {
            return Err(TrxError::InvalidConfig(format!(
                "validator count {} must match parties {}",
                parties, self.parties
            )));
        }
        if threshold as usize != self.threshold {
            return Err(TrxError::InvalidConfig(format!(
                "threshold {} must match crypto configuration {}",
                threshold, self.threshold
            )));
        }

        // Aggregate the public keys deterministically
        // This is the non-interactive "DKG" - just aggregation of published public keys
        let agg_key = self.tess_scheme.aggregate_public_key(
            validator_public_keys,
            &epoch_setup.global_setup.params,
            parties,
        )?;

        Ok(EpochKeys {
            epoch_id: epoch_setup.epoch_id,
            public_key: ThresholdEncryptionPublicKey { agg_key },
            epoch_setup,
        })
    }
}
