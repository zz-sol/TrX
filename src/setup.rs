//! Trusted setup generation and distributed key generation (DKG).
//!
//! This module handles the cryptographic setup required for TrX:
//!
//! # Trusted Setup
//!
//! The [`TrustedSetup`] contains:
//! - **SRS (Structured Reference String)**: Powers of tau for KZG commitments
//! - **Kappa Contexts**: Randomized contexts for per-epoch decryption
//!
//! The setup is generated once and shared across all epochs. It must be generated
//! using a secure ceremony or trusted randomness source.
//!
//! # Distributed Key Generation (DKG)
//!
//! The [`SetupManager`] trait provides DKG for generating threshold keys:
//! - Each validator receives a secret key share
//! - Public keys are aggregated into a threshold public key
//! - Clients encrypt to the aggregate key
//! - Threshold-many validators can decrypt
//!
//! # Epoch Keys
//!
//! [`EpochKeys`] bundles the cryptographic material for a single epoch:
//! - Aggregate public key for encryption
//! - Validator secret key shares for decryption
//! - Reference to the trusted setup
//!
//! # Example
//!
//! ```rust,no_run
//! # use trx2::*;
//! # use std::sync::Arc;
//! # fn example() -> Result<(), TrxError> {
//! let mut rng = rand::thread_rng();
//! let crypto = TrxCrypto::<tess::Bn254>::new(&mut rng, 5, 3)?;
//!
//! // Generate trusted setup (once)
//! let setup = crypto.generate_trusted_setup(&mut rng, 128, 1000)?;
//!
//! // Run DKG for each epoch
//! let validators = vec![0, 1, 2, 3, 4];
//! let epoch_keys = crypto.run_dkg(&mut rng, &validators, 3, Arc::new(setup))?;
//!
//! // Use epoch_keys.public_key for encryption
//! // Validators use epoch_keys.validator_shares for decryption
//! # Ok(())
//! # }
//! ```

use core::sync::atomic::AtomicBool;
use std::collections::HashMap;
use std::sync::Arc;

use rand_core::RngCore;
use tess::{CurvePoint, FieldElement, Fr, PairingBackend, SRS, ThresholdEncryption};

use crate::{PublicKey, SecretKeyShare, TrxCrypto, TrxError, ValidatorId};

/// Trusted setup for KZG commitments and threshold encryption.
///
/// Contains the cryptographic parameters needed for the entire system:
/// - SRS for KZG polynomial commitments
/// - Powers of tau in both G1 and G2 for various operations
/// - Kappa contexts for randomness binding in batch decryption
///
/// The setup is generated once during system initialization and must be
/// generated using secure randomness. It can be reused across multiple epochs.
#[derive(Debug)]
pub struct TrustedSetup<B: PairingBackend<Scalar = Fr>> {
    /// Structured reference string for KZG commitments
    pub srs: SRS<B>,
    /// Powers of tau in G1: [τ⁰G, τ¹G, τ²G, ..., τⁿG]
    pub powers_of_tau: Vec<B::G1>,
    /// Powers of tau in G2: [τ⁰H, τ¹H, τ²H, ..., τⁿH]
    pub powers_of_tau_g2: Vec<B::G2>,
    /// Randomized kappa contexts (one per potential decryption context)
    pub kappa_setups: Vec<KappaSetup<B>>,
}

/// Single-use randomized context for batch decryption.
///
/// Each kappa context provides a unique randomness binding for a specific
/// decryption session. Contexts are marked as "used" atomically to prevent
/// replay attacks and ensure fresh randomness per batch.
///
/// The elements are computed as `κ * powers_of_tau` where `κ` is a random scalar.
#[derive(Debug)]
pub struct KappaSetup<B: PairingBackend> {
    /// Sequential index of this kappa context
    pub index: u32,
    /// Randomized SRS elements: [κτ⁰G, κτ¹G, κτ²G, ...]
    pub elements: Vec<B::G1>,
    /// Atomic flag indicating if this context has been consumed
    pub used: AtomicBool,
}

/// Cryptographic material for a single epoch.
///
/// Bundles together all keys and setup parameters needed for an epoch:
/// - Threshold public key for client encryption
/// - Validator secret key shares for decryption
/// - Reference to the shared trusted setup
///
/// Epochs are typically rotated periodically (e.g., daily) to provide
/// forward secrecy and limit exposure from key compromises.
#[derive(Clone, Debug)]
pub struct EpochKeys<B: PairingBackend<Scalar = Fr>> {
    /// Unique identifier for this epoch
    pub epoch_id: u64,
    /// Aggregate threshold public key for encryption
    pub public_key: PublicKey<B>,
    /// Map from validator ID to their secret key share
    pub validator_shares: HashMap<ValidatorId, SecretKeyShare<B>>,
    /// Shared reference to the trusted setup
    pub setup: Arc<TrustedSetup<B>>,
}

/// Setup and key generation interface for TrX.
///
/// Provides methods for:
/// - Generating the initial trusted setup
/// - Running DKG to create epoch keys
/// - Verifying setup correctness
pub trait SetupManager<B: PairingBackend<Scalar = Fr>> {
    /// Generates a trusted setup for the TrX system.
    ///
    /// Creates an SRS (structured reference string) for KZG commitments and
    /// generates randomized kappa contexts for batch decryption. This is a
    /// one-time operation performed during system initialization.
    ///
    /// # Arguments
    ///
    /// * `rng` - Cryptographically secure random number generator
    /// * `max_batch_size` - Maximum number of transactions per batch (determines SRS size)
    /// * `max_contexts` - Number of kappa contexts to pre-generate (limits concurrent batches)
    ///
    /// # Returns
    ///
    /// A [`TrustedSetup`] containing the SRS and kappa contexts.
    ///
    /// # Errors
    ///
    /// Returns [`TrxError::InvalidConfig`] if `max_batch_size` is zero.
    ///
    /// # Security
    ///
    /// The randomness source must be secure. In production, use a trusted setup
    /// ceremony or hardware security module. The setup is binding under the
    /// discrete log assumption.
    fn generate_trusted_setup(
        &self,
        rng: &mut impl RngCore,
        max_batch_size: usize,
        max_contexts: usize,
    ) -> Result<TrustedSetup<B>, TrxError>;

    /// Runs distributed key generation for a new epoch.
    ///
    /// Generates threshold encryption keys where:
    /// - Each validator receives a secret key share
    /// - Public keys are aggregated into a threshold public key
    /// - Any threshold-many validators can collaborate to decrypt
    ///
    /// # Arguments
    ///
    /// * `rng` - Cryptographically secure random number generator
    /// * `validators` - List of validator IDs participating in this epoch
    /// * `threshold` - Minimum number of validators needed to decrypt (must be < parties)
    /// * `setup` - Shared trusted setup reference
    ///
    /// # Returns
    ///
    /// [`EpochKeys`] containing the aggregate key and validator shares.
    ///
    /// # Errors
    ///
    /// - [`TrxError::InvalidConfig`] if validators list is empty, mismatches parties,
    ///   or threshold is invalid
    ///
    /// # Notes
    ///
    /// This implementation uses a simulated DKG (keys generated locally). In a real
    /// deployment, use a secure multi-party DKG protocol.
    fn run_dkg(
        &self,
        rng: &mut impl RngCore,
        validators: &[ValidatorId],
        threshold: u32,
        setup: Arc<TrustedSetup<B>>,
    ) -> Result<EpochKeys<B>, TrxError>;

    /// Verifies the integrity of a trusted setup.
    ///
    /// Performs basic sanity checks on the setup parameters. In production,
    /// this should include pairing checks to verify the powers-of-tau structure.
    ///
    /// # Arguments
    ///
    /// * `setup` - Trusted setup to verify
    ///
    /// # Errors
    ///
    /// Returns [`TrxError::InvalidInput`] if setup is malformed (e.g., empty powers).
    fn verify_setup(&self, setup: &TrustedSetup<B>) -> Result<(), TrxError>;
}

impl<B: PairingBackend<Scalar = Fr>> SetupManager<B> for TrxCrypto<B> {
    fn generate_trusted_setup(
        &self,
        rng: &mut impl RngCore,
        max_batch_size: usize,
        max_contexts: usize,
    ) -> Result<TrustedSetup<B>, TrxError> {
        if max_batch_size == 0 {
            return Err(TrxError::InvalidConfig("max_batch_size must be > 0".into()));
        }
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let srs = <tess::KZG as tess::PolynomialCommitment<B>>::setup(max_batch_size, &seed)
            .map_err(|e| TrxError::Backend(e.to_string()))?;

        let powers_of_tau = srs.powers_of_g.clone();
        let powers_of_tau_g2 = srs.powers_of_h.clone();

        let mut kappa_setups = Vec::with_capacity(max_contexts);
        for idx in 0..max_contexts {
            let kappa = B::Scalar::random(rng);
            let elements = powers_of_tau
                .iter()
                .map(|g| g.mul_scalar(&kappa))
                .collect::<Vec<_>>();
            kappa_setups.push(KappaSetup {
                index: idx as u32,
                elements,
                used: AtomicBool::new(false),
            });
        }

        Ok(TrustedSetup {
            srs,
            powers_of_tau,
            powers_of_tau_g2,
            kappa_setups,
        })
    }

    fn run_dkg(
        &self,
        rng: &mut impl RngCore,
        validators: &[ValidatorId],
        threshold: u32,
        setup: Arc<TrustedSetup<B>>,
    ) -> Result<EpochKeys<B>, TrxError> {
        let parties = validators.len();
        if parties == 0 {
            return Err(TrxError::InvalidConfig("validators cannot be empty".into()));
        }
        if parties != self.parties {
            return Err(TrxError::InvalidConfig(
                "validators length must match parties".into(),
            ));
        }
        if threshold as usize != self.threshold {
            return Err(TrxError::InvalidConfig(
                "threshold must match crypto configuration".into(),
            ));
        }

        let keys = self.scheme.keygen(rng, parties, &self.params)?;
        let agg_key = self
            .scheme
            .aggregate_public_key(&keys.public_keys, &self.params, parties)?;

        let mut validator_shares = HashMap::new();
        for (idx, sk) in keys.secret_keys.iter().enumerate() {
            let id = validators
                .get(idx)
                .ok_or_else(|| TrxError::InvalidInput("validator index mismatch".into()))?;
            validator_shares.insert(
                *id,
                SecretKeyShare {
                    share: sk.scalar,
                    index: idx as u32,
                },
            );
        }

        Ok(EpochKeys {
            epoch_id: 0,
            public_key: PublicKey { agg_key },
            validator_shares,
            setup,
        })
    }

    fn verify_setup(&self, setup: &TrustedSetup<B>) -> Result<(), TrxError> {
        if setup.powers_of_tau.is_empty() || setup.powers_of_tau_g2.is_empty() {
            return Err(TrxError::InvalidInput(
                "trusted setup missing powers".into(),
            ));
        }
        Ok(())
    }
}
