//! Cryptographic engine configuration and key generation helpers.

use rand_core::RngCore;
use tess::{Fr, PairingBackend, Params, SilentThresholdScheme, ThresholdEncryption};
use tracing::instrument;

use super::setup::ValidatorKeyPair;
use crate::{ThresholdEncryptionSecretKeyShare, TrxError, ValidatorId};

/// Primary cryptographic engine for TrX protocol.
///
/// Wraps the Tess threshold encryption library and provides implementations
/// of all TrX cryptographic traits. Each instance is configured with fixed
/// threshold parameters (parties, threshold) that determine the security level.
#[derive(Debug)]
pub struct TrxCrypto<B: PairingBackend<Scalar = Fr>> {
    /// Tess threshold encryption scheme
    pub(crate) tess_scheme: SilentThresholdScheme<B>,
    /// Tess cryptographic parameters (SRS, Lagrange powers)
    pub(crate) params: Params<B>,
    /// Total number of parties (validators)
    pub(crate) parties: usize,
    /// Minimum shares needed for decryption
    pub(crate) threshold: usize,
}

impl<B: PairingBackend<Scalar = Fr>> TrxCrypto<B> {
    /// Creates a new TrX cryptographic engine.
    ///
    /// Initializes the Tess threshold encryption scheme with the specified
    /// parameters and generates fresh cryptographic parameters.
    ///
    /// # Arguments
    ///
    /// * `rng` - Cryptographically secure random number generator
    /// * `parties` - Total number of validators participating
    /// * `threshold` - Minimum validators needed to decrypt
    ///
    /// # Returns
    ///
    /// A configured [`TrxCrypto`] instance ready for encryption/decryption.
    ///
    /// # Errors
    ///
    /// Returns [`TrxError::InvalidConfig`] if:
    /// - `threshold` is zero
    /// - `threshold >= parties` (must leave at least one validator redundant)
    #[instrument(level = "info", skip_all, fields(parties, threshold))]
    pub fn new(rng: &mut impl RngCore, parties: usize, threshold: usize) -> Result<Self, TrxError> {
        if threshold == 0 || threshold >= parties {
            return Err(TrxError::InvalidConfig(
                "threshold must be in 1..parties".into(),
            ));
        }
        let tess_scheme = SilentThresholdScheme::<B>::new();
        let params = tess_scheme.param_gen(rng, parties, threshold)?;
        Ok(Self {
            tess_scheme,
            params,
            parties,
            threshold,
        })
    }

    /// Helper method to generate all validator keypairs at once.
    ///
    /// This is useful for testing and simulates the silent setup where each validator
    /// would independently generate their own keys then publish their public keys.
    #[instrument(level = "info", skip_all, fields(num_validators = validator_ids.len()))]
    pub fn unsafe_keygen_all_validators(
        &self,
        rng: &mut impl RngCore,
        validator_ids: &[ValidatorId],
    ) -> Result<Vec<ValidatorKeyPair<B>>, TrxError> {
        if validator_ids.len() != self.parties {
            return Err(TrxError::InvalidConfig(format!(
                "validator count {} must match parties {}",
                validator_ids.len(),
                self.parties
            )));
        }

        // Generate all keys at once (in reality, each validator would do this independently)
        let keys = self
            .tess_scheme
            .keygen_unsafe(rng, self.parties, &self.params)?;

        let mut validator_keypairs = Vec::with_capacity(self.parties);
        for (index, validator_id) in validator_ids.iter().enumerate() {
            validator_keypairs.push(ValidatorKeyPair {
                validator_id: *validator_id,
                public_key: keys.public_keys[index].clone(),
                secret_share: ThresholdEncryptionSecretKeyShare {
                    share: keys.secret_keys[index].scalar,
                    validator_id: *validator_id,
                },
            });
        }

        Ok(validator_keypairs)
    }

    /// Generates a key pair for a single validator (silent setup - no interaction).
    ///
    /// Each validator calls this independently to create their own keys using only
    /// their validator ID and an RNG. No coordination with other validators required!
    ///
    /// # Arguments
    ///
    /// * `rng` - Cryptographically secure random number generator
    /// * `validator_id` - This validator's unique ID (must be in range [0, parties))
    ///
    /// # Returns
    ///
    /// A `ValidatorKeyPair` containing both the public key (to be published) and
    /// secret share (to be kept private).
    #[instrument(level = "trace", skip_all, fields(validator_id))]
    pub fn keygen_single_validator(
        &self,
        rng: &mut impl RngCore,
        validator_id: ValidatorId,
    ) -> Result<ValidatorKeyPair<B>, TrxError> {
        // True silent setup: each validator independently generates their own key pair
        // using Tess's keygen_single_validator API. No coordination required!
        //
        // Each validator:
        //   1. Samples their own random BLS secret key
        //   2. Derives public key using precomputed Lagrange commitments
        //   3. Publishes their public key
        //
        // The coordinator later aggregates all published public keys deterministically.
        let (secret_key, public_key) =
            self.tess_scheme
                .keygen_single_validator(rng, validator_id as usize, &self.params)?;

        let secret_share = ThresholdEncryptionSecretKeyShare {
            share: secret_key.scalar,
            validator_id,
        };

        Ok(ValidatorKeyPair {
            validator_id,
            public_key,
            secret_share,
        })
    }
}
