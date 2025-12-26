use core::sync::atomic::AtomicBool;
use std::collections::HashMap;
use std::sync::Arc;

use rand_core::RngCore;
use tess::{CurvePoint, FieldElement, Fr, PairingBackend, ThresholdEncryption};

use crate::{PublicKey, SecretKeyShare, TrxCrypto, TrxError, ValidatorId};

/// Trusted setup containing powers of tau and randomized kappa contexts.
#[derive(Debug)]
pub struct TrustedSetup<B: PairingBackend<Scalar = Fr>> {
    pub powers_of_tau: Vec<B::G1>,
    pub powers_of_tau_g2: Vec<B::G2>,
    pub kappa_setups: Vec<KappaSetup<B>>,
}

/// Kappa context that can be consumed at most once.
#[derive(Debug)]
pub struct KappaSetup<B: PairingBackend> {
    pub index: u32,
    pub elements: Vec<B::G1>,
    pub used: AtomicBool,
}

/// Per-epoch keys and setup bundle.
#[derive(Clone, Debug)]
pub struct EpochKeys<B: PairingBackend<Scalar = Fr>> {
    pub epoch_id: u64,
    pub public_key: PublicKey<B>,
    pub validator_shares: HashMap<ValidatorId, SecretKeyShare<B>>,
    pub setup: Arc<TrustedSetup<B>>,
}

/// Setup manager for TrX.
pub trait SetupManager<B: PairingBackend<Scalar = Fr>> {
    fn generate_trusted_setup(
        &self,
        rng: &mut impl RngCore,
        max_batch_size: usize,
        max_contexts: usize,
    ) -> Result<TrustedSetup<B>, TrxError>;

    fn run_dkg(
        &self,
        rng: &mut impl RngCore,
        validators: &[ValidatorId],
        threshold: u32,
        setup: Arc<TrustedSetup<B>>,
    ) -> Result<EpochKeys<B>, TrxError>;

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
