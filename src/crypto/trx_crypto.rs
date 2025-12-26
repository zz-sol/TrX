//! Cryptographic engine and protocol traits.

use core::sync::atomic::AtomicBool;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use blake3::Hasher;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::RngCore;
use tess::{
    AggregateKey, Ciphertext as TessCiphertext, CurvePoint, DecryptionResult, FieldElement, Fr,
    PairingBackend, Params, SilentThresholdScheme, ThresholdEncryption, SRS,
};
use tracing::instrument;

use crate::{
    verify_eval_proofs, BatchCommitment, BatchContext, DecryptionContext, EncryptedTransaction,
    EvalProof, PartialDecryption, PublicKey, SecretKeyShare, TrxError, ValidatorId,
};

/// Primary cryptographic engine for TrX protocol.
///
/// Wraps the Tess threshold encryption library and provides implementations
/// of all TrX cryptographic traits. Each instance is configured with fixed
/// threshold parameters (parties, threshold) that determine the security level.
#[derive(Debug)]
pub struct TrxCrypto<B: PairingBackend<Scalar = Fr>> {
    /// Tess threshold encryption scheme
    pub(crate) scheme: SilentThresholdScheme<B>,
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
        let scheme = SilentThresholdScheme::<B>::new();
        let params = scheme.param_gen(rng, parties, threshold)?;
        Ok(Self {
            scheme,
            params,
            parties,
            threshold,
        })
    }
}

/// Trusted setup for KZG commitments and threshold encryption.
///
/// Contains the cryptographic parameters needed for the entire system:
/// - SRS for KZG polynomial commitments
/// - Powers of tau in both G1 and G2 for various operations
/// - Kappa contexts for randomness binding in batch decryption
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

impl<B: PairingBackend<Scalar = Fr>> TrustedSetup<B> {
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
                "context_index {} {} (from trusted setup)",
                context_index, max_msg
            )));
        }
        Ok(())
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
    pub epoch_id: u64,
    /// Aggregate threshold public key for encryption
    pub public_key: PublicKey<B>,
    /// Map from validator ID to their secret key share
    pub validator_shares: HashMap<ValidatorId, SecretKeyShare<B>>,
    /// Shared reference to the trusted setup
    pub setup: Arc<TrustedSetup<B>>,
}

/// Setup and key generation interface for TrX.
pub trait SetupManager<B: PairingBackend<Scalar = Fr>> {
    /// Generates a trusted setup for the TrX system.
    fn generate_trusted_setup(
        &self,
        rng: &mut impl RngCore,
        max_batch_size: usize,
        max_contexts: usize,
    ) -> Result<TrustedSetup<B>, TrxError>;

    /// Runs distributed key generation for a new epoch.
    fn run_dkg(
        &self,
        rng: &mut impl RngCore,
        validators: &[ValidatorId],
        threshold: u32,
        setup: Arc<TrustedSetup<B>>,
    ) -> Result<EpochKeys<B>, TrxError>;

    /// Verifies the integrity of a trusted setup.
    fn verify_setup(&self, setup: &TrustedSetup<B>) -> Result<(), TrxError>;
}

impl<B: PairingBackend<Scalar = Fr>> SetupManager<B> for TrxCrypto<B> {
    #[instrument(level = "info", skip_all, fields(max_batch_size, max_contexts))]
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

    #[instrument(
        level = "info",
        skip_all,
        fields(num_validators = validators.len(), threshold)
    )]
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

    #[instrument(
        level = "info",
        skip_all,
        fields(
            powers_g1 = setup.powers_of_tau.len(),
            powers_g2 = setup.powers_of_tau_g2.len(),
            kappa_len = setup.kappa_setups.len()
        )
    )]
    fn verify_setup(&self, setup: &TrustedSetup<B>) -> Result<(), TrxError> {
        if setup.powers_of_tau.is_empty() || setup.powers_of_tau_g2.is_empty() {
            return Err(TrxError::InvalidInput(
                "trusted setup missing powers".into(),
            ));
        }
        Ok(())
    }
}

/// Client-side transaction encryption interface.
pub trait TransactionEncryption<B: PairingBackend<Scalar = Fr>> {
    /// Encrypts a transaction payload using threshold encryption.
    fn encrypt_transaction(
        &self,
        ek: &PublicKey<B>,
        payload: &[u8],
        associated_data: &[u8],
        signing_key: &SigningKey,
    ) -> Result<EncryptedTransaction<B>, TrxError>;

    /// Verifies the validity of an encrypted transaction.
    fn verify_ciphertext(ct: &EncryptedTransaction<B>) -> Result<(), TrxError>;
}

impl<B: PairingBackend<Scalar = Fr>> TransactionEncryption<B> for TrxCrypto<B> {
    #[instrument(
        level = "info",
        skip_all,
        fields(payload_len = payload.len(), associated_len = associated_data.len())
    )]
    fn encrypt_transaction(
        &self,
        ek: &PublicKey<B>,
        payload: &[u8],
        associated_data: &[u8],
        signing_key: &SigningKey,
    ) -> Result<EncryptedTransaction<B>, TrxError> {
        let mut rng = rand::thread_rng();
        let ciphertext =
            self.scheme
                .encrypt(&mut rng, &ek.agg_key, &self.params, self.threshold, payload)?;
        let signing_message = client_signature_message(&ciphertext, associated_data);
        let signature = signing_key.sign(signing_message.as_ref());
        let vk_sig = signing_key.verifying_key();

        Ok(EncryptedTransaction {
            ciphertext,
            associated_data: associated_data.to_vec(),
            signature,
            vk_sig,
        })
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(payload_len = ct.ciphertext.payload.len(), associated_len = ct.associated_data.len())
    )]
    fn verify_ciphertext(ct: &EncryptedTransaction<B>) -> Result<(), TrxError> {
        if ct.ciphertext.payload.is_empty() {
            return Err(TrxError::InvalidInput(
                "ciphertext payload cannot be empty".into(),
            ));
        }
        let signing_message = client_signature_message(&ct.ciphertext, &ct.associated_data);
        ct.vk_sig
            .verify_strict(signing_message.as_ref(), &ct.signature)
            .map_err(|err| TrxError::InvalidInput(format!("invalid client signature: {err}")))?;
        Ok(())
    }
}

/// Constructs the signing message for client transaction signatures.
fn client_signature_message<B: PairingBackend>(
    ciphertext: &TessCiphertext<B>,
    associated_data: &[u8],
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&ciphertext.payload);
    hasher.update(associated_data);
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(digest.as_bytes());
    output
}

/// Batch decryption interface for consensus-layer transaction processing.
pub trait BatchDecryption<B: PairingBackend<Scalar = Fr>> {
    /// Computes a KZG commitment (digest) over a batch of encrypted transactions.
    fn compute_digest(
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &TrustedSetup<B>,
    ) -> Result<BatchCommitment<B>, TrxError>;

    /// Generates a partial decryption share for a single transaction.
    fn generate_partial_decryption(
        sk_share: &SecretKeyShare<B>,
        commitment: &BatchCommitment<B>,
        context: &DecryptionContext,
        tx_index: usize,
        ciphertext: &TessCiphertext<B>,
    ) -> Result<PartialDecryption<B>, TrxError>;

    /// Verifies a partial decryption share.
    fn verify_partial_decryption(
        pd: &PartialDecryption<B>,
        commitment: &BatchCommitment<B>,
        public_keys: &HashMap<ValidatorId, PublicKey<B>>,
    ) -> Result<(), TrxError>;

    /// Computes KZG evaluation proofs for each transaction in the batch.
    fn compute_eval_proofs(
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &TrustedSetup<B>,
    ) -> Result<Vec<EvalProof<B>>, TrxError>;

    /// Combines partial decryptions and decrypts the batch.
    #[allow(clippy::too_many_arguments)]
    fn combine_and_decrypt<'a>(
        &self,
        partial_decryptions: Vec<PartialDecryption<B>>,
        batch_ctx: BatchContext<'a, B>,
        threshold: u32,
        setup: &TrustedSetup<B>,
        agg_key: &AggregateKey<B>,
    ) -> Result<Vec<DecryptionResult>, TrxError>
    where
        B::G1: PartialEq;
}

impl<B: PairingBackend<Scalar = Fr>> BatchDecryption<B> for TrxCrypto<B> {
    #[instrument(
        level = "info",
        skip_all,
        fields(batch_len = batch.len(), context_index = context.context_index, block_height = context.block_height)
    )]
    fn compute_digest(
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &TrustedSetup<B>,
    ) -> Result<BatchCommitment<B>, TrxError> {
        BatchCommitment::compute(batch, context, setup)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(tx_index, validator_id = sk_share.index)
    )]
    fn generate_partial_decryption(
        sk_share: &SecretKeyShare<B>,
        _commitment: &BatchCommitment<B>,
        context: &DecryptionContext,
        tx_index: usize,
        ciphertext: &TessCiphertext<B>,
    ) -> Result<PartialDecryption<B>, TrxError> {
        let response = ciphertext.gamma_g2.mul_scalar(&sk_share.share);
        Ok(PartialDecryption {
            pd: response,
            validator_id: sk_share.index,
            context: context.clone(),
            tx_index,
        })
    }

    #[instrument(level = "info", skip_all, fields(validator_id = pd.validator_id))]
    fn verify_partial_decryption(
        pd: &PartialDecryption<B>,
        _commitment: &BatchCommitment<B>,
        public_keys: &HashMap<ValidatorId, PublicKey<B>>,
    ) -> Result<(), TrxError> {
        if !public_keys.contains_key(&pd.validator_id) {
            return Err(TrxError::InvalidInput("unknown validator id".into()));
        }
        Ok(())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(batch_len = batch.len(), context_index = context.context_index, block_height = context.block_height)
    )]
    fn compute_eval_proofs(
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &TrustedSetup<B>,
    ) -> Result<Vec<EvalProof<B>>, TrxError> {
        EvalProof::compute_for_batch(batch, context, setup)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(
            batch_len = batch_ctx.batch.len(),
            proofs_len = batch_ctx.eval_proofs.len(),
            partials_len = partial_decryptions.len(),
            threshold
        )
    )]
    fn combine_and_decrypt<'a>(
        &self,
        partial_decryptions: Vec<PartialDecryption<B>>,
        batch_ctx: BatchContext<'a, B>,
        threshold: u32,
        setup: &TrustedSetup<B>,
        agg_key: &AggregateKey<B>,
    ) -> Result<Vec<DecryptionResult>, TrxError>
    where
        B::G1: PartialEq,
    {
        if partial_decryptions.is_empty() {
            return Err(TrxError::NotEnoughShares {
                required: threshold as usize,
                provided: 0,
            });
        }

        let context = batch_ctx.context.clone();
        for pd in &partial_decryptions {
            if pd.context.block_height != context.block_height
                || pd.context.context_index != context.context_index
            {
                return Err(TrxError::InvalidInput(
                    "partial decryptions have mismatched contexts".into(),
                ));
            }
        }

        let parties = agg_key.public_keys.len();
        if parties == 0 {
            return Err(TrxError::InvalidConfig("no parties in agg key".into()));
        }

        if !batch_ctx.eval_proofs.is_empty() || !batch_ctx.batch.is_empty() {
            verify_eval_proofs(
                setup,
                batch_ctx.commitment,
                batch_ctx.batch,
                batch_ctx.context,
                batch_ctx.eval_proofs,
            )?;
        }

        let mut grouped: BTreeMap<usize, Vec<tess::PartialDecryption<B>>> = BTreeMap::new();
        for pd in partial_decryptions {
            grouped
                .entry(pd.tx_index)
                .or_default()
                .push(tess::PartialDecryption {
                    participant_id: pd.validator_id as usize,
                    response: pd.pd,
                });
        }

        let mut results = Vec::with_capacity(batch_ctx.batch.len());
        for (idx, tx) in batch_ctx.batch.iter().enumerate() {
            let partials = grouped.get(&idx).cloned().unwrap_or_default();
            if partials.len() < threshold as usize {
                return Err(TrxError::NotEnoughShares {
                    required: threshold as usize,
                    provided: partials.len(),
                });
            }
            let mut selector = vec![false; parties];
            for partial in &partials {
                if partial.participant_id < parties {
                    selector[partial.participant_id] = true;
                }
            }
            if !selector[0] {
                return Err(TrxError::InvalidInput(
                    "selector[0] must be true for interpolation".into(),
                ));
            }
            let result =
                self.scheme
                    .aggregate_decrypt(&tx.ciphertext, &partials, &selector, agg_key)?;
            results.push(result);
        }

        Ok(results)
    }
}
