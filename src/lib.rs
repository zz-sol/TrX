//! TrX protocol scaffolding built on top of Tess.
//!
//! This module wires the TrX spec to the existing Tess threshold encryption
//! implementation. It focuses on a minimal, compiling API surface with:
//! - Core data types matching the spec
//! - Setup/DKG wrappers
//! - Encryption and batch decryption adapters
//! - Precomputation cache and mempool scaffolding
//!
//! Notes:
//! - Batch digest and evaluation proofs are placeholders based on hashing and
//!   are meant to be replaced by real KZG evaluation proofs when available.
//! - The TrxCrypto instance owns a single Tess Params (SRS + Lagrange powers)
//!   so encryption and key aggregation stay consistent.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::sync::atomic::AtomicBool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use blake3::Hasher;
use rand_core::RngCore;
use tess::{
    AggregateKey, Ciphertext as TessCiphertext, CurvePoint, DecryptionResult, FieldElement, Fr,
    PairingBackend, PairingEngine, Params, SilentThresholdScheme, ThresholdEncryption,
};

/// Configuration constants from the spec.
pub const MAX_BATCH_SIZE: usize = 128;
pub const MAX_CONTEXTS_PER_EPOCH: usize = 100_000;
pub const THREADS_FOR_CRYPTO: usize = 16;

/// TrX-specific error type.
#[derive(Debug)]
pub enum TrxError {
    Backend(String),
    InvalidConfig(String),
    InvalidInput(String),
    NotEnoughShares { required: usize, provided: usize },
}

impl From<tess::Error> for TrxError {
    fn from(err: tess::Error) -> Self {
        TrxError::Backend(err.to_string())
    }
}

// === Core types ===

/// Public encryption key wrapper.
#[derive(Clone, Debug)]
pub struct PublicKey<B: PairingBackend<Scalar = Fr>> {
    /// Aggregate key used for encryption and verification.
    pub agg_key: AggregateKey<B>,
}

/// Secret key share bound to a validator.
#[derive(Clone, Debug)]
pub struct SecretKeyShare<B: PairingBackend> {
    pub share: B::Scalar,
    pub index: u32,
}

/// Encrypted transaction container.
#[derive(Clone, Debug)]
pub struct EncryptedTransaction<B: PairingBackend> {
    pub ciphertext: TessCiphertext<B>,
    pub associated_data: Vec<u8>,
    pub signature: Signature,
    pub vk_sig: PublicVerifyKey,
}

/// Partial decryption for a transaction in a batch.
#[derive(Clone, Debug)]
pub struct PartialDecryption<B: PairingBackend> {
    pub pd: B::G2,
    pub validator_id: ValidatorId,
    pub context: DecryptionContext,
    pub tx_index: usize,
}

/// Decryption context scoped to a block/epoch.
#[derive(Clone, Debug)]
pub struct DecryptionContext {
    pub block_height: u64,
    pub context_index: u32,
}

/// Batch commitment placeholder produced by hashing.
#[derive(Debug)]
pub struct BatchCommitment<B: PairingBackend> {
    pub com: B::G1,
    pub polynomial_degree: u32,
}

impl<B: PairingBackend> Clone for BatchCommitment<B>
where
    B::G1: Clone,
{
    fn clone(&self) -> Self {
        Self {
            com: self.com.clone(),
            polynomial_degree: self.polynomial_degree,
        }
    }
}

/// Placeholder evaluation proof bytes.
#[derive(Clone, Debug)]
pub struct EvalProof {
    pub bytes: Vec<u8>,
}

pub type ValidatorId = u32;

/// Placeholder signature types.
#[derive(Clone, Debug)]
pub struct PublicVerifyKey(pub Vec<u8>);

#[derive(Clone, Debug)]
pub struct Signature(pub Vec<u8>);

// === Setup types ===

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

// === Traits ===

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

/// Encryption interface for TrX transactions.
pub trait TransactionEncryption<B: PairingBackend<Scalar = Fr>> {
    fn encrypt_transaction(
        &self,
        ek: &PublicKey<B>,
        payload: &[u8],
        associated_data: &[u8],
    ) -> Result<EncryptedTransaction<B>, TrxError>;

    fn verify_ciphertext(ct: &EncryptedTransaction<B>) -> Result<(), TrxError>;
}

/// Batch decryption interface used by consensus.
pub trait BatchDecryption<B: PairingBackend<Scalar = Fr>> {
    fn compute_digest(
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &TrustedSetup<B>,
    ) -> Result<BatchCommitment<B>, TrxError>;

    fn generate_partial_decryption(
        sk_share: &SecretKeyShare<B>,
        commitment: &BatchCommitment<B>,
        context: &DecryptionContext,
        tx_index: usize,
        ciphertext: &TessCiphertext<B>,
    ) -> Result<PartialDecryption<B>, TrxError>;

    fn verify_partial_decryption(
        pd: &PartialDecryption<B>,
        commitment: &BatchCommitment<B>,
        public_keys: &HashMap<ValidatorId, PublicKey<B>>,
    ) -> Result<(), TrxError>;

    fn compute_eval_proofs(
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &TrustedSetup<B>,
    ) -> Result<Vec<EvalProof>, TrxError>;

    fn combine_and_decrypt(
        &self,
        partial_decryptions: Vec<PartialDecryption<B>>,
        eval_proofs: &[EvalProof],
        batch: &[EncryptedTransaction<B>],
        threshold: u32,
        agg_key: &AggregateKey<B>,
    ) -> Result<Vec<DecryptionResult>, TrxError>;
}

// === TrX crypto adapter ===

/// Concrete TrX cryptographic engine built on Tess.
///
/// This adapter owns the Tess parameters, performs key generation,
/// and wraps encryption/decryption to match the TrX spec types.
#[derive(Debug)]
pub struct TrxCrypto<B: PairingBackend<Scalar = Fr>> {
    scheme: SilentThresholdScheme<B>,
    params: Params<B>,
    parties: usize,
    threshold: usize,
}

impl<B: PairingBackend<Scalar = Fr>> TrxCrypto<B> {
    /// Creates a TrX crypto instance with a fresh Tess parameter set.
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

impl<B: PairingBackend<Scalar = Fr>> TransactionEncryption<B> for TrxCrypto<B> {
    fn encrypt_transaction(
        &self,
        ek: &PublicKey<B>,
        payload: &[u8],
        associated_data: &[u8],
    ) -> Result<EncryptedTransaction<B>, TrxError> {
        let mut rng = rand::thread_rng();
        let ciphertext =
            self.scheme
                .encrypt(&mut rng, &ek.agg_key, &self.params, self.threshold, payload)?;

        Ok(EncryptedTransaction {
            ciphertext,
            associated_data: associated_data.to_vec(),
            signature: Signature(Vec::new()),
            vk_sig: PublicVerifyKey(Vec::new()),
        })
    }

    fn verify_ciphertext(ct: &EncryptedTransaction<B>) -> Result<(), TrxError> {
        if ct.ciphertext.payload.is_empty() {
            return Err(TrxError::InvalidInput(
                "ciphertext payload cannot be empty".into(),
            ));
        }
        Ok(())
    }
}

impl<B: PairingBackend<Scalar = Fr>> BatchDecryption<B> for TrxCrypto<B> {
    fn compute_digest(
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &TrustedSetup<B>,
    ) -> Result<BatchCommitment<B>, TrxError> {
        let scalar = hash_to_scalar::<B>(batch, context);
        let com = setup.powers_of_tau[0].mul_scalar(&scalar);
        Ok(BatchCommitment {
            com,
            polynomial_degree: batch.len() as u32,
        })
    }

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

    fn compute_eval_proofs(
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        _setup: &TrustedSetup<B>,
    ) -> Result<Vec<EvalProof>, TrxError> {
        let mut proofs = Vec::with_capacity(batch.len());
        for (idx, tx) in batch.iter().enumerate() {
            let mut hasher = Hasher::new();
            hasher.update(&context.block_height.to_le_bytes());
            hasher.update(&context.context_index.to_le_bytes());
            hasher.update(&idx.to_le_bytes());
            hasher.update(&tx.ciphertext.payload);
            proofs.push(EvalProof {
                bytes: hasher.finalize().as_bytes().to_vec(),
            });
        }
        Ok(proofs)
    }

    fn combine_and_decrypt(
        &self,
        partial_decryptions: Vec<PartialDecryption<B>>,
        _eval_proofs: &[EvalProof],
        batch: &[EncryptedTransaction<B>],
        threshold: u32,
        agg_key: &AggregateKey<B>,
    ) -> Result<Vec<DecryptionResult>, TrxError> {
        if partial_decryptions.is_empty() {
            return Err(TrxError::NotEnoughShares {
                required: threshold as usize,
                provided: 0,
            });
        }

        let parties = agg_key.public_keys.len();
        if parties == 0 {
            return Err(TrxError::InvalidConfig("no parties in agg key".into()));
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

        let mut results = Vec::with_capacity(batch.len());
        for (idx, tx) in batch.iter().enumerate() {
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

// === Precomputation ===

/// Precomputation engine for digest and proofs.
///
/// This cache is keyed on batch payload hashes and context so consensus can
/// reuse work across voting rounds.
#[derive(Debug)]
pub struct PrecomputationEngine<B: PairingBackend<Scalar = Fr>> {
    cache: Mutex<HashMap<Vec<u8>, PrecomputedData<B>>>,
}

/// Cached precomputation output.
#[derive(Debug)]
pub struct PrecomputedData<B: PairingBackend> {
    pub digest: BatchCommitment<B>,
    pub eval_proofs: Vec<EvalProof>,
    pub computation_time: Duration,
}

impl<B: PairingBackend> Clone for PrecomputedData<B>
where
    B::G1: Clone,
{
    fn clone(&self) -> Self {
        Self {
            digest: self.digest.clone(),
            eval_proofs: self.eval_proofs.clone(),
            computation_time: self.computation_time,
        }
    }
}
impl<B: PairingBackend<Scalar = Fr>> PrecomputationEngine<B> {
    /// Creates a new empty precomputation cache.
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Computes and caches the digest + eval proofs for a batch/context.
    pub fn precompute(
        &self,
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &TrustedSetup<B>,
    ) -> Result<PrecomputedData<B>, TrxError> {
        let key = precompute_key(batch, context);
        if let Some(cached) = self.cache.lock().unwrap().get(&key).cloned() {
            return Ok(cached);
        }
        let start = Instant::now();
        let digest = TrxCrypto::<B>::compute_digest(batch, context, setup)?;
        let eval_proofs = TrxCrypto::<B>::compute_eval_proofs(batch, context, setup)?;
        let data = PrecomputedData {
            digest,
            eval_proofs,
            computation_time: start.elapsed(),
        };
        self.cache.lock().unwrap().insert(key, data.clone());
        Ok(data)
    }
}

// === Mempool ===

/// Encrypted mempool implementation.
#[derive(Debug)]
pub struct EncryptedMempool<B: PairingBackend> {
    encrypted_txs: Vec<EncryptedTransaction<B>>,
    max_size: usize,
}

impl<B: PairingBackend<Scalar = Fr>> EncryptedMempool<B> {
    /// Creates a bounded mempool.
    pub fn new(max_size: usize) -> Self {
        Self {
            encrypted_txs: Vec::new(),
            max_size,
        }
    }

    /// Adds a transaction to the mempool after basic validation.
    pub fn add_encrypted_tx(&mut self, tx: EncryptedTransaction<B>) -> Result<(), TrxError> {
        TrxCrypto::<B>::verify_ciphertext(&tx)?;
        if self.encrypted_txs.len() >= self.max_size {
            return Err(TrxError::InvalidConfig("mempool full".into()));
        }
        self.encrypted_txs.push(tx);
        Ok(())
    }

    /// Pops up to `max_size` entries for block proposal.
    pub fn get_batch(&mut self, max_size: usize) -> Vec<EncryptedTransaction<B>> {
        let take = max_size.min(self.encrypted_txs.len());
        self.encrypted_txs.drain(0..take).collect()
    }
}

// === Network messages ===

/// TrX network message types.
#[derive(Clone, Debug)]
pub enum TrxMessage<B: PairingBackend> {
    SubmitEncryptedTx(EncryptedTransaction<B>),
    ProposeBlock {
        block_hash: Vec<u8>,
        encrypted_txs: Vec<EncryptedTransaction<B>>,
    },
    VoteWithDecryption {
        vote: Vec<u8>,
        partial_decryption: Option<PartialDecryption<B>>,
    },
    RequestDecryptionShares {
        block_hash: Vec<u8>,
        context: DecryptionContext,
    },
    DecryptionShare {
        block_hash: Vec<u8>,
        share: PartialDecryption<B>,
    },
}

/// Convenience alias for the default backend (blst BLS12-381).
pub type DefaultBackend = PairingEngine;

// === Helpers ===

fn hash_to_scalar<B: PairingBackend<Scalar = Fr>>(
    batch: &[EncryptedTransaction<B>],
    context: &DecryptionContext,
) -> B::Scalar {
    let mut hasher = Hasher::new();
    hasher.update(&context.block_height.to_le_bytes());
    hasher.update(&context.context_index.to_le_bytes());
    for tx in batch {
        hasher.update(&tx.ciphertext.payload);
        hasher.update(&tx.associated_data);
    }
    let digest = hasher.finalize();
    scalar_from_hash::<B>(digest.as_bytes())
}

/// Attempts to map a hash digest into a field element by rejection sampling.
fn scalar_from_hash<B: PairingBackend<Scalar = Fr>>(bytes: &[u8]) -> B::Scalar {
    let mut counter = 0u64;
    loop {
        let mut hasher = Hasher::new();
        hasher.update(bytes);
        hasher.update(&counter.to_le_bytes());
        let digest = hasher.finalize();
        let mut repr = B::Scalar::zero().to_repr();
        let repr_bytes: &mut [u8] = repr.as_mut();
        let take = repr_bytes.len().min(digest.as_bytes().len());
        repr_bytes[..take].copy_from_slice(&digest.as_bytes()[..take]);
        if let Ok(scalar) = B::Scalar::from_repr(&repr) {
            return scalar;
        }
        counter = counter.wrapping_add(1);
    }
}

fn precompute_key<B: PairingBackend>(
    batch: &[EncryptedTransaction<B>],
    context: &DecryptionContext,
) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(&context.block_height.to_le_bytes());
    hasher.update(&context.context_index.to_le_bytes());
    for tx in batch {
        hasher.update(&tx.ciphertext.payload);
    }
    hasher.finalize().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn happy_path_encrypt_decrypt() {
        let mut rng = thread_rng();
        let parties = 4;
        let threshold = 2;
        let trx = TrxCrypto::<DefaultBackend>::new(&mut rng, parties, threshold).unwrap();
        let keys = trx.scheme.keygen(&mut rng, parties, &trx.params).unwrap();
        let agg_key = trx
            .scheme
            .aggregate_public_key(&keys.public_keys, &trx.params, parties)
            .unwrap();
        let pk = PublicKey { agg_key };
        let encrypted = trx.encrypt_transaction(&pk, b"payload", b"aad").unwrap();

        let share_count = threshold + 1;
        let partials: Vec<tess::PartialDecryption<DefaultBackend>> = keys
            .secret_keys
            .iter()
            .take(share_count)
            .map(|sk| {
                trx.scheme
                    .partial_decrypt(sk, &encrypted.ciphertext)
                    .unwrap()
            })
            .collect();

        let mut selector = vec![false; parties];
        for idx in 0..share_count {
            selector[idx] = true;
        }
        let result = trx
            .scheme
            .aggregate_decrypt(&encrypted.ciphertext, &partials, &selector, &pk.agg_key)
            .unwrap();
        assert_eq!(result.plaintext.unwrap(), b"payload");
    }

    #[test]
    fn batch_decrypt_flow() {
        let mut rng = thread_rng();
        let parties = 4;
        let threshold = 2;
        let trx = TrxCrypto::<DefaultBackend>::new(&mut rng, parties, threshold).unwrap();
        let setup = trx.generate_trusted_setup(&mut rng, parties, 2).unwrap();
        let setup = std::sync::Arc::new(setup);
        let validators: Vec<ValidatorId> = (0..parties as u32).collect();
        let epoch = trx
            .run_dkg(&mut rng, &validators, threshold as u32, setup.clone())
            .unwrap();

        let context = DecryptionContext {
            block_height: 1,
            context_index: 0,
        };

        let batch = vec![
            trx.encrypt_transaction(&epoch.public_key, b"a", b"")
                .unwrap(),
            trx.encrypt_transaction(&epoch.public_key, b"b", b"")
                .unwrap(),
        ];

        let commitment =
            TrxCrypto::<DefaultBackend>::compute_digest(&batch, &context, &setup).unwrap();
        let eval_proofs =
            TrxCrypto::<DefaultBackend>::compute_eval_proofs(&batch, &context, &setup).unwrap();

        let mut partials = Vec::new();
        for (tx_index, tx) in batch.iter().enumerate() {
            for validator_id in [0u32, 1u32, 2u32] {
                let share = epoch.validator_shares.get(&validator_id).unwrap();
                let pd = TrxCrypto::<DefaultBackend>::generate_partial_decryption(
                    share,
                    &commitment,
                    &context,
                    tx_index,
                    &tx.ciphertext,
                )
                .unwrap();
                partials.push(pd);
            }
        }

        let results = trx
            .combine_and_decrypt(
                partials,
                &eval_proofs,
                &batch,
                threshold as u32,
                &epoch.public_key.agg_key,
            )
            .unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].plaintext.as_ref().unwrap(), b"a");
        assert_eq!(results[1].plaintext.as_ref().unwrap(), b"b");
    }

    #[test]
    fn mempool_roundtrip() {
        let mut rng = thread_rng();
        let parties = 4;
        let threshold = 2;
        let trx = TrxCrypto::<DefaultBackend>::new(&mut rng, parties, threshold).unwrap();
        let setup = trx.generate_trusted_setup(&mut rng, parties, 1).unwrap();
        let setup = std::sync::Arc::new(setup);
        let validators: Vec<ValidatorId> = (0..parties as u32).collect();
        let epoch = trx
            .run_dkg(&mut rng, &validators, threshold as u32, setup)
            .unwrap();

        let mut mempool = EncryptedMempool::<DefaultBackend>::new(2);
        let tx1 = trx
            .encrypt_transaction(&epoch.public_key, b"one", b"")
            .unwrap();
        let tx2 = trx
            .encrypt_transaction(&epoch.public_key, b"two", b"")
            .unwrap();
        mempool.add_encrypted_tx(tx1).unwrap();
        mempool.add_encrypted_tx(tx2).unwrap();

        let batch = mempool.get_batch(1);
        assert_eq!(batch.len(), 1);
        let remaining = mempool.get_batch(2);
        assert_eq!(remaining.len(), 1);
    }
}
