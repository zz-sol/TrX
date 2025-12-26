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

use crate::utils::hash_to_scalar;
use crate::{
    BatchCommitment, EvalProof, PublicKey, PublicVerifyKey, SecretKeyShare, Signature,
    TrustedSetup, TrxCrypto, TrxError, ValidatorId,
};

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

// === Traits ===

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
