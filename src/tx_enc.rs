use std::collections::{BTreeMap, HashMap};

use blake3::Hasher;
use ed25519_dalek::{Signer, SigningKey};
use tess::{
    AggregateKey, Ciphertext as TessCiphertext, CurvePoint, DecryptionResult, Fr, PairingBackend,
    ThresholdEncryption,
};

use crate::{
    BatchCommitment, EvalProof, PublicKey, SecretKeyShare, TrustedSetup, TrxCrypto, TrxError,
    TxPublicVerifyKey, TxSignature, ValidatorId, verify_eval_proofs,
};

/// Encryption interface for TrX transactions.
pub trait TransactionEncryption<B: PairingBackend<Scalar = Fr>> {
    fn encrypt_transaction(
        &self,
        ek: &PublicKey<B>,
        payload: &[u8],
        associated_data: &[u8],
        signing_key: &SigningKey,
    ) -> Result<EncryptedTransaction<B>, TrxError>;

    fn verify_ciphertext(ct: &EncryptedTransaction<B>) -> Result<(), TrxError>;
}

impl<B: PairingBackend<Scalar = Fr>> TransactionEncryption<B> for TrxCrypto<B> {
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

/// Encrypted transaction container.
#[derive(Clone, Debug)]
pub struct EncryptedTransaction<B: PairingBackend> {
    pub ciphertext: TessCiphertext<B>,
    pub associated_data: Vec<u8>,
    pub signature: TxSignature,
    pub vk_sig: TxPublicVerifyKey,
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
    ) -> Result<Vec<EvalProof<B>>, TrxError>;

    #[allow(clippy::too_many_arguments)]
    fn combine_and_decrypt(
        &self,
        partial_decryptions: Vec<PartialDecryption<B>>,
        eval_proofs: &[EvalProof<B>],
        batch: &[EncryptedTransaction<B>],
        threshold: u32,
        setup: &TrustedSetup<B>,
        commitment: &BatchCommitment<B>,
        agg_key: &AggregateKey<B>,
    ) -> Result<Vec<DecryptionResult>, TrxError>
    where
        B::G1: PartialEq;
}

// === TrX crypto adapter ===

impl<B: PairingBackend<Scalar = Fr>> BatchDecryption<B> for TrxCrypto<B> {
    fn compute_digest(
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &TrustedSetup<B>,
    ) -> Result<BatchCommitment<B>, TrxError> {
        BatchCommitment::compute(batch, context, setup)
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
        setup: &TrustedSetup<B>,
    ) -> Result<Vec<EvalProof<B>>, TrxError> {
        EvalProof::compute_for_batch(batch, context, setup)
    }

    fn combine_and_decrypt(
        &self,
        partial_decryptions: Vec<PartialDecryption<B>>,
        eval_proofs: &[EvalProof<B>],
        batch: &[EncryptedTransaction<B>],
        threshold: u32,
        setup: &TrustedSetup<B>,
        commitment: &BatchCommitment<B>,
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

        let context = partial_decryptions[0].context.clone();
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

        if !eval_proofs.is_empty() || !batch.is_empty() {
            verify_eval_proofs(setup, commitment, batch, &context, eval_proofs)?;
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
