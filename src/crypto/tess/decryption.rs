//! Collective decryption operations for consensus processing.

use std::collections::BTreeMap;

use tess::TargetGroup;
use tess::{
    AggregateKey, Ciphertext as TessCiphertext, CurvePoint, DecryptionResult, Fr, PairingBackend,
    ThresholdEncryption,
};
use tracing::instrument;

use super::engine::TrxCrypto;
use crate::{
    verify_eval_proofs, BatchContext, DecryptionContext, EncryptedTransaction, EvalProof,
    PartialDecryption, ThresholdEncryptionSecretKeyShare, TransactionBatchCommitment, TrxError,
};

/// Collective decryption interface for consensus-layer transaction processing.
pub trait CollectiveDecryption<B: PairingBackend<Scalar = Fr>> {
    /// Computes a KZG commitment (digest) over a batch of encrypted transactions.
    fn compute_digest(
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &super::setup::EpochSetup<B>,
    ) -> Result<TransactionBatchCommitment<B>, TrxError>;

    /// Generates a partial decryption share for a single transaction.
    fn generate_partial_decryption(
        sk_share: &ThresholdEncryptionSecretKeyShare<B>,
        commitment: &TransactionBatchCommitment<B>,
        context: &DecryptionContext,
        tx_index: usize,
        ciphertext: &TessCiphertext<B>,
    ) -> Result<PartialDecryption<B>, TrxError>;

    /// Verifies a partial decryption share.
    /// TODO: defer the pairing check when multiple shares are verified together.
    fn verify_partial_decryption(
        pd: &PartialDecryption<B>,
        commitment: &TransactionBatchCommitment<B>,
        ciphertext: &TessCiphertext<B>,
        agg_key: &AggregateKey<B>,
    ) -> Result<(), TrxError>;

    /// Computes KZG evaluation proofs for each transaction in the batch.
    fn compute_eval_proofs(
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &super::setup::EpochSetup<B>,
    ) -> Result<Vec<EvalProof<B>>, TrxError>;

    /// Combines partial decryptions and decrypts the batch.
    #[allow(clippy::too_many_arguments)]
    fn combine_and_decrypt(
        &self,
        partial_decryptions: Vec<PartialDecryption<B>>,
        batch_ctx: &BatchContext<B>,
        threshold: u32,
        setup: &super::setup::EpochSetup<B>,
        agg_key: &AggregateKey<B>,
    ) -> Result<Vec<DecryptionResult>, TrxError>
    where
        B::G1: PartialEq;
}

impl<B: PairingBackend<Scalar = Fr>> CollectiveDecryption<B> for TrxCrypto<B> {
    #[instrument(
        level = "info",
        skip_all,
        fields(batch_len = batch.len(), context_index = context.context_index, block_height = context.block_height)
    )]
    fn compute_digest(
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &super::setup::EpochSetup<B>,
    ) -> Result<TransactionBatchCommitment<B>, TrxError> {
        TransactionBatchCommitment::compute(batch, context, setup)
    }

    #[instrument(
        level = "trace",
        skip_all,
        fields(tx_index, validator_id = sk_share.validator_id)
    )]
    fn generate_partial_decryption(
        sk_share: &ThresholdEncryptionSecretKeyShare<B>,
        _commitment: &TransactionBatchCommitment<B>,
        context: &DecryptionContext,
        tx_index: usize,
        ciphertext: &TessCiphertext<B>,
    ) -> Result<PartialDecryption<B>, TrxError> {
        let response = ciphertext.gamma_g2.mul_scalar(&sk_share.share);
        Ok(PartialDecryption {
            pd: response,
            validator_id: sk_share.validator_id,
            context: context.clone(),
            tx_index,
            signature: None,
            validator_vk: None,
        })
    }

    #[instrument(level = "info", skip_all, fields(validator_id = pd.validator_id))]
    fn verify_partial_decryption(
        pd: &PartialDecryption<B>,
        _commitment: &TransactionBatchCommitment<B>,
        ciphertext: &TessCiphertext<B>,
        agg_key: &AggregateKey<B>,
    ) -> Result<(), TrxError> {
        let validator_id = pd.validator_id as usize;
        let pk = agg_key
            .public_keys
            .iter()
            .find(|pk| pk.participant_id == validator_id)
            .ok_or_else(|| TrxError::InvalidInput("unknown validator id".into()))?;

        // Check e(pk_i, gamma_g2) == e(g1, pd_i) using a single multi-pairing.
        let g1 = B::G1::generator();
        let neg_pd = pd.pd.negate();
        let check = B::multi_pairing(&[pk.bls_key, g1], &[ciphertext.gamma_g2, neg_pd])
            .map_err(|err| TrxError::Backend(err.to_string()))?;
        if check != B::Target::identity() {
            return Err(TrxError::InvalidInput(
                "invalid partial decryption share".into(),
            ));
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
        setup: &super::setup::EpochSetup<B>,
    ) -> Result<Vec<EvalProof<B>>, TrxError> {
        EvalProof::compute_for_batch(batch, context, setup)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(
            batch_len = batch_ctx.transactions.len(),
            proofs_len = batch_ctx.batch_proofs.proofs.len(),
            partials_len = partial_decryptions.len(),
            threshold
        )
    )]
    fn combine_and_decrypt(
        &self,
        partial_decryptions: Vec<PartialDecryption<B>>,
        batch_ctx: &BatchContext<B>,
        threshold: u32,
        setup: &super::setup::EpochSetup<B>,
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

        if !batch_ctx.batch_proofs.proofs.is_empty() || !batch_ctx.transactions.is_empty() {
            verify_eval_proofs(
                setup,
                &batch_ctx.batch_proofs.commitment,
                &batch_ctx.transactions,
                &batch_ctx.context,
                &batch_ctx.batch_proofs.proofs,
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

        let mut results = Vec::with_capacity(batch_ctx.transactions.len());
        for (idx, tx) in batch_ctx.transactions.iter().enumerate() {
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
            let result = self.tess_scheme.aggregate_decrypt(
                &tx.ciphertext,
                &partials,
                &selector,
                agg_key,
            )?;
            results.push(result);
        }

        Ok(results)
    }
}
