use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use blake3::Hasher;
use tess::{Fr, PairingBackend};

use crate::{
    BatchCommitment, BatchDecryption, DecryptionContext, EncryptedTransaction, EvalProof,
    TrustedSetup, TrxCrypto, TrxError,
};
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
pub struct PrecomputedData<B: PairingBackend<Scalar = Fr>> {
    pub digest: BatchCommitment<B>,
    pub eval_proofs: Vec<EvalProof<B>>,
    pub computation_time: Duration,
}

impl<B: PairingBackend<Scalar = Fr>> Clone for PrecomputedData<B>
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

impl<B: PairingBackend<Scalar = Fr>> Default for PrecomputationEngine<B> {
    fn default() -> Self {
        Self::new()
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
