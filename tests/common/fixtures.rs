//! Test fixtures for common test scenarios.

pub use ed25519_dalek::SigningKey;
use rand::thread_rng;
use std::sync::Arc;
use tess::PairingEngine;
use trx::*;

/// Standard test configuration with 4 validators, threshold 2
pub const DEFAULT_PARTIES: usize = 4;
pub const DEFAULT_THRESHOLD: usize = 2;
pub const DEFAULT_MAX_BATCH_SIZE: usize = 4;
pub const DEFAULT_MAX_CONTEXTS: usize = 2;

/// Test fixture containing all components needed for TrX testing
pub struct TrxTestFixture {
    pub trx: TrxCrypto<PairingEngine>,
    pub epoch_setup: Arc<EpochSetup<PairingEngine>>,
    pub epoch_keys: EpochKeys<PairingEngine>,
    pub validator_shares: Vec<ThresholdEncryptionSecretKeyShare<PairingEngine>>,
    pub client_key: SigningKey,
    pub parties: usize,
    pub threshold: u32,
}

impl TrxTestFixture {
    /// Creates a new test fixture with default parameters (4 parties, threshold 2)
    pub fn new() -> Self {
        Self::with_params(DEFAULT_PARTIES, DEFAULT_THRESHOLD)
    }

    /// Creates a new test fixture with custom parameters
    pub fn with_params(parties: usize, threshold: usize) -> Self {
        let mut rng = thread_rng();

        let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold)
            .expect("failed to create TrxCrypto");

        let epoch_setup =
            generate_epoch_setup(&trx, &mut rng, DEFAULT_MAX_BATCH_SIZE, DEFAULT_MAX_CONTEXTS);

        let (epoch_keys, validator_shares) = generate_epoch_keys(
            &trx,
            &mut rng,
            parties,
            threshold as u32,
            epoch_setup.clone(),
        )
        .expect("failed to generate epoch keys");

        let client_key = SigningKey::generate(&mut rand::rngs::OsRng);

        Self {
            trx,
            epoch_setup,
            epoch_keys,
            validator_shares,
            client_key,
            parties,
            threshold: threshold as u32,
        }
    }

    /// Encrypts a transaction with custom payload and associated data
    pub fn encrypt(&self, payload: &[u8], aad: &[u8]) -> EncryptedTransaction<PairingEngine> {
        self.trx
            .encrypt_transaction(&self.epoch_keys.public_key, payload, aad, &self.client_key)
            .expect("encryption failed")
    }

    /// Creates a default decryption context for testing
    pub fn default_context() -> DecryptionContext {
        DecryptionContext {
            block_height: 1,
            context_index: 0,
        }
    }

    /// Computes batch commitment for a batch of transactions
    pub fn compute_commitment(
        &self,
        batch: &[EncryptedTransaction<PairingEngine>],
        context: &DecryptionContext,
    ) -> TransactionBatchCommitment<PairingEngine> {
        TrxCrypto::<PairingEngine>::compute_digest(batch, context, &self.epoch_setup)
            .expect("commitment computation failed")
    }

    /// Computes evaluation proofs for a batch of transactions
    pub fn compute_proofs(
        &self,
        batch: &[EncryptedTransaction<PairingEngine>],
        context: &DecryptionContext,
    ) -> Vec<EvalProof<PairingEngine>> {
        TrxCrypto::<PairingEngine>::compute_eval_proofs(batch, context, &self.epoch_setup)
            .expect("proof computation failed")
    }

    /// Generates partial decryptions from the first `threshold` validators
    pub fn generate_partial_decryptions(
        &self,
        commitment: &TransactionBatchCommitment<PairingEngine>,
        context: &DecryptionContext,
        tx_index: usize,
        ciphertext: &tess::Ciphertext<PairingEngine>,
    ) -> Vec<PartialDecryption<PairingEngine>> {
        (0..self.threshold)
            .map(|validator_id| {
                let share = &self.validator_shares[validator_id as usize];
                TrxCrypto::<PairingEngine>::generate_partial_decryption(
                    share, commitment, context, tx_index, ciphertext,
                )
                .expect("partial decryption generation failed")
            })
            .collect()
    }
}

impl Default for TrxTestFixture {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to generate epoch keys using the silent setup API
pub fn generate_epoch_keys(
    trx: &TrxCrypto<PairingEngine>,
    rng: &mut impl rand::RngCore,
    parties: usize,
    threshold: u32,
    setup: Arc<EpochSetup<PairingEngine>>,
) -> Result<
    (
        EpochKeys<PairingEngine>,
        Vec<ThresholdEncryptionSecretKeyShare<PairingEngine>>,
    ),
    TrxError,
> {
    let validators: Vec<ValidatorId> = (0..parties as u32).collect();

    // Generate all validator key pairs (simulates silent setup)
    let validator_keypairs = validators
        .iter()
        .map(|&vid| trx.keygen_single_validator(rng, vid))
        .collect::<Result<Vec<_>, _>>()?;

    let validator_secret_keys = validator_keypairs
        .iter()
        .map(|kp| kp.secret_share.clone())
        .collect::<Vec<_>>();

    // Aggregate the published public keys (non-interactive)
    let public_keys: Vec<_> = validator_keypairs
        .iter()
        .map(|kp| kp.public_key.clone())
        .collect();
    let epoch_keys = trx.aggregate_epoch_keys(&public_keys, threshold, setup)?;

    Ok((epoch_keys, validator_secret_keys))
}

/// Helper function to generate epoch setup with global setup
pub fn generate_epoch_setup(
    trx: &TrxCrypto<PairingEngine>,
    rng: &mut impl rand::RngCore,
    max_batch_size: usize,
    max_contexts: usize,
) -> Arc<EpochSetup<PairingEngine>> {
    let global_setup = trx
        .generate_global_setup(rng, max_batch_size)
        .expect("global setup generation failed");
    trx.generate_epoch_setup(rng, 1, max_contexts, global_setup)
        .expect("epoch setup generation failed")
}
