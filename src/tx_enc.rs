//! Transaction encryption and batch decryption module.
//!
//! This module provides the core encryption and decryption interfaces for the TrX protocol:
//!
//! # Client-Side Encryption
//!
//! The [`TransactionEncryption`] trait enables clients to encrypt transaction payloads
//! using a threshold public key. Each encrypted transaction includes:
//! - Tess threshold ciphertext
//! - Associated metadata
//! - Ed25519 client signature for authenticity
//!
//! # Batch Decryption Protocol
//!
//! The [`BatchDecryption`] trait implements the consensus-layer decryption flow:
//!
//! 1. **Digest Computation**: Generate KZG commitment over the batch polynomial
//! 2. **Partial Decryption**: Validators produce shares using their secret key shares
//! 3. **Share Verification**: Verify partial decryptions against validator public keys
//! 4. **Proof Generation**: Compute KZG evaluation proofs for each transaction
//! 5. **Combine & Decrypt**: Aggregate shares and decrypt with proof verification
//!
//! # Example
//!
//! ```rust,no_run
//! # use trx::*;
//! # use ed25519_dalek::SigningKey;
//! # use std::sync::Arc;
//! # fn example() -> Result<(), TrxError> {
//! # let mut rng = rand::thread_rng();
//! # let crypto = TrxCrypto::<tess::PairingEngine>::new(&mut rng, 5, 3)?;
//! # let setup = crypto.generate_trusted_setup(&mut rng, 128, 1000)?;
//! # let epoch_keys = crypto.run_dkg(&mut rng, &vec![0,1,2,3,4], 3, Arc::new(setup))?;
//! let signing_key = SigningKey::generate(&mut rng);
//! let payload = b"secret data";
//!
//! // Encrypt transaction
//! let encrypted_tx = crypto.encrypt_transaction(
//!     &epoch_keys.public_key,
//!     payload,
//!     b"metadata",
//!     &signing_key,
//! )?;
//!
//! // Batch decryption
//! let batch = vec![encrypted_tx];
//! let context = DecryptionContext { block_height: 1, context_index: 0 };
//! let commitment = TrxCrypto::<tess::PairingEngine>::compute_digest(&batch, &context, &epoch_keys.setup)?;
//! # Ok(())
//! # }
//! ```

use std::collections::{BTreeMap, HashMap};

use blake3::Hasher;
use ed25519_dalek::{Signer, SigningKey};
use tess::{
    AggregateKey, Ciphertext as TessCiphertext, CurvePoint, DecryptionResult, Fr, PairingBackend,
    ThresholdEncryption,
};

use crate::{
    verify_eval_proofs, BatchCommitment, EvalProof, PublicKey, SecretKeyShare, TrustedSetup,
    TrxCrypto, TrxError, TxPublicVerifyKey, TxSignature, ValidatorId,
};

/// Client-side transaction encryption interface.
///
/// This trait provides methods for encrypting transaction payloads and verifying
/// ciphertext validity. Implementations must ensure:
/// - Encryption uses the threshold public key
/// - Each ciphertext includes a valid Ed25519 signature
/// - Signature covers both ciphertext and associated data
pub trait TransactionEncryption<B: PairingBackend<Scalar = Fr>> {
    /// Encrypts a transaction payload using threshold encryption.
    ///
    /// # Arguments
    ///
    /// * `ek` - Threshold public key for encryption
    /// * `payload` - Transaction data to encrypt
    /// * `associated_data` - Public metadata (not encrypted, but signed)
    /// * `signing_key` - Ed25519 key for client signature
    ///
    /// # Returns
    ///
    /// An [`EncryptedTransaction`] containing the ciphertext, metadata, and signature.
    ///
    /// # Errors
    ///
    /// Returns [`TrxError`] if encryption fails or signature generation fails.
    fn encrypt_transaction(
        &self,
        ek: &PublicKey<B>,
        payload: &[u8],
        associated_data: &[u8],
        signing_key: &SigningKey,
    ) -> Result<EncryptedTransaction<B>, TrxError>;

    /// Verifies the validity of an encrypted transaction.
    ///
    /// Checks that:
    /// - Ciphertext payload is non-empty
    /// - Ed25519 signature is valid over (ciphertext || associated_data)
    ///
    /// # Arguments
    ///
    /// * `ct` - Encrypted transaction to verify
    ///
    /// # Errors
    ///
    /// Returns [`TrxError::InvalidInput`] if validation fails.
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

/// Encrypted transaction container with client signature.
///
/// Encapsulates a threshold-encrypted transaction payload along with:
/// - Public associated metadata
/// - Ed25519 client signature for authenticity
/// - Client's verification key
///
/// The signature covers `BLAKE3(ciphertext.payload || associated_data)`.
#[derive(Clone, Debug)]
pub struct EncryptedTransaction<B: PairingBackend> {
    /// Tess threshold ciphertext containing encrypted payload
    pub ciphertext: TessCiphertext<B>,
    /// Public metadata (not encrypted, but included in signature)
    pub associated_data: Vec<u8>,
    /// Ed25519 signature over the ciphertext and metadata
    pub signature: TxSignature,
    /// Client's Ed25519 verification key
    pub vk_sig: TxPublicVerifyKey,
}

/// Partial decryption share produced by a validator.
///
/// During batch decryption, each validator computes a partial decryption
/// for their assigned transactions using their secret key share. These
/// shares are later aggregated to recover the plaintext.
#[derive(Clone, Debug)]
pub struct PartialDecryption<B: PairingBackend> {
    /// Partial decryption value: γ^{sk_i} in G2
    pub pd: B::G2,
    /// ID of the validator who produced this share
    pub validator_id: ValidatorId,
    /// Decryption context (block height and context index)
    pub context: DecryptionContext,
    /// Index of the transaction within the batch
    pub tx_index: usize,
}

/// Decryption context identifying a batch within consensus.
///
/// Scopes partial decryptions to a specific block and KZG context to prevent
/// replay attacks and ensure proper randomness binding.
#[derive(Clone, Debug)]
pub struct DecryptionContext {
    /// Block height in the blockchain
    pub block_height: u64,
    /// Index of the KZG kappa context used for this batch
    pub context_index: u32,
}

/// Constructs the signing message for client transaction signatures.
///
/// Computes `BLAKE3(ciphertext.payload || associated_data)` to bind both
/// the encrypted payload and public metadata to the client's signature.
///
/// # Arguments
///
/// * `ciphertext` - Tess ciphertext containing encrypted payload
/// * `associated_data` - Public metadata to include in signature
///
/// # Returns
///
/// A 32-byte BLAKE3 digest used as the Ed25519 signing message.
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

/// Batch decryption interface for consensus-layer transaction processing.
///
/// This trait defines the complete batch decryption protocol:
///
/// 1. **Digest**: Compute a KZG commitment over the batch polynomial
/// 2. **Partial Decryption**: Each validator generates shares for their transactions
/// 3. **Verification**: Validate partial decryptions against validator keys
/// 4. **Proofs**: Generate KZG evaluation proofs for batch integrity
/// 5. **Combine**: Aggregate shares and decrypt with proof verification
///
/// All methods except `combine_and_decrypt` are stateless and can be called
/// as static methods on the implementing type.
pub trait BatchDecryption<B: PairingBackend<Scalar = Fr>> {
    /// Computes a KZG commitment (digest) over a batch of encrypted transactions.
    ///
    /// The digest is computed as `KZG.Commit(p(x))` where `p(x)` is a polynomial
    /// with coefficients derived from each transaction's hash in the context.
    ///
    /// # Arguments
    ///
    /// * `batch` - Encrypted transactions to commit
    /// * `context` - Decryption context (block height, context index)
    /// * `setup` - Trusted setup containing SRS for KZG
    ///
    /// # Returns
    ///
    /// A [`BatchCommitment`] containing the KZG commitment and polynomial degree.
    ///
    /// # Errors
    ///
    /// Returns [`TrxError::InvalidConfig`] if batch size exceeds available SRS powers.
    fn compute_digest(
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &TrustedSetup<B>,
    ) -> Result<BatchCommitment<B>, TrxError>;

    /// Generates a partial decryption share for a single transaction.
    ///
    /// Validators call this to produce their share: `γ^{sk_i}` where `γ` is
    /// the ciphertext's G2 element and `sk_i` is the validator's secret key share.
    ///
    /// # Arguments
    ///
    /// * `sk_share` - Validator's secret key share
    /// * `commitment` - Batch commitment (not currently used, reserved)
    /// * `context` - Decryption context
    /// * `tx_index` - Position of this transaction in the batch
    /// * `ciphertext` - Tess ciphertext to partially decrypt
    ///
    /// # Returns
    ///
    /// A [`PartialDecryption`] containing the share and metadata.
    fn generate_partial_decryption(
        sk_share: &SecretKeyShare<B>,
        commitment: &BatchCommitment<B>,
        context: &DecryptionContext,
        tx_index: usize,
        ciphertext: &TessCiphertext<B>,
    ) -> Result<PartialDecryption<B>, TrxError>;

    /// Verifies a partial decryption share.
    ///
    /// Currently performs basic validation (validator ID existence check).
    /// Future versions may include pairing-based verification.
    ///
    /// # Arguments
    ///
    /// * `pd` - Partial decryption to verify
    /// * `commitment` - Batch commitment (reserved for future verification)
    /// * `public_keys` - Map of validator IDs to their public keys
    ///
    /// # Errors
    ///
    /// Returns [`TrxError::InvalidInput`] if validator ID is unknown.
    fn verify_partial_decryption(
        pd: &PartialDecryption<B>,
        commitment: &BatchCommitment<B>,
        public_keys: &HashMap<ValidatorId, PublicKey<B>>,
    ) -> Result<(), TrxError>;

    /// Computes KZG evaluation proofs for each transaction in the batch.
    ///
    /// For each transaction at index `i`, generates a proof that the batch
    /// polynomial evaluates to the expected value at point `i+1`.
    ///
    /// # Arguments
    ///
    /// * `batch` - Encrypted transactions
    /// * `context` - Decryption context
    /// * `setup` - Trusted setup containing SRS
    ///
    /// # Returns
    ///
    /// A vector of [`EvalProof`]s, one per transaction.
    ///
    /// # Errors
    ///
    /// Returns [`TrxError::InvalidConfig`] if batch size exceeds SRS capacity.
    fn compute_eval_proofs(
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &TrustedSetup<B>,
    ) -> Result<Vec<EvalProof<B>>, TrxError>;

    /// Combines partial decryptions and decrypts the batch.
    ///
    /// This method:
    /// 1. Verifies all partial decryptions have consistent contexts
    /// 2. Verifies KZG evaluation proofs against the batch commitment
    /// 3. Groups partial shares by transaction index
    /// 4. Aggregates shares (requires threshold-many for each transaction)
    /// 5. Decrypts each transaction using Tess aggregation
    ///
    /// # Arguments
    ///
    /// * `partial_decryptions` - Validator shares to combine
    /// * `eval_proofs` - KZG evaluation proofs (one per transaction)
    /// * `batch` - Original encrypted transactions
    /// * `threshold` - Minimum shares needed per transaction
    /// * `setup` - Trusted setup for proof verification
    /// * `commitment` - Batch commitment to verify proofs against
    /// * `agg_key` - Aggregate public key from DKG
    ///
    /// # Returns
    ///
    /// A vector of [`DecryptionResult`]s containing decrypted payloads.
    ///
    /// # Errors
    ///
    /// - [`TrxError::NotEnoughShares`] if fewer than threshold shares per transaction
    /// - [`TrxError::InvalidInput`] if contexts mismatch or proofs are invalid
    /// - [`TrxError::InvalidConfig`] if aggregate key has no parties
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
