//! Core protocol data types.

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyKey};
use tess::{AggregateKey, Ciphertext as TessCiphertext, Fr, PairingBackend};

/// Validator identifier (u32 index).
pub type ValidatorId = u32;

/// Client's Ed25519 public verification key.
pub type TxPublicVerifyKey = Ed25519VerifyKey;

/// Client's Ed25519 signature over transaction ciphertext.
pub type TxSignature = Ed25519Signature;

/// Result of decrypting a transaction: Ok(plaintext) or Err(error message).
pub type DecryptionResult = tess::DecryptionResult;

/// Public encryption key wrapper.
#[derive(Clone, Debug)]
pub struct PublicKey<B: PairingBackend<Scalar = Fr>> {
    /// Aggregate key used for encryption and verification.
    pub agg_key: AggregateKey<B>,
}

/// Secret key share bound to a validator.
#[derive(Debug, Clone)]
pub struct SecretKeyShare<B: PairingBackend> {
    pub share: B::Scalar,
    pub validator_id: ValidatorId,
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

/// KZG polynomial commitment over a batch of encrypted transactions.
///
/// This commitment binds the proposer to a specific set of transactions in a
/// succinctly verifiable way. The polynomial has degree `n-1` for `n` transactions,
/// with each coefficient derived from `BLAKE3(tx || context)`.
///
/// The commitment is included in block proposals and later used to verify
/// [`EvalProof`]s during batch decryption.
#[derive(Debug)]
pub struct BatchCommitment<B: PairingBackend> {
    /// KZG commitment: C = [p(τ)]₁ where τ is from the global setup SRS
    pub com: B::G1,
    /// Degree of the committed polynomial (batch_size - 1)
    pub polynomial_degree: u32,
}

impl<B: PairingBackend> Clone for BatchCommitment<B>
where
    B::G1: Clone,
{
    fn clone(&self) -> Self {
        Self {
            com: self.com,
            polynomial_degree: self.polynomial_degree,
        }
    }
}

/// KZG evaluation proof for a single transaction in a batch.
///
/// Proves that the batch polynomial `p(x)` evaluates to a specific value at a
/// specific point, without revealing the entire polynomial. Used to verify that
/// individual transactions were correctly included in the batch commitment.
///
/// For transaction at index `i` in the batch:
/// - `point = i + 1` (evaluation point, 1-indexed)
/// - `value = p(i+1) = H(tx_i || context)` (expected polynomial value)
/// - `proof = [q(τ)]₁` where `q(x) = (p(x) - value) / (x - point)`
#[derive(Debug)]
pub struct EvalProof<B: PairingBackend<Scalar = Fr>> {
    /// Evaluation point (transaction index + 1)
    pub point: B::Scalar,
    /// Claimed polynomial value at the point
    pub value: B::Scalar,
    /// KZG opening proof: quotient polynomial commitment
    pub proof: B::G1,
}

impl<B: PairingBackend<Scalar = Fr>> Clone for EvalProof<B>
where
    B::G1: Clone,
{
    fn clone(&self) -> Self {
        Self {
            point: self.point,
            value: self.value,
            proof: self.proof,
        }
    }
}

/// Bundled batch inputs used during decryption.
#[derive(Clone, Copy, Debug)]
pub struct BatchContext<'a, B: PairingBackend<Scalar = Fr>> {
    /// Batch of encrypted transactions
    pub batch: &'a [EncryptedTransaction<B>],
    /// Decryption context binding
    pub context: &'a DecryptionContext,
    /// Batch commitment
    pub commitment: &'a BatchCommitment<B>,
    /// Evaluation proofs for the batch
    pub eval_proofs: &'a [EvalProof<B>],
}
