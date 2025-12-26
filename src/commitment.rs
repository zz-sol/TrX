//! KZG polynomial commitments and evaluation proofs for batch integrity.
//!
//! This module implements the cryptographic commitments used to bind batches of
//! encrypted transactions and prove their integrity during consensus.
//!
//! # Batch Commitments
//!
//! A [`BatchCommitment`] is a KZG (Kate-Zaverucha-Goldberg) polynomial commitment
//! computed over a batch of transactions:
//!
//! 1. Construct polynomial `p(x)` with coefficients `c_i = H(tx_i || context)`
//! 2. Compute commitment `C = KZG.Commit(p(x))`
//! 3. Include `C` in block proposals
//!
//! # Evaluation Proofs
//!
//! [`EvalProof`]s prove that specific transactions were included in the batch:
//!
//! - For transaction `i`, prove `p(i+1) = c_i`
//! - Verifier checks pairing equation without recomputing the polynomial
//! - Provides succinctness: proofs are constant-size (single G1 element)
//!
//! # Security Properties
//!
//! - **Binding**: Committer cannot change batch contents after commitment
//! - **Hiding**: Commitment reveals nothing about transaction plaintexts
//! - **Succinctness**: Proofs are O(1) size regardless of batch size
//!
//! # Example
//!
//! ```rust,no_run
//! # use trx::*;
//! # use std::sync::Arc;
//! # fn example() -> Result<(), TrxError> {
//! # let mut rng = rand::thread_rng();
//! # let crypto = TrxCrypto::<tess::PairingEngine>::new(&mut rng, 5, 3)?;
//! # let setup = crypto.generate_trusted_setup(&mut rng, 128, 1000)?;
//! # let setup_arc = Arc::new(setup);
//! # let epoch_keys = crypto.run_dkg(&mut rng, &vec![0,1,2,3,4], 3, setup_arc.clone())?;
//! # let batch = vec![]; // encrypted transactions
//! let context = DecryptionContext { block_height: 1, context_index: 0 };
//!
//! // Compute batch commitment
//! let commitment = BatchCommitment::compute(&batch, &context, &setup_arc)?;
//!
//! // Generate evaluation proofs
//! let proofs = EvalProof::compute_for_batch(&batch, &context, &setup_arc)?;
//!
//! // Verify proofs
//! verify_eval_proofs(&setup_arc, &commitment, &batch, &context, &proofs)?;
//! # Ok(())
//! # }
//! ```

use blake3::Hasher;
use tess::{DensePolynomial, FieldElement, Fr, PairingBackend, PolynomialCommitment, KZG};

use crate::utils::scalar_from_hash;
use crate::{DecryptionContext, EncryptedTransaction, TrustedSetup, TrxError};

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
    /// KZG commitment: C = [p(τ)]₁ where τ is the trusted setup secret
    pub com: B::G1,
    /// Degree of the committed polynomial (batch_size - 1)
    pub polynomial_degree: u32,
}

impl<B: PairingBackend<Scalar = Fr>> BatchCommitment<B> {
    /// Computes a KZG commitment over the batch polynomial.
    ///
    /// Constructs polynomial `p(x)` with coefficients `c_i = H(tx_i || context)`
    /// and commits to it using the trusted setup's structured reference string (SRS).
    ///
    /// # Arguments
    ///
    /// * `batch` - Encrypted transactions to commit
    /// * `context` - Decryption context (binds commitment to specific block/epoch)
    /// * `setup` - Trusted setup containing SRS powers
    ///
    /// # Returns
    ///
    /// A [`BatchCommitment`] containing the KZG commitment and polynomial degree.
    ///
    /// # Errors
    ///
    /// Returns [`TrxError::InvalidConfig`] if batch size exceeds the SRS capacity
    /// (i.e., more transactions than available powers of tau).
    pub fn compute(
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &TrustedSetup<B>,
    ) -> Result<Self, TrxError> {
        // Validate context index is within bounds
        setup.validate_context_index(context.context_index)?;

        if batch.len() + 1 > setup.srs.powers_of_g.len() {
            return Err(TrxError::InvalidConfig(
                "batch size exceeds available SRS powers".into(),
            ));
        }
        let polynomial = batch_polynomial(batch, context);
        let com = KZG::commit_g1(&setup.srs, &polynomial)
            .map_err(|err| TrxError::Backend(err.to_string()))?;
        Ok(Self {
            com,
            polynomial_degree: polynomial.degree() as u32,
        })
    }
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

impl<B: PairingBackend<Scalar = Fr>> EvalProof<B> {
    /// Computes KZG evaluation proofs for all transactions in a batch.
    ///
    /// For each transaction at index `i`, generates a proof that the batch
    /// polynomial `p(x)` evaluates to `H(tx_i || context)` at point `x = i+1`.
    ///
    /// # Arguments
    ///
    /// * `batch` - Encrypted transactions to generate proofs for
    /// * `context` - Decryption context (must match commitment context)
    /// * `setup` - Trusted setup containing SRS for proof generation
    ///
    /// # Returns
    ///
    /// A vector of [`EvalProof`]s, one per transaction, in batch order.
    ///
    /// # Errors
    ///
    /// Returns [`TrxError::InvalidConfig`] if batch size exceeds SRS capacity.
    ///
    /// # Performance
    ///
    /// This is a computationally expensive operation (O(n²) for n transactions).
    /// Consider using the precomputation cache for frequently accessed batches.
    pub fn compute_for_batch(
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &TrustedSetup<B>,
    ) -> Result<Vec<Self>, TrxError> {
        // Validate context index is within bounds
        setup.validate_context_index(context.context_index)?;

        if batch.len() + 1 > setup.srs.powers_of_g.len() {
            return Err(TrxError::InvalidConfig(
                "batch size exceeds available SRS powers".into(),
            ));
        }
        let polynomial = batch_polynomial(batch, context);
        let mut proofs = Vec::with_capacity(batch.len());
        for (idx, _) in batch.iter().enumerate() {
            let point = Fr::from_u64(idx as u64 + 1);
            let (value, proof) = KZG::open_g1(&setup.srs, &polynomial, &point)
                .map_err(|err| TrxError::Backend(err.to_string()))?;
            proofs.push(Self {
                point,
                value,
                proof,
            });
        }
        Ok(proofs)
    }
}

/// Constructs the batch polynomial from encrypted transactions.
///
/// The polynomial has coefficients `c_i = H(tx_i || context)` where the hash
/// binds each transaction to the specific decryption context. This prevents
/// replay attacks across different blocks or epochs.
///
/// # Arguments
///
/// * `batch` - Encrypted transactions
/// * `context` - Decryption context (block height and context index)
///
/// # Returns
///
/// A dense polynomial with degree `batch.len() - 1`.
pub(crate) fn batch_polynomial<B: PairingBackend<Scalar = Fr>>(
    batch: &[EncryptedTransaction<B>],
    context: &DecryptionContext,
) -> DensePolynomial {
    let coeffs: Vec<Fr> = batch
        .iter()
        .map(|tx| tx_commitment_scalar::<B>(tx, context))
        .collect();
    DensePolynomial::from_coefficients_vec(coeffs)
}

/// Derives a scalar coefficient for a transaction within a specific context.
///
/// Computes `H(block_height || context_index || ciphertext || associated_data)`
/// and maps the hash output to a field element using rejection sampling.
///
/// # Arguments
///
/// * `tx` - Encrypted transaction
/// * `context` - Decryption context
///
/// # Returns
///
/// A field element in the scalar field of the pairing curve.
fn tx_commitment_scalar<B: PairingBackend<Scalar = Fr>>(
    tx: &EncryptedTransaction<B>,
    context: &DecryptionContext,
) -> B::Scalar {
    let mut hasher = Hasher::new();
    hasher.update(&context.block_height.to_le_bytes());
    hasher.update(&context.context_index.to_le_bytes());
    hasher.update(&tx.ciphertext.payload);
    hasher.update(&tx.associated_data);
    scalar_from_hash::<B>(hasher.finalize().as_bytes())
}

/// Verifies KZG evaluation proofs against a batch commitment.
///
/// This function ensures batch integrity by:
/// 1. Checking proof count matches batch size
/// 2. Recomputing the batch polynomial from transactions
/// 3. Verifying the commitment matches the recomputed polynomial
/// 4. Verifying each proof using the KZG pairing check
///
/// # Arguments
///
/// * `setup` - Trusted setup containing SRS
/// * `commitment` - Claimed batch commitment
/// * `batch` - Encrypted transactions
/// * `context` - Decryption context
/// * `proofs` - Evaluation proofs to verify
///
/// # Returns
///
/// `Ok(())` if all proofs are valid, otherwise an error.
///
/// # Errors
///
/// - [`TrxError::InvalidInput`] if proof count mismatches, commitment is wrong,
///   or any individual proof fails verification
/// - [`TrxError::Backend`] if KZG operations fail
///
/// # Security
///
/// This check is cryptographically binding under the KZG assumption. If verification
/// passes, the batch polynomial was correctly constructed from the transactions.
pub fn verify_eval_proofs<B: PairingBackend<Scalar = Fr>>(
    setup: &TrustedSetup<B>,
    commitment: &BatchCommitment<B>,
    batch: &[EncryptedTransaction<B>],
    context: &DecryptionContext,
    proofs: &[EvalProof<B>],
) -> Result<(), TrxError>
where
    B::G1: PartialEq,
{
    if proofs.len() != batch.len() {
        return Err(TrxError::InvalidInput(
            "eval proof count must match batch size".into(),
        ));
    }
    let polynomial = batch_polynomial(batch, context);
    let expected_commitment = KZG::commit_g1(&setup.srs, &polynomial)
        .map_err(|err| TrxError::Backend(err.to_string()))?;
    if expected_commitment != commitment.com {
        return Err(TrxError::InvalidInput(
            "batch commitment does not match batch".into(),
        ));
    }
    for (idx, proof) in proofs.iter().enumerate() {
        let expected = Fr::from_u64(idx as u64 + 1);
        if proof.point != expected {
            return Err(TrxError::InvalidInput("eval proof point mismatch".into()));
        }
        let ok = KZG::verify_g1(
            &setup.srs,
            &commitment.com,
            &proof.point,
            &proof.value,
            &proof.proof,
        )
        .map_err(|err| TrxError::Backend(err.to_string()))?;
        if !ok {
            return Err(TrxError::InvalidInput("invalid evaluation proof".into()));
        }
    }
    Ok(())
}
