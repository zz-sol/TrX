use blake3::Hasher;
use tess::{DensePolynomial, FieldElement, Fr, KZG, PairingBackend, PolynomialCommitment};

use crate::utils::scalar_from_hash;
use crate::{DecryptionContext, EncryptedTransaction, TrustedSetup, TrxError};

/// Batch commitment produced by KZG.
#[derive(Debug)]
pub struct BatchCommitment<B: PairingBackend> {
    pub com: B::G1,
    pub polynomial_degree: u32,
}

impl<B: PairingBackend<Scalar = Fr>> BatchCommitment<B> {
    pub fn compute(
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &TrustedSetup<B>,
    ) -> Result<Self, TrxError> {
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
            com: self.com.clone(),
            polynomial_degree: self.polynomial_degree,
        }
    }
}

#[derive(Debug)]
pub struct EvalProof<B: PairingBackend<Scalar = Fr>> {
    pub point: B::Scalar,
    pub value: B::Scalar,
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
            proof: self.proof.clone(),
        }
    }
}

impl<B: PairingBackend<Scalar = Fr>> EvalProof<B> {
    pub fn compute_for_batch(
        batch: &[EncryptedTransaction<B>],
        context: &DecryptionContext,
        setup: &TrustedSetup<B>,
    ) -> Result<Vec<Self>, TrxError> {
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
