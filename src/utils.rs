use blake3::Hasher;
use tess::{Ciphertext as TessCiphertext, CurvePoint, FieldElement, Fr, PairingBackend};

use crate::{DecryptionContext, TransactionBatchCommitment};

/// Maximum attempts for rejection sampling to prevent infinite loops.
const MAX_REJECTION_SAMPLING_ATTEMPTS: u64 = 1000;

/// Attempts to map a hash digest into a field element by rejection sampling.
///
/// Uses BLAKE3-based rejection sampling to derive a scalar from arbitrary bytes.
/// This should succeed quickly for properly configured field parameters.
///
/// # Arguments
///
/// * `bytes` - Input bytes to hash
///
/// # Returns
///
/// A field element derived from the input bytes.
///
/// # Panics
///
/// Panics if rejection sampling fails after [`MAX_REJECTION_SAMPLING_ATTEMPTS`] attempts.
/// This should never happen with proper field parameters (e.g., BN254, BLS12-381).
pub(crate) fn scalar_from_hash<B: PairingBackend<Scalar = Fr>>(bytes: &[u8]) -> B::Scalar {
    let mut counter = 0u64;

    loop {
        if counter >= MAX_REJECTION_SAMPLING_ATTEMPTS {
            // This should never happen with proper field parameters.
            // If it does, there's a fundamental issue with the field configuration.
            panic!(
                "Failed to derive scalar after {} attempts. Check field parameters.",
                MAX_REJECTION_SAMPLING_ATTEMPTS
            );
        }

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

/// Hashes transaction ciphertext and associated data for client signature verification.
///
/// This function computes the message that clients sign when submitting transactions.
/// The signature proves the client authorized this specific encrypted payload.
///
/// # Arguments
///
/// * `ciphertext` - The encrypted transaction payload
/// * `associated_data` - Public associated data (e.g., metadata)
///
/// # Returns
///
/// A 32-byte hash digest used for Ed25519 signature verification.
pub(crate) fn hash_transaction_for_signature<B: PairingBackend>(
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

/// Hashes a batch commitment for binding decryption shares to a batch.
pub(crate) fn hash_commitment_for_signature<B: PairingBackend>(
    commitment: &TransactionBatchCommitment<B>,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(commitment.com.to_repr().as_ref());
    hasher.update(&commitment.polynomial_degree.to_le_bytes());
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(digest.as_bytes());
    output
}

/// Hashes a ciphertext for decryption-share signatures.
pub(crate) fn hash_ciphertext_for_share_signature<B: PairingBackend>(
    ciphertext: &TessCiphertext<B>,
    associated_data: &[u8],
) -> [u8; 32] {
    hash_transaction_for_signature::<B>(ciphertext, associated_data)
}

/// Hashes transaction for batch commitment polynomial construction.
///
/// This function computes the scalar coefficient used in KZG batch commitments.
/// It binds the transaction to a specific decryption context (block height and context index)
/// to prevent replay attacks across different blocks or epochs.
///
/// # Arguments
///
/// * `ciphertext` - The encrypted transaction payload
/// * `associated_data` - Public associated data
/// * `context` - Decryption context (block height and context index)
///
/// # Returns
///
/// A field element in the scalar field of the pairing curve.
pub(crate) fn hash_transaction_for_commitment<B: PairingBackend<Scalar = Fr>>(
    ciphertext: &TessCiphertext<B>,
    associated_data: &[u8],
    context: &DecryptionContext,
) -> B::Scalar {
    let mut hasher = Hasher::new();
    hasher.update(&context.block_height.to_le_bytes());
    hasher.update(&context.context_index.to_le_bytes());
    hasher.update(&ciphertext.payload);
    hasher.update(associated_data);
    scalar_from_hash::<B>(hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::scalar_from_hash;
    use tess::PairingEngine;

    #[test]
    fn scalar_from_hash_is_deterministic() {
        let input = b"test_input";
        let scalar1 = scalar_from_hash::<PairingEngine>(input);
        let scalar2 = scalar_from_hash::<PairingEngine>(input);
        assert_eq!(scalar1, scalar2);

        let different_input = b"different_input";
        let scalar3 = scalar_from_hash::<PairingEngine>(different_input);
        assert_ne!(scalar1, scalar3);
    }
}
