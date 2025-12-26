use blake3::Hasher;
use tess::{FieldElement, Fr, PairingBackend};

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
