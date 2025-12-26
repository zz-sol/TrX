use blake3::Hasher;
use tess::{FieldElement, Fr, PairingBackend};

use crate::{DecryptionContext, EncryptedTransaction};

pub(crate) fn hash_to_scalar<B: PairingBackend<Scalar = Fr>>(
    batch: &[EncryptedTransaction<B>],
    context: &DecryptionContext,
) -> B::Scalar {
    let mut hasher = Hasher::new();
    hasher.update(&context.block_height.to_le_bytes());
    hasher.update(&context.context_index.to_le_bytes());
    for tx in batch {
        hasher.update(&tx.ciphertext.payload);
        hasher.update(&tx.associated_data);
    }
    let digest = hasher.finalize();
    scalar_from_hash::<B>(digest.as_bytes())
}

/// Attempts to map a hash digest into a field element by rejection sampling.

pub(crate) fn scalar_from_hash<B: PairingBackend<Scalar = Fr>>(bytes: &[u8]) -> B::Scalar {
    let mut counter = 0u64;
    loop {
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
