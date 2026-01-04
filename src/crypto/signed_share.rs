//! Signed partial decryption shares for strict batch binding.

use tess::PairingBackend;

use crate::{PartialDecryption, ValidatorSignature, ValidatorVerifyKey};

/// Partial decryption share with a validator signature and verify key.
#[derive(Clone, Debug)]
pub struct SignedPartialDecryption<B: PairingBackend> {
    /// The underlying partial decryption share.
    pub share: PartialDecryption<B>,
    /// BLS signature over the bound share message.
    pub signature: ValidatorSignature,
    /// Validator's BLS public verification key.
    pub validator_vk: ValidatorVerifyKey,
}
