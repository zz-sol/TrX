//! Client-side transaction encryption and verification.

use ed25519_dalek::{Signer, SigningKey};
use tess::{Ciphertext as TessCiphertext, Fr, PairingBackend, ThresholdEncryption};
use tracing::instrument;

use super::engine::TrxCrypto;
use crate::{EncryptedTransaction, ThresholdEncryptionPublicKey, TrxError};

/// Client-side transaction encryption interface.
pub trait TransactionEncryption<B: PairingBackend<Scalar = Fr>> {
    /// Encrypts a transaction payload using threshold encryption.
    fn encrypt_transaction(
        &self,
        ek: &ThresholdEncryptionPublicKey<B>,
        payload: &[u8],
        associated_data: &[u8],
        signing_key: &SigningKey,
    ) -> Result<EncryptedTransaction<B>, TrxError>;

    /// Verifies the validity of an encrypted transaction.
    fn verify_ciphertext(ct: &EncryptedTransaction<B>) -> Result<(), TrxError>;
}

impl<B: PairingBackend<Scalar = Fr>> TransactionEncryption<B> for TrxCrypto<B> {
    #[instrument(
        level = "info",
        skip_all,
        fields(payload_len = payload.len(), associated_len = associated_data.len())
    )]
    fn encrypt_transaction(
        &self,
        ek: &ThresholdEncryptionPublicKey<B>,
        payload: &[u8],
        associated_data: &[u8],
        signing_key: &SigningKey,
    ) -> Result<EncryptedTransaction<B>, TrxError> {
        let mut rng = rand::thread_rng();
        let ciphertext = self.tess_scheme.encrypt(
            &mut rng,
            &ek.agg_key,
            &self.params,
            self.threshold,
            payload,
        )?;
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

    #[instrument(
        level = "info",
        skip_all,
        fields(payload_len = ct.ciphertext.payload.len(), associated_len = ct.associated_data.len())
    )]
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

/// Constructs the signing message for client transaction signatures.
fn client_signature_message<B: PairingBackend>(
    ciphertext: &TessCiphertext<B>,
    associated_data: &[u8],
) -> [u8; 32] {
    crate::utils::hash_transaction_for_signature::<B>(ciphertext, associated_data)
}
