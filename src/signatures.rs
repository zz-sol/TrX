use blake3::Hasher;
use solana_bls_signatures::{pubkey::VerifiablePubkey, SecretKey};
use tess::{CurvePoint, PairingBackend};

use crate::{PartialDecryption, TrxError};

pub type TxPublicVerifyKey = ed25519_dalek::VerifyingKey;
pub type TxSignature = ed25519_dalek::Signature;

pub type ValidatorSigningKey = SecretKey;
pub type ValidatorVerifyKey = solana_bls_signatures::PubkeyCompressed;
pub type ValidatorSignature = solana_bls_signatures::SignatureCompressed;

pub fn sign_validator_vote<B: PairingBackend>(
    signing_key: &ValidatorSigningKey,
    vote: &[u8],
    partial_decryption: Option<&PartialDecryption<B>>,
) -> ValidatorSignature {
    let message = validator_vote_message(vote, partial_decryption);
    signing_key.sign(message.as_ref()).into()
}

pub fn verify_validator_vote<B: PairingBackend>(
    verify_key: &ValidatorVerifyKey,
    signature: &ValidatorSignature,
    vote: &[u8],
    partial_decryption: Option<&PartialDecryption<B>>,
) -> Result<(), TrxError> {
    let message = validator_vote_message(vote, partial_decryption);
    let ok = verify_key
        .verify_signature(signature, message.as_ref())
        .map_err(|err| TrxError::InvalidInput(format!("invalid validator signature: {err}")))?;
    if !ok {
        return Err(TrxError::InvalidInput(
            "invalid validator signature".into(),
        ));
    }
    Ok(())
}

pub fn sign_validator_share<B: PairingBackend>(
    signing_key: &ValidatorSigningKey,
    block_hash: &[u8],
    share: &PartialDecryption<B>,
) -> ValidatorSignature {
    let message = validator_share_message(block_hash, share);
    signing_key.sign(message.as_ref()).into()
}

pub fn verify_validator_share<B: PairingBackend>(
    verify_key: &ValidatorVerifyKey,
    signature: &ValidatorSignature,
    block_hash: &[u8],
    share: &PartialDecryption<B>,
) -> Result<(), TrxError> {
    let message = validator_share_message(block_hash, share);
    let ok = verify_key
        .verify_signature(signature, message.as_ref())
        .map_err(|err| TrxError::InvalidInput(format!("invalid validator signature: {err}")))?;
    if !ok {
        return Err(TrxError::InvalidInput(
            "invalid validator signature".into(),
        ));
    }
    Ok(())
}

fn validator_vote_message<B: PairingBackend>(
    vote: &[u8],
    partial_decryption: Option<&PartialDecryption<B>>,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"trx:validator-vote:v1");
    hasher.update(vote);
    if let Some(pd) = partial_decryption {
        hasher.update(b"trx:partial-decryption:v1");
        hasher.update(&pd.validator_id.to_le_bytes());
        hasher.update(&pd.tx_index.to_le_bytes());
        hasher.update(&pd.context.block_height.to_le_bytes());
        hasher.update(&pd.context.context_index.to_le_bytes());
        hasher.update(pd.pd.to_repr().as_ref());
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn validator_share_message<B: PairingBackend>(
    block_hash: &[u8],
    share: &PartialDecryption<B>,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"trx:decryption-share:v1");
    hasher.update(block_hash);
    hasher.update(&share.validator_id.to_le_bytes());
    hasher.update(&share.tx_index.to_le_bytes());
    hasher.update(&share.context.block_height.to_le_bytes());
    hasher.update(&share.context.context_index.to_le_bytes());
    hasher.update(share.pd.to_repr().as_ref());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}
