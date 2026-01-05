//! Cryptographic signature helpers for clients and validators.
//!
//! This module provides signature functionality for two different parties in TrX.
//! All BLS signature functions and types are **public API** and can be used for
//! custom consensus protocols.
//!
//! # Client Signatures (Ed25519)
//!
//! Clients sign their encrypted transactions using Ed25519:
//! - Fast signature generation and verification
//! - Small signature size (64 bytes)
//! - Binds transaction ciphertext to associated metadata
//!
//! The signature message is `BLAKE3(ciphertext.payload || associated_data)`.
//!
//! Client signatures are handled internally by [`TransactionEncryption::encrypt_transaction`]
//! and [`TransactionEncryption::verify_ciphertext`].
//!
//! # Validator Signatures (BLS) - Public API
//!
//! Validators use BLS signatures for consensus operations:
//! - **Vote Signatures**: Sign votes with optional partial decryptions
//! - **Share Signatures**: Sign decryption shares for authenticity
//!
//! BLS signatures enable aggregation and batch verification in consensus.
//!
//! ## Public Functions
//!
//! - [`sign_validator_vote`] / [`verify_validator_vote`] - Consensus votes
//! - [`sign_validator_share`] / [`verify_validator_share`] - Decryption shares
//! - [`sign_validator_share_bound`] / [`verify_validator_share_bound`] - Bound shares
//! - [`validator_vote_message`] / [`validator_share_message`] - Message construction
//! - [`validator_share_message_bound`] - Bound share message construction
//!
//! ## Type Aliases
//!
//! - [`ValidatorSigningKey`] - BLS secret key
//! - [`ValidatorVerifyKey`] - BLS compressed public key
//! - [`ValidatorSignature`] - BLS compressed signature
//!
//! # Message Formats
//!
//! All signature messages include domain separation tags (e.g., `"trx:validator-vote:v1"`)
//! to prevent cross-protocol attacks and enable protocol versioning.
//!
//! # Example
//!
//! ```rust,ignore
//! # use trx::*;
//! # fn example() -> Result<(), TrxError> {
//! # let signing_key = ValidatorSigningKey::new();
//! # let vote = b"vote_data";
//! # let pd = PartialDecryption::<tess::PairingEngine> {
//! #     pd: tess::PairingEngine::G2::default(),
//! #     validator_id: 0,
//! #     context: DecryptionContext { block_height: 1, context_index: 0 },
//! #     tx_index: 0,
//! # };
//! // Validator signs a vote with partial decryption
//! let signature = sign_validator_vote(&signing_key, vote, Some(&pd));
//!
//! // Verify the signature
//! let verify_key = signing_key.pubkey().compress();
//! verify_validator_vote(&verify_key, &signature, vote, Some(&pd))?;
//! # Ok(())
//! # }
//! ```
//!
//! [`TransactionEncryption::encrypt_transaction`]: crate::TransactionEncryption::encrypt_transaction
//! [`TransactionEncryption::verify_ciphertext`]: crate::TransactionEncryption::verify_ciphertext

use blake3::Hasher;
use solana_bls_signatures::{pubkey::PubkeyProjective, pubkey::VerifiablePubkey, SecretKey};
use tess::{CurvePoint, PairingBackend};
use tracing::instrument;

use crate::{PartialDecryption, TrxError};

/// Validator's BLS secret signing key.
pub type ValidatorSigningKey = SecretKey;

/// Validator's compressed BLS public verification key.
pub type ValidatorVerifyKey = solana_bls_signatures::PubkeyCompressed;

/// Validator's compressed BLS signature.
pub type ValidatorSignature = solana_bls_signatures::SignatureCompressed;

/// Derive a validator verification key from a signing key.
pub fn validator_verify_key(signing_key: &ValidatorSigningKey) -> ValidatorVerifyKey {
    PubkeyProjective::from_secret(signing_key).into()
}

/// Signs a validator vote, optionally including a partial decryption.
///
/// Validators sign their consensus votes using BLS signatures. The vote may
/// include a partial decryption share for the current batch.
///
/// # Arguments
///
/// * `signing_key` - Validator's BLS secret key
/// * `vote` - Vote message (e.g., block hash, proposal ID)
/// * `partial_decryption` - Optional partial decryption to include in signature
///
/// # Returns
///
/// A compressed BLS signature over the vote message.
///
/// # Message Format
///
/// The signed message is:
/// ```text
/// BLAKE3("trx:validator-vote:v1" || vote || optional_pd_data)
/// ```
#[instrument(
    level = "info",
    skip_all,
    fields(vote_len = vote.len(), has_pd = partial_decryption.is_some())
)]
pub fn sign_validator_vote<B: PairingBackend>(
    signing_key: &ValidatorSigningKey,
    vote: &[u8],
    partial_decryption: Option<&PartialDecryption<B>>,
) -> ValidatorSignature {
    let message = validator_vote_message(vote, partial_decryption);
    signing_key.sign(message.as_ref()).into()
}

/// Verifies a validator vote signature.
///
/// # Arguments
///
/// * `verify_key` - Validator's BLS public key
/// * `signature` - Signature to verify
/// * `vote` - Vote message that was signed
/// * `partial_decryption` - Optional partial decryption included in signature
///
/// # Errors
///
/// Returns [`TrxError::InvalidInput`] if signature verification fails.
#[instrument(
    level = "info",
    skip_all,
    fields(vote_len = vote.len(), has_pd = partial_decryption.is_some())
)]
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
        return Err(TrxError::InvalidInput("invalid validator signature".into()));
    }
    Ok(())
}

/// Signs a decryption share for a specific block.
///
/// Used when validators distribute their partial decryptions separately from votes
/// (e.g., in an optimistic decryption protocol where shares are sent after finality).
///
/// # Arguments
///
/// * `signing_key` - Validator's BLS secret key
/// * `block_hash` - Hash of the block containing the batch
/// * `share` - Partial decryption share to sign
///
/// # Returns
///
/// A compressed BLS signature binding the share to the block.
///
/// # Message Format
///
/// ```text
/// BLAKE3("trx:decryption-share:v1" || block_hash || share_data)
/// ```
#[instrument(
    level = "info",
    skip_all,
    fields(block_hash_len = block_hash.len(), validator_id = share.validator_id, tx_index = share.tx_index)
)]
pub fn sign_validator_share<B: PairingBackend>(
    signing_key: &ValidatorSigningKey,
    block_hash: &[u8],
    share: &PartialDecryption<B>,
) -> ValidatorSignature {
    let message = validator_share_message(block_hash, share);
    signing_key.sign(message.as_ref()).into()
}

/// Signs a decryption share bound to a batch commitment and ciphertext hash.
///
/// This enforces strict binding between a share and the specific batch/transaction.
#[instrument(
    level = "info",
    skip_all,
    fields(validator_id = share.validator_id, tx_index = share.tx_index)
)]
pub fn sign_validator_share_bound<B: PairingBackend>(
    signing_key: &ValidatorSigningKey,
    commitment_hash: &[u8; 32],
    ciphertext_hash: &[u8; 32],
    share: &PartialDecryption<B>,
) -> ValidatorSignature {
    let message = validator_share_message_bound(commitment_hash, ciphertext_hash, share);
    signing_key.sign(message.as_ref()).into()
}

/// Verifies a decryption share signature.
///
/// # Arguments
///
/// * `verify_key` - Validator's BLS public key
/// * `signature` - Signature to verify
/// * `block_hash` - Block hash included in signature
/// * `share` - Partial decryption share that was signed
///
/// # Errors
///
/// Returns [`TrxError::InvalidInput`] if signature verification fails.
#[instrument(
    level = "info",
    skip_all,
    fields(block_hash_len = block_hash.len(), validator_id = share.validator_id, tx_index = share.tx_index)
)]
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
        return Err(TrxError::InvalidInput("invalid validator signature".into()));
    }
    Ok(())
}

/// Verifies a commitment-bound decryption share signature.
#[instrument(
    level = "info",
    skip_all,
    fields(validator_id = share.validator_id, tx_index = share.tx_index)
)]
pub fn verify_validator_share_bound<B: PairingBackend>(
    verify_key: &ValidatorVerifyKey,
    signature: &ValidatorSignature,
    commitment_hash: &[u8; 32],
    ciphertext_hash: &[u8; 32],
    share: &PartialDecryption<B>,
) -> Result<(), TrxError> {
    let message = validator_share_message_bound(commitment_hash, ciphertext_hash, share);
    let ok = verify_key
        .verify_signature(signature, message.as_ref())
        .map_err(|err| TrxError::InvalidInput(format!("invalid validator signature: {err}")))?;
    if !ok {
        return Err(TrxError::InvalidInput("invalid validator signature".into()));
    }
    Ok(())
}

/// Constructs the signing message for validator votes.
///
/// Includes domain separation and optionally binds partial decryption data.
///
/// # Arguments
///
/// * `vote` - Vote payload
/// * `partial_decryption` - Optional partial decryption to include
///
/// # Returns
///
/// A 32-byte BLAKE3 digest used as the BLS signing message.
pub fn validator_vote_message<B: PairingBackend>(
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

/// Constructs the signing message for decryption shares.
///
/// Binds the share to a specific block and includes all share metadata.
///
/// # Arguments
///
/// * `block_hash` - Hash of the block
/// * `share` - Partial decryption share
///
/// # Returns
///
/// A 32-byte BLAKE3 digest used as the BLS signing message.
pub fn validator_share_message<B: PairingBackend>(
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

/// Constructs the signing message for commitment-bound decryption shares.
pub fn validator_share_message_bound<B: PairingBackend>(
    commitment_hash: &[u8; 32],
    ciphertext_hash: &[u8; 32],
    share: &PartialDecryption<B>,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"trx:decryption-share-bound:v1");
    hasher.update(commitment_hash);
    hasher.update(ciphertext_hash);
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
