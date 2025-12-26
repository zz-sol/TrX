//! Network protocol message types.
//!
//! Defines the messages exchanged between clients, proposers, and validators
//! during the encrypted transaction lifecycle.

use tess::PairingBackend;

use crate::{
    DecryptionContext, EncryptedTransaction, PartialDecryption, ValidatorSignature,
    ValidatorVerifyKey,
};

/// Network protocol messages for TrX.
///
/// Defines the complete set of messages exchanged between clients, validators,
/// and proposers during the encrypted transaction lifecycle.
///
/// # Message Flow
///
/// ```text
/// Client               Proposer/Leader            Validators
///   │                      │                          │
///   ├─SubmitEncryptedTx──→ │                          │
///   │                      ├───ProposeBlock─────────→ │
///   │                      │ ←──VoteWithDecryption────┤
///   │                      ├──RequestDecryptionShares→│
///   │                      │ ←───DecryptionShare──────┤
///   │                      │                          │
/// ```
#[derive(Clone, Debug)]
pub enum TrxMessage<B: PairingBackend> {
    /// Client submits an encrypted transaction to the network.
    ///
    /// The transaction includes ciphertext, associated data, and client signature.
    SubmitEncryptedTx(EncryptedTransaction<B>),

    /// Proposer proposes a block containing encrypted transactions.
    ///
    /// Validators will vote on this block and optionally include partial decryptions.
    ProposeBlock {
        /// Hash of the proposed block
        block_hash: Vec<u8>,
        /// Batch of encrypted transactions in the block
        encrypted_txs: Vec<EncryptedTransaction<B>>,
    },

    /// Validator votes on a block, optionally including a partial decryption.
    ///
    /// Used in optimistic protocols where decryption happens during voting.
    VoteWithDecryption {
        /// Vote message (e.g., block hash, approval)
        vote: Vec<u8>,
        /// Optional partial decryption share for the batch
        partial_decryption: Option<PartialDecryption<B>>,
        /// BLS signature over (vote || partial_decryption)
        validator_sig: ValidatorSignature,
        /// Validator's BLS public key
        validator_vk: ValidatorVerifyKey,
    },

    /// Request validators to produce decryption shares for a finalized batch.
    ///
    /// Used in pessimistic protocols where decryption happens after finality.
    RequestDecryptionShares {
        /// Hash of the finalized block
        block_hash: Vec<u8>,
        /// Decryption context for the batch
        context: DecryptionContext,
    },

    /// Validator provides a decryption share for a specific block.
    ///
    /// Response to RequestDecryptionShares or sent proactively after finality.
    DecryptionShare {
        /// Hash of the block being decrypted
        block_hash: Vec<u8>,
        /// Partial decryption share
        share: PartialDecryption<B>,
        /// BLS signature over (block_hash || share)
        validator_sig: ValidatorSignature,
        /// Validator's BLS public key
        validator_vk: ValidatorVerifyKey,
    },
}
