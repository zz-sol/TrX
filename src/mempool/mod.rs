//! Encrypted transaction mempool for pending transactions.
//!
//! This module provides a simple bounded mempool for storing encrypted transactions
//! before they are included in blocks.
//!
//! # Design
//!
//! The [`EncryptedMempool`] is a FIFO (first-in-first-out) queue that:
//! - Validates transactions before admission (signature check)
//! - Enforces a maximum size to prevent memory exhaustion
//! - Provides batch extraction for block proposals
//!
//! # Usage
//!
//! ```rust,no_run
//! # use trx::*;
//! # use ed25519_dalek::SigningKey;
//! # fn example() -> Result<(), TrxError> {
//! # let mut rng = rand::thread_rng();
//! # let crypto = TrxCrypto::<tess::PairingEngine>::new(&mut rng, 5, 3)?;
//! # let signing_key = SigningKey::generate(&mut rng);
//! # let global_setup = crypto.generate_global_setup(&mut rng, 128)?;
//! # let setup = crypto.generate_epoch_setup(&mut rng, 1, 1000, global_setup)?;
//! # let validators: Vec<u32> = (0..5).collect();
//! # let validator_keypairs: Vec<_> = validators
//! #     .iter()
//! #     .map(|&id| crypto.keygen_single_validator(&mut rng, id))
//! #     .collect::<Result<Vec<_>, _>>()?;
//! # let public_keys = validator_keypairs
//! #     .iter()
//! #     .map(|kp| kp.public_key.clone())
//! #     .collect();
//! # let epoch_keys = crypto.aggregate_epoch_keys(public_keys, 3, setup)?;
//! # let encrypted_tx = crypto.encrypt_transaction(&epoch_keys.public_key, b"data", b"metadata", &signing_key)?;
//! // Create mempool with max 1000 transactions
//! let mut mempool = EncryptedMempool::<tess::PairingEngine>::new(1000);
//!
//! // Add encrypted transaction
//! mempool.add_encrypted_tx(encrypted_tx)?;
//!
//! // Get batch for block proposal
//! let batch = mempool.get_batch(100); // Up to 100 transactions
//! # Ok(())
//! # }
//! ```
//!
//! # Future Improvements
//!
//! - Priority queue based on fees (requires fee extraction mechanism)
//! - Transaction replacement policies
//! - Age-based eviction
//! - Spam prevention mechanisms

use tess::{Fr, PairingBackend};
use tracing::instrument;

use crate::{EncryptedTransaction, TransactionEncryption, TrxCrypto, TrxError};

/// Bounded FIFO queue for encrypted transactions awaiting inclusion in blocks.
///
/// The mempool validates transaction signatures before admission and enforces
/// a maximum size limit. Transactions are extracted in FIFO order for block proposals.
#[derive(Debug)]
pub struct EncryptedMempool<B: PairingBackend> {
    /// Queue of validated encrypted transactions
    encrypted_txs: Vec<EncryptedTransaction<B>>,
    /// Maximum number of transactions allowed in the mempool
    max_size: usize,
}

impl<B: PairingBackend<Scalar = Fr>> EncryptedMempool<B> {
    /// Creates a new bounded mempool.
    ///
    /// # Arguments
    ///
    /// * `max_size` - Maximum number of transactions the mempool can hold
    ///
    /// # Returns
    ///
    /// An empty mempool with the specified capacity limit.
    #[instrument(level = "info", skip_all, fields(max_size))]
    pub fn new(max_size: usize) -> Self {
        Self {
            encrypted_txs: Vec::new(),
            max_size,
        }
    }

    /// Adds an encrypted transaction to the mempool after validation.
    ///
    /// Validates the transaction's client signature before admission. Rejects
    /// the transaction if the mempool is full.
    ///
    /// # Arguments
    ///
    /// * `tx` - Encrypted transaction to add
    ///
    /// # Errors
    ///
    /// - [`TrxError::InvalidInput`] if signature verification fails
    /// - [`TrxError::InvalidConfig`] if mempool is at capacity
    ///
    /// # Validation
    ///
    /// Checks:
    /// - Ciphertext payload is non-empty
    /// - Ed25519 signature is valid over (ciphertext || associated_data)
    #[instrument(level = "info", skip_all, fields(current_len = self.encrypted_txs.len(), max_size = self.max_size))]
    pub fn add_encrypted_tx(&mut self, tx: EncryptedTransaction<B>) -> Result<(), TrxError> {
        TrxCrypto::<B>::verify_ciphertext(&tx)?;
        if self.encrypted_txs.len() >= self.max_size {
            return Err(TrxError::InvalidConfig("mempool full".into()));
        }
        self.encrypted_txs.push(tx);
        Ok(())
    }

    /// Extracts a batch of transactions for block proposal.
    ///
    /// Removes up to `max_size` transactions from the front of the mempool (FIFO order).
    /// The extracted transactions are removed from the mempool.
    ///
    /// # Arguments
    ///
    /// * `max_size` - Maximum number of transactions to extract
    ///
    /// # Returns
    ///
    /// A vector of encrypted transactions, with length ≤ `max_size`.
    /// Returns fewer than `max_size` if the mempool doesn't have enough transactions.
    ///
    /// # Notes
    ///
    /// This method mutates the mempool by removing the extracted transactions.
    /// If you need to peek without removing, clone the transactions first.
    #[instrument(level = "info", skip_all, fields(requested = max_size, available = self.encrypted_txs.len()))]
    pub fn get_batch(&mut self, max_size: usize) -> Vec<EncryptedTransaction<B>> {
        let take = max_size.min(self.encrypted_txs.len());
        self.encrypted_txs.drain(0..take).collect()
    }

    /// Returns the current number of transactions in the mempool.
    ///
    /// # Returns
    ///
    /// The number of pending transactions currently stored.
    pub fn size(&self) -> usize {
        self.encrypted_txs.len()
    }
}
