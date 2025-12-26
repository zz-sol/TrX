use tess::{Fr, PairingBackend};

use crate::{EncryptedTransaction, TransactionEncryption, TrxCrypto, TrxError};

/// Encrypted mempool implementation.
#[derive(Debug)]
pub struct EncryptedMempool<B: PairingBackend> {
    encrypted_txs: Vec<EncryptedTransaction<B>>,
    max_size: usize,
}

impl<B: PairingBackend<Scalar = Fr>> EncryptedMempool<B> {
    /// Creates a bounded mempool.
    pub fn new(max_size: usize) -> Self {
        Self {
            encrypted_txs: Vec::new(),
            max_size,
        }
    }

    /// Adds a transaction to the mempool after basic validation.
    pub fn add_encrypted_tx(&mut self, tx: EncryptedTransaction<B>) -> Result<(), TrxError> {
        TrxCrypto::<B>::verify_ciphertext(&tx)?;
        if self.encrypted_txs.len() >= self.max_size {
            return Err(TrxError::InvalidConfig("mempool full".into()));
        }
        self.encrypted_txs.push(tx);
        Ok(())
    }

    /// Pops up to `max_size` entries for block proposal.
    pub fn get_batch(&mut self, max_size: usize) -> Vec<EncryptedTransaction<B>> {
        let take = max_size.min(self.encrypted_txs.len());
        self.encrypted_txs.drain(0..take).collect()
    }
}
