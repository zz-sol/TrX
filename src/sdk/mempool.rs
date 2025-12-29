//! Mempool Phase API - Encrypted transaction queue management.
//!
//! This phase handles node-side operations for managing a queue of
//! encrypted transactions awaiting inclusion in blocks.

use crate::{EncryptedMempool, EncryptedTransaction, TrxError};
use tess::{Fr, PairingBackend};

/// Mempool Phase API for transaction queue management.
///
/// This phase handles:
/// - Adding encrypted transactions to the mempool (with validation)
/// - Retrieving batches for block proposal
/// - Managing mempool capacity
///
/// # Example
///
/// ```no_run
/// use trx::sdk::TrxClient;
/// use tess::PairingEngine;
/// use rand::thread_rng;
///
/// let mut rng = thread_rng();
/// let client = TrxClient::<PairingEngine>::new(&mut rng, 5, 3)?;
///
/// // Create mempool with capacity for 1000 transactions
/// let mut mempool = client.mempool().create(1000);
///
/// # let encrypted_tx = todo!();
/// // Add transaction to mempool
/// mempool.add_encrypted_tx(encrypted_tx)?;
///
/// // Retrieve batch for block proposal
/// let batch = mempool.get_batch(32);
/// # Ok::<(), trx::TrxError>(())
/// ```
pub struct MempoolPhase<B: PairingBackend<Scalar = Fr>> {
    _phantom: std::marker::PhantomData<B>,
}

impl<B: PairingBackend<Scalar = Fr>> MempoolPhase<B> {
    pub(crate) fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Create a new encrypted mempool with the specified capacity.
    ///
    /// The mempool implements a bounded FIFO queue that:
    /// - Validates Ed25519 signatures before admission
    /// - Enforces maximum capacity to prevent DoS
    /// - Provides batches in FIFO order for fairness
    ///
    /// # Arguments
    ///
    /// * `max_size` - Maximum number of transactions the mempool can hold
    ///
    /// # Returns
    ///
    /// A new `EncryptedMempool` instance.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use trx::sdk::TrxClient;
    /// use tess::PairingEngine;
    /// use rand::thread_rng;
    ///
    /// let mut rng = thread_rng();
    /// let client = TrxClient::<PairingEngine>::new(&mut rng, 100, 67)?;
    ///
    /// // Create mempool for 10,000 pending transactions
    /// let mut mempool = client.mempool().create(10_000);
    /// # Ok::<(), trx::TrxError>(())
    /// ```
    pub fn create(&self, max_size: usize) -> EncryptedMempool<B> {
        EncryptedMempool::new(max_size)
    }

    /// Add an encrypted transaction to the mempool.
    ///
    /// This method:
    /// 1. Verifies the Ed25519 signature on the transaction
    /// 2. Checks mempool capacity
    /// 3. Adds transaction to FIFO queue if valid
    ///
    /// # Arguments
    ///
    /// * `mempool` - The mempool instance to add to
    /// * `encrypted_tx` - The encrypted transaction to add
    ///
    /// # Errors
    ///
    /// Returns `TrxError::InvalidInput` if:
    /// - Transaction signature is invalid
    /// - Mempool is at capacity
    ///
    /// # Example
    ///
    /// ```no_run
    /// use trx::sdk::TrxClient;
    /// use tess::PairingEngine;
    /// use ed25519_dalek::SigningKey;
    /// use rand::thread_rng;
    ///
    /// let mut rng = thread_rng();
    /// let client = TrxClient::<PairingEngine>::new(&mut rng, 5, 3)?;
    /// let mut mempool = client.mempool().create(1000);
    ///
    /// # let epoch_key = todo!();
    /// let signing_key = SigningKey::generate(&mut rng);
    /// let tx = client.client().encrypt_transaction(
    ///     &epoch_key,
    ///     b"payload",
    ///     b"metadata",
    ///     &signing_key,
    /// )?;
    ///
    /// // Add transaction with validation
    /// match client.mempool().add_transaction(&mut mempool, tx) {
    ///     Ok(_) => println!("Transaction added to mempool"),
    ///     Err(e) => println!("Transaction rejected: {}", e),
    /// }
    /// # Ok::<(), trx::TrxError>(())
    /// ```
    pub fn add_transaction(
        &self,
        mempool: &mut EncryptedMempool<B>,
        encrypted_tx: EncryptedTransaction<B>,
    ) -> Result<(), TrxError> {
        mempool.add_encrypted_tx(encrypted_tx)
    }

    /// Retrieve a batch of transactions from the mempool.
    ///
    /// This method:
    /// 1. Removes up to `max_size` transactions from the FIFO queue
    /// 2. Returns them in the order they were added (fair ordering)
    /// 3. Transactions are removed from mempool (not returned to pool)
    ///
    /// # Arguments
    ///
    /// * `mempool` - The mempool instance to get batch from
    /// * `max_size` - Maximum number of transactions to retrieve
    ///
    /// # Returns
    ///
    /// A vector of encrypted transactions (may be less than `max_size` if
    /// mempool has fewer transactions).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use trx::sdk::TrxClient;
    /// use tess::PairingEngine;
    /// use rand::thread_rng;
    ///
    /// let mut rng = thread_rng();
    /// let client = TrxClient::<PairingEngine>::new(&mut rng, 5, 3)?;
    /// let mut mempool = client.mempool().create(1000);
    ///
    /// // Proposer retrieves batch for block
    /// let batch = client.mempool().get_batch(&mut mempool, 32);
    ///
    /// if batch.is_empty() {
    ///     println!("Mempool empty, no transactions to propose");
    /// } else {
    ///     println!("Proposing batch of {} transactions", batch.len());
    /// }
    /// # Ok::<(), trx::TrxError>(())
    /// ```
    pub fn get_batch(
        &self,
        mempool: &mut EncryptedMempool<B>,
        max_size: usize,
    ) -> Vec<EncryptedTransaction<B>> {
        mempool.get_batch(max_size)
    }

    /// Get the current number of transactions in the mempool.
    ///
    /// # Arguments
    ///
    /// * `mempool` - The mempool instance to query
    ///
    /// # Returns
    ///
    /// The number of pending transactions currently in the mempool.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use trx::sdk::TrxClient;
    /// use tess::PairingEngine;
    /// use rand::thread_rng;
    ///
    /// let mut rng = thread_rng();
    /// let client = TrxClient::<PairingEngine>::new(&mut rng, 5, 3)?;
    /// let mempool = client.mempool().create(1000);
    ///
    /// let count = client.mempool().size(&mempool);
    /// println!("Mempool has {} pending transactions", count);
    /// # Ok::<(), trx::TrxError>(())
    /// ```
    pub fn size(&self, mempool: &EncryptedMempool<B>) -> usize {
        mempool.size()
    }
}
