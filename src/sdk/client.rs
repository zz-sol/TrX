//! Client Phase API - Transaction encryption and submission.
//!
//! This phase handles client-side operations for encrypting transactions
//! before submission to the encrypted mempool.

use crate::{
    EncryptedTransaction, ThresholdEncryptionPublicKey, TransactionEncryption, TrxCrypto, TrxError,
};
use ed25519_dalek::SigningKey;
use tess::{Fr, PairingBackend};

/// Client Phase API for transaction encryption.
///
/// This phase handles:
/// - Encrypting transaction payloads with threshold encryption
/// - Signing encrypted transactions for authenticity
/// - Verifying ciphertext integrity
///
/// # Example
///
/// ```no_run
/// use trx::TrxMinion;
/// use tess::PairingEngine;
/// use ed25519_dalek::SigningKey;
/// use rand::thread_rng;
///
/// let mut rng = thread_rng();
/// let client = TrxMinion::<PairingEngine>::new(&mut rng, 100, 67)?;
///
/// // Client generates signing key
/// let signing_key = SigningKey::generate(&mut rng);
///
/// // Encrypt transaction (epoch_key obtained from setup phase)
/// # let epoch_key = todo!();
/// let encrypted_tx = client.client().encrypt_transaction(
///     &epoch_key,
///     b"send 10 tokens to alice",
///     b"nonce:42,fee:1",
///     &signing_key,
/// )?;
/// # Ok::<(), trx::TrxError>(())
/// ```
pub struct ClientPhase<'a, B: PairingBackend<Scalar = Fr>> {
    crypto: &'a TrxCrypto<B>,
}

impl<'a, B: PairingBackend<Scalar = Fr>> ClientPhase<'a, B> {
    pub(crate) fn new(crypto: &'a TrxCrypto<B>) -> Self {
        Self { crypto }
    }

    /// Encrypt a transaction for submission to the encrypted mempool.
    ///
    /// This function:
    /// 1. Encrypts the `payload` using threshold encryption (TESS)
    /// 2. Attaches `associated_data` (authenticated but not encrypted)
    /// 3. Signs `BLAKE3(ciphertext || associated_data)` with Ed25519
    ///
    /// The resulting `EncryptedTransaction` can be broadcast to the network
    /// and will only be decryptable when threshold validators cooperate.
    ///
    /// # Arguments
    ///
    /// * `epoch_key` - The aggregate public key from the current epoch
    /// * `payload` - The transaction data to encrypt (e.g., "send 10 to alice")
    /// * `associated_data` - Metadata authenticated but not encrypted (e.g., nonce, fee)
    /// * `signing_key` - Client's Ed25519 key for authenticating the transaction
    ///
    /// # Security Considerations
    ///
    /// - **Payload**: Encrypted and hidden until threshold validators decrypt
    /// - **Associated Data**: NOT encrypted, visible to all nodes (use for public metadata only)
    /// - **Signature**: Proves the transaction was created by the holder of `signing_key`
    ///
    /// # Errors
    ///
    /// Returns `TrxError::Backend` if encryption or signing fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use trx::TrxMinion;
    /// use tess::PairingEngine;
    /// use ed25519_dalek::SigningKey;
    /// use rand::thread_rng;
    ///
    /// let mut rng = thread_rng();
    /// let client = TrxMinion::<PairingEngine>::new(&mut rng, 100, 67)?;
    /// let signing_key = SigningKey::generate(&mut rng);
    ///
    /// # let epoch_key = todo!();
    /// // Encrypt a payment transaction
    /// let tx = client.client().encrypt_transaction(
    ///     &epoch_key,
    ///     b"transfer(alice, 100)",  // Hidden payload
    ///     b"nonce:42,fee:1,gas:50000",  // Public metadata
    ///     &signing_key,
    /// )?;
    ///
    /// // Transaction is now ready for broadcast
    /// // Payload is encrypted, metadata is visible
    /// # Ok::<(), trx::TrxError>(())
    /// ```
    pub fn encrypt_transaction(
        &self,
        epoch_key: &ThresholdEncryptionPublicKey<B>,
        payload: &[u8],
        associated_data: &[u8],
        signing_key: &SigningKey,
    ) -> Result<EncryptedTransaction<B>, TrxError> {
        self.crypto
            .encrypt_transaction(epoch_key, payload, associated_data, signing_key)
    }

    /// Verify the signature and integrity of an encrypted transaction.
    ///
    /// This checks:
    /// 1. Ed25519 signature is valid for `BLAKE3(ciphertext || associated_data)`
    /// 2. Ciphertext structure is well-formed
    ///
    /// Nodes should call this before admitting transactions to the mempool.
    ///
    /// # Arguments
    ///
    /// * `encrypted_tx` - The transaction to verify
    ///
    /// # Errors
    ///
    /// Returns `TrxError::InvalidInput` if:
    /// - Signature verification fails
    /// - Ciphertext structure is malformed
    ///
    /// # Example
    ///
    /// ```no_run
    /// use trx::TrxMinion;
    /// use tess::PairingEngine;
    /// use rand::thread_rng;
    ///
    /// let mut rng = thread_rng();
    /// let client = TrxMinion::<PairingEngine>::new(&mut rng, 100, 67)?;
    ///
    /// # let encrypted_tx = todo!();
    /// // Verify transaction before adding to mempool
    /// match client.client().verify_ciphertext(&encrypted_tx) {
    ///     Ok(_) => {
    ///         println!("Transaction signature valid");
    ///         // Safe to add to mempool
    ///     }
    ///     Err(e) => {
    ///         println!("Invalid transaction: {}", e);
    ///         // Reject transaction
    ///     }
    /// }
    /// # Ok::<(), trx::TrxError>(())
    /// ```
    pub fn verify_ciphertext(
        &self,
        encrypted_tx: &EncryptedTransaction<B>,
    ) -> Result<(), TrxError> {
        TrxCrypto::<B>::verify_ciphertext(encrypted_tx)
    }
}
