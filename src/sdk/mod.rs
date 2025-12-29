//! # TrX SDK - Encrypted Mempool API
//!
//! This SDK provides a phase-based API for building encrypted mempool systems.
//!
//! ## Architecture Overview
//!
//! The encrypted mempool operates in six distinct phases:
//!
//! 1. **Setup Phase**: One-time system initialization and trusted setup generation
//! 2. **Validator Key Generation**: Non-interactive, silent key generation per validator
//! 3. **Client Phase**: Transaction encryption and submission
//! 4. **Mempool Phase**: Transaction admission, validation, and queuing
//! 5. **Proposer Phase**: Batch commitment and KZG proof generation
//! 6. **Decryption Phase**: Partial decryption, share aggregation, and plaintext recovery
//!
//! ## Quick Start
//!
//! ```no_run
//! use trx::{TrxClient, SetupPhase, ValidatorPhase, ClientPhase};
//! use tess::PairingEngine;
//! use rand::thread_rng;
//!
//! // Phase 1: Setup
//! let mut rng = thread_rng();
//! let client = TrxClient::<PairingEngine>::new(&mut rng, 100, 67)?;
//! let setup = client.setup().generate_trusted_setup(&mut rng, 1000, 100)?;
//!
//! // Phase 2: Validator key generation
//! let keypair = client.validator().keygen_single_validator(&mut rng, 0)?;
//!
//! // Phase 3: Client encryption (requires epoch key and signing key)
//! # let epoch_key = todo!();
//! # let signing_key = todo!();
//! let tx = client.client().encrypt_transaction(
//!     &epoch_key,
//!     b"transaction payload",
//!     b"metadata",
//!     &signing_key,
//! )?;
//! # Ok::<(), trx::TrxError>(())
//! ```

pub mod client;
pub mod decryption;
pub mod mempool;
pub mod proposer;
pub mod setup;
pub mod validator;

pub use client::ClientPhase;
pub use decryption::DecryptionPhase;
pub use mempool::MempoolPhase;
pub use proposer::ProposerPhase;
pub use setup::SetupPhase;
pub use validator::ValidatorPhase;

use crate::{TrxCrypto, TrxError};
use tess::{Fr, PairingBackend};

/// Main SDK entry point providing access to all phases of the encrypted mempool.
///
/// The `TrxClient` is generic over the pairing backend `B`, allowing you to use
/// different pairing-friendly curves. The default backend is `tess::PairingEngine`
/// which uses BLST for BLS12-381 pairing operations.
///
/// # Type Parameters
///
/// * `B` - The pairing backend implementing `PairingBackend<Scalar = Fr>`
///
/// # Example
///
/// ```no_run
/// use trx::TrxClient;
/// use tess::PairingEngine;
/// use rand::thread_rng;
///
/// let mut rng = thread_rng();
/// let client = TrxClient::<PairingEngine>::new(&mut rng, 100, 67)?;
/// # Ok::<(), trx::TrxError>(())
/// ```
pub struct TrxClient<B: PairingBackend<Scalar = Fr>> {
    crypto: TrxCrypto<B>,
}

impl<B: PairingBackend<Scalar = Fr>> TrxClient<B>
where
    B::G1: PartialEq,
{
    /// Creates a new TrX client with the specified network parameters.
    ///
    /// # Arguments
    ///
    /// * `rng` - Random number generator for key generation
    /// * `num_validators` - Total number of validators in the network
    /// * `threshold` - Minimum number of validators needed for decryption (must be < num_validators)
    ///
    /// # Errors
    ///
    /// Returns `TrxError::InvalidConfig` if threshold >= num_validators
    ///
    /// # Example
    ///
    /// ```no_run
    /// use trx::TrxClient;
    /// use tess::PairingEngine;
    /// use rand::thread_rng;
    ///
    /// let mut rng = thread_rng();
    /// // 100 validators, 67 needed for threshold (2/3 majority)
    /// let client = TrxClient::<PairingEngine>::new(&mut rng, 100, 67)?;
    /// # Ok::<(), trx::TrxError>(())
    /// ```
    pub fn new(
        rng: &mut impl rand_core::RngCore,
        num_validators: usize,
        threshold: usize,
    ) -> Result<Self, TrxError> {
        let crypto = TrxCrypto::new(rng, num_validators, threshold)?;
        Ok(Self { crypto })
    }

    /// Access the Setup Phase API for system initialization.
    ///
    /// # Returns
    ///
    /// A `SetupPhase` instance for generating and verifying trusted setup.
    pub fn setup(&self) -> SetupPhase<'_, B> {
        SetupPhase::new(&self.crypto)
    }

    /// Access the Validator Phase API for key generation and decryption.
    ///
    /// # Returns
    ///
    /// A `ValidatorPhase` instance for validator operations.
    pub fn validator(&self) -> ValidatorPhase<'_, B> {
        ValidatorPhase::new(&self.crypto)
    }

    /// Access the Client Phase API for transaction encryption.
    ///
    /// # Returns
    ///
    /// A `ClientPhase` instance for encrypting transactions.
    pub fn client(&self) -> ClientPhase<'_, B> {
        ClientPhase::new(&self.crypto)
    }

    /// Access the Mempool Phase API for transaction management.
    ///
    /// # Returns
    ///
    /// A `MempoolPhase` instance for mempool operations.
    pub fn mempool(&self) -> MempoolPhase<B> {
        MempoolPhase::new()
    }

    /// Access the Proposer Phase API for batch commitment.
    ///
    /// # Returns
    ///
    /// A `ProposerPhase` instance for creating batch commitments.
    pub fn proposer(&self) -> ProposerPhase<B> {
        ProposerPhase::new()
    }

    /// Access the Decryption Phase API for combining partial decryptions.
    ///
    /// # Returns
    ///
    /// A `DecryptionPhase` instance for final decryption.
    pub fn decryption(&self) -> DecryptionPhase<'_, B> {
        DecryptionPhase::new(&self.crypto)
    }

    /// Get a reference to the underlying crypto engine.
    ///
    /// This provides access to the raw `TrxCrypto` implementation for advanced use cases.
    pub fn crypto(&self) -> &TrxCrypto<B> {
        &self.crypto
    }
}
