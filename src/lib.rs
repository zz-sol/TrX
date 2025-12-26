//! TrX: Threshold Encryption Protocol for MEV Protection
//!
//! TrX is a complete Rust implementation of a threshold encryption system designed
//! for protecting blockchain transactions from MEV (Maximal Extractable Value) attacks.
//! Built on top of the [Tess](https://github.com/tess-threshold-encryption/tess) threshold
//! encryption library, it provides encrypted transaction processing with batch decryption.
//!
//! # Overview
//!
//! TrX enables secure transaction ordering by encrypting transactions before inclusion:
//!
//! 1. **Clients** encrypt transactions using a threshold public key
//! 2. **Validators** process encrypted transactions without seeing contents
//! 3. **Consensus** orders transactions while they remain encrypted
//! 4. **Decryption** happens after ordering using threshold shares
//!
//! This prevents validators from reordering, front-running, or censoring based on
//! transaction content, providing MEV protection.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                     TrX Protocol Stack                       │
//! ├──────────────────────────────────────────────────────────────┤
//! │  tx_enc          │ Transaction encryption & batch decryption │
//! │  commitment      │ KZG commitments & evaluation proofs       │
//! │  setup           │ Trusted setup & DKG                       │
//! │  signatures      │ Ed25519 (client) & BLS (validator) sigs  │
//! │  pre_computation │ Caching layer for KZG operations          │
//! │  mempool         │ Encrypted transaction queue               │
//! │  transactions    │ Network protocol messages                 │
//! └──────────────────────────────────────────────────────────────┘
//! │                     Tess Library                             │
//! │  Silent threshold encryption with pairing-based crypto       │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Core Components
//!
//! ## Cryptographic Engine
//!
//! - [`TrxCrypto`]: Main cryptographic engine implementing all protocol traits
//! - [`TransactionEncryption`]: Client-side encryption interface
//! - [`BatchDecryption`]: Consensus-layer batch decryption protocol
//! - [`SetupManager`]: Trusted setup and DKG operations
//!
//! ## Data Structures
//!
//! - [`EncryptedTransaction`]: Encrypted transaction with client signature
//! - [`BatchCommitment`]: KZG commitment over transaction batch
//! - [`EvalProof`]: KZG evaluation proof for batch integrity
//! - [`PartialDecryption`]: Validator's decryption share
//! - [`DecryptionContext`]: Context binding (block height, context index)
//!
//! ## Infrastructure
//!
//! - [`EncryptedMempool`]: Bounded FIFO queue for pending transactions
//! - [`PrecomputationEngine`]: Cache for expensive KZG computations
//! - [`TrxMessage`]: Network protocol message types
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use trx::*;
//! use ed25519_dalek::SigningKey;
//! use std::sync::Arc;
//! # use rand::thread_rng;
//! # fn main() -> Result<(), TrxError> {
//!
//! let mut rng = thread_rng();
//!
//! // 1. Initialize crypto engine (5 validators, 3 threshold)
//! let crypto = TrxCrypto::<tess::PairingEngine>::new(&mut rng, 5, 3)?;
//!
//! // 2. Generate trusted setup
//! let setup = crypto.generate_trusted_setup(&mut rng, 128, 1000)?;
//!
//! // 3. Run DKG for epoch keys
//! let validators = vec![0, 1, 2, 3, 4];
//! let epoch_keys = crypto.run_dkg(&mut rng, &validators, 3, Arc::new(setup))?;
//!
//! // 4. Client encrypts transaction
//! let signing_key = SigningKey::generate(&mut rng);
//! let encrypted_tx = crypto.encrypt_transaction(
//!     &epoch_keys.public_key,
//!     b"secret transaction data",
//!     b"public metadata",
//!     &signing_key,
//! )?;
//!
//! // 5. Validators decrypt batch
//! let batch = vec![encrypted_tx];
//! let context = DecryptionContext { block_height: 1, context_index: 0 };
//! let commitment = TrxCrypto::<tess::PairingEngine>::compute_digest(&batch, &context, &epoch_keys.setup)?;
//! // ... generate partial decryptions, then combine to decrypt
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! - **Threshold Encryption**: Configurable threshold parameters (t-of-n)
//! - **KZG Commitments**: Succinct batch commitments with constant-size proofs
//! - **Dual Signatures**: Ed25519 for clients, BLS for validators
//! - **Precomputation**: Performance optimization via caching
//! - **MEV Protection**: Transaction privacy until post-ordering decryption
//!
//! # Security Notes
//!
//! - Trusted setup must be generated using secure ceremony or trusted randomness
//! - Threshold parameters affect both security and availability
//! - Decryption contexts prevent replay across blocks/epochs
//! - Client signatures bind transactions to specific ciphertext+metadata
//!
//! # Module Organization
//!
//! - `core`: Protocol types and errors
//! - `crypto`: Tess/KZG/BLS/Ed25519 adapters
//! - `mempool`: Encrypted transaction mempool
//! - `network`: Network message types
//!
//! # References
//!
//! - [spec.md](../spec.md): Complete protocol specification
//! - [plan.md](../plan.md): Implementation roadmap

extern crate alloc;

mod core;
mod crypto;
mod mempool;
mod network;
mod utils;

pub use core::errors::*;
pub use core::types::*;
pub use crypto::kzg::*;
pub use crypto::pre_computation::*;
pub use crypto::signatures::*;
pub use crypto::trx_crypto::*;
pub use mempool::*;
pub use network::messages::*;
