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
//! │  setup           │ Global/epoch setup & silent key generation │
//! │  signatures      │ Ed25519 (client) & BLS (validator) sigs   │
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
//! - [`SetupManager`]: Global/epoch setup and silent key generation operations
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
//! # SDK Usage (Recommended)
//!
//! The [`sdk`] module provides a high-level, phase-based API for building encrypted
//! mempool systems:
//!
//! ```rust,no_run
//! use trx::TrxMinion;
//! use tess::PairingEngine;
//! use ed25519_dalek::SigningKey;
//! # use rand::thread_rng;
//! # fn main() -> Result<(), trx::TrxError> {
//!
//! let mut rng = thread_rng();
//!
//! // Create minion helper (5 validators, 3 threshold)
//! let minion = TrxMinion::<PairingEngine>::new(&mut rng, 5, 3)?;
//!
//! // Phase 1: Setup
//! let global_setup = minion.setup().generate_global_setup(&mut rng, 128)?;
//! let setup = minion
//!     .setup()
//!     .generate_epoch_setup(&mut rng, 1, 1000, global_setup.clone())?;
//!
//! // Phase 2: Silent key generation
//! let validators: Vec<u32> = (0..5).collect();
//! let validator_keypairs: Vec<_> = validators
//!     .iter()
//!     .map(|&id| minion.validator().keygen_single_validator(&mut rng, id))
//!     .collect::<Result<Vec<_>, _>>()?;
//! let public_keys: Vec<_> = validator_keypairs
//!     .iter()
//!     .map(|kp| kp.public_key.clone())
//!     .collect();
//! let epoch_keys = minion
//!     .setup()
//!     .aggregate_epoch_keys(&public_keys, 3, setup.clone())?;
//!
//! // Phase 3: Client encryption
//! let signing_key = SigningKey::generate(&mut rng);
//! let encrypted_tx = minion.client().encrypt_transaction(
//!     &epoch_keys.public_key,
//!     b"secret transaction data",
//!     b"public metadata",
//!     &signing_key,
//! )?;
//!
//! // Phase 4: Mempool
//! let mut mempool = minion.mempool().create(1000);
//! minion.mempool().add_transaction(&mut mempool, encrypted_tx)?;
//!
//! // See examples/sdk_example.rs for complete workflow
//! # Ok(())
//! # }
//! ```
//!
//! # Low-Level API
//!
//! For advanced use cases, you can use the trait-based API directly:
//!
//! ```rust,no_run
//! use trx::*;
//! use ed25519_dalek::SigningKey;
//! # use rand::thread_rng;
//! # fn main() -> Result<(), TrxError> {
//!
//! let mut rng = thread_rng();
//!
//! // 1. Initialize crypto engine (5 validators, 3 threshold)
//! let crypto = TrxCrypto::<tess::PairingEngine>::new(&mut rng, 5, 3)?;
//!
//! // 2. Generate setup
//! let global_setup = crypto.generate_global_setup(&mut rng, 128)?;
//! let setup = crypto.generate_epoch_setup(&mut rng, 1, 1000, global_setup.clone())?;
//!
//! // 3. Silent setup: each validator independently generates their own key
//! let validators: Vec<u32> = (0..5).collect();
//! let validator_keypairs: Vec<_> = validators
//!     .iter()
//!     .map(|&id| crypto.keygen_single_validator(&mut rng, id))
//!     .collect::<Result<Vec<_>, _>>()?;
//! let public_keys: Vec<_> = validator_keypairs
//!     .iter()
//!     .map(|kp| kp.public_key.clone())
//!     .collect();
//! let epoch_keys = crypto.aggregate_epoch_keys(&public_keys, 3, setup.clone())?;
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
//! let commitment =
//!     TrxCrypto::<tess::PairingEngine>::compute_digest(&batch, &context, &epoch_keys.epoch_setup)?;
//! // ... generate partial decryptions, then combine to decrypt
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! - **Threshold Encryption**: Configurable threshold parameters (t-of-n)
//! - **Silent Setup**: Non-interactive key generation via Tess protocol
//! - **KZG Commitments**: Succinct batch commitments with constant-size proofs
//! - **Dual Signatures**: Ed25519 for clients, BLS for validators
//! - **Precomputation**: Performance optimization via caching
//! - **MEV Protection**: Transaction privacy until post-ordering decryption
//! - **JSON Serialization**: Full serde support for all cryptographic types
//! - **CLI Tool**: Command-line interface for testing and development
//!
//! # Security Notes
//!
//! - Setup must be generated using secure ceremony or trusted randomness
//! - Threshold parameters affect both security and availability
//! - Decryption contexts prevent replay across blocks/epochs
//! - Client signatures bind transactions to specific ciphertext+metadata
//!
//! # Serialization
//!
//! All TrX and Tess types support JSON serialization via serde:
//!
//! ```rust,no_run
//! # use trx::*;
//! # use tess::PairingEngine;
//! # fn example(encrypted_tx: EncryptedTransaction<PairingEngine>) -> Result<(), Box<dyn std::error::Error>> {
//! use serde_json;
//!
//! // Serialize to JSON
//! let json = serde_json::to_string(&encrypted_tx)?;
//!
//! // Deserialize from JSON
//! let tx: EncryptedTransaction<PairingEngine> = serde_json::from_str(&json)?;
//! # Ok(())
//! # }
//! ```
//!
//! This enables persistent storage, network transmission, and easy integration with
//! JSON-based APIs.
//!
//! # CLI Tool
//!
//! TrX includes a command-line interface for testing and development. Build and run:
//!
//! ```bash
//! cargo build --release --bin trx
//! ./target/release/trx demo
//! ```
//!
//! Available commands: `setup`, `keygen`, `aggregate-keys`, `encrypt`, `commit`,
//! `partial-decrypt`, `decrypt`, and `demo`. All commands support JSON input/output.
//!
//! # Module Organization
//!
//! - `core`: Protocol types and errors
//! - `crypto`: Tess/KZG/BLS/Ed25519 adapters
//! - `sdk`: High-level phase-based API
//! - `mempool`: Encrypted transaction mempool
//! - `network`: Network message types
//!
//! # References
//!
//! - [TrX Paper](https://eprint.iacr.org/2025/2032): Encrypted Mempools in High Performance BFT
//! - [Tess Paper](https://eprint.iacr.org/2024/263): Threshold Encryption with Silent Setup

extern crate alloc;

pub mod cli;
mod core;
mod crypto;
mod mempool;
mod network;
mod sdk;
mod serde;
mod utils;

// Re-export only SDK-related types
pub use core::errors::TrxError;
pub use core::types::{
    BatchCommitment, BatchContext, BatchProofs, DecryptionContext, DecryptionResult,
    EncryptedTransaction, EvalProof, PartialDecryption, ThresholdEncryptionPublicKey,
    ThresholdEncryptionSecretKeyShare, ValidatorId,
};
pub use crypto::kzg::verify_eval_proofs;
pub use crypto::pre_computation::PrecomputationEngine;
pub use crypto::{
    BatchDecryption, EpochKeys, EpochSetup, GlobalSetup, SetupManager, TransactionEncryption,
    TrxCrypto, ValidatorKeyPair,
};
pub use mempool::EncryptedMempool;
pub use network::messages::TrxMessage;
pub use sdk::{
    ClientPhase, DecryptionPhase, MempoolPhase, ProposerPhase, SetupPhase, TrxMinion,
    ValidatorPhase,
};

// Signature utilities for consensus messages
pub use crypto::signatures::{
    sign_validator_share, sign_validator_share_bound, sign_validator_vote, validator_share_message,
    validator_share_message_bound, validator_verify_key, validator_vote_message,
    verify_validator_share, verify_validator_share_bound, verify_validator_vote,
    ValidatorSignature, ValidatorSigningKey, ValidatorVerifyKey,
};
