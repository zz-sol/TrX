//! Cryptographic primitives and protocol implementations.
//!
//! This module contains all cryptographic components of TrX, including threshold
//! encryption adapters, KZG commitments, signature schemes, and performance
//! optimizations.
//!
//! # Submodules
//!
//! - [`engine`]: Cryptographic engine configuration and key generation helpers
//! - [`setup`]: Setup types and key aggregation logic
//! - [`encryption`]: Client-side transaction encryption and verification
//! - [`decryption`]: Batch decryption operations for consensus processing
//! - [`kzg`]: KZG polynomial commitments and evaluation proofs
//! - [`signatures`]: Ed25519 (client) and BLS (validator) signature helpers
//! - [`pre_computation`]: Caching layer for expensive KZG operations
//!
//! # Cryptographic Stack
//!
//! ```text
//! TrX Crypto Layer
//! ├── Threshold Encryption (Tess)
//! │   ├── Silent setup protocol (non-interactive key generation)
//! │   ├── Non-interactive public key aggregation
//! │   └── Threshold decryption
//! ├── KZG Commitments
//! │   ├── Batch polynomial commitment
//! │   ├── Evaluation proof generation
//! │   └── Proof verification (pairing check)
//! └── Signatures
//!     ├── Ed25519 (client transaction authenticity)
//!     └── BLS (validator consensus messages)
//! ```

pub mod decryption;
pub mod encryption;
pub mod engine;
pub mod kzg;
pub mod pre_computation;
mod serde_impl;
pub mod setup;
pub mod signatures;

pub use decryption::BatchDecryption;
pub use encryption::TransactionEncryption;
pub use engine::TrxCrypto;
pub use setup::{EpochKeys, EpochSetup, GlobalSetup, KappaSetup, SetupManager, ValidatorKeyPair};
