//! Cryptographic primitives and protocol implementations.
//!
//! This module contains all cryptographic components of TrX, including threshold
//! encryption adapters, KZG commitments, signature schemes, and performance
//! optimizations.
//!
//! # Submodules
//!
//! - [`trx_crypto`]: Main cryptographic engine and protocol trait implementations
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

pub mod kzg;
pub mod pre_computation;
pub mod signatures;
pub mod trx_crypto;
