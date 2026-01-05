//! Cryptographic primitives and protocol implementations.
//!
//! This module contains all cryptographic components of TrX, organized by primitive type:
//!
//! # Submodules
//!
//! - [`tess`]: Threshold encryption adapters (engine, setup, encryption, decryption)
//! - [`kzg`]: KZG polynomial commitments and precomputation
//! - [`signatures`]: Ed25519 (client) and BLS (validator) signatures
//!
//! # Cryptographic Stack
//!
//! ```text
//! TrX Crypto Layer
//! ├── Threshold Encryption (tess/)
//! │   ├── Silent setup protocol (non-interactive key generation)
//! │   ├── Non-interactive public key aggregation
//! │   └── Threshold decryption
//! ├── KZG Commitments (kzg/)
//! │   ├── Batch polynomial commitment
//! │   ├── Evaluation proof generation
//! │   └── Proof verification (pairing check)
//! └── Signatures (signatures/)
//!     ├── Ed25519 (client transaction authenticity)
//!     └── BLS (validator consensus messages)
//! ```

pub mod errors;
pub mod kzg;
pub mod signatures;
pub mod tess;
pub mod types;
