//! TrX protocol scaffolding built on top of Tess.
//!
//! This module wires the TrX spec to the existing Tess threshold encryption
//! implementation. It focuses on a minimal, compiling API surface with:
//! - Core data types matching the spec
//! - Setup/DKG wrappers
//! - Encryption and batch decryption adapters
//! - Precomputation cache and mempool scaffolding
//!
//! Notes:
//! - Batch digest and evaluation proofs use KZG commitments and openings.
//! - The TrxCrypto instance owns a single Tess Params (SRS + Lagrange powers)
//!   so encryption and key aggregation stay consistent.

extern crate alloc;

mod commitment;
mod constants;
mod errors;
mod keys;
mod mempool;
mod pre_computation;
mod setup;
mod signatures;
mod transactions;
mod tx_enc;
mod utils;

pub use commitment::*;
pub use constants::*;
pub use errors::*;
pub use keys::*;
pub use mempool::*;
pub use pre_computation::*;
pub use setup::*;
pub use signatures::*;
pub use transactions::*;
pub use tx_enc::*;

#[cfg(test)]
mod tests;
