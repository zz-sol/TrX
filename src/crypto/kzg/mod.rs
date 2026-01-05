//! KZG polynomial commitment scheme.
//!
//! This module implements KZG commitments for batch integrity:
//!
//! - [`commitment`]: Core KZG commitment and evaluation proof logic
//! - [`precompute`]: Caching layer for expensive KZG operations

pub mod commitment;
pub mod precompute;

pub use commitment::verify_eval_proofs;
pub use precompute::PrecomputationEngine;
