//! BLS signature schemes for validator consensus messages.
//!
//! This module provides BLS signature functions for validators:
//! - Vote signatures (consensus votes with optional partial decryptions)
//! - Share signatures (decryption share authenticity)
//! - Bound share signatures (commitment-bound decryption shares)
//!
//! **Note**: Ed25519 client signatures are handled internally by
//! `TransactionEncryption::encrypt_transaction()` in the `crypto::tess` module.

mod bls;

pub use bls::*;
