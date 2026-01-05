//! Tess threshold encryption adapters.
//!
//! This module contains all components that adapt the Tess threshold encryption
//! library to TrX's encrypted mempool protocol:
//!
//! - [`engine`]: Main cryptographic engine and configuration
//! - [`setup`]: Global/epoch setup and key aggregation
//! - [`encryption`]: Client-side transaction encryption
//! - [`decryption`]: Threshold decryption and share verification

pub mod decryption;
pub mod encryption;
pub mod engine;
pub mod setup;

pub use decryption::CollectiveDecryption;
pub use encryption::TransactionEncryption;
pub use engine::TrxCrypto;
pub use setup::{EpochKeys, EpochSetup, GlobalSetup, KappaSetup, SetupManager, ValidatorKeyPair};
