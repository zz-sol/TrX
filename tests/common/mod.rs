//! Shared test infrastructure for TrX integration tests.
//!
//! This module provides reusable components for writing integration tests,
//! reducing duplication and ensuring consistency across test scenarios.
//!
//! # Components
//!
//! ## Fixtures ([`fixtures`])
//!
//! - [`TrxTestFixture`]: Complete test setup with validators, keys, and crypto engine
//! - [`generate_epoch_keys()`]: Helper for silent key generation protocol
//! - [`generate_epoch_setup()`]: Helper for epoch setup creation
//!
//! The fixture encapsulates all components needed for testing (default: 4 validators, threshold 2):
//! - Cryptographic engine (TrxCrypto)
//! - Epoch setup and keys
//! - Validator key shares
//! - Client signing key
//!
//! ## Helpers ([`helpers`])
//!
//! - [`assert_decrypted_eq()`]: Assert decryption result matches expected plaintext
//! - [`create_batch_context()`]: Construct batch context from components
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use common::*;
//!
//! #[test]
//! fn test_encryption_decryption() {
//!     let fixture = TrxTestFixture::new();
//!
//!     let encrypted = fixture.encrypt(b"payload", b"aad");
//!     let context = TrxTestFixture::default_context();
//!     let commitment = fixture.compute_commitment(&[encrypted], &context);
//!
//!     // ... test logic ...
//! }
//! ```
//!
//! # Design Goals
//!
//! - **Reduce boilerplate**: Standard setup in ~2 lines instead of ~50
//! - **Consistency**: All tests use same default parameters
//! - **Maintainability**: Changes to setup logic in one place
//! - **Clarity**: Tests focus on what's being tested, not setup

pub mod fixtures;
pub mod helpers;

pub use fixtures::*;
pub use helpers::*;
