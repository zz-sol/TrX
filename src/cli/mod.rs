//! Command-line interface for TrX operations.
//!
//! This module provides a modular CLI structure for testing and development,
//! with clear separation of concerns:
//! - [`commands`]: Command definitions using `clap` (argument parsing)
//! - `handlers`: Business logic for each command (SDK operations)
//! - [`output`]: File I/O utilities (JSON read/write)
//!
//! # Available Commands
//!
//! - `setup`: Generate global and epoch setup parameters
//! - `keygen-encryption`: Generate validator threshold key pairs
//! - `keygen-signing`: Generate BLS signing keys for validators
//! - `aggregate-keys`: Aggregate validator public keys into epoch key
//! - `encrypt`: Encrypt a transaction for inclusion in mempool
//! - `commit`: Compute batch commitment and evaluation proofs
//! - `partial-decrypt-signed`: Generate signed partial decryption share
//! - `decrypt-signed`: Combine signed shares and decrypt batch
//! - `demo`: Run end-to-end demo of the protocol
//!
//! # Usage
//!
//! The CLI can be invoked programmatically:
//!
//! ```rust,ignore
//! use trx::cli;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     cli::run()
//! }
//! ```
//!
//! Or from the command line:
//!
//! ```bash
//! cargo run --bin trx -- demo
//! cargo run --bin trx -- setup --batch-size 128 --contexts 1000 -o setup.json
//! ```
//!
//! # Design
//!
//! The CLI is structured for easy extension:
//!
//! 1. Add command definition to [`commands::Commands`]
//! 2. Implement handler logic in `handlers::execute()`
//! 3. Use [`output`] utilities for consistent JSON I/O
//!
//! All commands support JSON input/output for easy integration with scripts
//! and tooling.

pub mod commands;
mod handlers;
pub mod output;

use clap::Parser;
use commands::Cli;

/// Run the CLI application.
///
/// This is the main entry point for the TrX command-line interface.
/// It parses arguments and dispatches to the appropriate handler.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    handlers::execute(cli.command)
}
