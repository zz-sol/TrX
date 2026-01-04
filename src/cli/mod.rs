//! Command-line interface for TrX operations.
//!
//! This module provides a modular CLI structure that separates:
//! - Command definitions ([`commands`])
//! - Business logic implementation ([`handlers`])
//! - Output formatting and file I/O ([`output`])
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
