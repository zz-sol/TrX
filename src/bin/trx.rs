//! TrX CLI - Threshold encryption command-line interface.
//!
//! This is the main entry point for the TrX CLI tool.
//! All command logic is implemented in the `trx::cli` module.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    trx::cli::run()
}
