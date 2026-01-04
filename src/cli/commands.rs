//! Command-line argument definitions using clap.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "trx")]
#[command(about = "TrX - Threshold Encryption CLI", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate epoch setup (global setup + randomized kappa contexts)
    Setup {
        /// Maximum batch size
        #[arg(long)]
        batch_size: usize,

        /// Maximum number of contexts
        #[arg(long)]
        contexts: usize,

        /// Output file (JSON)
        #[arg(long, short = 'o', default_value = "epoch_setup.json")]
        output: PathBuf,

        /// Epoch identifier
        #[arg(long, default_value = "1")]
        epoch_id: u64,

        /// Number of validators
        #[arg(long, default_value = "5")]
        num_validators: usize,

        /// Threshold
        #[arg(long, default_value = "3")]
        threshold: usize,
    },

    /// Generate validator keypair
    Keygen {
        /// Validator ID
        #[arg(long)]
        validator_id: u32,

        /// Output file (JSON)
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,

        /// Number of validators
        #[arg(long, default_value = "5")]
        num_validators: usize,

        /// Threshold
        #[arg(long, default_value = "3")]
        threshold: usize,
    },

    /// Generate validator BLS signing key
    KeygenSigning {
        /// Output file (JSON)
        #[arg(long, short = 'o', default_value = "validator_signing_key.json")]
        output: PathBuf,
    },

    /// Aggregate validator public keys into epoch key
    AggregateKeys {
        /// Input keypairs file (JSON array)
        #[arg(long)]
        keypairs: PathBuf,

        /// Threshold
        #[arg(long)]
        threshold: u32,

        /// Epoch setup file
        #[arg(long)]
        setup: PathBuf,

        /// Output file (JSON)
        #[arg(long, short = 'o', default_value = "epoch_keys.json")]
        output: PathBuf,

        /// Number of validators
        #[arg(long, default_value = "5")]
        num_validators: usize,
    },

    /// Encrypt a transaction
    Encrypt {
        /// Public key file
        #[arg(long)]
        public_key: PathBuf,

        /// Payload data
        #[arg(long)]
        payload: String,

        /// Metadata
        #[arg(long)]
        metadata: String,

        /// Output file (JSON)
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,

        /// Number of validators
        #[arg(long, default_value = "5")]
        num_validators: usize,

        /// Threshold
        #[arg(long, default_value = "3")]
        threshold: usize,
    },

    /// Compute batch commitment
    Commit {
        /// Batch file (JSON array of encrypted transactions)
        #[arg(long)]
        batch: PathBuf,

        /// Block height
        #[arg(long)]
        block_height: u64,

        /// Context index
        #[arg(long, default_value = "0")]
        context_index: u64,

        /// Epoch setup file
        #[arg(long)]
        setup: PathBuf,

        /// Output file (JSON)
        #[arg(long, short = 'o', default_value = "commitment.json")]
        output: PathBuf,

        /// Number of validators
        #[arg(long, default_value = "5")]
        num_validators: usize,

        /// Threshold
        #[arg(long, default_value = "3")]
        threshold: usize,
    },

    /// Generate signed partial decryption share
    PartialDecryptSigned {
        /// Secret key share file
        #[arg(long)]
        secret_share: PathBuf,

        /// Commitment file
        #[arg(long)]
        commitment: PathBuf,

        /// Encrypted transaction file
        #[arg(long)]
        encrypted_tx: PathBuf,

        /// Validator signing key file
        #[arg(long)]
        signing_key: PathBuf,

        /// Transaction index in batch
        #[arg(long)]
        tx_index: usize,

        /// Block height
        #[arg(long)]
        block_height: u64,

        /// Context index
        #[arg(long, default_value = "0")]
        context_index: u64,

        /// Output file (JSON)
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,

        /// Number of validators
        #[arg(long, default_value = "5")]
        num_validators: usize,

        /// Threshold
        #[arg(long, default_value = "3")]
        threshold: usize,
    },

    /// Decrypt batch using signed partial decryptions
    DecryptSigned {
        /// Batch file (JSON array)
        #[arg(long)]
        batch: PathBuf,

        /// Signed partial decryptions file (JSON array)
        #[arg(long)]
        signed_shares: PathBuf,

        /// Threshold
        #[arg(long)]
        threshold: u32,

        /// Epoch setup file
        #[arg(long)]
        setup: PathBuf,

        /// Public key file
        #[arg(long)]
        public_key: PathBuf,

        /// Commitment file
        #[arg(long)]
        commitment: PathBuf,

        /// Eval proofs file
        #[arg(long)]
        eval_proofs: PathBuf,

        /// Block height
        #[arg(long)]
        block_height: u64,

        /// Context index
        #[arg(long, default_value = "0")]
        context_index: u64,

        /// Number of validators
        #[arg(long, default_value = "5")]
        num_validators: usize,
    },

    /// Run full demo workflow
    Demo {
        /// Number of validators (must be power of 2)
        #[arg(long, default_value = "4")]
        num_validators: usize,

        /// Threshold
        #[arg(long, default_value = "2")]
        threshold: usize,

        /// Number of transactions
        #[arg(long, default_value = "3")]
        num_txs: usize,
    },
}
