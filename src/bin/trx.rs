//! TrX CLI - Command-line interface for threshold encryption operations
//!
//! Usage:
//!   trx setup --batch-size <N> --contexts <N> [--output <file>]
//!   trx keygen --validator-id <ID> [--output <file>]
//!   trx aggregate-keys --keypairs <file> --threshold <T> --setup <file> [--output <file>]
//!   trx encrypt --public-key <file> --payload <data> --metadata <data> [--output <file>]
//!   trx decrypt --batch <file> --shares <file> --threshold <T> --setup <file> --public-key <file>

use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::thread_rng;
use tess::PairingEngine;
use trx::{
    BatchCommitment, BatchContext, DecryptionContext, EncryptedTransaction, EvalProof,
    EpochSetup, PartialDecryption, PublicKey, SecretKeyShare, TrxMinion, ValidatorKeyPair,
};

type Backend = PairingEngine;

#[derive(Parser)]
#[command(name = "trx")]
#[command(about = "TrX - Threshold Encryption CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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

    /// Generate partial decryption share
    PartialDecrypt {
        /// Secret key share file
        #[arg(long)]
        secret_share: PathBuf,

        /// Commitment file
        #[arg(long)]
        commitment: PathBuf,

        /// Transaction ciphertext file
        #[arg(long)]
        ciphertext: PathBuf,

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

    /// Decrypt batch using partial decryptions
    Decrypt {
        /// Batch file (JSON array)
        #[arg(long)]
        batch: PathBuf,

        /// Partial decryptions file (JSON array)
        #[arg(long)]
        shares: PathBuf,

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

        /// Evaluation proofs file
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Setup {
            batch_size,
            contexts,
            output,
            epoch_id,
            num_validators,
            threshold,
        } => {
            println!("Generating epoch setup...");
            let mut rng = thread_rng();
            let client = TrxMinion::<Backend>::new(&mut rng, num_validators, threshold)?;
            let global_setup = client.setup().generate_global_setup(&mut rng, batch_size)?;
            let setup = client.setup().generate_epoch_setup(
                &mut rng,
                epoch_id,
                contexts,
                global_setup.clone(),
            )?;

            let json = serde_json::to_string_pretty(&*setup)?;
            fs::write(&output, json)?;
            println!("✓ Epoch setup written to {}", output.display());
        }

        Commands::Keygen {
            validator_id,
            output,
            num_validators,
            threshold,
        } => {
            println!("Generating keypair for validator {}...", validator_id);
            let mut rng = thread_rng();
            let client = TrxMinion::<Backend>::new(&mut rng, num_validators, threshold)?;
            let keypair = client
                .validator()
                .keygen_single_validator(&mut rng, validator_id)?;

            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&keypair)?;
                fs::write(&output_path, json)?;
                println!("✓ Keypair written to {}", output_path.display());
            } else {
                let json = serde_json::to_string_pretty(&keypair)?;
                println!("{}", json);
            }
        }

        Commands::AggregateKeys {
            keypairs,
            threshold,
            setup,
            output,
            num_validators,
        } => {
            println!("Aggregating validator public keys...");
            let mut rng = thread_rng();
            let client = TrxMinion::<Backend>::new(&mut rng, num_validators, threshold as usize)?;

            let keypairs_json = fs::read_to_string(&keypairs)?;
            let validator_keypairs: Vec<ValidatorKeyPair<Backend>> =
                serde_json::from_str(&keypairs_json)?;

            let setup_json = fs::read_to_string(&setup)?;
            let epoch_setup: EpochSetup<Backend> = serde_json::from_str(&setup_json)?;

            // Extract only public keys for aggregation
            let public_keys = validator_keypairs
                .into_iter()
                .map(|kp| kp.public_key)
                .collect();

            let epoch_keys = client.setup().aggregate_epoch_keys(
                public_keys,
                threshold,
                std::sync::Arc::new(epoch_setup),
            )?;

            let json = serde_json::to_string_pretty(&epoch_keys)?;
            fs::write(&output, json)?;
            println!("✓ Epoch keys written to {}", output.display());
        }

        Commands::Encrypt {
            public_key,
            payload,
            metadata,
            output,
            num_validators,
            threshold,
        } => {
            println!("Encrypting transaction...");
            let mut rng = thread_rng();
            let client = TrxMinion::<Backend>::new(&mut rng, num_validators, threshold)?;

            let pk_json = fs::read_to_string(&public_key)?;
            let pk: PublicKey<Backend> = serde_json::from_str(&pk_json)?;

            let signing_key = SigningKey::generate(&mut rng);
            let encrypted_tx = client.client().encrypt_transaction(
                &pk,
                payload.as_bytes(),
                metadata.as_bytes(),
                &signing_key,
            )?;

            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&encrypted_tx)?;
                fs::write(&output_path, json)?;
                println!(
                    "✓ Encrypted transaction written to {}",
                    output_path.display()
                );
            } else {
                let json = serde_json::to_string_pretty(&encrypted_tx)?;
                println!("{}", json);
            }
        }

        Commands::Commit {
            batch,
            block_height,
            context_index,
            setup,
            output,
            num_validators,
            threshold,
        } => {
            println!("Computing batch commitment...");
            let mut rng = thread_rng();
            let client = TrxMinion::<Backend>::new(&mut rng, num_validators, threshold)?;

            let batch_json = fs::read_to_string(&batch)?;
            let batch_txs: Vec<EncryptedTransaction<Backend>> = serde_json::from_str(&batch_json)?;

            let setup_json = fs::read_to_string(&setup)?;
            let epoch_setup: EpochSetup<Backend> = serde_json::from_str(&setup_json)?;

            let context = DecryptionContext {
                block_height,
                context_index: context_index as u32,
            };

            let commitment =
                client
                    .proposer()
                    .compute_digest(&batch_txs, &context, &epoch_setup)?;

            let json = serde_json::to_string_pretty(&commitment)?;
            fs::write(&output, json)?;
            println!("✓ Commitment written to {}", output.display());
        }

        Commands::PartialDecrypt {
            secret_share,
            commitment,
            ciphertext,
            tx_index,
            block_height,
            context_index,
            output,
            num_validators,
            threshold,
        } => {
            println!("Generating partial decryption...");
            let mut rng = thread_rng();
            let client = TrxMinion::<Backend>::new(&mut rng, num_validators, threshold)?;

            let share_json = fs::read_to_string(&secret_share)?;
            let secret: SecretKeyShare<Backend> = serde_json::from_str(&share_json)?;

            let comm_json = fs::read_to_string(&commitment)?;
            let comm: BatchCommitment<Backend> = serde_json::from_str(&comm_json)?;

            let ct_json = fs::read_to_string(&ciphertext)?;
            let ct: tess::Ciphertext<Backend> = serde_json::from_str(&ct_json)?;

            let context = DecryptionContext {
                block_height,
                context_index: context_index as u32,
            };

            let pd = client
                .validator()
                .generate_partial_decryption(&secret, &comm, &context, tx_index, &ct)?;

            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&pd)?;
                fs::write(&output_path, json)?;
                println!("✓ Partial decryption written to {}", output_path.display());
            } else {
                let json = serde_json::to_string_pretty(&pd)?;
                println!("{}", json);
            }
        }

        Commands::Decrypt {
            batch,
            shares,
            threshold,
            setup,
            public_key,
            commitment,
            eval_proofs,
            block_height,
            context_index,
            num_validators,
        } => {
            println!("Decrypting batch...");
            let mut rng = thread_rng();
            let client = TrxMinion::<Backend>::new(&mut rng, num_validators, threshold as usize)?;

            let batch_json = fs::read_to_string(&batch)?;
            let batch_txs: Vec<EncryptedTransaction<Backend>> = serde_json::from_str(&batch_json)?;

            let shares_json = fs::read_to_string(&shares)?;
            let partial_decryptions: Vec<PartialDecryption<Backend>> =
                serde_json::from_str(&shares_json)?;

            let setup_json = fs::read_to_string(&setup)?;
            let epoch_setup: EpochSetup<Backend> = serde_json::from_str(&setup_json)?;

            let pk_json = fs::read_to_string(&public_key)?;
            let pk: PublicKey<Backend> = serde_json::from_str(&pk_json)?;

            let comm_json = fs::read_to_string(&commitment)?;
            let comm: BatchCommitment<Backend> = serde_json::from_str(&comm_json)?;

            let proofs_json = fs::read_to_string(&eval_proofs)?;
            let proofs: Vec<EvalProof<Backend>> = serde_json::from_str(&proofs_json)?;

            let context = DecryptionContext {
                block_height,
                context_index: context_index as u32,
            };

            let batch_ctx = BatchContext {
                batch: &batch_txs,
                context: &context,
                commitment: &comm,
                eval_proofs: &proofs,
            };

            let results = client.decryption().combine_and_decrypt(
                partial_decryptions,
                batch_ctx,
                threshold,
                &epoch_setup,
                &pk,
            )?;

            println!("\n=== Decryption Results ===\n");
            for (i, result) in results.iter().enumerate() {
                if let Some(plaintext) = &result.plaintext {
                    println!("Transaction {}: SUCCESS", i);
                    println!("  Plaintext: {}", String::from_utf8_lossy(plaintext));
                } else {
                    println!("Transaction {}: FAILED", i);
                }
            }
        }

        Commands::Demo {
            num_validators,
            threshold,
            num_txs,
        } => {
            run_demo(num_validators, threshold, num_txs)?;
        }
    }

    Ok(())
}

fn run_demo(
    num_validators: usize,
    threshold: usize,
    num_txs: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    use rand::{rngs::StdRng, SeedableRng};
    use std::collections::HashMap;

    println!("========================================");
    println!("      TrX Encrypted Mempool Demo");
    println!("========================================\n");

    let mut rng = thread_rng();

    // Phase 1: Setup
    println!("Phase 1: System Setup");
    let client = TrxMinion::<Backend>::new(&mut rng, num_validators, threshold)?;
    let global_setup = client.setup().generate_global_setup(&mut rng, 10)?;
    let setup = client
        .setup()
        .generate_epoch_setup(&mut rng, 1, 100, global_setup.clone())?;
    client.setup().verify_epoch_setup(&setup)?;
    println!("  ✓ Setup complete\n");

    // Phase 2: Validator keygen
    println!("Phase 2: Validator Key Generation");
    let mut rngs: Vec<StdRng> = (0..num_validators)
        .map(|i| StdRng::seed_from_u64(i as u64))
        .collect();
    let validator_keypairs: Vec<_> = (0..num_validators)
        .zip(rngs.iter_mut())
        .map(|(id, rng)| client.validator().keygen_single_validator(rng, id as u32))
        .collect::<Result<Vec<_>, _>>()?;

    // Extract only public keys for aggregation
    let public_keys = validator_keypairs
        .iter()
        .map(|kp| kp.public_key.clone())
        .collect();

    let epoch_keys =
        client
            .setup()
            .aggregate_epoch_keys(public_keys, threshold as u32, setup.clone())?;
    println!("  ✓ Keys aggregated\n");

    let validator_secret_shares: Vec<_> = validator_keypairs
        .iter()
        .map(|kp| kp.secret_share.clone())
        .collect();

    let public_keys: HashMap<u32, _> = (0..num_validators as u32)
        .map(|id| (id, epoch_keys.public_key.clone()))
        .collect();

    // Phase 3: Client encryption
    println!("Phase 3: Transaction Encryption");
    let mut encrypted_txs = Vec::new();
    for i in 0..num_txs {
        let signing_key = SigningKey::generate(&mut rng);
        let payload = format!("Transaction {} payload", i);
        let encrypted_tx = client.client().encrypt_transaction(
            &epoch_keys.public_key,
            payload.as_bytes(),
            b"metadata",
            &signing_key,
        )?;
        encrypted_txs.push(encrypted_tx);
    }
    println!("  ✓ {} transactions encrypted\n", num_txs);

    // Phase 4: Mempool
    println!("Phase 4: Mempool Management");
    let mut mempool = client.mempool().create(1000);
    for tx in &encrypted_txs {
        client.mempool().add_transaction(&mut mempool, tx.clone())?;
    }
    println!(
        "  ✓ {} transactions in mempool\n",
        client.mempool().size(&mempool)
    );

    // Phase 5: Proposer
    println!("Phase 5: Batch Commitment");
    let batch = client.mempool().get_batch(&mut mempool, 10);
    let context = DecryptionContext {
        block_height: 100,
        context_index: 0,
    };
    let commitment = client.proposer().compute_digest(&batch, &context, &setup)?;
    let eval_proofs = client
        .proposer()
        .compute_eval_proofs(&batch, &context, &setup)?;
    client
        .proposer()
        .verify_eval_proofs(&setup, &commitment, &batch, &context, &eval_proofs)?;
    println!("  ✓ Batch committed with proofs\n");

    // Phase 6: Decryption
    println!("Phase 6: Threshold Decryption");
    let mut partial_decryptions = Vec::new();
    for (tx_index, tx) in batch.iter().enumerate() {
        for secret_share in validator_secret_shares.iter().take(threshold + 1) {
            let pd = client.validator().generate_partial_decryption(
                secret_share,
                &commitment,
                &context,
                tx_index,
                &tx.ciphertext,
            )?;
            client
                .validator()
                .verify_partial_decryption(&pd, &commitment, &public_keys)?;
            partial_decryptions.push(pd);
        }
    }

    let batch_ctx = BatchContext {
        batch: &batch,
        context: &context,
        commitment: &commitment,
        eval_proofs: &eval_proofs,
    };

    let results = client.decryption().combine_and_decrypt(
        partial_decryptions,
        batch_ctx,
        threshold as u32,
        &setup,
        &epoch_keys.public_key,
    )?;

    println!("\n=== Results ===");
    let mut successful = 0;
    for (i, result) in results.iter().enumerate() {
        if let Some(plaintext) = &result.plaintext {
            println!(
                "  Transaction {}: {}",
                i,
                String::from_utf8_lossy(plaintext)
            );
            successful += 1;
        }
    }
    println!(
        "\n  ✓ {}/{} transactions decrypted successfully",
        successful,
        batch.len()
    );

    Ok(())
}
