//! # TrX Complete Example: Threshold-Encrypted Transaction Flow
//!
//! This example demonstrates the full lifecycle of a confidential transaction in TrX:
//! 1. Trusted setup and validator DKG
//! 2. Client transaction encryption with Ed25519 signature
//! 3. Mempool validation and queueing
//! 4. Batch commitment with KZG proofs
//! 5. Threshold decryption by validators
//! 6. Share aggregation and final decryption
//!
//! ## Network Configuration
//! - 2048 validators with threshold of 1400 (68% required for decryption)
//! - Batch size: 32 transactions
//! - Supports 16 concurrent decryption contexts
//!
//! Run with: `cargo run --example toy_example`

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand::thread_rng;
use tess::PairingEngine;
use tracing_subscriber::fmt;
use trx::{
    BatchContext, BatchDecryption, DecryptionContext, EncryptedMempool, SetupManager,
    TransactionEncryption, TrxCrypto, ValidatorId,
};

/// Number of validators in the network
const NUM_VALIDATORS: usize = 2048;

/// Threshold number of validators required for decryption (must be < NUM_VALIDATORS)
const THRESHOLD: usize = 1400;

/// Maximum number of encrypted transactions per batch/block
/// Also determines the SRS size for KZG commitments
const MAX_BATCH: usize = 32;

/// Number of pre-generated Kappa contexts in the trusted setup
/// Determines how many concurrent batches/contexts can be supported before re-setup
const MAX_CONTEXTS: usize = 16;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging to track the flow
    fmt()
        .with_max_level(tracing::Level::INFO)
        .with_span_events(fmt::format::FmtSpan::ENTER | fmt::format::FmtSpan::CLOSE)
        .init();

    let mut rng = thread_rng();

    println!("=== TrX Threshold-Encrypted Transaction Example ===\n");

    // ========================================================================
    // PHASE 1: System Bootstrapping (One-time Setup)
    // ========================================================================
    println!("Phase 1: Bootstrapping...");

    // Initialize the cryptographic system with network parameters
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, NUM_VALIDATORS, THRESHOLD)?;
    println!(
        "  ✓ Initialized TrxCrypto for {} validators (threshold: {})",
        NUM_VALIDATORS, THRESHOLD
    );

    // Generate trusted setup: SRS for KZG and kappa contexts for threshold encryption
    let setup = Arc::new(trx.generate_trusted_setup(&mut rng, MAX_BATCH, MAX_CONTEXTS)?);
    println!(
        "  ✓ Generated trusted setup (max batch: {}, contexts: {})",
        MAX_BATCH, MAX_CONTEXTS
    );

    // Run distributed key generation to create validator shares and aggregate public key
    let validators: Vec<ValidatorId> = (0..NUM_VALIDATORS as u32).collect();
    let epoch = trx.run_dkg(&mut rng, &validators, THRESHOLD as u32, setup.clone())?;
    println!(
        "  ✓ Completed DKG for epoch - {} validator shares generated\n",
        epoch.validator_shares.len()
    );

    // ========================================================================
    // PHASE 2: Client Transaction Submission
    // ========================================================================
    println!("Phase 2: Client submits encrypted transaction...");

    // Client generates a signing key and encrypts their transaction
    // Payload is encrypted with threshold encryption, then signed with Ed25519
    let client_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let tx = trx.encrypt_transaction(
        &epoch.public_key,
        b"pay 10 to bob", // Confidential payload
        b"nonce:123",     // Associated data (authenticated but not encrypted)
        &client_key,      // Client's Ed25519 signing key
    )?;
    println!("  ✓ Transaction encrypted and signed by client");
    println!("    Payload: \"pay 10 to bob\" (encrypted)");
    println!("    Associated data: \"nonce:123\" (authenticated)\n");

    // ========================================================================
    // PHASE 3: Mempool Admission
    // ========================================================================
    println!("Phase 3: Mempool validates and queues transaction...");

    // Node verifies the Ed25519 signature and adds to mempool
    let mut mempool = EncryptedMempool::<PairingEngine>::new(MAX_BATCH);
    mempool.add_encrypted_tx(tx)?;
    println!("  ✓ Transaction verified and added to mempool\n");

    // ========================================================================
    // PHASE 4: Block Proposal and Batch Commitment
    // ========================================================================
    println!("Phase 4: Block proposer creates batch with KZG commitment...");

    // Proposer pulls transactions from mempool to form a batch
    let batch = mempool.get_batch(MAX_BATCH);
    println!(
        "  ✓ Retrieved batch of {} transaction(s) from mempool",
        batch.len()
    );

    // Define the decryption context (identifies this specific batch)
    let context = DecryptionContext {
        block_height: 100, // Current block height
        context_index: 0,  // Index within the block (if multiple batches per block)
    };

    // Compute KZG commitment to the batch polynomial
    let commitment = TrxCrypto::<PairingEngine>::compute_digest(&batch, &context, &setup)?;
    println!("  ✓ Computed KZG commitment to batch");

    // Generate KZG evaluation proofs for each transaction in the batch
    let eval_proofs = TrxCrypto::<PairingEngine>::compute_eval_proofs(&batch, &context, &setup)?;
    println!(
        "  ✓ Generated {} KZG evaluation proofs\n",
        eval_proofs.len()
    );

    // ========================================================================
    // PHASE 5: Validators Generate Partial Decryptions
    // ========================================================================
    println!("Phase 5: Validators create decryption shares...");

    // Each validator uses their secret share to create a partial decryption
    // We need at least THRESHOLD + 1 validators to participate
    let mut partials = Vec::new();
    for (tx_index, tx) in batch.iter().enumerate() {
        // Collect shares from THRESHOLD + 1 validators (minimum required)
        for validator_id in 0..(THRESHOLD + 1) {
            let share = epoch
                .validator_shares
                .get(&(validator_id as u32))
                .expect("share exists");

            // Each validator generates a partial decryption for this transaction
            let pd = TrxCrypto::<PairingEngine>::generate_partial_decryption(
                share,
                &commitment,
                &context,
                tx_index,
                &tx.ciphertext,
            )?;
            partials.push(pd);
        }
    }
    println!(
        "  ✓ Collected {} partial decryption shares from validators",
        partials.len()
    );
    println!(
        "    ({} shares per transaction from {} validators)\n",
        THRESHOLD + 1,
        THRESHOLD + 1
    );

    // ========================================================================
    // PHASE 6: Share Aggregation and Final Decryption
    // ========================================================================
    println!("Phase 6: Combining shares and decrypting batch...");

    // Bundle all context needed for decryption verification
    let batch_ctx = BatchContext {
        batch: &batch,
        context: &context,
        commitment: &commitment,
        eval_proofs: &eval_proofs,
    };

    // Combine partial decryptions and verify KZG proofs
    // This validates:
    // - Context consistency across all shares
    // - KZG eval proofs match the batch commitment
    // - Threshold requirement is met
    let results = trx.combine_and_decrypt(
        partials,
        batch_ctx,
        THRESHOLD as u32,
        &setup,
        &epoch.public_key.agg_key,
    )?;
    println!("  ✓ Successfully combined shares and decrypted batch\n");

    // ========================================================================
    // Results
    // ========================================================================
    println!("=== Decryption Results ===");
    for (idx, res) in results.iter().enumerate() {
        let plaintext = res.plaintext.as_ref().map(|p| p.as_slice()).unwrap_or(&[]);
        println!(
            "Transaction {}: {:?}",
            idx,
            String::from_utf8_lossy(plaintext)
        );
    }

    println!("\n✓ Example completed successfully!");

    Ok(())
}
