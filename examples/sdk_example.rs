//! # TrX SDK Complete Example
//!
//! This example demonstrates how to use the TrX SDK to build an encrypted
//! mempool system with all six phases:
//!
//! 1. Setup Phase - System initialization
//! 2. Validator Key Generation - Silent setup
//! 3. Client Phase - Transaction encryption
//! 4. Mempool Phase - Transaction queuing
//! 5. Proposer Phase - Batch commitment
//! 6. Decryption Phase - Threshold decryption
//!
//! Run with: `cargo run --example sdk_example`

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand::{rngs::StdRng, thread_rng, SeedableRng};
use tess::PairingEngine;
use trx::TrxClient;
use trx::{BatchContext, DecryptionContext, ValidatorId};

/// Network configuration
const NUM_VALIDATORS: usize = 5;
const THRESHOLD: usize = 3;
const MAX_BATCH_SIZE: usize = 10;
const MAX_CONTEXTS: usize = 100;
const MEMPOOL_CAPACITY: usize = 1000;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== TrX SDK Example: Encrypted Mempool Workflow ===\n");

    // Initialize RNG
    let mut rng = thread_rng();

    // ========================================================================
    // PHASE 1: SETUP - System Initialization
    // ========================================================================
    println!("Phase 1: System Setup");
    println!(
        "  - Creating TrX client with {} validators, threshold {}",
        NUM_VALIDATORS, THRESHOLD
    );

    let client = TrxClient::<PairingEngine>::new(&mut rng, NUM_VALIDATORS, THRESHOLD)?;

    println!(
        "  - Generating trusted setup (max batch: {}, contexts: {})",
        MAX_BATCH_SIZE, MAX_CONTEXTS
    );

    let setup = Arc::new(client.setup().generate_trusted_setup(
        &mut rng,
        MAX_BATCH_SIZE,
        MAX_CONTEXTS,
    )?);

    println!("  - Verifying setup integrity...");
    client.setup().verify_setup(&setup)?;
    println!("  ✓ Setup verified successfully!\n");

    // ========================================================================
    // PHASE 2: VALIDATOR KEY GENERATION - Silent Setup
    // ========================================================================
    println!("Phase 2: Validator Key Generation (Silent Setup)");
    println!("  - Each validator independently generates their keypair...");

    // Simulate each validator running keygen independently
    let mut rngs: Vec<StdRng> = (0..NUM_VALIDATORS)
        .map(|i| StdRng::seed_from_u64(12345 + i as u64))
        .collect();

    let validator_keypairs: Vec<_> = (0..NUM_VALIDATORS)
        .zip(rngs.iter_mut())
        .map(|(id, rng)| {
            println!("    - Validator {} generating keypair...", id);
            client.validator().keygen_single_validator(rng, id as u32)
        })
        .collect::<Result<Vec<_>, _>>()?;

    println!(
        "  - Aggregating {} public keys...",
        validator_keypairs.len()
    );

    let epoch_keys = client.setup().aggregate_epoch_keys(
        validator_keypairs.clone(),
        THRESHOLD as u32,
        setup.clone(),
    )?;

    println!("  ✓ Epoch keys ready for client encryption!\n");

    // Extract secret shares for later use in decryption
    let validator_secret_shares: Vec<_> = validator_keypairs
        .iter()
        .map(|kp| kp.secret_share.clone())
        .collect();

    // Build public key map for verification
    // Note: We use the epoch public key for all validators since
    // verify_partial_decryption uses the aggregate key, not individual keys
    let public_keys: HashMap<ValidatorId, _> = (0..NUM_VALIDATORS as u32)
        .map(|id| (id, epoch_keys.public_key.clone()))
        .collect();

    // ========================================================================
    // PHASE 3: CLIENT PHASE - Transaction Encryption
    // ========================================================================
    println!("Phase 3: Client Transaction Encryption");

    let num_txs = 5;
    let mut client_keys = Vec::new();
    let mut encrypted_txs = Vec::new();

    for i in 0..num_txs {
        let signing_key = SigningKey::generate(&mut rng);
        let payload = format!("transfer {} tokens to alice", i * 10 + 10);
        let metadata = format!("nonce:{},fee:1", i);

        println!("  - Client {} encrypting: '{}'", i, payload);

        let encrypted_tx = client.client().encrypt_transaction(
            &epoch_keys.public_key,
            payload.as_bytes(),
            metadata.as_bytes(),
            &signing_key,
        )?;

        client_keys.push(signing_key);
        encrypted_txs.push(encrypted_tx);
    }

    println!("  ✓ {} transactions encrypted!\n", num_txs);

    // ========================================================================
    // PHASE 4: MEMPOOL PHASE - Transaction Queue Management
    // ========================================================================
    println!("Phase 4: Mempool Management");
    println!("  - Creating mempool (capacity: {})", MEMPOOL_CAPACITY);

    let mut mempool = client.mempool().create(MEMPOOL_CAPACITY);

    println!(
        "  - Adding {} encrypted transactions to mempool...",
        encrypted_txs.len()
    );

    for (i, tx) in encrypted_txs.iter().enumerate() {
        // Verify before adding
        client.client().verify_ciphertext(tx)?;
        client.mempool().add_transaction(&mut mempool, tx.clone())?;
        println!("    ✓ Transaction {} added", i);
    }

    println!("  - Mempool size: {}", client.mempool().size(&mempool));
    println!("  ✓ Mempool ready for batch proposal!\n");

    // ========================================================================
    // PHASE 5: PROPOSER PHASE - Batch Commitment
    // ========================================================================
    println!("Phase 5: Batch Commitment (Proposer)");
    println!("  - Retrieving batch from mempool...");

    let batch = client.mempool().get_batch(&mut mempool, MAX_BATCH_SIZE);
    println!("  - Batch size: {}", batch.len());

    let context = DecryptionContext {
        block_height: 100,
        context_index: 0,
    };

    println!(
        "  - Computing KZG commitment (block {}, context {})...",
        context.block_height, context.context_index
    );

    let commitment = client.proposer().compute_digest(&batch, &context, &setup)?;
    println!("  ✓ Batch commitment computed!");

    println!(
        "  - Generating evaluation proofs for {} transactions...",
        batch.len()
    );
    let eval_proofs = client
        .proposer()
        .compute_eval_proofs(&batch, &context, &setup)?;
    println!("  ✓ {} proofs generated!", eval_proofs.len());

    println!("  - Verifying evaluation proofs...");
    client
        .proposer()
        .verify_eval_proofs(&setup, &commitment, &batch, &context, &eval_proofs)?;
    println!("  ✓ Batch proofs verified!\n");

    // ========================================================================
    // PHASE 6: DECRYPTION PHASE - Threshold Decryption
    // ========================================================================
    println!("Phase 6: Threshold Decryption");
    println!("  - Validators generating partial decryptions...");

    let mut partial_decryptions = Vec::new();

    // For each transaction, collect threshold+1 partial decryptions
    for (tx_index, tx) in batch.iter().enumerate() {
        println!(
            "    Transaction {} - collecting shares from {} validators:",
            tx_index,
            THRESHOLD + 1
        );

        // Get shares from first threshold+1 validators
        for (validator_idx, secret_share) in validator_secret_shares
            .iter()
            .take(THRESHOLD + 1)
            .enumerate()
        {
            let pd = client.validator().generate_partial_decryption(
                secret_share,
                &commitment,
                &context,
                tx_index,
                &tx.ciphertext,
            )?;

            // Verify the partial decryption
            client
                .validator()
                .verify_partial_decryption(&pd, &commitment, &public_keys)?;

            println!("      ✓ Validator {} share verified", validator_idx);
            partial_decryptions.push(pd);
        }
    }

    println!(
        "  - Combining {} partial decryptions...",
        partial_decryptions.len()
    );

    let batch_ctx = BatchContext {
        batch: &batch,
        context: &context,
        commitment: &commitment,
        eval_proofs: &eval_proofs,
    };

    let results = client.decryption().combine_and_decrypt(
        partial_decryptions,
        batch_ctx,
        THRESHOLD as u32,
        &setup,
        &epoch_keys.public_key,
    )?;

    println!("  ✓ Decryption complete!\n");

    // ========================================================================
    // RESULTS
    // ========================================================================
    println!("=== Decryption Results ===\n");

    let mut successful = 0;
    for (i, result) in results.iter().enumerate() {
        if let Some(plaintext) = &result.plaintext {
            let plaintext_str = String::from_utf8_lossy(plaintext);
            println!("Transaction {}: SUCCESS", i);
            println!("  Payload: {}", plaintext_str);
            println!(
                "  Metadata: {:?}",
                String::from_utf8_lossy(&batch[i].associated_data)
            );
            successful += 1;
        } else {
            println!("Transaction {}: FAILED - decryption returned None", i);
        }
        println!();
    }

    println!("=== Workflow Complete ===");
    println!("  - {} transactions encrypted", num_txs);
    println!("  - {} transactions included in batch", batch.len());
    println!("  - {} transactions successfully decrypted", successful);

    Ok(())
}
