//! Command handlers for TrX CLI.
//!
//! This module contains the business logic for each CLI command.
//! Each match arm implements the logic for one command.

use ed25519_dalek::SigningKey;
use rand::thread_rng;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tess::PairingEngine;

use crate::crypto::signatures::ValidatorSigningKey;
use crate::crypto::tess::{EpochSetup, ValidatorKeyPair};
use crate::crypto::types::{
    BatchContext, BatchProofs, DecryptionContext, EncryptedTransaction, EvalProof,
    PartialDecryption, ThresholdEncryptionPublicKey, ThresholdEncryptionSecretKeyShare,
    TransactionBatchCommitment,
};
use crate::sdk::TrxMinion;

use super::commands::Commands;

type Backend = PairingEngine;

/// Helper function to read validator signing key from file
fn read_signing_key(path: &PathBuf) -> Result<ValidatorSigningKey, Box<dyn std::error::Error>> {
    let key_json = fs::read_to_string(path)?;
    let bytes: Vec<u8> = serde_json::from_str(&key_json)?;
    let key = ValidatorSigningKey::try_from(bytes.as_slice())
        .map_err(|err| format!("invalid signing key: {err}"))?;
    Ok(key)
}

/// Execute a CLI command.
///
/// This function dispatches to the appropriate handler based on the command type.
pub fn execute(command: Commands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
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

        Commands::KeygenEncryption {
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

        Commands::KeygenSigning { output } => {
            let signing_key = ValidatorSigningKey::new();
            let bytes: [u8; 32] = (&signing_key).into();
            let json = serde_json::to_string_pretty(&bytes.to_vec())?;
            fs::write(&output, json)?;
            println!("✓ Signing key written to {}", output.display());
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
            let public_keys: Vec<_> = validator_keypairs
                .iter()
                .map(|kp| kp.public_key.clone())
                .collect();

            let epoch_keys = client.setup().aggregate_epoch_keys(
                &public_keys,
                threshold,
                Arc::new(epoch_setup),
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
            let pk: ThresholdEncryptionPublicKey<Backend> = serde_json::from_str(&pk_json)?;

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

        Commands::PartialDecryptSigned {
            secret_share,
            commitment,
            encrypted_tx,
            signing_key,
            tx_index,
            block_height,
            context_index,
            output,
            num_validators,
            threshold,
        } => {
            println!("Generating signed partial decryption...");
            let mut rng = thread_rng();
            let client = TrxMinion::<Backend>::new(&mut rng, num_validators, threshold)?;

            let share_json = fs::read_to_string(&secret_share)?;
            let secret: ThresholdEncryptionSecretKeyShare<Backend> =
                serde_json::from_str(&share_json)?;

            let comm_json = fs::read_to_string(&commitment)?;
            let comm: TransactionBatchCommitment<Backend> = serde_json::from_str(&comm_json)?;

            let tx_json = fs::read_to_string(&encrypted_tx)?;
            let tx: EncryptedTransaction<Backend> = serde_json::from_str(&tx_json)?;

            let signing_key_val = read_signing_key(&signing_key)?;

            let context = DecryptionContext {
                block_height,
                context_index: context_index as u32,
            };

            let signed = client.validator().generate_signed_partial_decryption(
                &signing_key_val,
                &secret,
                &comm,
                &context,
                tx_index,
                &tx.ciphertext,
                &tx.associated_data,
            )?;

            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&signed)?;
                fs::write(&output_path, json)?;
                println!("✓ Signed share written to {}", output_path.display());
            } else {
                let json = serde_json::to_string_pretty(&signed)?;
                println!("{}", json);
            }
        }

        Commands::DecryptSigned {
            batch,
            signed_shares,
            threshold,
            setup,
            public_key,
            commitment,
            eval_proofs,
            block_height,
            context_index,
            num_validators,
        } => {
            println!("Decrypting batch with signed shares...");
            let mut rng = thread_rng();
            let client = TrxMinion::<Backend>::new(&mut rng, num_validators, threshold as usize)?;

            let batch_json = fs::read_to_string(&batch)?;
            let batch_txs: Vec<EncryptedTransaction<Backend>> = serde_json::from_str(&batch_json)?;

            let shares_json = fs::read_to_string(&signed_shares)?;
            let signed_partial_decryptions: Vec<PartialDecryption<Backend>> =
                serde_json::from_str(&shares_json)?;

            let setup_json = fs::read_to_string(&setup)?;
            let epoch_setup: EpochSetup<Backend> = serde_json::from_str(&setup_json)?;

            let pk_json = fs::read_to_string(&public_key)?;
            let pk: ThresholdEncryptionPublicKey<Backend> = serde_json::from_str(&pk_json)?;

            let comm_json = fs::read_to_string(&commitment)?;
            let comm: TransactionBatchCommitment<Backend> = serde_json::from_str(&comm_json)?;

            let proofs_json = fs::read_to_string(&eval_proofs)?;
            let proofs: Vec<EvalProof<Backend>> = serde_json::from_str(&proofs_json)?;

            let context = DecryptionContext {
                block_height,
                context_index: context_index as u32,
            };

            let batch_ctx = BatchContext::new(batch_txs, context, BatchProofs::new(comm, proofs));

            let results = client.decryption().combine_and_decrypt_signed(
                signed_partial_decryptions,
                &batch_ctx,
                threshold,
                &epoch_setup,
                &pk,
            )?;

            println!("\n=== Decryption Results ===\n");
            for (i, result) in results.iter().enumerate() {
                if let Some(plaintext) = &result.plaintext {
                    println!("  [{}] {}", i, String::from_utf8_lossy(plaintext));
                } else {
                    println!("  [{}] (decryption failed)", i);
                }
            }
        }

        Commands::Demo {
            num_validators,
            threshold,
            num_txs,
        } => {
            println!("\n========================================");
            println!("      TrX Encrypted Mempool Demo");
            println!("========================================\n");
            println!(
                "Configuration: {} validators, threshold={}, {} transactions\n",
                num_validators, threshold, num_txs
            );

            let mut rng = thread_rng();

            // Phase 1: Setup
            println!("Phase 1: System Setup");
            let client = TrxMinion::<Backend>::new(&mut rng, num_validators, threshold)?;
            let global_setup = client.setup().generate_global_setup(&mut rng, 10)?;
            let setup =
                client
                    .setup()
                    .generate_epoch_setup(&mut rng, 1, 100, global_setup.clone())?;
            client.setup().verify_epoch_setup(&setup)?;
            println!("  ✓ Global and epoch setup complete\n");

            // Phase 2: Keygen
            println!("Phase 2: Silent Key Generation");
            let validators: Vec<u32> = (0..num_validators as u32).collect();
            let validator_keypairs: Vec<_> = validators
                .iter()
                .map(|&id| {
                    client
                        .validator()
                        .keygen_single_validator(&mut rng, id)
                        .unwrap()
                })
                .collect();
            println!("  ✓ Generated {} keypairs", num_validators);

            let public_keys: Vec<_> = validator_keypairs
                .iter()
                .map(|kp| kp.public_key.clone())
                .collect();
            let epoch_keys = client.setup().aggregate_epoch_keys(
                &public_keys,
                threshold as u32,
                setup.clone(),
            )?;
            println!("  ✓ Aggregated epoch keys\n");

            // Phase 3: Client encryption
            println!("Phase 3: Client Encryption");
            let signing_key = SigningKey::generate(&mut rng);
            let mut batch = Vec::new();
            for i in 0..num_txs {
                let message = format!("Transaction #{}", i);
                let encrypted_tx = client.client().encrypt_transaction(
                    &epoch_keys.public_key,
                    message.as_bytes(),
                    b"metadata",
                    &signing_key,
                )?;
                batch.push(encrypted_tx);
            }
            println!("  ✓ Encrypted {} transactions\n", num_txs);

            // Phase 4: Mempool
            println!("Phase 4: Mempool");
            let mut mempool = client.mempool().create(100);
            for tx in &batch {
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
            client.proposer().verify_eval_proofs(
                &setup,
                &commitment,
                &batch,
                &context,
                &eval_proofs,
            )?;
            println!("  ✓ Batch committed with proofs\n");

            // Phase 6: Decryption
            println!("Phase 6: Threshold Decryption");
            let validator_signing_keys: Vec<_> = (0..num_validators)
                .map(|_| ValidatorSigningKey::new())
                .collect();
            let mut signed_partial_decryptions = Vec::new();
            for (tx_index, tx) in batch.iter().enumerate() {
                for keypair in validator_keypairs.iter().take(threshold) {
                    let signing_key = &validator_signing_keys[keypair.validator_id as usize];
                    let signed = client.validator().generate_signed_partial_decryption(
                        signing_key,
                        &keypair.secret_share,
                        &commitment,
                        &context,
                        tx_index,
                        &tx.ciphertext,
                        &tx.associated_data,
                    )?;
                    signed_partial_decryptions.push(signed);
                }
            }

            let batch_ctx =
                BatchContext::new(batch, context, BatchProofs::new(commitment, eval_proofs));

            let results = client.decryption().combine_and_decrypt_signed(
                signed_partial_decryptions,
                &batch_ctx,
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
                } else {
                    println!("  Transaction {}: Failed to decrypt", i);
                }
            }

            println!(
                "\n{}/{} transactions decrypted successfully",
                successful,
                results.len()
            );
            println!("========================================\n");
        }
    }

    Ok(())
}
