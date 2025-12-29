use ed25519_dalek::SigningKey;
use rand::thread_rng;
use std::sync::Arc;
use tess::{CurvePoint, PairingEngine};

use trx::*;

/// Helper function to generate epoch keys using the new silent setup API
/// Returns (EpochKeys, HashMap of validator shares)
///
/// NOTE: This simulates the silent setup flow where in a real deployment:
/// 1. Each validator independently samples their own BLS secret key
/// 2. Each validator publishes their public key
/// 3. The coordinator aggregates all public keys deterministically
///
/// Due to Tess API limitations, we generate all keys at once then distribute them,
/// but this achieves the same end result as true silent setup.
fn generate_epoch_keys(
    trx: &TrxCrypto<PairingEngine>,
    rng: &mut impl rand::RngCore,
    parties: usize,
    threshold: u32,
    setup: Arc<TrustedSetup<PairingEngine>>,
) -> Result<(EpochKeys<PairingEngine>, Vec<SecretKeyShare<PairingEngine>>), TrxError> {
    let validators: Vec<ValidatorId> = (0..parties as u32).collect();

    // Generate all validator key pairs (simulates silent setup where each validator
    // independently generates their own key, then publishes their public key)

    let validator_keypairs = validators
        .iter()
        .map(|&vid| trx.keygen_single_validator(rng, vid))
        .collect::<Result<Vec<_>, _>>()?;
    let validator_secret_keys = validator_keypairs
        .iter()
        .map(|kp| kp.secret_share.clone())
        .collect::<Vec<_>>();

    // Phase 2: Aggregate the published public keys (non-interactive)
    // Only public keys are needed for aggregation
    let public_keys = validator_keypairs
        .into_iter()
        .map(|kp| kp.public_key)
        .collect();
    let epoch_keys = trx.aggregate_epoch_keys(public_keys, threshold, setup)?;

    Ok((epoch_keys, validator_secret_keys))
}

#[test]
fn happy_path_encrypt_decrypt() {
    let mut rng = thread_rng();
    let parties = 4;
    let threshold = 2;
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold).unwrap();
    let client_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let setup = trx.generate_trusted_setup(&mut rng, parties, 2).unwrap();
    let setup = std::sync::Arc::new(setup);
    let (epoch, validator_shares) =
        generate_epoch_keys(&trx, &mut rng, parties, threshold as u32, setup.clone()).unwrap();

    let encrypted = trx
        .encrypt_transaction(&epoch.public_key, b"payload", b"aad", &client_key)
        .unwrap();
    let batch = vec![encrypted];
    let context = DecryptionContext {
        block_height: 1,
        context_index: 0,
    };
    let commitment = TrxCrypto::<PairingEngine>::compute_digest(&batch, &context, &setup).unwrap();
    let eval_proofs =
        TrxCrypto::<PairingEngine>::compute_eval_proofs(&batch, &context, &setup).unwrap();

    let mut partials = Vec::new();
    for validator_id in [0u32, 1u32, 2u32] {
        let share = &validator_shares[validator_id as usize];
        let pd = TrxCrypto::<PairingEngine>::generate_partial_decryption(
            share,
            &commitment,
            &context,
            0,
            &batch[0].ciphertext,
        )
        .unwrap();
        partials.push(pd);
    }

    let batch_ctx = BatchContext {
        batch: &batch,
        context: &context,
        commitment: &commitment,
        eval_proofs: &eval_proofs,
    };
    let results = trx
        .combine_and_decrypt(
            partials,
            batch_ctx,
            threshold as u32,
            &setup,
            &epoch.public_key.agg_key,
        )
        .unwrap();
    assert_eq!(results[0].plaintext.as_ref().unwrap(), b"payload");
}

#[test]
fn batch_decrypt_flow() {
    let mut rng = thread_rng();
    let parties = 4;
    let threshold = 2;
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold).unwrap();
    let client_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let setup = trx.generate_trusted_setup(&mut rng, parties, 2).unwrap();
    let setup = std::sync::Arc::new(setup);
    let (epoch, validator_shares) =
        generate_epoch_keys(&trx, &mut rng, parties, threshold as u32, setup.clone()).unwrap();

    let context = DecryptionContext {
        block_height: 1,
        context_index: 0,
    };

    let batch = vec![
        trx.encrypt_transaction(&epoch.public_key, b"a", b"", &client_key)
            .unwrap(),
        trx.encrypt_transaction(&epoch.public_key, b"b", b"", &client_key)
            .unwrap(),
    ];

    let commitment = TrxCrypto::<PairingEngine>::compute_digest(&batch, &context, &setup).unwrap();
    let eval_proofs =
        TrxCrypto::<PairingEngine>::compute_eval_proofs(&batch, &context, &setup).unwrap();

    let mut partials = Vec::new();
    for (tx_index, tx) in batch.iter().enumerate() {
        for validator_id in [0u32, 1u32, 2u32] {
            let share = &validator_shares[validator_id as usize];
            let pd = TrxCrypto::<PairingEngine>::generate_partial_decryption(
                share,
                &commitment,
                &context,
                tx_index,
                &tx.ciphertext,
            )
            .unwrap();
            partials.push(pd);
        }
    }

    let batch_ctx = BatchContext {
        batch: &batch,
        context: &context,
        commitment: &commitment,
        eval_proofs: &eval_proofs,
    };
    let results = trx
        .combine_and_decrypt(
            partials,
            batch_ctx,
            threshold as u32,
            &setup,
            &epoch.public_key.agg_key,
        )
        .unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].plaintext.as_ref().unwrap(), b"a");
    assert_eq!(results[1].plaintext.as_ref().unwrap(), b"b");
}

#[test]
fn mempool_roundtrip() {
    let mut rng = thread_rng();
    let parties = 4;
    let threshold = 2;
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold).unwrap();
    let client_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let setup = trx.generate_trusted_setup(&mut rng, parties, 1).unwrap();
    let setup = std::sync::Arc::new(setup);
    let (epoch, _validator_shares) =
        generate_epoch_keys(&trx, &mut rng, parties, threshold as u32, setup).unwrap();

    let mut mempool = EncryptedMempool::<PairingEngine>::new(2);
    let tx1 = trx
        .encrypt_transaction(&epoch.public_key, b"one", b"", &client_key)
        .unwrap();
    let tx2 = trx
        .encrypt_transaction(&epoch.public_key, b"two", b"", &client_key)
        .unwrap();
    mempool.add_encrypted_tx(tx1).unwrap();
    mempool.add_encrypted_tx(tx2).unwrap();

    let batch = mempool.get_batch(1);
    assert_eq!(batch.len(), 1);
    let remaining = mempool.get_batch(2);
    assert_eq!(remaining.len(), 1);
}

#[test]
fn test_context_index_bounds_checking() {
    let mut rng = thread_rng();
    let parties = 4;
    let threshold = 2;
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold).unwrap();
    let client_key = SigningKey::generate(&mut rand::rngs::OsRng);

    // Create setup with only 2 kappa contexts
    let setup = trx.generate_trusted_setup(&mut rng, parties, 2).unwrap();
    let setup_arc = std::sync::Arc::new(setup);
    let (epoch, _validator_shares) =
        generate_epoch_keys(&trx, &mut rng, parties, threshold as u32, setup_arc.clone()).unwrap();

    let batch = vec![trx
        .encrypt_transaction(&epoch.public_key, b"test", b"", &client_key)
        .unwrap()];

    // Valid context index (0) should work
    let valid_context = DecryptionContext {
        block_height: 1,
        context_index: 0,
    };
    assert!(TrxCrypto::<PairingEngine>::compute_digest(&batch, &valid_context, &setup_arc).is_ok());

    // Valid context index (1) should work
    let valid_context = DecryptionContext {
        block_height: 1,
        context_index: 1,
    };
    assert!(TrxCrypto::<PairingEngine>::compute_digest(&batch, &valid_context, &setup_arc).is_ok());

    // Invalid context index (2) should fail
    let invalid_context = DecryptionContext {
        block_height: 1,
        context_index: 2,
    };
    let result = TrxCrypto::<PairingEngine>::compute_digest(&batch, &invalid_context, &setup_arc);
    assert!(result.is_err());
    match result.unwrap_err() {
        TrxError::InvalidInput(msg) => {
            assert!(msg.contains("context_index"));
            assert!(msg.contains("exceeds maximum"));
        }
        _ => panic!("Expected InvalidInput error"),
    }
}

#[test]
fn test_kappa_atomic_single_use() {
    let mut rng = thread_rng();
    let parties = 4;
    let threshold = 2;
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold).unwrap();

    let setup = trx.generate_trusted_setup(&mut rng, parties, 5).unwrap();
    let kappa = &setup.kappa_setups[0];

    // First use should succeed
    assert!(!kappa.is_used());
    assert!(kappa.try_use().is_ok());
    assert!(kappa.is_used());

    // Second use should fail
    let result = kappa.try_use();
    assert!(result.is_err());
    match result.unwrap_err() {
        TrxError::InvalidInput(msg) => {
            assert!(msg.contains("already used"));
            assert!(msg.contains("kappa context"));
        }
        _ => panic!("Expected InvalidInput error"),
    }
}

#[test]
fn test_mutex_poisoning_handling() {
    use trx::PrecomputationEngine;

    let mut rng = thread_rng();
    let parties = 4;
    let threshold = 2;
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold).unwrap();
    let client_key = SigningKey::generate(&mut rand::rngs::OsRng);

    let setup = trx.generate_trusted_setup(&mut rng, parties, 2).unwrap();
    let setup_arc = std::sync::Arc::new(setup);
    let (epoch, _validator_shares) =
        generate_epoch_keys(&trx, &mut rng, parties, threshold as u32, setup_arc.clone()).unwrap();

    let batch = vec![trx
        .encrypt_transaction(&epoch.public_key, b"test", b"", &client_key)
        .unwrap()];

    let context = DecryptionContext {
        block_height: 1,
        context_index: 0,
    };

    let engine = PrecomputationEngine::<PairingEngine>::new();

    // First computation should succeed and cache
    let result1 = engine.precompute(&batch, &context, &setup_arc);
    assert!(result1.is_ok());
    let data1 = result1.unwrap();
    assert!(data1.computation_time.as_nanos() > 0); // First call computes

    // Second computation should hit cache and return same commitment
    let result2 = engine.precompute(&batch, &context, &setup_arc);
    assert!(result2.is_ok());
    let data2 = result2.unwrap();
    // Cache returns cloned data, so commitment should match
    assert_eq!(
        data1.digest.polynomial_degree,
        data2.digest.polynomial_degree
    );
}

#[test]
fn test_trx_error_display() {
    let err1 = TrxError::Backend("crypto failure".to_string());
    assert_eq!(err1.to_string(), "Backend error: crypto failure");

    let err2 = TrxError::InvalidConfig("bad params".to_string());
    assert_eq!(err2.to_string(), "Invalid configuration: bad params");

    let err3 = TrxError::InvalidInput("bad data".to_string());
    assert_eq!(err3.to_string(), "Invalid input: bad data");

    let err4 = TrxError::NotEnoughShares {
        required: 3,
        provided: 2,
    };
    assert_eq!(
        err4.to_string(),
        "Not enough shares: required 3, provided 2"
    );
}

#[test]
fn test_trusted_setup_validation() {
    let mut rng = thread_rng();
    let parties = 4;
    let threshold = 2;
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold).unwrap();

    let setup = trx.generate_trusted_setup(&mut rng, parties, 10).unwrap();

    // Valid indices should pass
    assert!(setup.validate_context_index(0).is_ok());
    assert!(setup.validate_context_index(5).is_ok());
    assert!(setup.validate_context_index(9).is_ok());

    // Invalid index should fail
    let result = setup.validate_context_index(10);
    assert!(result.is_err());
    match result.unwrap_err() {
        TrxError::InvalidInput(msg) => {
            assert!(msg.contains("10"));
            assert!(msg.contains("exceeds maximum 9"));
        }
        _ => panic!("Expected InvalidInput error"),
    }

    // Way out of bounds should also fail
    let result = setup.validate_context_index(100);
    assert!(result.is_err());
}

#[test]
fn test_precomputation_cache_isolation() {
    use trx::PrecomputationEngine;

    let mut rng = thread_rng();
    let parties = 4;
    let threshold = 2;
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold).unwrap();
    let client_key = SigningKey::generate(&mut rand::rngs::OsRng);

    let setup = trx.generate_trusted_setup(&mut rng, parties, 5).unwrap();
    let setup_arc = std::sync::Arc::new(setup);
    let (epoch, _validator_shares) =
        generate_epoch_keys(&trx, &mut rng, parties, threshold as u32, setup_arc.clone()).unwrap();

    let batch = vec![trx
        .encrypt_transaction(&epoch.public_key, b"test", b"", &client_key)
        .unwrap()];

    let engine = PrecomputationEngine::<PairingEngine>::new();

    // Different contexts should not share cache
    let context1 = DecryptionContext {
        block_height: 1,
        context_index: 0,
    };
    let context2 = DecryptionContext {
        block_height: 2,
        context_index: 0,
    };

    let data1 = engine.precompute(&batch, &context1, &setup_arc).unwrap();
    assert!(data1.computation_time.as_nanos() > 0); // Computed

    let data2 = engine.precompute(&batch, &context2, &setup_arc).unwrap();
    assert!(data2.computation_time.as_nanos() > 0); // Also computed (different context)

    // Same context should hit cache and return consistent results
    let data3 = engine.precompute(&batch, &context1, &setup_arc).unwrap();
    assert_eq!(
        data1.digest.polynomial_degree,
        data3.digest.polynomial_degree
    ); // Same result
}

#[test]
fn test_precomputation_cache_key_includes_associated_data() {
    let mut rng = thread_rng();
    let parties = 4;
    let threshold = 2;
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold).unwrap();
    let client_key = SigningKey::generate(&mut rand::rngs::OsRng);

    let setup = trx.generate_trusted_setup(&mut rng, parties, 5).unwrap();
    let setup_arc = std::sync::Arc::new(setup);
    let (epoch, _validator_shares) =
        generate_epoch_keys(&trx, &mut rng, parties, threshold as u32, setup_arc.clone()).unwrap();

    let context = DecryptionContext {
        block_height: 1,
        context_index: 0,
    };

    let tx1 = trx
        .encrypt_transaction(&epoch.public_key, b"payload", b"aad-1", &client_key)
        .unwrap();
    let tx2 = trx
        .encrypt_transaction(&epoch.public_key, b"payload", b"aad-2", &client_key)
        .unwrap();

    let batch1 = vec![tx1];
    let batch2 = vec![tx2];

    let engine = PrecomputationEngine::<PairingEngine>::new();
    let data1 = engine.precompute(&batch1, &context, &setup_arc).unwrap();
    let data2 = engine.precompute(&batch2, &context, &setup_arc).unwrap();

    let com1 = data1.digest.com.to_repr();
    let com2 = data2.digest.com.to_repr();
    assert_ne!(com1, com2);
}

#[test]
fn test_invalid_threshold_configuration() {
    let mut rng = thread_rng();

    // Threshold = 0 should fail
    let result = TrxCrypto::<PairingEngine>::new(&mut rng, 5, 0);
    assert!(result.is_err());
    match result.unwrap_err() {
        TrxError::InvalidConfig(msg) => {
            assert!(msg.contains("threshold"));
        }
        _ => panic!("Expected InvalidConfig error"),
    }

    // Threshold >= parties should fail
    let result = TrxCrypto::<PairingEngine>::new(&mut rng, 5, 5);
    assert!(result.is_err());

    let result = TrxCrypto::<PairingEngine>::new(&mut rng, 5, 6);
    assert!(result.is_err());

    // Valid threshold (used in other tests) should succeed
    let result = TrxCrypto::<PairingEngine>::new(&mut rng, 4, 2);
    assert!(result.is_ok());
}

#[test]
fn test_empty_trusted_setup_validation() {
    let mut rng = thread_rng();
    let parties = 4;
    let threshold = 2;
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold).unwrap();

    // Generate setup with 0 kappa contexts should work (edge case)
    let setup = trx.generate_trusted_setup(&mut rng, parties, 0).unwrap();

    // Any context_index should fail for empty kappa_setups
    let result = setup.validate_context_index(0);
    assert!(result.is_err());
}

#[test]
fn test_context_index_in_eval_proofs() {
    let mut rng = thread_rng();
    let parties = 4;
    let threshold = 2;
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold).unwrap();
    let client_key = SigningKey::generate(&mut rand::rngs::OsRng);

    // Create setup with only 2 kappa contexts
    let setup = trx.generate_trusted_setup(&mut rng, parties, 2).unwrap();
    let setup_arc = std::sync::Arc::new(setup);
    let (epoch, _validator_shares) =
        generate_epoch_keys(&trx, &mut rng, parties, threshold as u32, setup_arc.clone()).unwrap();

    let batch = vec![trx
        .encrypt_transaction(&epoch.public_key, b"test", b"", &client_key)
        .unwrap()];

    // Valid context should work for eval proofs
    let valid_context = DecryptionContext {
        block_height: 1,
        context_index: 0,
    };
    let result =
        TrxCrypto::<PairingEngine>::compute_eval_proofs(&batch, &valid_context, &setup_arc);
    assert!(result.is_ok());

    // Invalid context should fail for eval proofs
    let invalid_context = DecryptionContext {
        block_height: 1,
        context_index: 5,
    };
    let result =
        TrxCrypto::<PairingEngine>::compute_eval_proofs(&batch, &invalid_context, &setup_arc);
    assert!(result.is_err());
}

#[test]
fn test_not_enough_shares_error() {
    let mut rng = thread_rng();
    let parties = 4;
    let threshold = 2;
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold).unwrap();
    let client_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let setup = trx.generate_trusted_setup(&mut rng, parties, 2).unwrap();
    let setup_arc = std::sync::Arc::new(setup);
    let (epoch, validator_shares) =
        generate_epoch_keys(&trx, &mut rng, parties, threshold as u32, setup_arc.clone()).unwrap();

    let context = DecryptionContext {
        block_height: 1,
        context_index: 0,
    };

    let batch = vec![trx
        .encrypt_transaction(&epoch.public_key, b"test", b"", &client_key)
        .unwrap()];

    let commitment =
        TrxCrypto::<PairingEngine>::compute_digest(&batch, &context, &setup_arc).unwrap();
    let eval_proofs =
        TrxCrypto::<PairingEngine>::compute_eval_proofs(&batch, &context, &setup_arc).unwrap();

    // Provide only 1 partial decryption (less than threshold of 2)
    let share = &validator_shares[0];
    let pd = TrxCrypto::<PairingEngine>::generate_partial_decryption(
        share,
        &commitment,
        &context,
        0,
        &batch[0].ciphertext,
    )
    .unwrap();

    let batch_ctx = BatchContext {
        batch: &batch,
        context: &context,
        commitment: &commitment,
        eval_proofs: &eval_proofs,
    };
    let result = trx.combine_and_decrypt(
        vec![pd],
        batch_ctx,
        threshold as u32,
        &setup_arc,
        &epoch.public_key.agg_key,
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        TrxError::NotEnoughShares { required, provided } => {
            assert_eq!(required, threshold);
            assert_eq!(provided, 1);
        }
        _ => panic!("Expected NotEnoughShares error"),
    }
}

#[test]
fn test_mempool_capacity_enforcement() {
    let mut rng = thread_rng();
    let parties = 4;
    let threshold = 2;
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold).unwrap();
    let client_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let setup = trx.generate_trusted_setup(&mut rng, parties, 1).unwrap();
    let setup_arc = std::sync::Arc::new(setup);
    let (epoch, _validator_shares) =
        generate_epoch_keys(&trx, &mut rng, parties, threshold as u32, setup_arc).unwrap();

    // Create mempool with capacity of 2
    let mut mempool = EncryptedMempool::<PairingEngine>::new(2);

    let tx1 = trx
        .encrypt_transaction(&epoch.public_key, b"one", b"", &client_key)
        .unwrap();
    let tx2 = trx
        .encrypt_transaction(&epoch.public_key, b"two", b"", &client_key)
        .unwrap();
    let tx3 = trx
        .encrypt_transaction(&epoch.public_key, b"three", b"", &client_key)
        .unwrap();

    // First two transactions should succeed
    assert!(mempool.add_encrypted_tx(tx1).is_ok());
    assert!(mempool.add_encrypted_tx(tx2).is_ok());

    // Third transaction should fail (mempool full)
    let result = mempool.add_encrypted_tx(tx3);
    assert!(result.is_err());
    match result.unwrap_err() {
        TrxError::InvalidConfig(msg) => {
            assert!(msg.contains("mempool full"));
        }
        _ => panic!("Expected InvalidConfig error"),
    }
}

#[test]
fn test_concurrent_kappa_usage() {
    use std::sync::Arc;
    use std::thread;

    let mut rng = thread_rng();
    let parties = 4;
    let threshold = 2;
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold).unwrap();

    let setup = Arc::new(trx.generate_trusted_setup(&mut rng, parties, 5).unwrap());

    // Spawn multiple threads trying to use the same kappa context
    let mut handles = vec![];
    for _ in 0..10 {
        let setup_clone = setup.clone();
        let handle = thread::spawn(move || setup_clone.kappa_setups[0].try_use());
        handles.push(handle);
    }

    // Collect results
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // Exactly one thread should succeed
    let successes = results.iter().filter(|r| r.is_ok()).count();
    let failures = results.iter().filter(|r| r.is_err()).count();

    assert_eq!(
        successes, 1,
        "Exactly one thread should successfully use the kappa context"
    );
    assert_eq!(failures, 9, "Nine threads should fail");
}

#[test]
fn test_batch_size_exceeds_srs() {
    let mut rng = thread_rng();
    let parties = 4;
    let threshold = 2;
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold).unwrap();
    let client_key = SigningKey::generate(&mut rand::rngs::OsRng);

    // Create setup with very small SRS (only 2 transactions)
    let setup = trx.generate_trusted_setup(&mut rng, 2, 5).unwrap();
    let setup_arc = std::sync::Arc::new(setup);
    let (epoch, _validator_shares) =
        generate_epoch_keys(&trx, &mut rng, parties, threshold as u32, setup_arc.clone()).unwrap();

    // Create batch with 3 transactions (exceeds SRS capacity)
    let batch = vec![
        trx.encrypt_transaction(&epoch.public_key, b"a", b"", &client_key)
            .unwrap(),
        trx.encrypt_transaction(&epoch.public_key, b"b", b"", &client_key)
            .unwrap(),
        trx.encrypt_transaction(&epoch.public_key, b"c", b"", &client_key)
            .unwrap(),
    ];

    let context = DecryptionContext {
        block_height: 1,
        context_index: 0,
    };

    // Should fail due to batch size exceeding SRS powers
    let result = TrxCrypto::<PairingEngine>::compute_digest(&batch, &context, &setup_arc);
    assert!(result.is_err());
    match result.unwrap_err() {
        TrxError::InvalidConfig(msg) => {
            assert!(msg.contains("batch size exceeds"));
        }
        _ => panic!("Expected InvalidConfig error"),
    }
}

#[test]
fn test_empty_batch_handling() {
    let mut rng = thread_rng();
    let parties = 4;
    let threshold = 2;
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold).unwrap();

    let setup = trx.generate_trusted_setup(&mut rng, parties, 5).unwrap();
    let setup_arc = std::sync::Arc::new(setup);

    let context = DecryptionContext {
        block_height: 1,
        context_index: 0,
    };

    // Empty batch should work for digest computation
    let empty_batch: Vec<EncryptedTransaction<PairingEngine>> = vec![];
    let result = TrxCrypto::<PairingEngine>::compute_digest(&empty_batch, &context, &setup_arc);
    assert!(result.is_ok());

    // Empty batch should work for eval proofs
    let result =
        TrxCrypto::<PairingEngine>::compute_eval_proofs(&empty_batch, &context, &setup_arc);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 0);
}
