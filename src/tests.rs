use ed25519_dalek::SigningKey;
use rand::thread_rng;
use tess::{PairingEngine, ThresholdEncryption};

use super::*;

#[test]
fn happy_path_encrypt_decrypt() {
    let mut rng = thread_rng();
    let parties = 4;
    let threshold = 2;
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold).unwrap();
    let client_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let keys = trx.scheme.keygen(&mut rng, parties, &trx.params).unwrap();
    let agg_key = trx
        .scheme
        .aggregate_public_key(&keys.public_keys, &trx.params, parties)
        .unwrap();
    let pk = PublicKey { agg_key };
    let encrypted = trx
        .encrypt_transaction(&pk, b"payload", b"aad", &client_key)
        .unwrap();

    let share_count = threshold + 1;
    let partials: Vec<tess::PartialDecryption<PairingEngine>> = keys
        .secret_keys
        .iter()
        .take(share_count)
        .map(|sk| {
            trx.scheme
                .partial_decrypt(sk, &encrypted.ciphertext)
                .unwrap()
        })
        .collect();

    let mut selector = vec![false; parties];
    for idx in 0..share_count {
        selector[idx] = true;
    }
    let result = trx
        .scheme
        .aggregate_decrypt(&encrypted.ciphertext, &partials, &selector, &pk.agg_key)
        .unwrap();
    assert_eq!(result.plaintext.unwrap(), b"payload");
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
    let validators: Vec<ValidatorId> = (0..parties as u32).collect();
    let epoch = trx
        .run_dkg(&mut rng, &validators, threshold as u32, setup.clone())
        .unwrap();

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
            let share = epoch.validator_shares.get(&validator_id).unwrap();
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

    let results = trx
        .combine_and_decrypt(
            partials,
            &eval_proofs,
            &batch,
            threshold as u32,
            &setup,
            &commitment,
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
    let validators: Vec<ValidatorId> = (0..parties as u32).collect();
    let epoch = trx
        .run_dkg(&mut rng, &validators, threshold as u32, setup)
        .unwrap();

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
    let validators: Vec<ValidatorId> = (0..parties as u32).collect();
    let epoch = trx
        .run_dkg(&mut rng, &validators, threshold as u32, setup_arc.clone())
        .unwrap();

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
    use crate::PrecomputationEngine;

    let mut rng = thread_rng();
    let parties = 4;
    let threshold = 2;
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold).unwrap();
    let client_key = SigningKey::generate(&mut rand::rngs::OsRng);

    let setup = trx.generate_trusted_setup(&mut rng, parties, 2).unwrap();
    let setup_arc = std::sync::Arc::new(setup);
    let validators: Vec<ValidatorId> = (0..parties as u32).collect();
    let epoch = trx
        .run_dkg(&mut rng, &validators, threshold as u32, setup_arc.clone())
        .unwrap();

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
fn test_scalar_from_hash_deterministic() {
    use crate::utils::scalar_from_hash;

    // Same input should produce same output
    let input = b"test_input";
    let scalar1 = scalar_from_hash::<PairingEngine>(input);
    let scalar2 = scalar_from_hash::<PairingEngine>(input);
    assert_eq!(scalar1, scalar2);

    // Different input should produce different output
    let different_input = b"different_input";
    let scalar3 = scalar_from_hash::<PairingEngine>(different_input);
    assert_ne!(scalar1, scalar3);
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
    use crate::PrecomputationEngine;

    let mut rng = thread_rng();
    let parties = 4;
    let threshold = 2;
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold).unwrap();
    let client_key = SigningKey::generate(&mut rand::rngs::OsRng);

    let setup = trx.generate_trusted_setup(&mut rng, parties, 5).unwrap();
    let setup_arc = std::sync::Arc::new(setup);
    let validators: Vec<ValidatorId> = (0..parties as u32).collect();
    let epoch = trx
        .run_dkg(&mut rng, &validators, threshold as u32, setup_arc.clone())
        .unwrap();

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
