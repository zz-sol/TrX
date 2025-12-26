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
