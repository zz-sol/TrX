use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand::thread_rng;
use tess::PairingEngine;
use trx::{
    BatchDecryption, DecryptionContext, EncryptedMempool, SetupManager, TransactionEncryption,
    TrxCrypto, ValidatorId,
};

const NUM_VALIDATORS: usize = 4;
const THRESHOLD: usize = 2;
const MAX_BATCH: usize = 32;
const MAX_CONTEXTS: usize = 16;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    // 1) Bootstrapping (operator)
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, NUM_VALIDATORS, THRESHOLD)?;
    let setup = Arc::new(trx.generate_trusted_setup(&mut rng, MAX_BATCH, MAX_CONTEXTS)?);
    let validators: Vec<ValidatorId> = (0..NUM_VALIDATORS as u32).collect();
    let epoch = trx.run_dkg(&mut rng, &validators, THRESHOLD as u32, setup.clone())?;

    // 2) Client encrypts + signs
    let client_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let tx = trx.encrypt_transaction(
        &epoch.public_key,
        b"pay 10 to bob",
        b"nonce:123",
        &client_key,
    )?;

    // 3) Mempool admission
    let mut mempool = EncryptedMempool::<PairingEngine>::new(MAX_BATCH);
    mempool.add_encrypted_tx(tx)?;

    // 4) Block proposal + batch precompute
    let batch = mempool.get_batch(MAX_BATCH);
    let context = DecryptionContext {
        block_height: 100,
        context_index: 0,
    };
    let commitment = TrxCrypto::<PairingEngine>::compute_digest(&batch, &context, &setup)?;
    let eval_proofs = TrxCrypto::<PairingEngine>::compute_eval_proofs(&batch, &context, &setup)?;

    // 5) Validators produce partial decryptions
    let mut partials = Vec::new();
    for (tx_index, tx) in batch.iter().enumerate() {
        for validator_id in 0..(THRESHOLD + 1) {
            let share = epoch
                .validator_shares
                .get(&(validator_id as u32))
                .expect("share exists");
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

    // 6) Combine shares and decrypt
    let results = trx.combine_and_decrypt(
        partials,
        &eval_proofs,
        &batch,
        THRESHOLD as u32,
        &setup,
        &commitment,
        &epoch.public_key.agg_key,
    )?;

    for (idx, res) in results.iter().enumerate() {
        let plaintext = res.plaintext.as_ref().map(|p| p.as_slice()).unwrap_or(&[]);
        println!("tx {}: {:?}", idx, plaintext);
    }

    Ok(())
}
