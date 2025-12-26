# TrX2

Threshold-encrypted transaction flow for blockchain networks, built on Tess.

This crate wires:
- Tess threshold encryption (silent setup)
- KZG batch commitments and openings
- Client Ed25519 transaction signatures
- Validator BLS signature helpers

## End-to-End Workflow
1. **Setup**: Generate a trusted setup (SRS + kappa contexts).
2. **Epoch DKG**: Run DKG to produce validator shares and an aggregate public key.
3. **Client encrypt + sign**: Client encrypts payload and signs
   `hash(ciphertext.payload || associated_data)` with Ed25519.
4. **Mempool**: Nodes verify the client signature and store encrypted txs.
5. **Batch commit + proofs**: Build a batch polynomial, commit with KZG, and
   generate per-tx KZG openings (eval proofs).
6. **Partial decryptions**: Validators produce decryption shares per tx.
7. **Combine + decrypt**: Verify KZG eval proofs against the batch commitment,
   then combine shares once the threshold is met.

## Architecture Map
```
client -> encrypt + sign (Ed25519)
node   -> verify_ciphertext -> mempool
node   -> batch -> compute_digest + compute_eval_proofs (KZG)
validator -> generate_partial_decryption
leader -> combine_and_decrypt (verifies KZG proofs, aggregates shares)
```

```
┌─────────────────────────────────────────────────────────┐
│  Client Layer                                           │
│  • Encrypt transactions with Ed25519 signatures         │
│  • Submit to network via SubmitEncryptedTx              │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│  Mempool Layer                                          │
│  • Validate ciphertext and signatures                   │
│  • Queue transactions with bounded size                 │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│  Consensus Layer                                        │
│  • Propose batches with KZG commitments                 │
│  • Validators generate partial decryptions              │
│  • Combine shares to decrypt batch                      │
└─────────────────────────────────────────────────────────┘
```

## Key Types
- `EncryptedTransaction`: Tess ciphertext + associated data + Ed25519 signature.
- `BatchCommitment`: KZG commitment to the batch polynomial.
- `EvalProof`: KZG opening `(point, value, proof)` for each tx.
- `PartialDecryption`: Validator share for a single tx.

## Core APIs
### Setup and DKG
- `TrxCrypto::new(rng, parties, threshold)`
- `generate_trusted_setup(rng, max_batch_size, max_contexts)`
- `run_dkg(rng, validators, threshold, setup)`

### Client Encryption
- `encrypt_transaction(ek, payload, associated_data, signing_key)`
- `verify_ciphertext(tx)`

### Batch Operations
- `compute_digest(batch, context, setup)` -> `BatchCommitment`
- `compute_eval_proofs(batch, context, setup)` -> `Vec<EvalProof>`
- `generate_partial_decryption(share, commitment, context, tx_index, ciphertext)`
- `combine_and_decrypt(partials, eval_proofs, batch, threshold, setup, commitment, agg_key)`

### Validator Signatures (BLS)
- `sign_validator_vote`
- `verify_validator_vote`
- `sign_validator_share`
- `verify_validator_share`

## Usage Example
``` rust
let trx = TrxCrypto::<PairingEngine>::new(&mut rng, parties, threshold)?;
let setup = trx.generate_trusted_setup(&mut rng, max_batch, max_contexts)?;
let setup = Arc::new(setup);
let epoch = trx.run_dkg(&mut rng, &validators, threshold as u32, setup.clone())?;

let encrypted = trx.encrypt_transaction(&epoch.public_key, payload, aad, &client_key)?;
let batch = vec![encrypted];
let context = DecryptionContext { block_height: 1, context_index: 0 };
let commitment = TrxCrypto::<PairingEngine>::compute_digest(&batch, &context, &setup)?;
let eval_proofs = TrxCrypto::<PairingEngine>::compute_eval_proofs(&batch, &context, &setup)?;

// collect partial decryptions and combine
let results = trx.combine_and_decrypt(
    partials,
    &eval_proofs,
    &batch,
    threshold as u32,
    &setup,
    &commitment,
    &epoch.public_key.agg_key,
)?;
```

## E2E Toy Flow (Small Chain)
Assume a chain with 4 validators (V0..V3), threshold=2 (need 3 shares). One
user submits a confidential transaction.

### Example (Single File)
``` rust
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand::thread_rng;
use trx::{
    DecryptionContext, EncryptedMempool, PairingEngine, TrxCrypto, ValidatorId,
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
```

Each validator stores its `SecretKeyShare` from `epoch.validator_shares`.

### 2) Client submits an encrypted tx
Who: user / wallet  
Calls:
- `encrypt_transaction`
- (optional) `verify_ciphertext` locally

``` rust
let client_key = SigningKey::generate(&mut rand::rngs::OsRng);
let tx = trx.encrypt_transaction(
    &epoch.public_key,
    b"pay 10 to bob",
    b"nonce:123",
    &client_key,
)?;
```

The client sends `tx` to a node (mempool).

### 3) Mempool admission
Who: validator node  
Calls:
- `verify_ciphertext`
- `EncryptedMempool::add_encrypted_tx`

``` rust
TrxCrypto::<PairingEngine>::verify_ciphertext(&tx)?;
mempool.add_encrypted_tx(tx)?;
```

### 4) Block proposal and batch precompute
Who: block proposer  
Calls:
- `get_batch`
- `compute_digest`
- `compute_eval_proofs`

``` rust
let batch = mempool.get_batch(32);
let context = DecryptionContext { block_height: 100, context_index: 0 };
let commitment = TrxCrypto::<PairingEngine>::compute_digest(&batch, &context, &setup)?;
let eval_proofs = TrxCrypto::<PairingEngine>::compute_eval_proofs(&batch, &context, &setup)?;
```

These values are included in the proposal or broadcast alongside it.

### 5) Validators produce decryption shares
Who: each validator  
Calls:
- `generate_partial_decryption`
- (optional) `sign_validator_share`

``` rust
let share = epoch.validator_shares.get(&validator_id).unwrap();
let pd = TrxCrypto::<PairingEngine>::generate_partial_decryption(
    share,
    &commitment,
    &context,
    tx_index,
    &batch[tx_index].ciphertext,
)?;
```

### 6) Leader combines shares and decrypts
Who: leader / aggregator  
Calls:
- `combine_and_decrypt`

``` rust
let results = trx.combine_and_decrypt(
    partials,
    &eval_proofs,
    &batch,
    2,
    &setup,
    &commitment,
    &epoch.public_key.agg_key,
)?;
```

`results[i].plaintext` now holds the decrypted payload for tx `i` once the
threshold is met.

## Batch Commitment Details
- The batch polynomial is built from per-tx scalar commitments derived from
  `hash(context || ciphertext.payload || associated_data)`.
- KZG commit is computed against the trusted SRS in `TrustedSetup`.
- Eval proofs are KZG openings at points `x = 1..batch_len`.

## Decryption Share Validation
- `combine_and_decrypt` validates:
  - context consistency across shares
  - eval proofs match the provided `BatchCommitment`
  - eval proofs open at expected points
  - threshold is met before aggregation

## Signatures
- **Client txs**: Ed25519. Verified in `verify_ciphertext`.
- **Validator votes/shares**: BLS helpers in `signatures.rs`; consensus layer
  decides how and when to enforce them.

## Dependencies
- `tess` via local path `../Tess` (must include KZG opening support).

## Configuration Notes
- `threshold` must be `< parties` and parties should be a power of two (Tess).
- Batch size must fit the SRS: `batch.len() + 1 <= setup.srs.powers_of_g.len()`.
- Ed25519 signatures use a 32-byte hash of payload + associated data.

## Error Handling
- Most crypto errors map to `TrxError::Backend`.
- Validation failures return `TrxError::InvalidInput` or `InvalidConfig`.

