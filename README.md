# TrX: Encrypted Mempools in High Performance BFT Protocols

![CI](https://github.com/zz-sol/TrX/actions/workflows/ci.yml/badge.svg?branch=main)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

A production-ready threshold-encrypted transaction system for blockchain networks, built on

- [TrX: Encrypted Mempools in High Performance BFT Protocols](https://eprint.iacr.org/2025/2032), and 
- [Threshold Encryption with Silent Setup](https://eprint.iacr.org/2024/263).

The overall archtecture follows [TrX paper](https://eprint.iacr.org/2025/2032). We replace the witness encryption scheme in TrX with the one in [Tess paper](https://eprint.iacr.org/2024/263) to achieve non-interactive key generation.

## Acknowledgements
If you use this library in your research, please cite the original papers:
```bibtex
@misc{cryptoeprint:2025/2032,
    author = {Rex Fernando and Guru-Vamsi Policharla and Andrei Tonkikh and Zhuolun Xiang},
    title = {{TrX}: Encrypted Mempools in High Performance {BFT} Protocols},
    howpublished = {Cryptology {ePrint} Archive, Paper 2025/2032},
    year = {2025},
    url = {https://eprint.iacr.org/2025/2032}
}
@misc{garg2024threshold,
    author = {Sanjam Garg and Guru-Vamsi Policharla and Mingyuan Wang},
    title = {Threshold Encryption with Silent Setup},
    howpublished = {Cryptology ePrint Archive, Paper 2024/263},
    year = {2024},
    url = {https://eprint.iacr.org/2024/263}
}
```

## Overview

TrX provides a complete cryptographic infrastructure for confidential transaction processing with threshold decryption. It combines:
- **Tess threshold encryption** with silent setup
- **KZG batch commitments** and openings for efficient proof generation
- **Ed25519 signatures** for client transaction authentication
- **BLS signatures** for validator coordination

## End-to-End Workflow
1. **Setup**: Generate a trusted setup (SRS + kappa contexts).
2. **Silent Setup**: Each validator independently generates their own key pair, then public keys are aggregated non-interactively.
3. **Client encrypt + sign**: Client encrypts payload and signs
   `hash(ciphertext.payload || associated_data)` with Ed25519.
4. **Mempool**: Nodes verify the client signature and store encrypted txs.
5. **Batch commit + proofs**: Build a batch polynomial, commit with KZG, and
   generate per-tx KZG openings (eval proofs).
6. **Partial decryptions**: Validators produce decryption shares per tx.
7. **Combine + decrypt**: Verify KZG eval proofs against the batch commitment,
   then combine shares once the threshold is met.

## Quick Start

Add TrX to your `Cargo.toml`:
```toml
[dependencies]
trx = { git = "https://github.com/zz-sol/TrX" }
```

## Toy Example

This example demonstrates a complete flow with 4 validators (threshold=2, requiring 3 shares) and one confidential transaction.

```rust
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand::thread_rng;
use trx::{
    BatchContext, DecryptionContext, EncryptedMempool, PairingEngine, TrxCrypto, ValidatorId,
};

/// Number of validators in the network
const NUM_VALIDATORS: usize = 4;

/// Threshold number of validators required for decryption (must be < NUM_VALIDATORS)
const THRESHOLD: usize = 2;

/// Maximum number of encrypted transactions per batch/block
/// Also determines the SRS size for KZG commitments
const MAX_BATCH: usize = 32;

/// Number of pre-generated Kappa contexts in the trusted setup
/// Determines how many concurrent batches/contexts can be supported before re-setup
const MAX_CONTEXTS: usize = 16;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    // 1) Bootstrapping (operator)
    let trx = TrxCrypto::<PairingEngine>::new(&mut rng, NUM_VALIDATORS, THRESHOLD)?;
    let setup = Arc::new(trx.generate_trusted_setup(&mut rng, MAX_BATCH, MAX_CONTEXTS)?);

    // 2) Silent Setup: Each validator independently generates their key pair (no interaction)
    let validators: Vec<ValidatorId> = (0..NUM_VALIDATORS as u32).collect();
    let validator_keypairs = validators
        .iter()
        .map(|&validator_id| trx.keygen_single_validator(&mut rng, validator_id))
        .collect::<Result<Vec<_>, _>>()?;

    let validator_secret_shares = validator_keypairs
        .iter()
        .map(|kp| kp.secret_share.clone())
        .collect::<Vec<_>>();

    // Aggregate the public keys non-interactively
    let epoch = trx.aggregate_epoch_keys(validator_keypairs, THRESHOLD as u32, setup.clone())?;

    // 3) Client encrypts + signs
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
            let share = &validator_secret_shares[validator_id];
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
    let batch_ctx = BatchContext {
        batch: &batch,
        context: &context,
        commitment: &commitment,
        eval_proofs: &eval_proofs,
    };
    let results = trx.combine_and_decrypt(
        partials,
        batch_ctx,
        THRESHOLD as u32,
        &setup,
        &epoch.public_key.agg_key,
    )?;

    for (idx, res) in results.iter().enumerate() {
        let plaintext = res.plaintext.as_ref().map(|p| p.as_slice()).unwrap_or(&[]);
        println!("tx {}: {:?}", idx, plaintext);
    }

    Ok(())
}
```

## Detailed Workflow by Role

### Client: Submit Encrypted Transaction
```rust
let client_key = SigningKey::generate(&mut rand::rngs::OsRng);
let tx = trx.encrypt_transaction(
    &epoch.public_key,
    b"pay 10 to bob",
    b"nonce:123",
    &client_key,
)?;
// Send tx to mempool
```

### Node: Mempool Admission
```rust
TrxCrypto::<PairingEngine>::verify_ciphertext(&tx)?;
mempool.add_encrypted_tx(tx)?;
```

### Block Proposer: Create Batch
```rust
let batch = mempool.get_batch(32);
let context = DecryptionContext { block_height: 100, context_index: 0 };
let commitment = TrxCrypto::<PairingEngine>::compute_digest(&batch, &context, &setup)?;
let eval_proofs = TrxCrypto::<PairingEngine>::compute_eval_proofs(&batch, &context, &setup)?;
// Broadcast commitment and eval_proofs with the proposal
```

### Validator: Generate Decryption Share
```rust
// Each validator uses their own secret share (generated during silent setup)
let share = &my_secret_share;
let pd = TrxCrypto::<PairingEngine>::generate_partial_decryption(
    share,
    &commitment,
    &context,
    tx_index,
    &batch[tx_index].ciphertext,
)?;
// Optionally sign with: sign_validator_share(&pd, &bls_key)
```

### Leader: Combine and Decrypt
```rust
let batch_ctx = BatchContext {
    batch: &batch,
    context: &context,
    commitment: &commitment,
    eval_proofs: &eval_proofs,
};
let results = trx.combine_and_decrypt(
    partials,
    batch_ctx,
    threshold as u32,
    &setup,
    &epoch.public_key.agg_key,
)?;
// results[i].plaintext contains the decrypted payload
```

## Architecture

### System Layers
```
┌─────────────────────────────────────────────────────────┐
│  Client Layer                                           │
│  • Encrypt transactions with Ed25519 signatures         │
│  • Submit to network                                    │
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

### Component Flow
```
client    -> encrypt_transaction + sign (Ed25519)
node      -> verify_ciphertext -> mempool
proposer  -> compute_digest + compute_eval_proofs (KZG)
validator -> generate_partial_decryption
leader    -> combine_and_decrypt (verifies KZG proofs, aggregates shares)
```

## Key Types

| Type | Description | Location |
|------|-------------|----------|
| `EncryptedTransaction` | Tess ciphertext + associated data + Ed25519 signature | [src/core/types.rs](src/core/types.rs) |
| `BatchCommitment` | KZG commitment to the batch polynomial | [src/crypto/kzg.rs](src/crypto/kzg.rs) |
| `EvalProof` | KZG opening `(point, value, proof)` for each tx | [src/crypto/kzg.rs](src/crypto/kzg.rs) |
| `PartialDecryption` | Validator share for a single tx | [src/core/types.rs](src/core/types.rs) |
| `BatchContext` | Bundle of `{batch, context, commitment, eval_proofs}` for decryption | [src/core/types.rs](src/core/types.rs) |

## Core APIs

All core functionality is implemented in [src/crypto/trx_crypto.rs](src/crypto/trx_crypto.rs).

### Setup and Silent Key Generation
| Function | Description |
|----------|-------------|
| `TrxCrypto::new(rng, parties, threshold)` | Initialize the cryptographic system |
| `generate_trusted_setup(rng, max_batch_size, max_contexts)` | Generate SRS and kappa contexts |
| `keygen_single_validator(rng, validator_id)` | Each validator independently generates their own key pair (silent setup) |
| `aggregate_epoch_keys(keypairs, threshold, setup)` | Non-interactively aggregate validator public keys into epoch keys |

### Client Operations
| Function | Description |
|----------|-------------|
| `encrypt_transaction(ek, payload, associated_data, signing_key)` | Encrypt and sign a transaction |
| `verify_ciphertext(tx)` | Verify transaction signature and structure |

### Batch Operations
| Function | Return Type | Description |
|----------|-------------|-------------|
| `compute_digest(batch, context, setup)` | `BatchCommitment` | KZG commit to batch polynomial |
| `compute_eval_proofs(batch, context, setup)` | `Vec<EvalProof>` | Generate per-tx KZG openings |
| `generate_partial_decryption(share, commitment, context, tx_index, ciphertext)` | `PartialDecryption` | Validator creates decryption share |
| `combine_and_decrypt(partials, batch_ctx, threshold, setup, agg_key)` | `Vec<DecryptionResult>` | Verify proofs and combine shares |

### Validator Signatures (BLS)
Implemented in [src/crypto/signatures.rs](src/crypto/signatures.rs):
- `sign_validator_vote` / `verify_validator_vote`
- `sign_validator_share` / `verify_validator_share`

## Technical Details

### Signature Schemes
| Component | Scheme | Location | Purpose |
|-----------|--------|----------|---------|
| Client transactions | Ed25519 | [verify_ciphertext](src/crypto/trx_crypto.rs) | Transaction authenticity |
| Validator votes/shares | BLS | [signatures.rs](src/crypto/signatures.rs) | Consensus coordination |

## Configuration

### System Requirements
- `threshold < parties` (typically `parties` is a power of two for Tess)
- Batch size constraint: `batch.len() + 1 <= setup.srs.powers_of_g.len()`
- Ed25519 signatures use 32-byte Blake3 hash

## Project Structure

```
src/
├── core/           # Core types and error definitions
├── crypto/         # Cryptographic operations
│   ├── trx_crypto.rs    # Main TrxCrypto implementation
│   ├── kzg.rs           # KZG commitments and proofs
│   ├── signatures.rs    # BLS validator signatures
│   └── pre_computation.rs
├── mempool/        # Transaction mempool
└── network/        # Network message types

examples/
└── toy_example.rs  # Complete working example

tests/
└── flow.rs         # End-to-end integration tests
```

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## References

- [TrX: Encrypted Mempools in High Performance BFT Protocols](https://eprint.iacr.org/2025/2032)
- [ePrint Archive Paper: Threshold Encryption with Silent Setup](https://eprint.iacr.org/2024/263)
- [Tess implementation](https://github.com/zz-sol/Tess)

