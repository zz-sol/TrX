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

## End-to-End Workflow
1. **Setup**: Generate a global setup (SRS), then derive an epoch setup (kappa contexts).
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

### Installation

Add TrX to your `Cargo.toml`:
```toml
[dependencies]
trx = { git = "https://github.com/zz-sol/TrX" }
```

### CLI Tool

TrX includes a command-line interface for testing and development:

```bash
# Build the CLI
cargo build --release --bin trx

# Run the demo (4 validators, threshold 2, 3 transactions)
./target/release/trx demo

# Customize demo parameters
./target/release/trx demo --num-validators 8 --threshold 5 --num-txs 10

# View all available commands
./target/release/trx --help
```

Available commands:
- `setup` - Generate epoch setup (global SRS + kappa contexts)
- `keygen-encryption` - Generate validator threshold keys (silent setup)
- `keygen-signing` - Generate validator BLS signing keys
- `aggregate-keys` - Aggregate validator public keys
- `encrypt` - Encrypt a transaction
- `commit` - Compute batch commitment
- `partial-decrypt` - Generate partial decryption
- `decrypt` - Combine shares and decrypt
- `demo` - Run full end-to-end workflow

All commands support JSON input/output for easy integration.

## SDK Usage 

The SDK provides a high-level, phase-based API that simplifies encrypted mempool integration:

```rust
use trx::TrxMinion;
use tess::PairingEngine;
use ed25519_dalek::SigningKey;
use rand::thread_rng;

fn main() -> Result<(), trx::TrxError> {
    let mut rng = thread_rng();

    // Create minion (5 validators, 3 threshold)
    let minion = TrxMinion::<PairingEngine>::new(&mut rng, 5, 3)?;

    // Phase 1: Setup
    let global_setup = minion.setup().generate_global_setup(&mut rng, 128)?;
    let setup = minion
        .setup()
        .generate_epoch_setup(&mut rng, 1, 1000, global_setup.clone())?;

    // Phase 2: Silent key generation
    let validators: Vec<u32> = (0..5).collect();
    let validator_keypairs: Vec<_> = validators
        .iter()
        .map(|&id| minion.validator().keygen_single_validator(&mut rng, id))
        .collect::<Result<Vec<_>, _>>()?;
    let public_keys: Vec<_> = validator_keypairs
        .iter()
        .map(|kp| kp.public_key.clone())
        .collect();
    let epoch_keys = minion.setup().aggregate_epoch_keys(
        &public_keys,
        3,
        setup.clone()
    )?;

    // Phase 3: Client encryption
    let signing_key = SigningKey::generate(&mut rng);
    let encrypted_tx = minion.client().encrypt_transaction(
        &epoch_keys.public_key,
        b"secret transaction data",
        b"public metadata",
        &signing_key,
    )?;

    // Phase 4: Mempool management
    let mut mempool = minion.mempool().create_mempool(128);
    mempool.add_encrypted_tx(encrypted_tx)?;

    // Phase 5: Batch commitment
    let batch = mempool.get_batch(10);
    let context = trx::DecryptionContext {
        block_height: 1,
        context_index: 0,
    };
    let (commitment, proofs) = minion.proposer().create_batch_commitment(
        &batch,
        &context,
        &setup,
    )?;

    // Phase 6: Threshold decryption
    let results = minion.decryption().decrypt_batch(
        &batch,
        &commitment,
        &proofs,
        &context,
        &validator_keypairs,
        3,
        &setup,
        &epoch_keys.public_key,
    )?;

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
let commitment = TrxCrypto::<PairingEngine>::compute_digest(&batch, &context, &epoch_setup)?;
let eval_proofs = TrxCrypto::<PairingEngine>::compute_eval_proofs(&batch, &context, &epoch_setup)?;
// Broadcast commitment and eval_proofs with the proposal
```

### Validator: Generate Decryption Share
```rust
// Each validator uses their own secret share (generated during silent setup).
let share = &my_secret_share;
let pd = trx.validator().generate_signed_partial_decryption(
    &signing_key,
    share,
    &commitment,
    &context,
    tx_index,
    &batch[tx_index].ciphertext,
    &batch[tx_index].associated_data,
)?;
```

### Leader: Combine and Decrypt
```rust
let batch_proofs = BatchProofs::new(commitment, eval_proofs);
let batch_ctx = BatchContext::new(batch, context, batch_proofs);
let results = trx.decryption().combine_and_decrypt_signed(
    partials,
    &batch_ctx,
    threshold as u32,
    &epoch_setup,
    &epoch.public_key.agg_key,
)?;
// results[i].plaintext contains the decrypted payload
```

## Serialization Support

All TrX and Tess types support JSON serialization via serde:

```rust
use serde_json;
use trx::{BatchCommitment, BatchProofs, EncryptedTransaction, EvalProof, PartialDecryption};

// Serialize encrypted transaction to JSON
let json = serde_json::to_string(&encrypted_tx)?;

// Deserialize from JSON
let tx: EncryptedTransaction<PairingEngine> = serde_json::from_str(&json)?;

// Works with all cryptographic types
let commitment_json = serde_json::to_string(&commitment)?;
let proof_json = serde_json::to_string(&eval_proof)?;
let share_json = serde_json::to_string(&partial_decryption)?;
```

## Architecture

### System Layers
```
┌─────────────────────────────────────────────────────────┐
│  Client Layer                                           │
│  • Encrypt transactions, sign with Ed25519 signatures   │
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

## Core APIs

### High-Level SDK

The SDK provides phase-based interfaces in [src/sdk](src/sdk):
- **`TrxMinion`**: Main client wrapping all phases
- **`SetupPhase`**: Global/epoch setup and key aggregation
- **`ValidatorPhase`**: Silent key generation
- **`ClientPhase`**: Transaction encryption
- **`MempoolPhase`**: Transaction queue management
- **`ProposerPhase`**: Batch commitment and proof generation
- **`DecryptionPhase`**: Threshold decryption

### Low-Level Cryptographic API

All core functionality is implemented in [src/crypto/tess/engine.rs](src/crypto/tess/engine.rs).

#### Setup and Silent Key Generation
| Function | Description |
|----------|-------------|
| `TrxCrypto::new(rng, parties, threshold)` | Initialize the cryptographic system |
| `generate_global_setup(rng, max_batch_size)` | Generate SRS (reusable across epochs) |
| `generate_epoch_setup(rng, epoch_id, max_contexts, global_setup)` | Derive kappa contexts for an epoch |
| `keygen_single_validator(rng, validator_id)` | Each validator independently generates their own key pair (silent setup) |
| `aggregate_epoch_keys(public_keys, threshold, epoch_setup)` | Non-interactively aggregate validator public keys into epoch keys |

#### Client Operations
| Function | Description |
|----------|-------------|
| `encrypt_transaction(ek, payload, associated_data, signing_key)` | Encrypt and sign a transaction |
| `verify_ciphertext(tx)` | Verify transaction signature and structure |

#### Batch Operations
| Function | Return Type | Description |
|----------|-------------|-------------|
| `compute_digest(batch, context, epoch_setup)` | `BatchCommitment` | KZG commit to batch polynomial |
| `compute_eval_proofs(batch, context, epoch_setup)` | `Vec<EvalProof>` | Generate per-tx KZG openings |
| `generate_partial_decryption(share, commitment, context, tx_index, ciphertext)` | `PartialDecryption` | Validator creates decryption share |
| `combine_and_decrypt(partials, batch_ctx, threshold, epoch_setup, agg_key)` | `Vec<DecryptionResult>` | Verify proofs and combine shares |

#### Validator Signatures (BLS)

Public API in [src/crypto/signatures.rs](src/crypto/signatures.rs):

| Function | Description |
|----------|-------------|
| `sign_validator_vote(signing_key, vote, partial_decryption)` | Sign consensus vote with optional PD |
| `verify_validator_vote(verify_key, signature, vote, partial_decryption)` | Verify validator vote signature |
| `sign_validator_share(signing_key, block_hash, share)` | Sign partial decryption share |
| `verify_validator_share(verify_key, signature, block_hash, share)` | Verify PD signature |
| `validator_vote_message(vote, partial_decryption)` | Compute BLAKE3 message for vote signing |
| `validator_share_message(block_hash, share)` | Compute BLAKE3 message for share signing |

Type aliases:
- `ValidatorSigningKey` - BLS secret key
- `ValidatorVerifyKey` - BLS compressed public key
- `ValidatorSignature` - BLS compressed signature

#### Network Messages

The `TrxMessage` enum ([src/network/messages.rs](src/network/messages.rs)) defines protocol messages:
- `SubmitEncryptedTx` - Client submits transaction
- `ProposeBlock` - Proposer broadcasts block
- `VoteWithDecryption` - Validator vote + optional PD
- `RequestDecryptionShares` - Request PDs for batch
- `DecryptionShare` - Validator responds with PD

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## References

- [TrX: Encrypted Mempools in High Performance BFT Protocols](https://eprint.iacr.org/2025/2032)
- [ePrint Archive Paper: Threshold Encryption with Silent Setup](https://eprint.iacr.org/2024/263)
- [Tess implementation](https://github.com/zz-sol/Tess)
