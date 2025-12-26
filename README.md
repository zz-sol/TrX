# TrX2

**TrX** (Threshold Encryption Protocol) is a Rust implementation of a threshold encryption system designed for MEV protection in blockchain environments. Built on top of the [Tess](https://github.com/tess-threshold-encryption/tess) threshold encryption library, TrX2 provides a complete scaffolding for encrypted transaction processing with batch decryption capabilities.

## Overview

TrX2 enables secure transaction encryption where:
- **Clients** encrypt transactions using a shared public key before submission
- **Validators** store encrypted transactions in a mempool without learning their contents
- **Consensus** triggers batch decryption using threshold cryptography after ordering
- **MEV Protection** is achieved by hiding transaction data until after finalization

### Key Features

- **Threshold Encryption**: Built on Tess library with configurable threshold parameters
- **KZG Commitments**: Batch digest and evaluation proofs using Kate-Zaverucha-Goldberg polynomial commitments
- **Dual Signature Schemes**:
  - Ed25519 for client transaction signatures
  - BLS for validator consensus signatures
- **Precomputation Cache**: Optimized digest and proof computation for reduced consensus latency
- **Bounded Mempool**: Memory-safe transaction queue with configurable limits
- **DKG Support**: Distributed key generation for validator epoch keys

## Architecture

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

## Current Status

✅ **Complete Implementation** (all phases finished):
- Core encryption/decryption interfaces
- KZG polynomial commitments and evaluation proofs
- Trusted setup generation and DKG
- Transaction and validator signature helpers
- Precomputation engine
- Encrypted mempool
- Comprehensive test suite

## Development

### Requirements

- **Rust**: Stable toolchain (1.70+)
- **Tess**: Local checkout at `../Tess` (path dependency)
  - Ensure Tess includes KZG opening changes

### Common Commands

```bash
# Format code
cargo fmt --all -- --check

# Run linter
cargo clippy --all

# Run tests
cargo test --all

# Build release
cargo build --release
```

### Running Tests

```bash
# All tests
cargo test

# Specific test
cargo test happy_path_encrypt_decrypt

# With output
cargo test -- --nocapture
```

## Usage Example

```rust
use trx2::*;
use ed25519_dalek::SigningKey;
use rand::thread_rng;

// Initialize crypto engine
let mut rng = thread_rng();
let parties = 5;
let threshold = 3;
let crypto = TrxCrypto::<Bn254>::new(&mut rng, parties, threshold)?;

// Generate trusted setup
let setup = crypto.generate_trusted_setup(&mut rng, 128, 1000)?;

// Run DKG for epoch keys
let validators = vec![0, 1, 2, 3, 4];
let epoch_keys = crypto.run_dkg(&mut rng, &validators, threshold as u32, Arc::new(setup))?;

// Client encrypts transaction
let signing_key = SigningKey::generate(&mut rng);
let payload = b"secret transaction data";
let encrypted_tx = crypto.encrypt_transaction(
    &epoch_keys.public_key,
    payload,
    b"metadata",
    &signing_key,
)?;

// Validators perform batch decryption (simplified)
let batch = vec![encrypted_tx];
let context = DecryptionContext { block_height: 1, context_index: 0 };
let commitment = TrxCrypto::<Bn254>::compute_digest(&batch, &context, &epoch_keys.setup)?;
// ... generate partial decryptions, then combine
```

## Implementation Notes

- **Batch Verification**: `combine_and_decrypt` verifies KZG evaluation proofs against the supplied `BatchCommitment` to ensure batch integrity
- **Consensus Integration**: Validator BLS signature handling for votes and shares is provided, but full consensus-layer integration is expected outside this crate
- **Context Management**: Each decryption context is scoped by `(block_height, context_index)` to prevent replay attacks
- **Precomputation**: The precomputation engine caches digest and proof computations keyed by batch hash for performance

## Documentation

- [spec.md](spec.md) - Complete protocol specification (30 sections)
- [plan.md](plan.md) - Implementation roadmap and progress
- API documentation: `cargo doc --open`

## License

[Add license information]

## Contributing

[Add contribution guidelines]
