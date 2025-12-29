# TrX Protocol Implementation Specification

## 1. System Overview

### 1.1 Core Components
```
┌─────────────────────────────────────────────────────────┐
│                     Application Layer                   │
├─────────────────────────────────────────────────────────┤
│                    Consensus Protocol                   │
│                    (with TrX hooks)                     │
├─────────────────────────────────────────────────────────┤
│                  TrX Encryption Layer                   │
│  ┌──────────┐  ┌──────────┐  ┌────────────────────┐     │
│  │  Setup   │  │  Batch   │  │   Precomputation   │     │
│  │  Manager │  │  Crypto  │  │      Engine        │     │
│  └──────────┘  └──────────┘  └────────────────────┘     │
├─────────────────────────────────────────────────────────┤
│                   Encrypted Mempool                     │
└─────────────────────────────────────────────────────────┘
```

## 2. Data Structures

### 2.1 Core Types
```rust
// Configuration constants
pub const MAX_BATCH_SIZE: usize = 128;
pub const MAX_CONTEXTS_PER_EPOCH: usize = 100_000;
pub const THREADS_FOR_CRYPTO: usize = 16;

// Basic cryptographic types
pub struct PublicKey {
    agg_key: AggregateKey,
}

pub struct SecretKeyShare {
    share: Fr,
    index: u32,
}

pub struct EncryptedTransaction {
    ciphertext: TessCiphertext,
    associated_data: Vec<u8>,
    // Client Ed25519 signature over hash(ciphertext.payload || associated_data)
    vk_sig: TxPublicVerifyKey,
    signature: TxSignature,
}

pub struct PartialDecryption {
    pd: G2Element,
    validator_id: ValidatorId,
    context: DecryptionContext,
    tx_index: usize,
}

pub struct DecryptionContext {
    block_height: u64,
    context_index: u32,  // κ index
}

pub struct BatchCommitment {
    com: G1Element,      // KZG commitment to batch polynomial
    polynomial_degree: u32,
}

pub struct EvalProof {
    point: Fr,
    value: Fr,
    proof: G1Element,
}

pub struct BatchContext<'a> {
    batch: &'a [EncryptedTransaction],
    context: &'a DecryptionContext,
    commitment: &'a BatchCommitment,
    eval_proofs: &'a [EvalProof],
}
```

### 2.2 Setup Structures
```rust
pub struct GlobalSetup {
    srs: SRS, // KZG parameters (reusable across epochs)
}

pub struct EpochSetup {
    epoch_id: u64,
    kappa_setups: Vec<KappaSetup>, // Randomized KZG setups
    global_setup: Arc<GlobalSetup>,
}

pub struct TrustedSetup { // Legacy combined setup
    srs: SRS,
    kappa_setups: Vec<KappaSetup>,
}

pub struct KappaSetup {
    index: u32,
    elements: Vec<G1Element>,  // [g^(κ·τ^j)] for j in 0..MAX_BATCH_SIZE
    used: AtomicBool,
}

pub struct EpochKeys {
    epoch_id: u64,
    public_key: PublicKey,
    // Note: validator shares are stored by validators themselves (silent setup)
    epoch_setup: Arc<EpochSetup>,
}
```

## 3. Cryptographic Layer

### 3.1 Setup Phase
```rust
pub trait SetupManager {
    /// One-time global setup (or distributed ceremony)
    fn generate_global_setup(max_batch_size: usize) -> Result<GlobalSetup>;

    /// Per-epoch setup derived from the global setup
    fn generate_epoch_setup(
        epoch_id: u64,
        max_contexts: usize,
        global_setup: Arc<GlobalSetup>,
    ) -> Result<EpochSetup>;

    /// Silent key generation: each validator independently generates their own key pair
    fn keygen_single_validator(
        validator_id: ValidatorId,
    ) -> Result<ValidatorKeyPair>;

    /// Non-interactive public key aggregation to create epoch keys
    fn aggregate_epoch_keys(
        validator_public_keys: Vec<PublicKey>,
        threshold: u32,
        epoch_setup: Arc<EpochSetup>,
    ) -> Result<EpochKeys>;

    /// Verify setup integrity
    fn verify_global_setup(setup: &GlobalSetup) -> Result<()>;
    fn verify_epoch_setup(setup: &EpochSetup) -> Result<()>;
}
```

### 3.2 BLS Signature Functions (Public API)

The following BLS signature functions are exposed as part of the public API for building custom consensus protocols:

```rust
/// Validator's BLS secret signing key
pub type ValidatorSigningKey = SecretKey;

/// Validator's compressed BLS public verification key
pub type ValidatorVerifyKey = solana_bls_signatures::PubkeyCompressed;

/// Validator's compressed BLS signature
pub type ValidatorSignature = solana_bls_signatures::SignatureCompressed;

/// Sign a validator vote (with optional partial decryption)
pub fn sign_validator_vote<B: PairingBackend>(
    signing_key: &ValidatorSigningKey,
    vote: &[u8],
    partial_decryption: Option<&PartialDecryption<B>>,
) -> ValidatorSignature;

/// Verify a validator vote signature
pub fn verify_validator_vote<B: PairingBackend>(
    verify_key: &ValidatorVerifyKey,
    vote: &[u8],
    partial_decryption: Option<&PartialDecryption<B>>,
    signature: &ValidatorSignature,
) -> Result<(), TrxError>;

/// Sign a validator decryption share
pub fn sign_validator_share<B: PairingBackend>(
    signing_key: &ValidatorSigningKey,
    share: &PartialDecryption<B>,
) -> ValidatorSignature;

/// Verify a validator decryption share signature
pub fn verify_validator_share<B: PairingBackend>(
    verify_key: &ValidatorVerifyKey,
    share: &PartialDecryption<B>,
    signature: &ValidatorSignature,
) -> Result<(), TrxError>;
```

These functions are available in the public API via:
```rust
use trx::{
    sign_validator_vote, verify_validator_vote,
    sign_validator_share, verify_validator_share,
    ValidatorSigningKey, ValidatorVerifyKey, ValidatorSignature,
}
```

### 3.3 Encryption Interface
```rust
pub trait TransactionEncryption {
    /// Client-side encryption
    fn encrypt_transaction(
        ek: &PublicKey,
        payload: &[u8],
        associated_data: &[u8],
        signing_key: &Ed25519SigningKey,
    ) -> Result<EncryptedTransaction>;

    /// Verify ciphertext validity
    fn verify_ciphertext(
        ct: &EncryptedTransaction,
    ) -> Result<()>;
}
```

### 3.4 Batch Decryption
```rust
pub trait BatchDecryption {
    /// Compute digest for batch (public operation)
    fn compute_digest(
        batch: &[EncryptedTransaction],
        context: &DecryptionContext,
        setup: &EpochSetup,
    ) -> Result<BatchCommitment>;
    
    /// Generate partial decryption share
    fn generate_partial_decryption(
        sk_share: &SecretKeyShare,
        commitment: &BatchCommitment,
        context: &DecryptionContext,
        tx_index: usize,
        ciphertext: &Ciphertext,
    ) -> Result<PartialDecryption>;
    
    /// Verify partial decryption
    fn verify_partial_decryption(
        pd: &PartialDecryption,
        commitment: &BatchCommitment,
        public_keys: &HashMap<ValidatorId, PublicKey>,
    ) -> Result<()>;
    
    /// Compute evaluation proofs (expensive, public)
    fn compute_eval_proofs(
        batch: &[EncryptedTransaction],
        context: &DecryptionContext,
        setup: &EpochSetup,
    ) -> Result<Vec<EvalProof>>;
    
    /// Combine shares and decrypt batch
    fn combine_and_decrypt(
        partial_decryptions: Vec<PartialDecryption>,
        batch_ctx: BatchContext,
        threshold: u32,
        setup: &EpochSetup,
        agg_key: &AggregateKey,
    ) -> Result<Vec<DecryptionResult>>;
}
```

## 4. Consensus Integration

### 4.1 Enhanced Consensus Interface
```rust
pub trait TrxConsensus {
    /// Propose block with encrypted transactions
    fn propose_encrypted_block(
        &mut self,
        encrypted_txs: Vec<EncryptedTransaction>,
    ) -> Result<Block>;
    
    /// Vote handler with precomputation
    fn on_proposal_received(
        &mut self,
        block: &Block,
    ) -> Result<()> {
        // Start async precomputation
        self.start_precomputation(block)?;
        // Continue with normal voting
        self.vote_on_block(block)
    }
    
    /// Fast-path: final vote with decryption share
    fn send_final_vote_with_decryption(
        &mut self,
        block: &Block,
        vote: Vote,
        partial_decryption: PartialDecryption,
    ) -> Result<()>;
    
    /// Collect and aggregate decryption shares
    fn collect_decryption_shares(
        &mut self,
        block: &Block,
        timeout: Duration,
    ) -> Result<Vec<PartialDecryption>>;
}
```

### 4.2 Precomputation Engine
```rust
pub struct PrecomputationEngine {
    thread_pool: ThreadPool,
    cache: LruCache<BlockHash, PrecomputedData>,
}

pub struct PrecomputedData {
    digest: BatchCommitment,
    eval_proofs: Vec<EvalProof>,
    computation_time: Duration,
}

impl PrecomputationEngine {
    /// Async precomputation during consensus
    pub async fn precompute(
        &self,
        block: &Block,
        setup: &EpochSetup,
    ) -> Result<PrecomputedData> {
        let (digest_handle, proofs_handle) = tokio::join!(
            self.compute_digest_async(block, setup),
            self.compute_proofs_async(block, setup)
        );
        
        Ok(PrecomputedData {
            digest: digest_handle?,
            eval_proofs: proofs_handle?,
            computation_time: start.elapsed(),
        })
    }
}
```

## 5. Mempool Layer

### 5.1 Encrypted Mempool
```rust
pub struct EncryptedMempool {
    encrypted_txs: PriorityQueue<EncryptedTransaction>,
    plaintext_cache: Option<LruCache<TxHash, Transaction>>, // For debugging
    max_size: usize,
}

impl EncryptedMempool {
    /// Add encrypted transaction
    pub fn add_encrypted_tx(
        &mut self,
        tx: EncryptedTransaction,
    ) -> Result<()> {
        // Verify signature and format
        verify_ciphertext(&tx)?;
        
        // Add to priority queue (ordered by gas price if visible)
        self.encrypted_txs.push(tx);
        
        Ok(())
    }
    
    /// Get batch for block proposal
    pub fn get_batch(
        &mut self,
        max_size: usize,
    ) -> Vec<EncryptedTransaction> {
        let mut batch = Vec::new();
        while batch.len() < max_size && !self.encrypted_txs.is_empty() {
            batch.push(self.encrypted_txs.pop().unwrap());
        }
        batch
    }
}
```

## 6. Network Protocol

### 6.1 Message Types (Public API)

The `TrxMessage` enum is exposed as part of the public API for building custom network layers:

```rust
pub enum TrxMessage<B: PairingBackend> {
    // Transaction submission
    SubmitEncryptedTx(EncryptedTransaction<B>),

    // Consensus messages
    ProposeBlock {
        block: Block,
        encrypted_txs: Vec<EncryptedTransaction<B>>,
    },

    VoteWithDecryption {
        vote: Vote,
        partial_decryption: Option<PartialDecryption<B>>,
        validator_sig: ValidatorSignature,
        validator_vk: ValidatorVerifyKey,
    },

    // Decryption coordination
    RequestDecryptionShares {
        block_hash: Hash,
        context: DecryptionContext,
    },

    DecryptionShare {
        block_hash: Hash,
        share: PartialDecryption<B>,
        validator_sig: ValidatorSignature,
        validator_vk: ValidatorVerifyKey,
    },
}
```

The message types are available in the public API via:
```rust
use trx::TrxMessage;
```

## 7. Serialization Support

All TrX and Tess types support JSON serialization via serde:

```rust
use serde_json;
use trx::sdk::setup::*;

// Setup phase
let setup_output = run_silent_setup(4, 2)?;

// Serialize to JSON
let json = serde_json::to_string(&setup_output)?;

// Deserialize from JSON
let recovered: SetupOutput = serde_json::from_str(&json)?;
```

Serialization is available for:
- All cryptographic types (curve points, field elements, target groups)
- Setup outputs (public keys, trusted parameters)
- Encrypted transactions and ciphertexts
- Partial decryptions and batch commitments
- Validator keys and signatures

## 8. Client SDK (Implemented)

The TrX SDK provides a modular 6-phase architecture for building encrypted transaction systems.

### 8.1 SDK Modules

```rust
use trx::sdk::{
    setup,      // Phase 1: Silent setup
    validator,  // Phase 2: Validator operations
    client,     // Phase 3: Client encryption
    mempool,    // Phase 4: Mempool management
    proposer,   // Phase 5: Block proposal
    decryption, // Phase 6: Batch decryption
};
```

### 8.2 Phase 1: Setup

Silent setup protocol with non-interactive key generation:

```rust
use trx::sdk::setup::*;

// Generate silent setup for 4 validators with threshold 2
let setup_output = run_silent_setup(4, 2)?;

// Extract components
let public_key = setup_output.public_key;
let validator_keys = setup_output.validator_keys;
let trusted_setup = setup_output.trusted_setup;
```

### 8.3 Phase 2: Validator

Validator key management and signature operations:

```rust
use trx::sdk::validator::*;

// Create validator instance
let validator = Validator::new(
    0,  // validator_id
    validator_keys[0].clone(),
    public_key.clone(),
);

// Generate BLS signing key for consensus
let bls_sk = validator.generate_bls_signing_key();
let bls_vk = validator.get_bls_verify_key(&bls_sk);
```

### 8.4 Phase 3: Client

Client-side transaction encryption:

```rust
use trx::sdk::client::*;

// Create client
let client = TrxMinion::new(public_key.clone());

// Encrypt transaction
let encrypted_tx = client.encrypt_transaction(
    b"transaction payload",
    b"associated data",
)?;
```

### 8.5 Phase 4: Mempool

Encrypted mempool management:

```rust
use trx::sdk::mempool::*;

// Create mempool
let mut mempool = TrxMempool::new();

// Add encrypted transaction
mempool.add_transaction(encrypted_tx)?;

// Get batch for proposal
let batch = mempool.get_batch(10);
```

### 8.6 Phase 5: Proposer

Block proposal with batch commitment:

```rust
use trx::sdk::proposer::*;

// Create proposer
let proposer = TrxProposer::new(
    public_key.clone(),
    trusted_setup.clone(),
);

// Propose batch
let proposal = proposer.propose_batch(
    batch,
    block_height,
    context_index,
)?;
```

### 8.7 Phase 6: Decryption

Threshold decryption with partial shares:

```rust
use trx::sdk::decryption::*;

// Create decryptor
let decryptor = TrxDecryptor::new(
    public_key.clone(),
    trusted_setup.clone(),
    threshold,
);

// Generate partial decryption (validator)
let partial = decryptor.generate_partial_decryption(
    &validator_keys[0],
    &proposal.commitment,
    &proposal.context,
    0,  // tx_index
    &batch[0].ciphertext,
)?;

// Combine shares and decrypt (after collecting threshold shares)
let decrypted_batch = decryptor.decrypt_batch(
    partial_decryptions,
    &batch,
    &proposal.commitment,
    &proposal.context,
)?;
```

## 9. CLI Tool

TrX includes a command-line interface for testing and development. The CLI binary is located at `src/bin/trx.rs`.

### 9.1 Building

```bash
cargo build --release --bin trx
./target/release/trx --help
```

### 9.2 Available Commands

| Command | Description |
|---------|-------------|
| `demo` | Run full end-to-end demo workflow |
| `setup` | Generate silent setup parameters |
| `keygen` | Generate validator keypair |
| `aggregate` | Aggregate validator keys into public key |
| `encrypt` | Encrypt a transaction |
| `propose` | Propose a batch with commitment |
| `partial-decrypt` | Generate partial decryption share |
| `decrypt` | Combine shares and decrypt batch |

### 9.3 Demo Command

Run a complete encrypted transaction workflow:

```bash
# Run with default parameters (4 validators, threshold 2, 3 transactions)
./target/release/trx demo

# Run with custom parameters
./target/release/trx demo --num-validators 8 --threshold 5 --num-txs 10
```

The demo command executes all 6 phases:
1. Silent setup
2. Validator key generation
3. Transaction encryption
4. Mempool management and batch proposal
5. Partial decryption generation
6. Threshold decryption

### 9.4 JSON I/O

All CLI commands support JSON input/output for integration with other tools:

```bash
# Setup outputs JSON
./target/release/trx setup --num-validators 4 --threshold 2 > setup.json

# Encrypt using setup parameters
cat setup.json | ./target/release/trx encrypt --payload "my transaction"
```
