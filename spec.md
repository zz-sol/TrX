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
pub struct TrustedSetup {
    srs: SRS, // KZG parameters
    kappa_setups: Vec<KappaSetup>,   // Randomized KZG setups
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
    setup: Arc<TrustedSetup>,
}
```

## 3. Cryptographic Layer

### 3.1 Setup Phase
```rust
pub trait SetupManager {
    /// One-time trusted setup (or distributed ceremony)
    fn generate_trusted_setup(max_batch_size: usize, max_contexts: usize)
        -> Result<TrustedSetup>;

    /// Silent key generation: each validator independently generates their own key pair
    fn keygen_single_validator(
        validator_id: ValidatorId,
    ) -> Result<ValidatorKeyPair>;

    /// Non-interactive public key aggregation to create epoch keys
    fn aggregate_epoch_keys(
        validator_keypairs: Vec<ValidatorKeyPair>,
        threshold: u32,
        setup: Arc<TrustedSetup>,
    ) -> Result<EpochKeys>;

    /// Verify setup integrity
    fn verify_setup(setup: &TrustedSetup) -> Result<()>;
}
```

### 3.2 Encryption Interface
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

### 3.3 Batch Decryption
```rust
pub trait BatchDecryption {
    /// Compute digest for batch (public operation)
    fn compute_digest(
        batch: &[EncryptedTransaction],
        context: &DecryptionContext,
        setup: &TrustedSetup,
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
        setup: &TrustedSetup,
    ) -> Result<Vec<EvalProof>>;
    
    /// Combine shares and decrypt batch
    fn combine_and_decrypt(
        partial_decryptions: Vec<PartialDecryption>,
        batch_ctx: BatchContext,
        threshold: u32,
        setup: &TrustedSetup,
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
        setup: &TrustedSetup,
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

### 6.1 Message Types
```rust
pub enum TrxMessage {
    // Transaction submission
    SubmitEncryptedTx(EncryptedTransaction),
    
    // Consensus messages
    ProposeBlock {
        block: Block,
        encrypted_txs: Vec<EncryptedTransaction>,
    },
    
    VoteWithDecryption {
        vote: Vote,
        partial_decryption: Option<PartialDecryption>,
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
        share: PartialDecryption,
        validator_sig: ValidatorSignature,
        validator_vk: ValidatorVerifyKey,
    },
}
```

## 7. Client SDK (not implemented)

### 7.1 Client Interface
```rust
pub struct TrxClient {
    node_url: String,
    current_epoch_key: PublicKey,
}

impl TrxClient {
    /// Encrypt and submit transaction
    pub async fn submit_transaction(
        &self,
        transaction: Transaction,
        enable_mev_protection: bool,
    ) -> Result<TxHash> {
        if enable_mev_protection {
            let encrypted = encrypt_transaction(
                &self.current_epoch_key,
                &transaction.encode(),
                &transaction.metadata(),
            )?;
            
            self.submit_encrypted(encrypted).await
        } else {
            self.submit_plaintext(transaction).await
        }
    }
}
```
