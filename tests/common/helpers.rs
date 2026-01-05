//! Helper functions for test assertions and common operations.

use tess::PairingEngine;
use trx::*;

/// Asserts that a decryption result contains the expected plaintext
pub fn assert_decrypted_eq(result: &DecryptionResult, expected: &[u8]) {
    match &result.plaintext {
        Some(plaintext) => assert_eq!(plaintext.as_slice(), expected, "plaintext mismatch"),
        None => panic!("expected successful decryption but got None"),
    }
}

/// Creates a BatchContext from components
pub fn create_batch_context(
    batch: Vec<EncryptedTransaction<PairingEngine>>,
    context: DecryptionContext,
    commitment: BatchCommitment<PairingEngine>,
    eval_proofs: Vec<EvalProof<PairingEngine>>,
) -> BatchContext<PairingEngine> {
    BatchContext::new(batch, context, BatchProofs::new(commitment, eval_proofs))
}
