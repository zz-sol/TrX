use rand_core::RngCore;
use tess::{Fr, PairingBackend, Params, SilentThresholdScheme, ThresholdEncryption};

use crate::{DecryptionContext, EncryptedTransaction, PartialDecryption, TrxError};

pub type ValidatorId = u32;

/// Concrete TrX cryptographic engine built on Tess.
///
/// This adapter owns the Tess parameters, performs key generation,
/// and wraps encryption/decryption to match the TrX spec types.
#[derive(Debug)]
pub struct TrxCrypto<B: PairingBackend<Scalar = Fr>> {
    pub(crate) scheme: SilentThresholdScheme<B>,
    pub(crate) params: Params<B>,
    pub(crate) parties: usize,
    pub(crate) threshold: usize,
}

impl<B: PairingBackend<Scalar = Fr>> TrxCrypto<B> {
    /// Creates a TrX crypto instance with a fresh Tess parameter set.
    pub fn new(rng: &mut impl RngCore, parties: usize, threshold: usize) -> Result<Self, TrxError> {
        if threshold == 0 || threshold >= parties {
            return Err(TrxError::InvalidConfig(
                "threshold must be in 1..parties".into(),
            ));
        }
        let scheme = SilentThresholdScheme::<B>::new();
        let params = scheme.param_gen(rng, parties, threshold)?;
        Ok(Self {
            scheme,
            params,
            parties,
            threshold,
        })
    }
}

/// TrX network message types.
#[derive(Clone, Debug)]
pub enum TrxMessage<B: PairingBackend> {
    SubmitEncryptedTx(EncryptedTransaction<B>),
    ProposeBlock {
        block_hash: Vec<u8>,
        encrypted_txs: Vec<EncryptedTransaction<B>>,
    },
    VoteWithDecryption {
        vote: Vec<u8>,
        partial_decryption: Option<PartialDecryption<B>>,
    },
    RequestDecryptionShares {
        block_hash: Vec<u8>,
        context: DecryptionContext,
    },
    DecryptionShare {
        block_hash: Vec<u8>,
        share: PartialDecryption<B>,
    },
}
