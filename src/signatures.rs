pub type TxPublicVerifyKey = ed25519_dalek::VerifyingKey;
pub type TxSignature = ed25519_dalek::Signature;

pub type ValidatorVerifyKey = solana_bls_signatures::PubkeyCompressed;
pub type ValidatorSignature = solana_bls_signatures::SignatureCompressed;
