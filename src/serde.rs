//! Serialization and deserialization for all TrX types.
//!
//! This module provides comprehensive JSON serialization support via `serde` for all TrX
//! protocol types, enabling persistent storage, network transmission, and integration
//! with JSON-based APIs.
//!
//! # Supported Types
//!
//! ## Core Protocol Types
//! - [`EncryptedTransaction`]: Client-encrypted transactions with Ed25519 signatures
//! - [`BatchCommitment`]: KZG polynomial commitments over transaction batches
//! - [`EvalProof`]: KZG evaluation proofs for batch integrity verification
//! - [`PartialDecryption`]: Validator decryption shares
//! - [`DecryptionContext`]: Context binding (block height, context index)
//! - [`BatchProofs`]: Combined commitment and evaluation proofs
//!
//! ## Cryptographic Setup Types
//! - [`GlobalSetup`]: SRS and batch commitment parameters
//! - [`EpochSetup`]: Per-epoch cryptographic parameters
//! - [`EpochKeys`]: Aggregated threshold public key for an epoch
//! - [`ValidatorKeyPair`]: Individual validator's key pair
//! - [`ThresholdEncryptionPublicKey`]: Threshold encryption public key
//! - [`ThresholdEncryptionSecretKeyShare`]: Secret key share for threshold decryption
//!
//! # Serialization Strategy
//!
//! All cryptographic primitives (field elements, curve points, pairings) are serialized
//! as **byte arrays** to ensure:
//! - **Portability**: Independent of specific curve implementations
//! - **Compatibility**: Works across different BLS12-381 libraries
//! - **Determinism**: Consistent serialization format
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use trx::{EncryptedTransaction, TrxCrypto};
//! use tess::PairingEngine;
//! use ed25519_dalek::SigningKey;
//!
//! // ... create encrypted transaction ...
//!
//! // Serialize to JSON
//! let json = serde_json::to_string_pretty(&encrypted)?;
//!
//! // Deserialize from JSON
//! let tx: EncryptedTransaction<PairingEngine> = serde_json::from_str(&json)?;
//! ```
//!
//! # Implementation Notes
//!
//! - Field elements: 32-byte arrays (little-endian)
//! - G1 points: 48-byte compressed representations
//! - G2 points: 96-byte compressed representations
//! - BLS signatures: compressed format (48 bytes for G1, 96 bytes for G2)
//! - Atomic booleans in setups: serialized as regular booleans

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use solana_bls_signatures::{PubkeyCompressed, SignatureCompressed};
use std::sync::{atomic::AtomicBool, Arc};
use tess::{CurvePoint, FieldElement, Fr, PairingBackend, SRS};

// Re-export types for internal use
use crate::core::types::{
    BatchCommitment, BatchProofs, DecryptionContext, EncryptedTransaction, EvalProof,
    PartialDecryption, ThresholdEncryptionPublicKey, ThresholdEncryptionSecretKeyShare,
};
use crate::crypto::tess::{EpochKeys, EpochSetup, GlobalSetup, KappaSetup, ValidatorKeyPair};

// ============================================================================
// Helper Functions - Shared utilities for serializing cryptographic primitives
// ============================================================================

/// Convert a field element to bytes for serialization
fn field_to_bytes<F: FieldElement>(f: &F) -> Vec<u8> {
    f.to_repr().as_ref().to_vec()
}

/// Deserialize a field element from bytes
fn field_from_bytes<F: FieldElement, E: de::Error>(bytes: &[u8]) -> Result<F, E> {
    let mut repr = F::Repr::default();
    if bytes.len() > repr.as_ref().len() {
        return Err(E::custom("field bytes too long"));
    }
    repr.as_mut()[..bytes.len()].copy_from_slice(bytes);
    F::from_repr(&repr).map_err(E::custom)
}

/// Convert a curve point to bytes for serialization
fn curve_point_to_bytes<F, C>(p: &C) -> Vec<u8>
where
    F: FieldElement,
    C: CurvePoint<F>,
{
    p.to_repr().as_ref().to_vec()
}

/// Deserialize a curve point from bytes
fn curve_point_from_bytes<F, C, E>(bytes: &[u8]) -> Result<C, E>
where
    F: FieldElement,
    C: CurvePoint<F>,
    E: de::Error,
{
    let mut repr = C::Repr::default();
    if bytes.len() > repr.as_ref().len() {
        return Err(E::custom("curve point bytes too long"));
    }
    repr.as_mut()[..bytes.len()].copy_from_slice(bytes);
    C::from_repr(&repr).map_err(E::custom)
}

// ============================================================================
// Core Types Serialization
// ============================================================================

// ThresholdEncryptionPublicKey
impl<B: PairingBackend<Scalar = Fr>> Serialize for ThresholdEncryptionPublicKey<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.agg_key.serialize(serializer)
    }
}

impl<'de, B: PairingBackend<Scalar = Fr>> Deserialize<'de> for ThresholdEncryptionPublicKey<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(ThresholdEncryptionPublicKey {
            agg_key: tess::AggregateKey::deserialize(deserializer)?,
        })
    }
}

// ThresholdEncryptionSecretKeyShare
impl<B: PairingBackend> Serialize for ThresholdEncryptionSecretKeyShare<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ThresholdEncryptionSecretKeyShare", 2)?;
        state.serialize_field("share", &field_to_bytes(&self.share))?;
        state.serialize_field("validator_id", &self.validator_id)?;
        state.end()
    }
}

impl<'de, B: PairingBackend> Deserialize<'de> for ThresholdEncryptionSecretKeyShare<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            share: Vec<u8>,
            validator_id: u32,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(ThresholdEncryptionSecretKeyShare {
            share: field_from_bytes(&helper.share)?,
            validator_id: helper.validator_id,
        })
    }
}

// EncryptedTransaction
impl<B: PairingBackend> Serialize for EncryptedTransaction<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("EncryptedTransaction", 4)?;
        state.serialize_field("ciphertext", &self.ciphertext)?;
        state.serialize_field("associated_data", &self.associated_data)?;
        state.serialize_field("signature", &self.signature.to_bytes().as_slice())?;
        state.serialize_field("vk_sig", &self.vk_sig.to_bytes().as_slice())?;
        state.end()
    }
}

impl<'de, B: PairingBackend> Deserialize<'de> for EncryptedTransaction<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(bound(deserialize = ""))]
        struct Helper<B: PairingBackend> {
            ciphertext: tess::Ciphertext<B>,
            associated_data: Vec<u8>,
            signature: Vec<u8>,
            vk_sig: Vec<u8>,
        }

        let helper = Helper::deserialize(deserializer)?;

        let sig_bytes: [u8; 64] = helper
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| de::Error::custom("signature must be 64 bytes"))?;
        let vk_bytes: [u8; 32] = helper
            .vk_sig
            .as_slice()
            .try_into()
            .map_err(|_| de::Error::custom("verifying key must be 32 bytes"))?;

        Ok(EncryptedTransaction {
            ciphertext: helper.ciphertext,
            associated_data: helper.associated_data,
            signature: ed25519_dalek::Signature::from_bytes(&sig_bytes),
            vk_sig: ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes)
                .map_err(de::Error::custom)?,
        })
    }
}

// PartialDecryption
impl<B: PairingBackend> Serialize for PartialDecryption<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("PartialDecryption", 6)?;
        state.serialize_field("pd", &curve_point_to_bytes::<B::Scalar, _>(&self.pd))?;
        state.serialize_field("validator_id", &self.validator_id)?;
        state.serialize_field("context", &self.context)?;
        state.serialize_field("tx_index", &self.tx_index)?;
        state.serialize_field("signature", &self.signature.as_ref().map(|s| s.0.to_vec()))?;
        state.serialize_field(
            "validator_vk",
            &self.validator_vk.as_ref().map(|vk| vk.0.to_vec()),
        )?;
        state.end()
    }
}

impl<'de, B: PairingBackend> Deserialize<'de> for PartialDecryption<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            pd: Vec<u8>,
            validator_id: u32,
            context: DecryptionContext,
            tx_index: usize,
            signature: Option<Vec<u8>>,
            validator_vk: Option<Vec<u8>>,
        }

        let helper = Helper::deserialize(deserializer)?;
        let signature = match helper.signature {
            Some(bytes) => {
                let raw: [u8; 96] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| de::Error::custom("signature must be 96 bytes"))?;
                Some(SignatureCompressed(raw))
            }
            None => None,
        };
        let validator_vk = match helper.validator_vk {
            Some(bytes) => {
                let raw: [u8; 48] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| de::Error::custom("validator_vk must be 48 bytes"))?;
                Some(PubkeyCompressed(raw))
            }
            None => None,
        };
        Ok(PartialDecryption {
            pd: curve_point_from_bytes::<B::Scalar, _, _>(&helper.pd)?,
            validator_id: helper.validator_id,
            context: helper.context,
            tx_index: helper.tx_index,
            signature,
            validator_vk,
        })
    }
}

// DecryptionContext
impl Serialize for DecryptionContext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("DecryptionContext", 2)?;
        state.serialize_field("block_height", &self.block_height)?;
        state.serialize_field("context_index", &self.context_index)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for DecryptionContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            block_height: u64,
            context_index: u32,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(DecryptionContext {
            block_height: helper.block_height,
            context_index: helper.context_index,
        })
    }
}

// BatchProofs
impl<B: PairingBackend<Scalar = Fr>> Serialize for BatchProofs<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("BatchProofs", 2)?;
        state.serialize_field("commitment", &self.commitment)?;
        state.serialize_field("proofs", &self.proofs)?;
        state.end()
    }
}

impl<'de, B: PairingBackend<Scalar = Fr>> Deserialize<'de> for BatchProofs<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(bound(deserialize = ""))]
        struct Helper<B: PairingBackend<Scalar = Fr>> {
            commitment: BatchCommitment<B>,
            proofs: Vec<EvalProof<B>>,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(BatchProofs::new(helper.commitment, helper.proofs))
    }
}

// BatchCommitment
impl<B: PairingBackend> Serialize for BatchCommitment<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("BatchCommitment", 2)?;
        state.serialize_field("com", &curve_point_to_bytes::<B::Scalar, _>(&self.com))?;
        state.serialize_field("polynomial_degree", &self.polynomial_degree)?;
        state.end()
    }
}

impl<'de, B: PairingBackend> Deserialize<'de> for BatchCommitment<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            com: Vec<u8>,
            polynomial_degree: u32,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(BatchCommitment {
            com: curve_point_from_bytes::<B::Scalar, _, _>(&helper.com)?,
            polynomial_degree: helper.polynomial_degree,
        })
    }
}

// EvalProof
impl<B: PairingBackend<Scalar = Fr>> Serialize for EvalProof<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("EvalProof", 3)?;
        state.serialize_field("point", &field_to_bytes(&self.point))?;
        state.serialize_field("value", &field_to_bytes(&self.value))?;
        state.serialize_field("proof", &curve_point_to_bytes::<B::Scalar, _>(&self.proof))?;
        state.end()
    }
}

impl<'de, B: PairingBackend<Scalar = Fr>> Deserialize<'de> for EvalProof<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            point: Vec<u8>,
            value: Vec<u8>,
            proof: Vec<u8>,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(EvalProof {
            point: field_from_bytes(&helper.point)?,
            value: field_from_bytes(&helper.value)?,
            proof: curve_point_from_bytes::<B::Scalar, _, _>(&helper.proof)?,
        })
    }
}

// ============================================================================
// Crypto Types Serialization
// ============================================================================

// GlobalSetup
impl<B: PairingBackend<Scalar = Fr>> Serialize for GlobalSetup<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("GlobalSetup", 2)?;
        state.serialize_field("params", &self.params)?;
        state.serialize_field("srs", &self.srs)?;
        state.end()
    }
}

impl<'de, B: PairingBackend<Scalar = Fr>> Deserialize<'de> for GlobalSetup<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(bound(deserialize = ""))]
        struct Helper<B: PairingBackend<Scalar = Fr>> {
            params: tess::Params<B>,
            srs: SRS<B>,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(GlobalSetup {
            params: helper.params,
            srs: helper.srs,
        })
    }
}

// KappaSetup
impl<B: PairingBackend> Serialize for KappaSetup<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("KappaSetup", 3)?;
        state.serialize_field("index", &self.index)?;
        state.serialize_field(
            "elements",
            &self
                .elements
                .iter()
                .map(curve_point_to_bytes::<B::Scalar, _>)
                .collect::<Vec<Vec<u8>>>(),
        )?;
        state.serialize_field("used", &self.is_used())?;
        state.end()
    }
}

impl<'de, B: PairingBackend> Deserialize<'de> for KappaSetup<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            index: u32,
            elements: Vec<Vec<u8>>,
            used: bool,
        }

        let helper = Helper::deserialize(deserializer)?;

        let elements = helper
            .elements
            .iter()
            .map(|bytes| curve_point_from_bytes::<B::Scalar, B::G1, _>(bytes))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(KappaSetup {
            index: helper.index,
            elements,
            used: AtomicBool::new(helper.used),
        })
    }
}

// EpochSetup
impl<B: PairingBackend<Scalar = Fr>> Serialize for EpochSetup<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("EpochSetup", 3)?;
        state.serialize_field("epoch_id", &self.epoch_id)?;
        state.serialize_field("kappa_setups", &self.kappa_setups)?;
        state.serialize_field("global_setup", &*self.global_setup)?;
        state.end()
    }
}

impl<'de, B: PairingBackend<Scalar = Fr>> Deserialize<'de> for EpochSetup<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(bound(deserialize = ""))]
        struct Helper<B: PairingBackend<Scalar = Fr>> {
            epoch_id: u64,
            kappa_setups: Vec<KappaSetup<B>>,
            global_setup: GlobalSetup<B>,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(EpochSetup {
            epoch_id: helper.epoch_id,
            kappa_setups: helper.kappa_setups,
            global_setup: Arc::new(helper.global_setup),
        })
    }
}

// EpochKeys
impl<B: PairingBackend<Scalar = Fr>> Serialize for EpochKeys<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("EpochKeys", 3)?;
        state.serialize_field("epoch_id", &self.epoch_id)?;
        state.serialize_field("public_key", &self.public_key)?;
        state.serialize_field("epoch_setup", &*self.epoch_setup)?;
        state.end()
    }
}

impl<'de, B: PairingBackend<Scalar = Fr>> Deserialize<'de> for EpochKeys<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(bound(deserialize = ""))]
        struct Helper<B: PairingBackend<Scalar = Fr>> {
            epoch_id: u64,
            public_key: ThresholdEncryptionPublicKey<B>,
            epoch_setup: EpochSetup<B>,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(EpochKeys {
            epoch_id: helper.epoch_id,
            public_key: helper.public_key,
            epoch_setup: Arc::new(helper.epoch_setup),
        })
    }
}

// ValidatorKeyPair
impl<B: PairingBackend<Scalar = Fr>> Serialize for ValidatorKeyPair<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ValidatorKeyPair", 3)?;
        state.serialize_field("validator_id", &self.validator_id)?;
        state.serialize_field("public_key", &self.public_key)?;
        state.serialize_field("secret_share", &self.secret_share)?;
        state.end()
    }
}

impl<'de, B: PairingBackend<Scalar = Fr>> Deserialize<'de> for ValidatorKeyPair<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(bound(deserialize = ""))]
        struct Helper<B: PairingBackend<Scalar = Fr>> {
            validator_id: u32,
            public_key: tess::PublicKey<B>,
            secret_share: ThresholdEncryptionSecretKeyShare<B>,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(ValidatorKeyPair {
            validator_id: helper.validator_id,
            public_key: helper.public_key,
            secret_share: helper.secret_share,
        })
    }
}
