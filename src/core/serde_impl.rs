//! Serde implementations for TrX core types.

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use tess::{CurvePoint, FieldElement, Fr, PairingBackend};

use super::types::{
    BatchCommitment, DecryptionContext, EncryptedTransaction, EvalProof, PartialDecryption,
    PublicKey, SecretKeyShare,
};

// Helper functions
fn field_to_bytes<F: FieldElement>(f: &F) -> Vec<u8> {
    f.to_repr().as_ref().to_vec()
}

fn field_from_bytes<F: FieldElement, E: de::Error>(bytes: &[u8]) -> Result<F, E> {
    let mut repr = F::Repr::default();
    if bytes.len() > repr.as_ref().len() {
        return Err(E::custom("field bytes too long"));
    }
    repr.as_mut()[..bytes.len()].copy_from_slice(bytes);
    F::from_repr(&repr).map_err(E::custom)
}

fn curve_point_to_bytes<F, C>(p: &C) -> Vec<u8>
where
    F: FieldElement,
    C: CurvePoint<F>,
{
    p.to_repr().as_ref().to_vec()
}

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

// PublicKey
impl<B: PairingBackend<Scalar = Fr>> Serialize for PublicKey<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.agg_key.serialize(serializer)
    }
}

impl<'de, B: PairingBackend<Scalar = Fr>> Deserialize<'de> for PublicKey<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(PublicKey {
            agg_key: tess::AggregateKey::deserialize(deserializer)?,
        })
    }
}

// SecretKeyShare
impl<B: PairingBackend> Serialize for SecretKeyShare<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SecretKeyShare", 2)?;
        state.serialize_field("share", &field_to_bytes(&self.share))?;
        state.serialize_field("validator_id", &self.validator_id)?;
        state.end()
    }
}

impl<'de, B: PairingBackend> Deserialize<'de> for SecretKeyShare<B> {
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
        Ok(SecretKeyShare {
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
        let mut state = serializer.serialize_struct("PartialDecryption", 4)?;
        state.serialize_field("pd", &curve_point_to_bytes::<B::Scalar, _>(&self.pd))?;
        state.serialize_field("validator_id", &self.validator_id)?;
        state.serialize_field("context", &self.context)?;
        state.serialize_field("tx_index", &self.tx_index)?;
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
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(PartialDecryption {
            pd: curve_point_from_bytes::<B::Scalar, _, _>(&helper.pd)?,
            validator_id: helper.validator_id,
            context: helper.context,
            tx_index: helper.tx_index,
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
