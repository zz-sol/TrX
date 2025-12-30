//! Serde implementations for TrX crypto types.

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::sync::{atomic::AtomicBool, Arc};
use tess::{CurvePoint, Fr, PairingBackend, SRS};

use super::{EpochKeys, EpochSetup, GlobalSetup, KappaSetup, ValidatorKeyPair};
use crate::core::types::{ThresholdEncryptionPublicKey, ThresholdEncryptionSecretKeyShare};

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
                .map(|p| p.to_repr().as_ref().to_vec())
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
            .map(|bytes| {
                let mut repr = <B::G1 as CurvePoint<B::Scalar>>::Repr::default();
                if bytes.len() > repr.as_ref().len() {
                    return Err(de::Error::custom("curve point bytes too long"));
                }
                repr.as_mut()[..bytes.len()].copy_from_slice(bytes);
                B::G1::from_repr(&repr).map_err(de::Error::custom)
            })
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
