use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::sync::atomic::AtomicBool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use blake3::Hasher;
use rand_core::RngCore;
use tess::{
    AggregateKey, Ciphertext as TessCiphertext, CurvePoint, DecryptionResult, FieldElement, Fr,
    PairingBackend, PairingEngine, Params, SilentThresholdScheme, ThresholdEncryption,
};

/// Public encryption key wrapper.
#[derive(Clone, Debug)]
pub struct PublicKey<B: PairingBackend<Scalar = Fr>> {
    /// Aggregate key used for encryption and verification.
    pub agg_key: AggregateKey<B>,
}

/// Secret key share bound to a validator.
#[derive(Clone, Debug)]
pub struct SecretKeyShare<B: PairingBackend> {
    pub share: B::Scalar,
    pub index: u32,
}
