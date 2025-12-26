use tess::{AggregateKey, Fr, PairingBackend};

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
