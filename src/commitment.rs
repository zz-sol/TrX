use tess::PairingBackend;

/// Batch commitment placeholder produced by hashing.
#[derive(Debug)]
pub struct BatchCommitment<B: PairingBackend> {
    pub com: B::G1,
    pub polynomial_degree: u32,
}

impl<B: PairingBackend> Clone for BatchCommitment<B>
where
    B::G1: Clone,
{
    fn clone(&self) -> Self {
        Self {
            com: self.com.clone(),
            polynomial_degree: self.polynomial_degree,
        }
    }
}

/// Placeholder evaluation proof bytes.
#[derive(Clone, Debug)]
pub struct EvalProof {
    pub bytes: Vec<u8>,
}
