/// TrX-specific error type.
#[derive(Debug)]
pub enum TrxError {
    /// Backend cryptographic library error
    Backend(String),
    /// Invalid configuration parameter
    InvalidConfig(String),
    /// Invalid input data
    InvalidInput(String),
    /// Not enough decryption shares
    NotEnoughShares {
        /// Number of shares required
        required: usize,
        /// Number of shares provided
        provided: usize,
    },
}

impl std::fmt::Display for TrxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrxError::Backend(msg) => write!(f, "Backend error: {}", msg),
            TrxError::InvalidConfig(msg) => write!(f, "Invalid configuration: {}", msg),
            TrxError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            TrxError::NotEnoughShares { required, provided } => write!(
                f,
                "Not enough shares: required {}, provided {}",
                required, provided
            ),
        }
    }
}

impl std::error::Error for TrxError {}

impl From<tess::Error> for TrxError {
    fn from(err: tess::Error) -> Self {
        TrxError::Backend(err.to_string())
    }
}
