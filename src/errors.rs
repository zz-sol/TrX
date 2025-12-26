/// TrX-specific error type.
#[derive(Debug)]
pub enum TrxError {
    Backend(String),
    InvalidConfig(String),
    InvalidInput(String),
    NotEnoughShares { required: usize, provided: usize },
}

impl From<tess::Error> for TrxError {
    fn from(err: tess::Error) -> Self {
        TrxError::Backend(err.to_string())
    }
}
