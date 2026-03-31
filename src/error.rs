use ergo_chain_types::autolykos_pow_scheme::AutolykosPowSchemeError;
use sigma_ser::ScorexParsingError;

/// Errors that can occur in header chain operations.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// Header deserialization failed.
    #[error("header parse failed: {0}")]
    Parse(#[from] ScorexParsingError),

    /// Proof-of-work verification failed.
    #[error("PoW verification failed: hit {hit} >= target {target}")]
    PowInvalid { hit: String, target: String },

    /// Error computing proof-of-work hit.
    #[error("PoW computation error: {0}")]
    PowCompute(#[from] AutolykosPowSchemeError),
}
