//! Header chain validation for the Ergo Rust node.
//!
//! Phase 1: Parse headers from wire bytes, track best known height.
//! Phase 2: Verify proof of work before accepting headers.

mod error;
mod pow;
#[cfg(test)]
mod tests;
mod tracker;

pub use ergo_chain_types::{BlockId, Header};
pub use error::ChainError;
pub use pow::verify_pow;
pub use tracker::HeaderTracker;

use sigma_ser::ScorexSerializable;

/// Parse an `ergo-chain-types::Header` from raw Scorex-serialized bytes.
///
/// The `data` argument is the raw payload from a ModifierResponse with modifier_type = 1.
/// The header's `id` field is computed automatically (blake2b256 of the serialized header).
///
/// Never panics on malformed input — returns `Err(ChainError::Parse)` instead.
pub fn parse_header(data: &[u8]) -> Result<Header, ChainError> {
    Ok(Header::scorex_parse_bytes(data)?)
}
