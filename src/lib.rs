//! Header chain validation for the Ergo Rust node.
//!
//! Phase 1: Parse headers from wire bytes, track best known height.
//! Phase 2: Verify proof of work before accepting headers.
//! Phase 3: Validate headers form a correct chain (parent, timestamp, difficulty).

mod chain;
mod config;
pub(crate) mod difficulty;
mod error;
mod pow;
mod section;
mod state_type;
mod sync_info;
#[cfg(test)]
mod tests;
mod tracker;

pub use chain::{AppendResult, HeaderChain};
pub use config::ChainConfig;
pub use ergo_chain_types::autolykos_pow_scheme::decode_compact_bits;
pub use ergo_chain_types::{BlockId, Header};
pub use error::ChainError;
pub use pow::verify_pow;
pub use section::{
    required_section_ids, section_ids,
    HEADER_TYPE_ID, BLOCK_TRANSACTIONS_TYPE_ID, AD_PROOFS_TYPE_ID, EXTENSION_TYPE_ID,
};
pub use state_type::StateType;
pub use sync_info::{build_sync_info, parse_sync_info, SyncInfo};
pub use num_bigint::BigUint;
pub use tracker::HeaderTracker;

use sigma_ser::ScorexSerializable;

/// Parse an `ergo-chain-types::Header` from raw Scorex-serialized bytes.
///
/// The `data` argument is the raw payload from a ModifierResponse with modifier_type = 101 (Header).
/// The header's `id` field is computed automatically (blake2b256 of the serialized header).
///
/// Never panics on malformed input — returns `Err(ChainError::Parse)` instead.
pub fn parse_header(data: &[u8]) -> Result<Header, ChainError> {
    Ok(Header::scorex_parse_bytes(data)?)
}
