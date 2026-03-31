use std::collections::HashMap;

use ergo_chain_types::{BlockId, Digest32, Header};

use crate::config::ChainConfig;
use crate::error::ChainError;

/// A validated chain of headers.
///
/// Every header in the chain has been checked for parent linkage, timestamp
/// bounds, PoW validity, and correct difficulty. The chain is append-only
/// and linear (no fork handling yet).
pub struct HeaderChain {
    config: ChainConfig,
    /// Headers indexed by height. Since the chain is linear, each height
    /// has exactly one header.
    by_height: Vec<Header>,
    /// Map from header ID to height for O(1) lookup.
    by_id: HashMap<BlockId, u32>,
}

/// All-zeros parent ID expected for the genesis header.
fn genesis_parent_id() -> BlockId {
    BlockId(Digest32::zero())
}

impl HeaderChain {
    /// Create a new empty chain with the given network configuration.
    pub fn new(config: ChainConfig) -> Self {
        Self {
            config,
            by_height: Vec::new(),
            by_id: HashMap::new(),
        }
    }

    /// Validate and append a header to the chain.
    ///
    /// On success, the header is added and `height()` may increase.
    /// On error, the chain is unchanged and the error describes which check failed.
    pub fn try_append(&mut self, header: Header) -> Result<(), ChainError> {
        if self.by_height.is_empty() {
            self.validate_genesis(&header)?;
        } else {
            self.validate_child(&header)?;
        }

        let height = header.height;
        self.by_id.insert(header.id, height);
        self.by_height.push(header);
        Ok(())
    }

    /// Height of the best validated chain tip, or 0 if empty.
    pub fn height(&self) -> u32 {
        self.by_height
            .last()
            .map_or(0, |h| h.height)
    }

    /// The tip header of the best validated chain.
    ///
    /// # Panics
    ///
    /// Panics if the chain is empty. Callers should ensure at least one
    /// header has been appended (genesis or bootstrap point).
    pub fn tip(&self) -> &Header {
        self.by_height
            .last()
            .expect("tip() called on empty chain")
    }

    /// Header at the given height, if it exists in the chain.
    pub fn header_at(&self, height: u32) -> Option<&Header> {
        if self.by_height.is_empty() {
            return None;
        }
        let base = self.by_height[0].height;
        let idx = height.checked_sub(base)? as usize;
        self.by_height.get(idx)
    }

    /// Whether this header ID is part of the validated chain.
    pub fn contains(&self, header_id: &BlockId) -> bool {
        self.by_id.contains_key(header_id)
    }

    /// Up to `count` sequential headers starting at `height`.
    pub fn headers_from(&self, height: u32, count: usize) -> Vec<&Header> {
        if self.by_height.is_empty() {
            return Vec::new();
        }
        let base = self.by_height[0].height;
        let start = match height.checked_sub(base) {
            Some(idx) => idx as usize,
            None => return Vec::new(),
        };
        self.by_height
            .iter()
            .skip(start)
            .take(count)
            .collect()
    }

    /// The chain configuration.
    pub fn config(&self) -> &ChainConfig {
        &self.config
    }

    /// Number of headers in the chain.
    pub fn len(&self) -> usize {
        self.by_height.len()
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.by_height.is_empty()
    }

    // --- Test support ---

    /// Append a header skipping PoW verification.
    /// For tests that need to validate chain logic without real mining solutions.
    #[cfg(test)]
    pub(crate) fn try_append_no_pow(&mut self, header: Header) -> Result<(), ChainError> {
        if self.by_height.is_empty() {
            self.validate_genesis_no_pow(&header)?;
        } else {
            self.validate_child_no_pow(&header)?;
        }

        let height = header.height;
        self.by_id.insert(header.id, height);
        self.by_height.push(header);
        Ok(())
    }

    #[cfg(test)]
    fn validate_genesis_no_pow(&self, header: &Header) -> Result<(), ChainError> {
        if header.parent_id != genesis_parent_id() {
            return Err(ChainError::InvalidGenesisParent { got: header.parent_id });
        }
        if header.height != 1 {
            return Err(ChainError::InvalidGenesisHeight { got: header.height });
        }
        if header.n_bits != self.config.initial_n_bits {
            return Err(ChainError::WrongDifficulty {
                height: header.height,
                expected: self.config.initial_n_bits,
                got: header.n_bits,
            });
        }
        Ok(())
    }

    #[cfg(test)]
    fn validate_child_no_pow(&self, header: &Header) -> Result<(), ChainError> {
        let parent = self
            .by_id
            .get(&header.parent_id)
            .and_then(|&h| self.header_at(h))
            .ok_or(ChainError::ParentNotFound { parent_id: header.parent_id })?;

        if header.height != parent.height + 1 {
            return Err(ChainError::NonSequentialHeight {
                expected: parent.height + 1,
                got: header.height,
            });
        }
        if header.timestamp <= parent.timestamp {
            return Err(ChainError::TimestampNotIncreasing {
                parent_ts: parent.timestamp,
                got: header.timestamp,
            });
        }
        // Skip future timestamp check in tests — constructed timestamps are in the past
        let expected_n_bits = crate::difficulty::expected_difficulty(parent, self)?;
        if header.n_bits != expected_n_bits {
            return Err(ChainError::WrongDifficulty {
                height: header.height,
                expected: expected_n_bits,
                got: header.n_bits,
            });
        }
        Ok(())
    }

    // --- Validation ---

    fn validate_genesis(&self, header: &Header) -> Result<(), ChainError> {
        // Genesis parent must be all zeros
        if header.parent_id != genesis_parent_id() {
            return Err(ChainError::InvalidGenesisParent {
                got: header.parent_id,
            });
        }

        // Genesis height must be 1
        if header.height != 1 {
            return Err(ChainError::InvalidGenesisHeight {
                got: header.height,
            });
        }

        // Genesis difficulty must match initial
        if header.n_bits != self.config.initial_n_bits {
            return Err(ChainError::WrongDifficulty {
                height: header.height,
                expected: self.config.initial_n_bits,
                got: header.n_bits,
            });
        }

        // PoW must be valid
        crate::verify_pow(header)?;

        Ok(())
    }

    fn validate_child(&self, header: &Header) -> Result<(), ChainError> {
        let parent = self
            .by_id
            .get(&header.parent_id)
            .and_then(|&h| self.header_at(h))
            .ok_or(ChainError::ParentNotFound {
                parent_id: header.parent_id,
            })?;

        // Height must be parent + 1
        if header.height != parent.height + 1 {
            return Err(ChainError::NonSequentialHeight {
                expected: parent.height + 1,
                got: header.height,
            });
        }

        // Timestamp must be strictly increasing
        if header.timestamp <= parent.timestamp {
            return Err(ChainError::TimestampNotIncreasing {
                parent_ts: parent.timestamp,
                got: header.timestamp,
            });
        }

        // Timestamp must not be too far in the future
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        if header.timestamp > now_ms + self.config.max_time_drift_ms {
            return Err(ChainError::TimestampTooFarInFuture {
                timestamp: header.timestamp,
                max_allowed: now_ms + self.config.max_time_drift_ms,
            });
        }

        // Difficulty must be correct
        let expected_n_bits = crate::difficulty::expected_difficulty(parent, self)?;
        if header.n_bits != expected_n_bits {
            return Err(ChainError::WrongDifficulty {
                height: header.height,
                expected: expected_n_bits,
                got: header.n_bits,
            });
        }

        // PoW must be valid
        crate::verify_pow(header)?;

        Ok(())
    }
}
