use std::collections::HashMap;

use ergo_chain_types::{BlockId, Digest32, Header};

use crate::config::ChainConfig;
use crate::error::ChainError;

/// A validated chain of headers.
///
/// Every header in the chain has been checked for parent linkage, timestamp
/// bounds, PoW validity, and correct difficulty. The chain is append-only
/// and linear with 1-deep reorganization support.
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

    /// Perform a 1-deep chain reorganization.
    ///
    /// Replaces the current tip with `alternative_tip` (a competing block at the
    /// same height sharing the same parent), then appends `continuation` on top.
    ///
    /// Returns the ID of the replaced tip on success.
    pub fn try_reorg(
        &mut self,
        alternative_tip: Header,
        continuation: Header,
    ) -> Result<BlockId, ChainError> {
        self.try_reorg_impl(alternative_tip, continuation, true)
    }

    /// Test variant of `try_reorg` that skips PoW verification.
    #[cfg(test)]
    pub(crate) fn try_reorg_no_pow(
        &mut self,
        alternative_tip: Header,
        continuation: Header,
    ) -> Result<BlockId, ChainError> {
        self.try_reorg_impl(alternative_tip, continuation, false)
    }

    fn try_reorg_impl(
        &mut self,
        alternative_tip: Header,
        continuation: Header,
        verify_pow: bool,
    ) -> Result<BlockId, ChainError> {
        // Need at least 2 headers — can't reorg genesis.
        if self.by_height.len() < 2 {
            return Err(ChainError::Reorg(
                "chain too short for reorg (need at least 2 headers)".into(),
            ));
        }

        let tip_height = self.height();
        let tip_parent_id = self.tip().parent_id;

        // Alternative must compete at the same height with the same parent.
        if alternative_tip.height != tip_height {
            return Err(ChainError::Reorg(format!(
                "alternative height {} != tip height {tip_height}",
                alternative_tip.height,
            )));
        }
        if alternative_tip.parent_id != tip_parent_id {
            return Err(ChainError::Reorg(
                "alternative parent doesn't match tip's parent".into(),
            ));
        }

        // Continuation must build on the alternative.
        if continuation.parent_id != alternative_tip.id {
            return Err(ChainError::Reorg(
                "continuation doesn't build on alternative".into(),
            ));
        }
        if continuation.height != alternative_tip.height + 1 {
            return Err(ChainError::NonSequentialHeight {
                expected: alternative_tip.height + 1,
                got: continuation.height,
            });
        }

        // Pop old tip so validation runs against the correct chain state.
        let old_tip = self.by_height.pop().unwrap();
        self.by_id.remove(&old_tip.id);

        // Validate alternative against the parent (now the chain tip).
        if let Err(e) = self.validate_reorg_header(&alternative_tip, verify_pow) {
            self.restore_tip(old_tip);
            return Err(e);
        }

        // Push alternative so continuation validation sees the correct chain.
        self.by_id.insert(alternative_tip.id, alternative_tip.height);
        self.by_height.push(alternative_tip);

        // Validate continuation against the alternative (now the chain tip).
        if let Err(e) = self.validate_reorg_header(&continuation, verify_pow) {
            // Roll back: pop alternative, restore old tip.
            let alt = self.by_height.pop().unwrap();
            self.by_id.remove(&alt.id);
            self.restore_tip(old_tip);
            return Err(e);
        }

        // Push continuation.
        self.by_id.insert(continuation.id, continuation.height);
        self.by_height.push(continuation);

        Ok(old_tip.id)
    }

    /// Validate a header against the current tip during a reorg operation.
    /// Same checks as `validate_child` but factored out to share between
    /// alternative and continuation validation.
    fn validate_reorg_header(&self, header: &Header, verify_pow: bool) -> Result<(), ChainError> {
        let tip = self.by_height.last().expect("validate_reorg_header called on non-empty chain");

        if header.timestamp <= tip.timestamp {
            return Err(ChainError::TimestampNotIncreasing {
                parent_ts: tip.timestamp,
                got: header.timestamp,
            });
        }

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

        let expected_n_bits = crate::difficulty::expected_difficulty(tip, self)?;
        if header.n_bits != expected_n_bits {
            return Err(ChainError::WrongDifficulty {
                height: header.height,
                expected: expected_n_bits,
                got: header.n_bits,
            });
        }

        if verify_pow {
            crate::verify_pow(header)?;
        }

        Ok(())
    }

    /// Restore a popped tip header back onto the chain.
    fn restore_tip(&mut self, header: Header) {
        self.by_id.insert(header.id, header.height);
        self.by_height.push(header);
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
        let tip = self.by_height.last().expect("validate_child_no_pow called on non-empty chain");

        // Linear chain: parent must be the current tip
        if header.parent_id != tip.id {
            return Err(ChainError::ParentNotFound { parent_id: header.parent_id });
        }

        if header.height != tip.height + 1 {
            return Err(ChainError::NonSequentialHeight {
                expected: tip.height + 1,
                got: header.height,
            });
        }
        if header.timestamp <= tip.timestamp {
            return Err(ChainError::TimestampNotIncreasing {
                parent_ts: tip.timestamp,
                got: header.timestamp,
            });
        }
        // Skip future timestamp check in tests — constructed timestamps are in the past
        let expected_n_bits = crate::difficulty::expected_difficulty(tip, self)?;
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
        let tip = self.by_height.last().expect("validate_child called on non-empty chain");

        // Linear chain: parent must be the current tip
        if header.parent_id != tip.id {
            return Err(ChainError::ParentNotFound {
                parent_id: header.parent_id,
            });
        }

        // Height must be tip + 1
        if header.height != tip.height + 1 {
            return Err(ChainError::NonSequentialHeight {
                expected: tip.height + 1,
                got: header.height,
            });
        }

        // Timestamp must be strictly increasing
        if header.timestamp <= tip.timestamp {
            return Err(ChainError::TimestampNotIncreasing {
                parent_ts: tip.timestamp,
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
        let expected_n_bits = crate::difficulty::expected_difficulty(tip, self)?;
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
