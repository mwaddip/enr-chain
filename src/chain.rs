use std::collections::HashMap;

use ergo_chain_types::autolykos_pow_scheme::decode_compact_bits;
use ergo_chain_types::{BlockId, Digest32, Header};
use num_bigint::BigUint;

use crate::config::ChainConfig;
use crate::error::ChainError;

/// Result of a successful `try_append` call.
#[derive(Debug)]
pub enum AppendResult {
    /// Header extends the best chain. Chain height increased.
    Extended,
    /// Header is valid but forks from the best chain at the given height.
    /// The header is NOT added to the chain — caller stores it separately.
    Forked { fork_height: u32 },
}

/// A validated chain of headers.
///
/// Every header in the chain has been checked for parent linkage, timestamp
/// bounds, PoW validity, and correct difficulty. Supports 1-deep and deep
/// reorganization when a competing fork proves longer.
pub struct HeaderChain {
    config: ChainConfig,
    /// Headers indexed by height. Since the chain is linear, each height
    /// has exactly one header.
    by_height: Vec<Header>,
    /// Map from header ID to height for O(1) lookup.
    by_id: HashMap<BlockId, u32>,
    /// Cumulative difficulty score at each height, parallel to `by_height`.
    scores: Vec<BigUint>,
}

/// All-zeros parent ID expected for the genesis header.
fn genesis_parent_id() -> BlockId {
    BlockId(Digest32::zero())
}

/// Compute the difficulty contribution of a header as BigUint.
fn header_difficulty(header: &Header) -> BigUint {
    decode_compact_bits(header.n_bits)
        .to_biguint()
        .unwrap_or_default()
}

impl HeaderChain {
    /// Create a new empty chain with the given network configuration.
    pub fn new(config: ChainConfig) -> Self {
        Self {
            config,
            by_height: Vec::new(),
            by_id: HashMap::new(),
            scores: Vec::new(),
        }
    }

    /// Validate and append a header to the chain.
    ///
    /// Returns `Extended` if the header extends the best chain, or
    /// `Forked` if its parent is in the chain but is not the tip.
    /// A `Forked` result does NOT add the header — the caller stores it.
    pub fn try_append(&mut self, header: Header) -> Result<AppendResult, ChainError> {
        if self.by_height.is_empty() {
            self.validate_genesis(&header)?;
            self.push_header(header);
            return Ok(AppendResult::Extended);
        }

        let tip_id = self.tip().id;
        if header.parent_id == tip_id {
            self.validate_child(&header)?;
            self.push_header(header);
            Ok(AppendResult::Extended)
        } else if let Some(&parent_height) = self.by_id.get(&header.parent_id) {
            // Parent exists but is not the tip — this is a fork.
            if header.height != parent_height + 1 {
                return Err(ChainError::NonSequentialHeight {
                    expected: parent_height + 1,
                    got: header.height,
                });
            }
            Ok(AppendResult::Forked { fork_height: parent_height })
        } else {
            Err(ChainError::ParentNotFound {
                parent_id: header.parent_id,
            })
        }
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

    /// Cumulative difficulty score at the chain tip.
    pub fn cumulative_score(&self) -> BigUint {
        self.scores.last().cloned().unwrap_or_default()
    }

    /// Cumulative difficulty score at a given height.
    pub fn score_at(&self, height: u32) -> Option<&BigUint> {
        if self.by_height.is_empty() {
            return None;
        }
        let base = self.by_height[0].height;
        let idx = height.checked_sub(base)? as usize;
        self.scores.get(idx)
    }

    // --- Reorg ---

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

    /// Rewind the chain to `fork_point_height` and apply `new_branch`.
    ///
    /// Returns the IDs of demoted headers on success. On any validation
    /// failure the chain is unchanged.
    pub fn try_reorg_deep(
        &mut self,
        fork_point_height: u32,
        new_branch: Vec<Header>,
    ) -> Result<Vec<BlockId>, ChainError> {
        self.try_reorg_deep_impl(fork_point_height, new_branch, true)
    }

    // --- Internal helpers ---

    /// Push a validated header onto the chain with its cumulative score.
    fn push_header(&mut self, header: Header) {
        let parent_score = self.scores.last().cloned().unwrap_or_default();
        let diff = header_difficulty(&header);
        self.scores.push(parent_score + diff);
        self.by_id.insert(header.id, header.height);
        self.by_height.push(header);
    }

    /// Pop the tip header and its score. Returns both for rollback.
    fn pop_header(&mut self) -> Option<(Header, BigUint)> {
        let header = self.by_height.pop()?;
        let score = self.scores.pop().unwrap_or_default();
        self.by_id.remove(&header.id);
        Some((header, score))
    }

    /// Restore a previously popped header with its score.
    fn restore_header(&mut self, header: Header, score: BigUint) {
        self.by_id.insert(header.id, header.height);
        self.by_height.push(header);
        self.scores.push(score);
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
        let (old_tip, old_score) = self.pop_header().unwrap();

        // Validate alternative against the parent (now the chain tip).
        if let Err(e) = self.validate_reorg_header(&alternative_tip, verify_pow) {
            self.restore_header(old_tip, old_score);
            return Err(e);
        }

        // Push alternative so continuation validation sees the correct chain.
        self.push_header(alternative_tip);

        // Validate continuation against the alternative (now the chain tip).
        if let Err(e) = self.validate_reorg_header(&continuation, verify_pow) {
            // Roll back: pop alternative, restore old tip.
            let (_, _) = self.pop_header().unwrap();
            self.restore_header(old_tip, old_score);
            return Err(e);
        }

        // Push continuation.
        self.push_header(continuation);

        Ok(old_tip.id)
    }

    fn try_reorg_deep_impl(
        &mut self,
        fork_point_height: u32,
        new_branch: Vec<Header>,
        verify_pow: bool,
    ) -> Result<Vec<BlockId>, ChainError> {
        if new_branch.is_empty() {
            return Err(ChainError::Reorg("new branch is empty".into()));
        }

        // Fork point must be in the chain.
        if self.by_height.is_empty() {
            return Err(ChainError::Reorg("chain is empty".into()));
        }
        let base = self.by_height[0].height;
        let fork_idx = fork_point_height
            .checked_sub(base)
            .map(|i| i as usize)
            .filter(|&i| i < self.by_height.len())
            .ok_or_else(|| {
                ChainError::Reorg(format!("fork point height {fork_point_height} not in chain"))
            })?;

        // First header's parent must match the fork point.
        let fork_point_id = self.by_height[fork_idx].id;
        if new_branch[0].parent_id != fork_point_id {
            return Err(ChainError::Reorg(
                "first header in branch doesn't connect to fork point".into(),
            ));
        }

        // Drain headers above the fork point — save for rollback.
        let saved_headers: Vec<Header> = self.by_height.drain(fork_idx + 1..).collect();
        let saved_scores: Vec<BigUint> = self.scores.drain(fork_idx + 1..).collect();
        for h in &saved_headers {
            self.by_id.remove(&h.id);
        }

        // Validate and append each header in the new branch.
        let mut failed = false;
        let mut fail_err = None;

        for (i, header) in new_branch.into_iter().enumerate() {
            // Check parent linkage: first header links to fork point (already checked),
            // subsequent headers must link to the previous (current tip).
            if i > 0 {
                let tip_id = self.tip().id;
                if header.parent_id != tip_id {
                    fail_err = Some(ChainError::ParentNotFound {
                        parent_id: header.parent_id,
                    });
                    failed = true;
                    break;
                }
            }

            // Check height is sequential.
            let expected_height = fork_point_height + 1 + i as u32;
            if header.height != expected_height {
                fail_err = Some(ChainError::NonSequentialHeight {
                    expected: expected_height,
                    got: header.height,
                });
                failed = true;
                break;
            }

            // Validate timestamp, difficulty, PoW.
            if let Err(e) = self.validate_reorg_header(&header, verify_pow) {
                fail_err = Some(e);
                failed = true;
                break;
            }

            self.push_header(header);
        }

        if failed {
            // Rollback: pop any new headers we added.
            while self.by_height.len() > fork_idx + 1 {
                self.pop_header();
            }
            // Restore saved state.
            for (header, score) in saved_headers.into_iter().zip(saved_scores) {
                self.by_id.insert(header.id, header.height);
                self.by_height.push(header);
                self.scores.push(score);
            }
            return Err(fail_err.unwrap());
        }

        let demoted_ids: Vec<BlockId> = saved_headers.iter().map(|h| h.id).collect();
        Ok(demoted_ids)
    }

    /// Validate a header against the current tip during a reorg operation.
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

    // --- Test support ---

    /// Append a header skipping PoW verification.
    /// For tests that need to validate chain logic without real mining solutions.
    #[cfg(test)]
    pub(crate) fn try_append_no_pow(
        &mut self,
        header: Header,
    ) -> Result<AppendResult, ChainError> {
        if self.by_height.is_empty() {
            self.validate_genesis_no_pow(&header)?;
            self.push_header(header);
            return Ok(AppendResult::Extended);
        }

        let tip_id = self.tip().id;
        if header.parent_id == tip_id {
            self.validate_child_no_pow(&header)?;
            self.push_header(header);
            Ok(AppendResult::Extended)
        } else if let Some(&parent_height) = self.by_id.get(&header.parent_id) {
            if header.height != parent_height + 1 {
                return Err(ChainError::NonSequentialHeight {
                    expected: parent_height + 1,
                    got: header.height,
                });
            }
            Ok(AppendResult::Forked { fork_height: parent_height })
        } else {
            Err(ChainError::ParentNotFound {
                parent_id: header.parent_id,
            })
        }
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

    /// Test variant of `try_reorg_deep` that skips PoW verification.
    #[cfg(test)]
    pub(crate) fn try_reorg_deep_no_pow(
        &mut self,
        fork_point_height: u32,
        new_branch: Vec<Header>,
    ) -> Result<Vec<BlockId>, ChainError> {
        self.try_reorg_deep_impl(fork_point_height, new_branch, false)
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
        if header.parent_id != genesis_parent_id() {
            return Err(ChainError::InvalidGenesisParent {
                got: header.parent_id,
            });
        }

        if header.height != 1 {
            return Err(ChainError::InvalidGenesisHeight {
                got: header.height,
            });
        }

        if header.n_bits != self.config.initial_n_bits {
            return Err(ChainError::WrongDifficulty {
                height: header.height,
                expected: self.config.initial_n_bits,
                got: header.n_bits,
            });
        }

        crate::verify_pow(header)?;

        Ok(())
    }

    fn validate_child(&self, header: &Header) -> Result<(), ChainError> {
        let tip = self.by_height.last().expect("validate_child called on non-empty chain");

        if header.parent_id != tip.id {
            return Err(ChainError::ParentNotFound {
                parent_id: header.parent_id,
            });
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

        crate::verify_pow(header)?;

        Ok(())
    }
}
