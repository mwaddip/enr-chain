use std::collections::HashMap;
use std::sync::Arc;

use ergo_chain_types::autolykos_pow_scheme::decode_compact_bits;
use ergo_chain_types::{BlockId, Digest32, Header};
use ergo_lib::chain::parameters::{Parameter, Parameters};
use num_bigint::BigUint;

use crate::config::ChainConfig;
use crate::error::ChainError;
use crate::voting::{default_parameters, SOFT_FORK_VOTE};

/// Map a signed parameter ID (1-8) to its [`Parameter`] enum variant.
///
/// Returns `None` for soft-fork IDs (120-124) and unknown IDs.
fn ordinary_param(signed_id: i8) -> Option<Parameter> {
    match signed_id.unsigned_abs() as i8 {
        1 => Some(Parameter::StorageFeeFactor),
        2 => Some(Parameter::MinValuePerByte),
        3 => Some(Parameter::MaxBlockSize),
        4 => Some(Parameter::MaxBlockCost),
        5 => Some(Parameter::TokenAccessCost),
        6 => Some(Parameter::InputCost),
        7 => Some(Parameter::DataInputCost),
        8 => Some(Parameter::OutputCost),
        _ => None,
    }
}

/// Callback type for loading the raw extension bytes for a given height.
///
/// Wired by the integrator (main crate) to bridge `enr-store`. Returns
/// `None` if no extension is available at that height.
pub type ExtensionLoader =
    Arc<dyn Fn(u32) -> Option<Vec<u8>> + Send + Sync + 'static>;

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
    /// Currently active blockchain parameters (Phase 6: Soft-Fork Voting).
    /// Updated only at epoch-boundary block validation via
    /// [`Self::apply_epoch_boundary_parameters`].
    ///
    /// Soft-fork lifecycle state (IDs 121, 122) lives directly inside
    /// `parameters_table` via `Parameter::SoftForkVotesCollected` and
    /// `Parameter::SoftForkStartingHeight`. When voting is inactive, those
    /// keys are absent. This mirrors JVM `parametersTable` exactly.
    active_parameters: Parameters,
    /// Variable-length encoding of `ErgoValidationSettingsUpdate` (param ID 124,
    /// `SoftForkDisablingRules`) from the most recent epoch-boundary block's
    /// extension. Empty when no disabling rules have been voted in.
    ///
    /// JVM stores this on `Parameters.proposedUpdate`, separate from
    /// `parametersTable`. Sigma-rust does not yet expose this on its
    /// `Parameters` type, so we track the raw bytes here on `HeaderChain`.
    active_disabling_rules: Vec<u8>,
    /// Optional callback for loading extension bytes by height. Required
    /// before calling [`Self::recompute_active_parameters_from_storage`]
    /// or [`crate::nipopow_proof::build_nipopow_proof`].
    extension_loader: Option<ExtensionLoader>,
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
        let active_parameters = default_parameters(config.network);
        Self {
            config,
            by_height: Vec::new(),
            by_id: HashMap::new(),
            scores: Vec::new(),
            active_parameters,
            active_disabling_rules: Vec::new(),
            extension_loader: None,
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

    /// Height of a header in the chain by its ID, or `None` if not present.
    pub fn height_of(&self, header_id: &BlockId) -> Option<u32> {
        self.by_id.get(header_id).copied()
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

    /// `true` iff `height` is the start of a new voting epoch.
    ///
    /// Mirrors JVM `(height % votingEpochLength == 0) && height > 0`.
    /// Pure computation; safe to call on an empty chain.
    pub fn is_epoch_boundary(&self, height: u32) -> bool {
        height > 0 && height % self.config.voting.voting_length == 0
    }

    /// Register a callback for loading raw extension bytes by height.
    ///
    /// Required before [`Self::recompute_active_parameters_from_storage`]
    /// or [`crate::nipopow_proof::build_nipopow_proof`] can do useful work.
    /// Tests that don't need voting/nipopow can skip this entirely.
    ///
    /// Wired by the integrator (main crate) to bridge `enr-store`. The
    /// loader returns `None` if no extension is available at that height.
    pub fn set_extension_loader<F>(&mut self, loader: F)
    where
        F: Fn(u32) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        self.extension_loader = Some(Arc::new(loader));
    }

    /// Whether an extension loader has been registered.
    pub fn has_extension_loader(&self) -> bool {
        self.extension_loader.is_some()
    }

    /// Internal accessor for nipopow_proof and other modules within the crate.
    pub(crate) fn extension_loader(&self) -> Option<&ExtensionLoader> {
        self.extension_loader.as_ref()
    }

    /// Walk back to the most recent epoch boundary, parse parameters from
    /// its extension, and set as active.
    ///
    /// Called at startup after wiring the extension loader. If the chain
    /// is shorter than one voting epoch (no boundary block exists yet),
    /// returns `Ok(())` and leaves [`Self::active_parameters`] at the
    /// chain-internal defaults.
    ///
    /// Errors if:
    /// - The loader is set but returns `None` for the boundary height
    /// - The extension bytes fail to parse
    /// - The parsed parameters are malformed
    ///
    /// Cost: bounded — at most one extension read. Acceptable at startup.
    pub fn recompute_active_parameters_from_storage(&mut self) -> Result<(), ChainError> {
        let voting_length = self.config.voting.voting_length;
        let tip_height = self.height();
        if tip_height < voting_length {
            // Chain shorter than one epoch — no boundary block to read.
            return Ok(());
        }
        let boundary_height = (tip_height / voting_length) * voting_length;
        if boundary_height == 0 {
            return Ok(());
        }

        let loader = self.extension_loader.as_ref().ok_or_else(|| {
            ChainError::Voting(
                "extension loader not set; cannot recompute parameters".into(),
            )
        })?;

        let extension_bytes = loader(boundary_height).ok_or_else(|| {
            ChainError::Voting(format!(
                "extension loader returned None for boundary height {boundary_height}"
            ))
        })?;

        let (_header_id, fields) = crate::voting::parse_extension_bytes(&extension_bytes)?;
        let parsed = crate::voting::parse_parameters_from_kv(&fields)?;

        // Build a Parameters table from the parsed kv. Start from network
        // defaults and override with any parsed entries.
        let mut new_params = default_parameters(self.config.network);
        for (signed_id, value) in parsed {
            if let Some(p) = ordinary_param(signed_id) {
                new_params.parameters_table.insert(p, value);
            } else if signed_id == crate::voting::ID_BLOCK_VERSION {
                new_params
                    .parameters_table
                    .insert(Parameter::BlockVersion, value);
            } else if signed_id == crate::voting::ID_SOFT_FORK_VOTES_COLLECTED {
                new_params
                    .parameters_table
                    .insert(Parameter::SoftForkVotesCollected, value);
            } else if signed_id == crate::voting::ID_SOFT_FORK_STARTING_HEIGHT {
                new_params
                    .parameters_table
                    .insert(Parameter::SoftForkStartingHeight, value);
            }
            // FIXME-PHASE-B: extract Parameter::SubblocksPerBlock (id 9)
            // here once the variant lands in sigma-rust.
        }

        // Extract SoftForkDisablingRules (ID 124) raw bytes if present.
        // JVM stores this on Parameters.proposedUpdate, not parametersTable;
        // we track it separately on HeaderChain.
        let disabling_rules = crate::voting::extract_disabling_rules_from_kv(&fields);

        self.active_parameters = new_params;
        self.active_disabling_rules = disabling_rules;
        Ok(())
    }

    /// Active `SoftForkDisablingRules` (ID 124) bytes from the most recent
    /// epoch-boundary block's extension. Empty when no disabling rules
    /// have been voted in.
    ///
    /// JVM stores this on `Parameters.proposedUpdate`. Sigma-rust does
    /// not yet expose it on its `Parameters` type, so we track the raw
    /// bytes here. The validator (in main repo) parses ID 124 from the
    /// extension and the caller calls
    /// [`Self::apply_epoch_boundary_disabling_rules`] after the block is
    /// validated.
    pub fn active_disabling_rules(&self) -> &[u8] {
        &self.active_disabling_rules
    }

    /// Set the active disabling rules after a successful epoch-boundary block.
    ///
    /// **Precondition**: `bytes` were parsed from the just-validated
    /// epoch-boundary block's extension (key `[0x00, 0x7C]` = ID 124).
    /// Caller must have already verified the block via the validator.
    ///
    /// Should be called alongside [`Self::apply_epoch_boundary_parameters`]
    /// at the same lifecycle point. Pass an empty `Vec` to clear.
    pub fn apply_epoch_boundary_disabling_rules(&mut self, bytes: Vec<u8>) {
        self.active_disabling_rules = bytes;
    }

    /// The blockchain parameters in effect at the current chain tip.
    ///
    /// Returns the parameters set by the most recent epoch-boundary block.
    /// On a fresh chain (or a chain shorter than one voting epoch), returns
    /// the chain-internal startup defaults from
    /// [`crate::voting::default_parameters`].
    ///
    /// Used by the validator to bound transaction costs and by mining when
    /// assembling new candidate blocks.
    pub fn active_parameters(&self) -> &Parameters {
        &self.active_parameters
    }

    /// Set the active parameters after a successful epoch-boundary block.
    ///
    /// **Precondition**: `params` was returned by
    /// [`Self::compute_expected_parameters`] for the just-validated
    /// epoch-boundary block AND was confirmed to match the params parsed
    /// from that block's extension.
    ///
    /// Called by the validator's caller (the block-application pipeline)
    /// AFTER the full block has been validated and persisted. Validators
    /// must NOT call this themselves — they are stateless w.r.t. chain
    /// state mutation.
    ///
    /// `params` carries the full table including soft-fork state
    /// (`Parameter::SoftForkVotesCollected`, `Parameter::SoftForkStartingHeight`) when voting
    /// is active. Both are absent when voting is inactive.
    pub fn apply_epoch_boundary_parameters(&mut self, params: Parameters) {
        self.active_parameters = params;
    }

    /// Tally the just-ended voting epoch's votes for an epoch boundary.
    ///
    /// The just-ended epoch nominally spans
    /// `[epoch_boundary_height - voting_length, epoch_boundary_height - 1]`,
    /// but since the chain's first valid block is height 1 (no block at
    /// height 0), the very first epoch is one block shorter. Walks
    /// `[max(1, h - voting_length), h - 1]` and tallies votes.
    fn tally_just_ended_epoch(
        &self,
        epoch_boundary_height: u32,
    ) -> Result<HashMap<i8, u32>, ChainError> {
        let voting_length = self.config.voting.voting_length;
        let nominal_start = epoch_boundary_height
            .checked_sub(voting_length)
            .unwrap_or(0);
        let start = nominal_start.max(1);
        let end = epoch_boundary_height
            .checked_sub(1)
            .ok_or_else(|| ChainError::Voting("epoch boundary cannot be 0".into()))?;

        if start > end {
            return Ok(HashMap::new());
        }

        let mut headers: Vec<&[u8; 3]> = Vec::with_capacity((end - start + 1) as usize);
        for h in start..=end {
            let header = self.header_at(h).ok_or_else(|| {
                ChainError::Voting(format!(
                    "header at height {h} missing from chain (epoch boundary {epoch_boundary_height})"
                ))
            })?;
            headers.push(&header.votes.0);
        }
        Ok(crate::voting::tally_votes(headers))
    }

    /// Compute the parameters that the block at `epoch_boundary_height`
    /// MUST emit in its extension.
    ///
    /// Mirrors JVM `Parameters.update`. The validator calls this BEFORE
    /// appending the boundary block; the chain's tip should be at
    /// `epoch_boundary_height - 1`.
    ///
    /// The returned `Parameters` table includes the full set: ordinary
    /// IDs 1-8, BlockVersion (123), and soft-fork lifecycle state
    /// (`Parameter::SoftForkVotesCollected` / `Parameter::SoftForkStartingHeight`) when active.
    ///
    /// **Determinism**: For any two correct implementations given the same
    /// chain history, the output is byte-identical. This is the consensus
    /// rule. Mismatch with the actual block extension = reject the block.
    pub fn compute_expected_parameters(
        &self,
        epoch_boundary_height: u32,
    ) -> Result<Parameters, ChainError> {
        let voting = &self.config.voting;
        if voting.voting_length == 0 {
            return Err(ChainError::Voting("voting_length must be > 0".into()));
        }

        let tally = self.tally_just_ended_epoch(epoch_boundary_height)?;

        let mut new_params = self.active_parameters.clone();

        // Step 1: ordinary parameter changes (IDs ±1..±8).
        for (&signed_id, &count) in &tally {
            let abs = signed_id.unsigned_abs() as i8;
            if !(1..=8).contains(&abs) {
                continue;
            }
            if voting.change_approved(count) {
                crate::voting::apply_ordinary_step(
                    &mut new_params.parameters_table,
                    signed_id,
                );
            }
        }

        // Step 2: soft-fork lifecycle (operates directly on parameters_table).
        let fork_votes = tally.get(&SOFT_FORK_VOTE).copied().unwrap_or(0);
        Self::apply_soft_fork_lifecycle(
            voting,
            epoch_boundary_height,
            fork_votes,
            &mut new_params,
        );

        // Step 3: forced v2 activation (mainnet hard-fork that pre-dates voting).
        if voting.version2_activation_height != 0
            && epoch_boundary_height == voting.version2_activation_height
        {
            let bv = new_params
                .parameters_table
                .get(&Parameter::BlockVersion)
                .copied()
                .unwrap_or(0);
            if bv == 1 {
                new_params
                    .parameters_table
                    .insert(Parameter::BlockVersion, 2);
            }
        }

        Ok(new_params)
    }

    /// Apply the six-state soft-fork lifecycle transition.
    ///
    /// Mirrors JVM `Parameters.updateFork`. Branches are mutually exclusive
    /// by height; at most one fires per call. After cleanup, a new voting
    /// can start in the same call (sequential, not exclusive).
    ///
    /// Operates directly on `params.parameters_table` via the new
    /// `Parameter::SoftForkVotesCollected` / `Parameter::SoftForkStartingHeight`
    /// variants — no separate state struct.
    fn apply_soft_fork_lifecycle(
        voting: &crate::voting::VotingConfig,
        height: u32,
        fork_votes: u32,
        params: &mut Parameters,
    ) {
        let voting_length = voting.voting_length;
        let soft_fork_epochs = voting.soft_fork_epochs;
        let activation_epochs = voting.activation_epochs;

        let starting_height = params
            .parameters_table
            .get(&Parameter::SoftForkStartingHeight)
            .copied();
        let votes_collected = params
            .parameters_table
            .get(&Parameter::SoftForkVotesCollected)
            .copied();

        if let (Some(starting_height), Some(votes_collected)) =
            (starting_height, votes_collected)
        {
            let starting_height = starting_height as u32;
            let votes_collected = votes_collected.max(0) as u32;
            let approved = voting.soft_fork_approved(votes_collected);
            let mid_end = starting_height + voting_length * soft_fork_epochs;
            let activation = starting_height + voting_length * (soft_fork_epochs + activation_epochs);
            let cleanup_fail = starting_height + voting_length * (soft_fork_epochs + 1);
            let cleanup_success = starting_height + voting_length * (soft_fork_epochs + activation_epochs + 1);

            if approved && height == cleanup_success {
                // Successful voting cleanup
                params.parameters_table.remove(&Parameter::SoftForkStartingHeight);
                params.parameters_table.remove(&Parameter::SoftForkVotesCollected);
            } else if !approved && height == cleanup_fail {
                // Unsuccessful voting cleanup
                params.parameters_table.remove(&Parameter::SoftForkStartingHeight);
                params.parameters_table.remove(&Parameter::SoftForkVotesCollected);
            } else if approved && height == activation {
                // Activation: bump BlockVersion
                let bv = params
                    .parameters_table
                    .get(&Parameter::BlockVersion)
                    .copied()
                    .unwrap_or(0);
                params
                    .parameters_table
                    .insert(Parameter::BlockVersion, bv + 1);
            } else if height <= mid_end {
                // Mid-voting: add this epoch's votes
                let new_total = votes_collected.saturating_add(fork_votes) as i32;
                params
                    .parameters_table
                    .insert(Parameter::SoftForkVotesCollected, new_total);
            }
            // else: activation period (between mid_end and activation), no action.
        }

        // After cleanup OR if no voting was active, start new voting if fork
        // votes are present this epoch.
        let still_inactive = !params
            .parameters_table
            .contains_key(&Parameter::SoftForkStartingHeight);
        if still_inactive && fork_votes > 0 {
            params
                .parameters_table
                .insert(Parameter::SoftForkStartingHeight, height as i32);
            // Per contract item 3: ID 121 = 0 on start. The current epoch's
            // fork votes are not double-counted; they were the trigger but
            // the running counter starts at zero.
            params
                .parameters_table
                .insert(Parameter::SoftForkVotesCollected, 0);
        }
    }

    /// Tally header vote slots across one voting epoch.
    ///
    /// Walks headers in `[epoch_end_height - voting_length + 1, epoch_end_height]`
    /// inclusive and sums the three signed-byte vote slots in each
    /// header's `votes` field. Used by [`Self::compute_expected_parameters`]
    /// and exposed for testability.
    ///
    /// Errors if any header in the requested range is missing from the
    /// chain — callers must ensure the precondition holds before calling.
    pub fn count_votes_in_epoch(
        &self,
        epoch_end_height: u32,
    ) -> Result<std::collections::HashMap<i8, u32>, ChainError> {
        let voting_length = self.config.voting.voting_length;
        if voting_length == 0 {
            return Err(ChainError::Voting(
                "voting_length must be > 0".into(),
            ));
        }

        let start = epoch_end_height
            .checked_sub(voting_length - 1)
            .ok_or_else(|| {
                ChainError::Voting(format!(
                    "epoch_end_height {epoch_end_height} < voting_length {voting_length}"
                ))
            })?;

        let mut headers: Vec<&[u8; 3]> = Vec::with_capacity(voting_length as usize);
        for h in start..=epoch_end_height {
            let header = self.header_at(h).ok_or_else(|| {
                ChainError::Voting(format!(
                    "header at height {h} missing from chain (epoch end {epoch_end_height})"
                ))
            })?;
            headers.push(&header.votes.0);
        }

        Ok(crate::voting::tally_votes(headers))
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
