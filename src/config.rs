/// Network parameters that affect header chain validation.
///
/// Determines epoch length, block interval, difficulty adjustment behavior,
/// and whether EIP-37 applies. Passed to `HeaderChain` at construction.
#[derive(Debug, Clone)]
pub struct ChainConfig {
    /// Blocks per difficulty epoch.
    pub epoch_length: u32,
    /// Target time between blocks, in milliseconds.
    pub block_interval_ms: u64,
    /// Number of past epochs used in difficulty recalculation.
    pub use_last_epochs: u32,
    /// Difficulty for the very first block (encoded as nBits).
    pub initial_n_bits: u32,
    /// Maximum allowed clock drift for timestamps, in milliseconds.
    /// Headers with `timestamp > now + max_time_drift` are rejected.
    pub max_time_drift_ms: u64,
    /// Height at which EIP-37 difficulty adjustment activates (mainnet only).
    /// `None` means EIP-37 is never active (testnet).
    pub eip37_activation_height: Option<u32>,
    /// Epoch length after EIP-37 activation (mainnet: 128).
    pub eip37_epoch_length: Option<u32>,
}

impl ChainConfig {
    /// Testnet configuration.
    pub fn testnet() -> Self {
        Self {
            epoch_length: 128,
            block_interval_ms: 45_000,
            use_last_epochs: 8,
            initial_n_bits: 16842752, // encode_compact_bits(1)
            max_time_drift_ms: 10 * 45_000, // 450 seconds
            eip37_activation_height: None,
            eip37_epoch_length: None,
        }
    }

    /// Mainnet configuration.
    pub fn mainnet() -> Self {
        Self {
            epoch_length: 1024,
            block_interval_ms: 120_000,
            use_last_epochs: 8,
            initial_n_bits: 16842752, // encode_compact_bits(1)
            max_time_drift_ms: 10 * 120_000, // 1200 seconds
            eip37_activation_height: Some(844_673),
            eip37_epoch_length: Some(128),
        }
    }

    /// Returns the effective epoch length for a given height.
    pub fn epoch_length_at(&self, height: u32) -> u32 {
        match (self.eip37_activation_height, self.eip37_epoch_length) {
            (Some(activation), Some(eip37_len)) if height >= activation => eip37_len,
            _ => self.epoch_length,
        }
    }

    /// Whether EIP-37 difficulty adjustment is active at the given height.
    pub fn eip37_active(&self, height: u32) -> bool {
        self.eip37_activation_height
            .is_some_and(|h| height >= h)
    }
}
