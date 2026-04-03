/// Node state management mode — determines which block sections are required
/// and how state transitions are validated.
///
/// Mirrors JVM's `StateType` enum (`utxo` vs `digest`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateType {
    /// Maintain the full UTXO set. Validate transactions by looking up inputs
    /// directly. Does not need AD proofs — state transitions are verified
    /// against the UTXO set itself.
    Utxo,
    /// Maintain only the AVL+ tree root hash (state digest). Validate state
    /// transitions using authenticated dictionary proofs (AD proofs) provided
    /// in each block. Requires downloading AD proofs from peers.
    Digest,
}

impl StateType {
    /// Whether this mode requires AD proofs for state validation.
    ///
    /// Mirrors JVM's `stateType.requireProofs`:
    /// - UTXO mode validates against the UTXO set directly → no proofs needed
    /// - Digest mode validates against the state root hash → proofs required
    pub fn requires_proofs(&self) -> bool {
        matches!(self, StateType::Digest)
    }
}
