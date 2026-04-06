//! Soft-fork voting state machine for Ergo.
//!
//! Tracks blockchain parameters voted on by miners across epochs. Vote counting,
//! parameter computation, and the soft-fork lifecycle (voting → activation →
//! version bump) are consensus-critical: implementations must agree byte-for-byte
//! on the parameters that the next epoch-boundary block must emit.
//!
//! Mirrors JVM `ergo-core/src/main/scala/org/ergoplatform/settings/Parameters.scala`
//! and `VotingSettings.scala`.

use std::collections::HashMap;

use ergo_lib::chain::parameters::{Parameter, Parameters};
use hashbrown::HashMap as HbHashMap;

// Note: Parameter::SoftForkVotesCollected (121) and Parameter::SoftForkStartingHeight (122)
// are added by a parallel sigma-rust patch (`feat/parameter-soft-fork-variants`).
// Until the integration branch lands and chain/Cargo.toml is bumped, references
// to these variants will fail to compile. The chain code is correct in structure;
// the build break is expected and will be unblocked by the main session.

/// Vote slot value reserved for soft-fork ballots.
///
/// Mirrors JVM `Parameters.SoftFork`. Header `votes` byte == 120 means
/// "vote for the current soft-fork." Distinct from ordinary parameter ID
/// votes (1-8) which appear as the same byte in their dedicated slot.
pub const SOFT_FORK_VOTE: i8 = 120;

/// Reserved soft-fork state param IDs. Numeric values mirror JVM
/// `Parameters.scala`. Stored directly in `parameters_table` via
/// `Parameter::SoftForkVotesCollected` / `Parameter::SoftForkStartingHeight`
/// (added in the parallel sigma-rust patch).
pub const ID_SOFT_FORK_VOTES_COLLECTED: i8 = 121;
pub const ID_SOFT_FORK_STARTING_HEIGHT: i8 = 122;

/// Param ID 123: current block version. Lives on [`Parameters`] as
/// [`Parameter::BlockVersion`].
pub const ID_BLOCK_VERSION: i8 = 123;

/// Param ID 124: variable-length soft-fork validation rules.
///
/// Deferred for first release — testnet won't be voting on validation rule
/// changes. Encoding is `ErgoValidationSettingsUpdate` bytes, not 4-byte BE
/// i32 like the other IDs.
pub const ID_SOFT_FORK_DISABLING_RULES: i8 = 124;

/// Voting epoch lengths and soft-fork timing parameters.
///
/// Derived from network type (testnet vs mainnet) — not a runtime config
/// entry. Pulled into [`crate::ChainConfig`] which selects the right preset.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct VotingConfig {
    /// Length of one voting epoch, in blocks. Mainnet 1024, testnet 128.
    pub voting_length: u32,
    /// Voting epochs collected before a soft-fork can be approved. Both nets: 32.
    pub soft_fork_epochs: u32,
    /// Voting epochs after approval before BlockVersion is incremented. Both nets: 32.
    pub activation_epochs: u32,
    /// JVM-hardcoded protocol-v2 forced activation height. Mainnet 417792.
    /// Testnet has no forced activation; set to 0 (the check is `height == this`).
    pub version2_activation_height: u32,
}

impl VotingConfig {
    /// Mainnet voting parameters. Mirrors JVM `MainnetVotingSettings`.
    pub fn mainnet() -> Self {
        Self {
            voting_length: 1024,
            soft_fork_epochs: 32,
            activation_epochs: 32,
            version2_activation_height: 417_792,
        }
    }

    /// Testnet voting parameters. Mirrors JVM `TestnetVotingSettings`.
    pub fn testnet() -> Self {
        Self {
            voting_length: 128,
            soft_fork_epochs: 32,
            activation_epochs: 32,
            version2_activation_height: 0,
        }
    }

    /// `true` iff the given vote count meets the soft-fork supermajority.
    ///
    /// JVM `softForkApproved`: `votes > votingLength * softForkEpochs * 9 / 10`
    /// (90% supermajority across all soft-fork voting epochs).
    pub fn soft_fork_approved(&self, votes: u32) -> bool {
        let threshold =
            (self.voting_length as u64) * (self.soft_fork_epochs as u64) * 9 / 10;
        (votes as u64) > threshold
    }

    /// `true` iff a vote count meets the ordinary parameter change threshold.
    ///
    /// JVM `changeApproved`: strict majority of voting epoch length:
    /// `votes > votingLength / 2`.
    pub fn change_approved(&self, votes: u32) -> bool {
        (votes as u64) > (self.voting_length as u64) / 2
    }
}

/// Steps applied to a parameter on each successful vote.
///
/// Mirrors JVM `Parameters.stepsTable`. Indexed by absolute parameter ID
/// (1-8). The step is added on positive vote majority and subtracted on
/// negative.
pub fn parameter_step(id: i8) -> Option<i32> {
    match id.unsigned_abs() as i8 {
        1 => Some(25_000),    // StorageFeeFactor
        2 => Some(2),         // MinValuePerByte
        3 => Some(100 * 1024), // MaxBlockSize
        4 => Some(100_000),   // MaxBlockCost
        5 => Some(10),        // TokenAccessCost
        6 => Some(50),        // InputCost
        7 => Some(10),        // DataInputCost
        8 => Some(10),        // OutputCost
        _ => None,
    }
}

/// Lower bound for an ordinary parameter (mirrors JVM `minValues`).
pub fn parameter_min(id: i8) -> Option<i32> {
    match id.unsigned_abs() as i8 {
        1 => Some(0),
        2 => Some(0),
        3 => Some(16 * 1024),
        4 => Some(16 * 1024),
        5 => Some(0),
        6 => Some(0),
        7 => Some(0),
        8 => Some(0),
        _ => None,
    }
}

/// Upper bound for an ordinary parameter (mirrors JVM `maxValues`).
pub fn parameter_max(id: i8) -> Option<i32> {
    match id.unsigned_abs() as i8 {
        1 => Some(i32::MAX),
        2 => Some(i32::MAX),
        3 => Some(i32::MAX),
        4 => Some(i32::MAX),
        5 => Some(i32::MAX),
        6 => Some(i32::MAX),
        7 => Some(i32::MAX),
        8 => Some(i32::MAX),
        _ => None,
    }
}

/// Map an ordinary parameter ID (1-8) to its [`Parameter`] enum variant.
fn ordinary_param(id: i8) -> Option<Parameter> {
    match id.unsigned_abs() as i8 {
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

/// Default starting [`Parameters`] used when chain is shorter than one
/// voting epoch (no boundary block to read from).
///
/// `ergo_lib::chain::parameters::Parameters::default()` is buggy in the
/// pinned revision — it does NOT insert `MaxBlockCost`, so any code that
/// reads `params.max_block_cost()` panics. We construct a complete default
/// here, mirroring JVM `Parameters.scala` startup defaults.
pub fn default_parameters() -> Parameters {
    Parameters::new(
        1,         // BlockVersion
        1_250_000, // StorageFeeFactor
        360,       // MinValuePerByte (30 * 12)
        524_288,   // MaxBlockSize (512 KiB)
        1_000_000, // MaxBlockCost
        100,       // TokenAccessCost
        2_000,     // InputCost
        100,       // DataInputCost
        100,       // OutputCost
    )
}

/// Apply a single ordinary parameter vote step to a parameters table.
///
/// `signed_id` is the raw byte from the header `votes` slot: positive
/// means "increase", negative means "decrease". The step magnitude comes
/// from [`parameter_step`], clamped by [`parameter_min`]/[`parameter_max`].
///
/// Returns `false` if `signed_id` is not an ordinary parameter (i.e. soft
/// fork or unknown).
pub(crate) fn apply_ordinary_step(table: &mut HbHashMap<Parameter, i32>, signed_id: i8) -> bool {
    let Some(param) = ordinary_param(signed_id) else {
        return false;
    };
    let Some(step) = parameter_step(signed_id) else {
        return false;
    };
    let Some(min) = parameter_min(signed_id) else {
        return false;
    };
    let Some(max) = parameter_max(signed_id) else {
        return false;
    };

    let current = *table.get(&param).unwrap_or(&0);
    let delta = if signed_id > 0 { step } else { -step };
    let new_val = current.saturating_add(delta).clamp(min, max);
    table.insert(param, new_val);
    true
}

/// Parse parameters from a sequence of extension key-value pairs.
///
/// Mirrors JVM `Parameters.parseExtension`. Walks `kv`, picks fields with
/// 2-byte key prefix `0x00` (parameter table prefix), parses the second key
/// byte as the signed parameter ID, and decodes the 4-byte BE i32 value.
///
/// **ID 124** (`SoftForkDisablingRules`) is deferred for first release —
/// testnet doesn't vote on validation rules. The parser SKIPS ID 124 entries
/// silently. The integration with `ErgoValidationSettingsUpdate` will be
/// added in a follow-up when sigma-rust exposes its serializer.
///
/// Returns a map keyed by signed param ID. The map will include ordinary
/// IDs 1-8 plus reserved IDs 121, 122, 123 when present.
pub fn parse_parameters_from_kv(
    kv: &[([u8; 2], Vec<u8>)],
) -> Result<HashMap<i8, i32>, crate::ChainError> {
    let mut out = HashMap::new();
    for (key, value) in kv {
        if key[0] != 0x00 {
            continue; // Not a parameter field.
        }
        let id = key[1] as i8;
        if id == ID_SOFT_FORK_DISABLING_RULES {
            // Variable-length encoding via ErgoValidationSettingsUpdate.
            // Deferred — see function docs.
            continue;
        }
        if value.len() != 4 {
            return Err(crate::ChainError::ExtensionParse(format!(
                "param id {id} has wrong value length: expected 4, got {}",
                value.len()
            )));
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(value);
        out.insert(id, i32::from_be_bytes(buf));
    }
    Ok(out)
}

/// Pack a parameter table into extension key-value pairs.
///
/// Inverse of [`parse_parameters_from_kv`]. Mirrors JVM
/// `Parameters.toExtensionCandidate` for the parameter portion. Output
/// fields all have 2-byte keys `[0x00, param_id_as_byte]` and 4-byte BE
/// i32 values.
///
/// Output ordering is sorted by param ID for determinism. Skips ID 124
/// (deferred — see [`parse_parameters_from_kv`]).
pub fn pack_parameters_to_kv(params: &HashMap<i8, i32>) -> Vec<([u8; 2], Vec<u8>)> {
    let mut entries: Vec<(i8, i32)> = params
        .iter()
        .filter(|(&id, _)| id != ID_SOFT_FORK_DISABLING_RULES)
        .map(|(&id, &v)| (id, v))
        .collect();
    entries.sort_by_key(|(id, _)| *id);
    entries
        .into_iter()
        .map(|(id, v)| ([0x00u8, id as u8], v.to_be_bytes().to_vec()))
        .collect()
}

/// Parse a JVM-format Extension modifier body into key-value fields.
///
/// **Wire format** (mirror of JVM `ExtensionSerializer.parseBody`,
/// verified against testnet for ~270k blocks via the in-repo
/// `validation/src/sections.rs::parse_extension`):
///
/// ```text
/// [header_id: 32 bytes]
/// [field_count: VLQ u32]
/// fields × field_count: {
///     [key: 2 bytes]
///     [val_len: 1 byte, max 64]
///     [value: val_len bytes]
/// }
/// ```
///
/// Returns the parent header ID followed by the parsed fields. Caller
/// should validate the header ID matches the expected modifier link.
pub fn parse_extension_bytes(
    bytes: &[u8],
) -> Result<(ergo_chain_types::BlockId, Vec<([u8; 2], Vec<u8>)>), crate::ChainError> {
    use crate::ChainError;
    use ergo_chain_types::{BlockId, Digest32};
    use sigma_ser::vlq_encode::ReadSigmaVlqExt;

    if bytes.len() < 32 {
        return Err(ChainError::ExtensionParse(format!(
            "extension body too short: {} bytes, need at least 32 for header_id",
            bytes.len()
        )));
    }
    let mut header_id_bytes = [0u8; 32];
    header_id_bytes.copy_from_slice(&bytes[..32]);
    let header_id = BlockId(Digest32::from(header_id_bytes));

    let mut cursor = std::io::Cursor::new(&bytes[32..]);
    let field_count = cursor
        .get_u32()
        .map_err(|e| ChainError::ExtensionParse(format!("VLQ field_count: {e}")))?
        as usize;

    let mut pos = 32 + cursor.position() as usize;
    let mut fields = Vec::with_capacity(field_count);
    for i in 0..field_count {
        if pos + 3 > bytes.len() {
            return Err(ChainError::ExtensionParse(format!(
                "truncated field header for field {i} at offset {pos}"
            )));
        }
        let key = [bytes[pos], bytes[pos + 1]];
        let value_len = bytes[pos + 2] as usize;
        pos += 3;
        if value_len > 64 {
            return Err(ChainError::ExtensionParse(format!(
                "field {i} value length {value_len} exceeds max 64"
            )));
        }
        if pos + value_len > bytes.len() {
            return Err(ChainError::ExtensionParse(format!(
                "truncated field {i} value at offset {pos}: need {value_len} bytes"
            )));
        }
        let value = bytes[pos..pos + value_len].to_vec();
        pos += value_len;
        fields.push((key, value));
    }

    Ok((header_id, fields))
}

/// Pack a parent header ID and field set into extension wire bytes.
///
/// Inverse of [`parse_extension_bytes`]. Mirrors the JVM
/// `ExtensionSerializer` body format (header_id + VLQ count + fields).
pub fn pack_extension_bytes(
    header_id: &ergo_chain_types::BlockId,
    fields: &[([u8; 2], Vec<u8>)],
) -> Vec<u8> {
    use sigma_ser::vlq_encode::WriteSigmaVlqExt;

    let mut out = Vec::with_capacity(
        32 + 5 + fields.iter().map(|(_, v)| v.len() + 3).sum::<usize>(),
    );
    out.extend_from_slice(&header_id.0 .0);
    // VLQ-encoded field count
    out.put_u32(fields.len() as u32).expect("Vec write");
    for (key, value) in fields {
        out.extend_from_slice(key);
        out.push(value.len() as u8);
        out.extend_from_slice(value);
    }
    out
}

/// Tally header vote slots for one epoch's worth of headers.
///
/// Each header `votes` field is `[i8; 3]` (or three signed-byte slots).
/// Each non-zero slot contributes one count to its slot ID. Soft-fork
/// votes (120) are tallied just like any other.
pub fn tally_votes<'a, I>(headers: I) -> HashMap<i8, u32>
where
    I: IntoIterator<Item = &'a [u8; 3]>,
{
    let mut tally: HashMap<i8, u32> = HashMap::new();
    for slots in headers {
        for &slot in slots {
            if slot != 0 {
                *tally.entry(slot as i8).or_insert(0) += 1;
            }
        }
    }
    tally
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voting_config_testnet_preset() {
        let cfg = VotingConfig::testnet();
        assert_eq!(cfg.voting_length, 128);
        assert_eq!(cfg.soft_fork_epochs, 32);
        assert_eq!(cfg.activation_epochs, 32);
        assert_eq!(cfg.version2_activation_height, 0);
    }

    #[test]
    fn voting_config_mainnet_preset() {
        let cfg = VotingConfig::mainnet();
        assert_eq!(cfg.voting_length, 1024);
        assert_eq!(cfg.soft_fork_epochs, 32);
        assert_eq!(cfg.activation_epochs, 32);
        assert_eq!(cfg.version2_activation_height, 417_792);
    }

    #[test]
    fn change_approved_strict_majority() {
        let cfg = VotingConfig::testnet();
        // votingLength = 128, threshold = 64
        assert!(!cfg.change_approved(0));
        assert!(!cfg.change_approved(64), "exact half is NOT approved");
        assert!(cfg.change_approved(65), "65 is strict majority");
        assert!(cfg.change_approved(128));
    }

    #[test]
    fn soft_fork_approved_supermajority() {
        let cfg = VotingConfig::testnet();
        // 128 * 32 * 9 / 10 = 36864 / 10 = 3686 (integer div)
        let threshold = 128u32 * 32 * 9 / 10;
        assert!(!cfg.soft_fork_approved(threshold));
        assert!(cfg.soft_fork_approved(threshold + 1));
    }

    #[test]
    fn tally_three_slots_per_header() {
        let headers = vec![[1u8, 0, 0], [1, 2, 0], [1, 2, 3]];
        let refs: Vec<&[u8; 3]> = headers.iter().collect();
        let tally = tally_votes(refs);
        assert_eq!(tally.get(&1), Some(&3));
        assert_eq!(tally.get(&2), Some(&2));
        assert_eq!(tally.get(&3), Some(&1));
    }

    #[test]
    fn tally_zero_slots_ignored() {
        let headers = vec![[0u8, 0, 0]; 100];
        let refs: Vec<&[u8; 3]> = headers.iter().collect();
        let tally = tally_votes(refs);
        assert!(tally.is_empty());
    }

    #[test]
    fn tally_negative_votes_distinct() {
        // 0xFF = -1 as i8 = "decrease StorageFeeFactor"
        let headers = vec![[1u8, 0xFF, 0]];
        let refs: Vec<&[u8; 3]> = headers.iter().collect();
        let tally = tally_votes(refs);
        assert_eq!(tally.get(&1), Some(&1));
        assert_eq!(tally.get(&-1), Some(&1));
    }

    #[test]
    fn default_parameters_includes_max_block_cost() {
        let p = default_parameters();
        // The bug we're working around: Parameters::default() omits this.
        let _ = p.max_block_cost();
    }

    #[test]
    fn apply_ordinary_step_increase() {
        let mut table: HbHashMap<Parameter, i32> = HbHashMap::new();
        table.insert(Parameter::StorageFeeFactor, 1_250_000);
        let applied = apply_ordinary_step(&mut table, 1);
        assert!(applied);
        assert_eq!(table[&Parameter::StorageFeeFactor], 1_275_000);
    }

    #[test]
    fn apply_ordinary_step_decrease() {
        let mut table: HbHashMap<Parameter, i32> = HbHashMap::new();
        table.insert(Parameter::StorageFeeFactor, 1_250_000);
        let applied = apply_ordinary_step(&mut table, -1);
        assert!(applied);
        assert_eq!(table[&Parameter::StorageFeeFactor], 1_225_000);
    }

    #[test]
    fn apply_ordinary_step_clamped_below_min() {
        let mut table: HbHashMap<Parameter, i32> = HbHashMap::new();
        table.insert(Parameter::MaxBlockSize, 16 * 1024); // at min
        let applied = apply_ordinary_step(&mut table, -3);
        assert!(applied);
        assert_eq!(table[&Parameter::MaxBlockSize], 16 * 1024, "clamped at min");
    }

    #[test]
    fn apply_ordinary_step_unknown_id() {
        let mut table: HbHashMap<Parameter, i32> = HbHashMap::new();
        let applied = apply_ordinary_step(&mut table, 99);
        assert!(!applied);
    }

    #[test]
    fn parse_parameters_roundtrip() {
        let mut input: HashMap<i8, i32> = HashMap::new();
        input.insert(1, 1_250_000); // StorageFeeFactor
        input.insert(4, 1_000_000); // MaxBlockCost
        input.insert(123, 2);       // BlockVersion

        let kv = pack_parameters_to_kv(&input);
        // Each entry is 2-byte key + 4-byte value
        for (key, value) in &kv {
            assert_eq!(key[0], 0x00);
            assert_eq!(value.len(), 4);
        }

        let parsed = parse_parameters_from_kv(&kv).unwrap();
        assert_eq!(parsed, input);
    }

    #[test]
    fn parse_parameters_skips_non_param_fields() {
        let kv = vec![
            ([0x01u8, 0x00], vec![0xAA; 33]), // Interlink field — ignored
            ([0x00u8, 0x01], 1_250_000i32.to_be_bytes().to_vec()),
        ];
        let parsed = parse_parameters_from_kv(&kv).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed.get(&1), Some(&1_250_000));
    }

    #[test]
    fn parse_parameters_negative_id() {
        // Negative param IDs (decrease votes) appear in vote slots, NOT in
        // the extension table. Only positive IDs are stored. But the parser
        // accepts any byte; let's just verify it round-trips.
        let kv = vec![([0x00u8, 0xFF], 100i32.to_be_bytes().to_vec())];
        let parsed = parse_parameters_from_kv(&kv).unwrap();
        assert_eq!(parsed.get(&-1), Some(&100));
    }

    #[test]
    fn parse_parameters_wrong_value_length_errors() {
        let kv = vec![([0x00u8, 0x01], vec![0u8; 3])];
        assert!(parse_parameters_from_kv(&kv).is_err());
    }

    #[test]
    fn parse_parameters_skips_id_124() {
        // ID 124 has variable-length encoding; we defer it.
        let kv = vec![
            ([0x00u8, 124], vec![0u8; 17]), // Bogus length — must be skipped, not error
            ([0x00u8, 1], 100i32.to_be_bytes().to_vec()),
        ];
        let parsed = parse_parameters_from_kv(&kv).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed.get(&1), Some(&100));
    }

    #[test]
    fn pack_parameters_skips_id_124() {
        let mut input: HashMap<i8, i32> = HashMap::new();
        input.insert(124, 999);
        input.insert(1, 100);
        let kv = pack_parameters_to_kv(&input);
        assert_eq!(kv.len(), 1);
        assert_eq!(kv[0].0, [0x00u8, 0x01]);
    }

    #[test]
    fn pack_parameters_deterministic_order() {
        let mut input: HashMap<i8, i32> = HashMap::new();
        input.insert(123, 2);
        input.insert(1, 1_250_000);
        input.insert(8, 100);
        let kv = pack_parameters_to_kv(&input);
        // Sorted by ID ascending
        assert_eq!(kv[0].0[1], 1);
        assert_eq!(kv[1].0[1], 8);
        assert_eq!(kv[2].0[1], 123);
    }

    #[test]
    fn extension_bytes_roundtrip() {
        use ergo_chain_types::{BlockId, Digest32};

        let header_id = BlockId(Digest32::from([0xABu8; 32]));
        let fields = vec![
            ([0x00u8, 0x01], 1_250_000i32.to_be_bytes().to_vec()),
            ([0x00u8, 0x7B], 2i32.to_be_bytes().to_vec()), // 0x7B = 123 = BlockVersion
            ([0x01u8, 0x00], vec![0xCD; 33]),                // interlink-style field
        ];

        let packed = pack_extension_bytes(&header_id, &fields);
        let (parsed_id, parsed_fields) = parse_extension_bytes(&packed).unwrap();

        assert_eq!(parsed_id.0 .0, [0xABu8; 32]);
        assert_eq!(parsed_fields, fields);
    }

    /// Hardcoded byte sequence in the corrected wire format. Verifies
    /// the parser handles the JVM-canonical layout:
    ///
    /// `[header_id: 32B][field_count: VLQ u32][fields...]`
    #[test]
    fn extension_bytes_hardcoded_layout() {
        // header_id = [0xAA; 32]
        // 2 fields:
        //   [0x00, 0x01] -> [0x00, 0x13, 0x12, 0xD0]  (4 bytes = 1_250_000 BE)
        //   [0x01, 0x00] -> [0xFF, 0xEE, 0xDD]        (3 bytes)
        // VLQ(2) = 0x02
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0xAAu8; 32]);
        bytes.push(0x02); // VLQ field_count = 2
        // Field 1
        bytes.extend_from_slice(&[0x00, 0x01]); // key
        bytes.push(4); // val_len
        bytes.extend_from_slice(&1_250_000i32.to_be_bytes()); // value
        // Field 2
        bytes.extend_from_slice(&[0x01, 0x00]); // key
        bytes.push(3); // val_len
        bytes.extend_from_slice(&[0xFF, 0xEE, 0xDD]); // value

        let (id, fields) = parse_extension_bytes(&bytes).expect("parse hardcoded");
        assert_eq!(id.0 .0, [0xAAu8; 32]);
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].0, [0x00, 0x01]);
        assert_eq!(fields[0].1, 1_250_000i32.to_be_bytes().to_vec());
        assert_eq!(fields[1].0, [0x01, 0x00]);
        assert_eq!(fields[1].1, vec![0xFF, 0xEE, 0xDD]);
    }

    /// Verify the writer matches the hardcoded layout exactly.
    #[test]
    fn extension_bytes_writer_matches_hardcoded_layout() {
        use ergo_chain_types::{BlockId, Digest32};
        let header_id = BlockId(Digest32::from([0xAAu8; 32]));
        let fields = vec![
            ([0x00u8, 0x01], 1_250_000i32.to_be_bytes().to_vec()),
            ([0x01u8, 0x00], vec![0xFF, 0xEE, 0xDD]),
        ];
        let packed = pack_extension_bytes(&header_id, &fields);

        let mut expected = Vec::new();
        expected.extend_from_slice(&[0xAAu8; 32]);
        expected.push(0x02); // VLQ field_count
        expected.extend_from_slice(&[0x00, 0x01, 4]);
        expected.extend_from_slice(&1_250_000i32.to_be_bytes());
        expected.extend_from_slice(&[0x01, 0x00, 3]);
        expected.extend_from_slice(&[0xFF, 0xEE, 0xDD]);

        assert_eq!(packed, expected);
    }

    #[test]
    fn extension_bytes_too_short_errors() {
        let result = parse_extension_bytes(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn extension_bytes_truncated_field_errors() {
        // Header ID + VLQ count = 1 + key (2 bytes) but no length byte
        let mut bytes = vec![0u8; 32];
        bytes.push(0x01); // VLQ count = 1
        bytes.extend_from_slice(&[0x00, 0x01]);
        let result = parse_extension_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn extension_bytes_truncated_value_errors() {
        // Header ID + VLQ count = 1 + key + len=10 but only 5 bytes follow
        let mut bytes = vec![0u8; 32];
        bytes.push(0x01);
        bytes.extend_from_slice(&[0x00, 0x01, 10]);
        bytes.extend_from_slice(&[0u8; 5]);
        let result = parse_extension_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn extension_bytes_value_over_64_errors() {
        let mut bytes = vec![0u8; 32];
        bytes.push(0x01);
        bytes.extend_from_slice(&[0x00, 0x01, 65]);
        bytes.extend_from_slice(&[0u8; 65]);
        let result = parse_extension_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn extension_bytes_empty_fields_ok() {
        use ergo_chain_types::{BlockId, Digest32};
        let header_id = BlockId(Digest32::from([0u8; 32]));
        let bytes = pack_extension_bytes(&header_id, &[]);
        let (id, fields) = parse_extension_bytes(&bytes).unwrap();
        assert_eq!(id.0 .0, [0u8; 32]);
        assert!(fields.is_empty());
        // Empty extension is exactly: 32 header bytes + 1 VLQ count byte (0)
        assert_eq!(bytes.len(), 33);
        assert_eq!(bytes[32], 0x00);
    }
}
