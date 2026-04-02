use ergo_chain_types::blake2b256_hash;
use ergo_chain_types::Header;

/// Modifier type IDs for block sections.
pub const HEADER_TYPE_ID: u8 = 101;
pub const BLOCK_TRANSACTIONS_TYPE_ID: u8 = 102;
pub const AD_PROOFS_TYPE_ID: u8 = 104;
pub const EXTENSION_TYPE_ID: u8 = 108;

/// Compute the modifier IDs for the three non-header block sections.
///
/// Returns `[(type_id, modifier_id); 3]` for BlockTransactions, ADProofs,
/// and Extension. Each modifier ID is `Blake2b256(type_id || header.id || section_root)`.
///
/// Matches JVM `NonHeaderBlockSection.computeId(typeId, headerId, digest)`.
pub fn section_ids(header: &Header) -> [(u8, [u8; 32]); 3] {
    [
        (BLOCK_TRANSACTIONS_TYPE_ID, prefixed_hash(BLOCK_TRANSACTIONS_TYPE_ID, &header.id.0 .0, &header.transaction_root.0)),
        (AD_PROOFS_TYPE_ID, prefixed_hash(AD_PROOFS_TYPE_ID, &header.id.0 .0, &header.ad_proofs_root.0)),
        (EXTENSION_TYPE_ID, prefixed_hash(EXTENSION_TYPE_ID, &header.id.0 .0, &header.extension_root.0)),
    ]
}

/// `Blake2b256(prefix_byte || data1 || data2)` — mirrors Scorex `Algos.hash.prefixedHash`.
fn prefixed_hash(prefix: u8, data1: &[u8; 32], data2: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + 32 + 32);
    buf.push(prefix);
    buf.extend_from_slice(data1);
    buf.extend_from_slice(data2);
    blake2b256_hash(&buf).0
}
