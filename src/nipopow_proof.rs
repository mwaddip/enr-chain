//! NiPoPoW proof construction and verification (Phase 6).
//!
//! Wraps `ergo-nipopow` for build/verify on the local header chain.
//! Light-client sync mode (applying a proof to chain state) is out of
//! scope — proofs are verified for correctness but not used to skip
//! block download.
//!
//! JVM reference:
//! - `ergo-core/src/main/scala/org/ergoplatform/modifiers/history/popow/NipopowProof.scala`
//! - `ergo-core/src/main/scala/org/ergoplatform/modifiers/history/popow/NipopowAlgos.scala`

use ergo_chain_types::{BlockId, ExtensionCandidate, Header};
use ergo_nipopow::{NipopowAlgos, NipopowProof, PoPowHeader};
use sigma_ser::ScorexSerializable;

use crate::chain::HeaderChain;
use crate::error::ChainError;

/// Cap on the m and k security parameters.
///
/// Both must be ≥ 1 and ≤ this value. Prevents pathological calls and
/// caps the proof size for sanity.
pub const MAX_M_K: u32 = 256;

/// Metadata extracted from a verified NiPoPoW proof.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NipopowProofMeta {
    /// Height of the suffix tip (highest header in the proof).
    pub suffix_tip_height: u32,
    /// Total number of headers in the proof (prefix + suffix).
    pub total_headers: usize,
    /// Whether the proof is in continuous mode (carries difficulty headers).
    ///
    /// Always `false` for first release; we don't currently propagate the
    /// continuous-mode flag from `NipopowProof`. Difficulty-recalculation
    /// header presence is not separately validated either.
    pub continuous: bool,
}

/// Build a NiPoPoW proof for the local chain.
///
/// **Preconditions**:
/// - `1 <= m, k <= MAX_M_K`
/// - The chain must contain at least `m + k` headers
/// - If `header_id` is `Some`, it must be in the chain (the suffix tip)
/// - An extension loader must be set on the chain (for fetching interlinks)
///
/// Returns the inner serialized NiPoPoW proof bytes — NO P2P envelope.
/// The main crate handles message wrapping when sending.
///
/// **Determinism**: For any two correct implementations on the same chain
/// state, the output is byte-identical.
pub fn build_nipopow_proof(
    chain: &HeaderChain,
    m: u32,
    k: u32,
    header_id: Option<BlockId>,
) -> Result<Vec<u8>, ChainError> {
    if m == 0 || k == 0 {
        return Err(ChainError::Nipopow("m and k must be >= 1".into()));
    }
    if m > MAX_M_K || k > MAX_M_K {
        return Err(ChainError::Nipopow(format!(
            "m and k must be <= {MAX_M_K}"
        )));
    }

    let loader = chain.extension_loader().ok_or_else(|| {
        ChainError::Nipopow("extension loader not set".into())
    })?;

    let suffix_tip_height = match header_id {
        Some(id) => chain.height_of(&id).ok_or_else(|| {
            ChainError::Nipopow("header_id not in chain".into())
        })?,
        None => chain.height(),
    };

    if suffix_tip_height < (m + k) {
        return Err(ChainError::Nipopow(format!(
            "chain too short: need at least m+k = {} headers, have {}",
            m + k,
            suffix_tip_height
        )));
    }

    // Build PoPowHeaders for heights 1..=suffix_tip_height.
    let mut popow_headers: Vec<PoPowHeader> = Vec::with_capacity(suffix_tip_height as usize);
    for h in 1..=suffix_tip_height {
        let header = chain
            .header_at(h)
            .ok_or_else(|| {
                ChainError::Nipopow(format!("header at height {h} missing"))
            })?
            .clone();

        let ext_bytes = loader(h).ok_or_else(|| {
            ChainError::Nipopow(format!("extension at height {h} missing from loader"))
        })?;
        let (_, fields) = crate::voting::parse_extension_bytes(&ext_bytes)?;
        let extension_candidate = ExtensionCandidate::new(fields).map_err(|e| {
            ChainError::Nipopow(format!("ExtensionCandidate::new failed: {e}"))
        })?;

        let interlinks = NipopowAlgos::unpack_interlinks(&extension_candidate)
            .map_err(|e| ChainError::Nipopow(format!("unpack_interlinks: {e}")))?;
        let interlinks_proof = NipopowAlgos::proof_for_interlink_vector(&extension_candidate)
            .ok_or_else(|| {
                ChainError::Nipopow("proof_for_interlink_vector returned None".into())
            })?;

        popow_headers.push(PoPowHeader {
            header,
            interlinks,
            interlinks_proof,
        });
    }

    let algos = NipopowAlgos::default();
    let proof = algos
        .prove(&popow_headers, k, m)
        .map_err(|e| ChainError::Nipopow(format!("prove failed: {e:?}")))?;

    proof
        .scorex_serialize_bytes()
        .map_err(|e| ChainError::Nipopow(format!("serialize failed: {e:?}")))
}

/// Verify a NiPoPoW proof from raw bytes.
///
/// **Precondition**: `bytes` is the inner NiPoPoW proof payload (the main
/// crate has stripped any P2P message envelope).
///
/// **Validation checks** (mirrors `NipopowProof.isValid`):
/// 1. The proof parses cleanly via the Scorex serializer.
/// 2. Heights strictly increasing across the headers chain.
/// 3. Each header's PoW passes [`crate::verify_pow`].
/// 4. Parent connections in the chain are consistent (via
///    `NipopowProof::has_valid_connections`).
///
/// Does NOT touch chain state. Does NOT apply the proof to local chain.
pub fn verify_nipopow_proof_bytes(bytes: &[u8]) -> Result<NipopowProofMeta, ChainError> {
    verify_inner(bytes, true)
}

/// Test-only: verify a NiPoPoW proof without running the per-header PoW
/// check. Used by unit tests on synthetic chains where headers don't have
/// real Autolykos solutions.
#[cfg(test)]
pub(crate) fn verify_nipopow_proof_bytes_no_pow(
    bytes: &[u8],
) -> Result<NipopowProofMeta, ChainError> {
    verify_inner(bytes, false)
}

fn verify_inner(bytes: &[u8], check_pow: bool) -> Result<NipopowProofMeta, ChainError> {
    if bytes.is_empty() {
        return Err(ChainError::Nipopow("empty proof bytes".into()));
    }
    let proof = NipopowProof::scorex_parse_bytes(bytes).map_err(|e| {
        ChainError::Nipopow(format!("parse failed: {e:?}"))
    })?;

    if !proof.has_valid_connections() {
        return Err(ChainError::Nipopow("invalid connections".into()));
    }

    // Walk all headers (prefix + suffix_head + suffix_tail) in order and
    // check strictly-increasing heights + (optionally) PoW.
    let all_headers: Vec<&Header> = proof
        .prefix
        .iter()
        .map(|p| &p.header)
        .chain(std::iter::once(&proof.suffix_head.header))
        .chain(proof.suffix_tail.iter())
        .collect();

    if all_headers.is_empty() {
        return Err(ChainError::Nipopow("empty proof headers chain".into()));
    }

    let mut last_height: Option<u32> = None;
    for h in &all_headers {
        if let Some(prev) = last_height {
            if h.height <= prev {
                return Err(ChainError::Nipopow(format!(
                    "non-increasing heights: {} after {}",
                    h.height, prev
                )));
            }
        }
        last_height = Some(h.height);
        if check_pow {
            crate::verify_pow(h)?;
        }
    }

    Ok(NipopowProofMeta {
        suffix_tip_height: last_height.unwrap_or(0),
        total_headers: all_headers.len(),
        continuous: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::voting::pack_extension_bytes;
    use crate::{ChainConfig, HeaderChain};
    use ergo_chain_types::{ADDigest, AutolykosSolution, BlockId, Digest32, EcPoint, Header, Votes};
    use sigma_ser::ScorexSerializable;
    use std::sync::{Arc, Mutex};

    fn make_synthetic_header(
        height: u32,
        parent_id: BlockId,
        timestamp: u64,
        n_bits: u32,
    ) -> Header {
        let zero32 = Digest32::zero();
        let mut header = Header {
            version: 2,
            id: BlockId(Digest32::zero()),
            parent_id,
            ad_proofs_root: zero32,
            state_root: ADDigest::zero(),
            transaction_root: zero32,
            timestamp,
            n_bits,
            height,
            extension_root: zero32,
            autolykos_solution: AutolykosSolution {
                miner_pk: Box::new(EcPoint::default()),
                pow_onetime_pk: None,
                nonce: height.to_be_bytes().repeat(2),
                pow_distance: None,
            },
            votes: Votes([0, 0, 0]),
            unparsed_bytes: Box::new([]),
        };
        let bytes = header.scorex_serialize_bytes().unwrap();
        let reparsed = Header::scorex_parse_bytes(&bytes).unwrap();
        header.id = reparsed.id;
        header
    }

    /// Build a synthetic chain of `count` headers + a per-height extension
    /// store containing interlink fields. Returns the chain (with loader
    /// already wired) and the synthetic store.
    fn build_chain_with_interlinks(count: u32) -> HeaderChain {
        let config = ChainConfig::testnet();
        let mut chain = HeaderChain::new(config.clone());
        let n_bits = config.initial_n_bits;

        // Build headers list first so we can compute interlinks for each
        // and store the extension bytes per height.
        let mut headers: Vec<Header> = Vec::with_capacity(count as usize);
        let mut prev_id = BlockId(Digest32::zero());
        let g = make_synthetic_header(1, prev_id, 1_000_000, n_bits);
        prev_id = g.id;
        headers.push(g);
        for h in 2..=count {
            // Compute expected difficulty based on currently-built chain
            // for nBits inheritance — but to avoid bringing in chain state
            // here, we just use the parent's n_bits within the first epoch.
            let header = make_synthetic_header(
                h,
                prev_id,
                1_000_000 + (h as u64 - 1) * 45_000,
                n_bits,
            );
            prev_id = header.id;
            headers.push(header);
        }

        // Build per-height interlinks and extension bytes.
        let mut interlinks: Vec<Vec<BlockId>> = Vec::with_capacity(headers.len());
        for (idx, h) in headers.iter().enumerate() {
            if idx == 0 {
                // Genesis: interlinks = [genesis_id]
                interlinks.push(vec![h.id]);
            } else {
                let prev_header = &headers[idx - 1];
                let prev_interlinks = interlinks[idx - 1].clone();
                let new_interlinks =
                    NipopowAlgos::update_interlinks(prev_header.clone(), prev_interlinks)
                        .expect("update_interlinks");
                interlinks.push(new_interlinks);
            }
        }

        // Pack each into extension bytes keyed by height.
        let mut store: std::collections::HashMap<u32, Vec<u8>> =
            std::collections::HashMap::new();
        for (idx, h) in headers.iter().enumerate() {
            let interlinks_for_h = &interlinks[idx];
            let fields = NipopowAlgos::pack_interlinks(interlinks_for_h.clone());
            let bytes = pack_extension_bytes(&h.id, &fields);
            store.insert(h.height, bytes);
        }

        // Append headers to chain (no_pow path).
        for h in headers {
            chain.try_append_no_pow(h).expect("append");
        }

        // Wire loader.
        let store_arc = Arc::new(Mutex::new(store));
        chain.set_extension_loader(move |height| {
            store_arc.lock().unwrap().get(&height).cloned()
        });

        chain
    }

    #[test]
    fn build_proof_too_short_chain_errors() {
        let chain = build_chain_with_interlinks(3);
        let r = build_nipopow_proof(&chain, 2, 2, None);
        assert!(r.is_err(), "chain of 3 < m+k=4 must error");
    }

    #[test]
    fn build_proof_invalid_m_k_errors() {
        let chain = build_chain_with_interlinks(20);
        assert!(build_nipopow_proof(&chain, 0, 2, None).is_err());
        assert!(build_nipopow_proof(&chain, 2, 0, None).is_err());
        assert!(build_nipopow_proof(&chain, 257, 2, None).is_err());
        assert!(build_nipopow_proof(&chain, 2, 257, None).is_err());
    }

    #[test]
    fn build_proof_no_loader_errors() {
        let mut chain = HeaderChain::new(ChainConfig::testnet());
        // Build small chain without loader
        let n_bits = chain.config().initial_n_bits;
        let mut prev = BlockId(Digest32::zero());
        for h in 1..=10 {
            let hdr = make_synthetic_header(
                h,
                prev,
                1_000_000 + (h as u64 - 1) * 45_000,
                n_bits,
            );
            prev = hdr.id;
            chain.try_append_no_pow(hdr).unwrap();
        }
        let r = build_nipopow_proof(&chain, 2, 2, None);
        assert!(r.is_err());
    }

    #[test]
    fn build_proof_returns_non_empty_bytes() {
        let chain = build_chain_with_interlinks(20);
        let bytes = build_nipopow_proof(&chain, 2, 2, None).expect("build");
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_then_verify_roundtrip_no_pow() {
        let chain = build_chain_with_interlinks(20);
        let bytes = build_nipopow_proof(&chain, 2, 2, None).expect("build");
        let meta = verify_nipopow_proof_bytes_no_pow(&bytes).expect("verify");
        assert!(meta.total_headers > 0);
        assert_eq!(meta.suffix_tip_height, 20);
    }

    #[test]
    fn verify_empty_bytes_errors() {
        let r = verify_nipopow_proof_bytes(&[]);
        assert!(r.is_err());
    }

    #[test]
    fn verify_garbage_bytes_errors() {
        let r = verify_nipopow_proof_bytes(&[0xFFu8; 32]);
        assert!(r.is_err());
    }

    #[test]
    fn verify_mutated_proof_fails() {
        let chain = build_chain_with_interlinks(20);
        let mut bytes = build_nipopow_proof(&chain, 2, 2, None).expect("build");

        // Mutate a byte well past the m, k header (around offset 50 to land
        // in the proof body, not in the m/k prefix).
        if bytes.len() > 50 {
            bytes[50] ^= 0xFFu8;
        }
        let r = verify_nipopow_proof_bytes_no_pow(&bytes);
        assert!(r.is_err(), "mutated proof must fail");
    }
}
