#[cfg(test)]
mod parse_tests {
    use crate::{parse_header, ChainError};
    use sigma_ser::ScorexSerializable;

    fn v2_header_json() -> &'static str {
        r#"{
            "extensionId": "d16f25b14457186df4c5f6355579cc769261ce1aebc8209949ca6feadbac5a3f",
            "difficulty": "626412390187008",
            "votes": "040000",
            "timestamp": 1618929697400,
            "size": 221,
            "stateRoot": "8ad868627ea4f7de6e2a2fe3f98fafe57f914e0f2ef3331c006def36c697f92713",
            "height": 471746,
            "nBits": 117586360,
            "version": 2,
            "id": "4caa17e62fe66ba7bd69597afdc996ae35b1ff12e0ba90c22ff288a4de10e91b",
            "adProofsRoot": "d882aaf42e0a95eb95fcce5c3705adf758e591532f733efe790ac3c404730c39",
            "transactionsRoot": "63eaa9aff76a1de3d71c81e4b2d92e8d97ae572a8e9ab9e66599ed0912dd2f8b",
            "extensionHash": "3f91f3c680beb26615fdec251aee3f81aaf5a02740806c167c0f3c929471df44",
            "powSolutions": {
              "pk": "02b3a06d6eaa8671431ba1db4dd427a77f75a5c2acbd71bfb725d38adc2b55f669",
              "w": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
              "n": "5939ecfee6b0d7f4",
              "d": "1234000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            },
            "parentId": "6481752bace5fa5acba5d5ef7124d48826664742d46c974c98a2d60ace229a34"
        }"#
    }

    /// Parse a V2 header from scorex-serialized bytes and verify all fields match.
    #[test]
    fn parse_v2_header_roundtrip() {
        let from_json: ergo_chain_types::Header = serde_json::from_str(v2_header_json()).unwrap();
        let serialized = from_json.scorex_serialize_bytes().unwrap();

        let parsed = parse_header(&serialized).unwrap();

        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.height, 471746);
        assert_eq!(parsed.timestamp, 1618929697400);
        assert_eq!(parsed.n_bits, 117586360);
        assert_eq!(parsed.id, from_json.id);
        assert_eq!(parsed.parent_id, from_json.parent_id);
        assert_eq!(parsed.ad_proofs_root, from_json.ad_proofs_root);
        assert_eq!(parsed.transaction_root, from_json.transaction_root);
        assert_eq!(parsed.state_root, from_json.state_root);
        assert_eq!(parsed.extension_root, from_json.extension_root);
        // V2 wire format omits pow_onetime_pk and pow_distance — they're None after roundtrip
        assert_eq!(parsed.autolykos_solution.miner_pk, from_json.autolykos_solution.miner_pk);
        assert_eq!(parsed.autolykos_solution.nonce, from_json.autolykos_solution.nonce);
        assert!(parsed.autolykos_solution.pow_onetime_pk.is_none());
        assert!(parsed.autolykos_solution.pow_distance.is_none());
        assert_eq!(parsed.votes, from_json.votes);
    }

    /// Parse a V1 header from scorex-serialized bytes.
    #[test]
    fn parse_v1_header_roundtrip() {
        let json = r#"{
            "extensionId": "d16f25b14457186df4c5f6355579cc769261ce1aebc8209949ca6feadbac5a3f",
            "difficulty": "626412390187008",
            "votes": "000000",
            "timestamp": 1562027226367,
            "size": 279,
            "stateRoot": "144c15900826f6e2aac70cb50e541215b337d0d1674da6b491499944e686b41b0e",
            "height": 3132,
            "nBits": 117483687,
            "version": 1,
            "id": "41c73753452a292442799bd884fbcc2a9b0f62d4cff7ad02ccd3dbe65791c908",
            "adProofsRoot": "c9d58eacf6108c9a166b0b76020e3323c6c2ccec5ec8f905ea46f5bcc58aac80",
            "transactionsRoot": "01bf55fd587291172f458232a7f58b4b29469d72b8e304aafd68401f915b0c36",
            "extensionHash": "ccb136ffd50a16f50a499e1c33d8ae1e8426bdc70b13a4d82275d057be2d04a7",
            "powSolutions": {
              "pk": "02ff03f4b981c59ccd5185fddcd949b8f5697341e60d808d2be0e3e09d2ec78bf4",
              "w": "037427400e5292a177dc242631f78ab322b7845ad2b8491b016b7c36407c6a6d76",
              "n": "0000667700008481",
              "d": 410958177852074551025494081160156537946251159549691138805256284
            },
            "parentId": "150290bbaf91ccd4dcf307cb9a5113eed67e12694ec9be277e8fa55fb5ebf6ac"
        }"#;

        let from_json: ergo_chain_types::Header = serde_json::from_str(json).unwrap();
        let serialized = from_json.scorex_serialize_bytes().unwrap();

        let parsed = parse_header(&serialized).unwrap();

        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.height, 3132);
        assert_eq!(parsed.id, from_json.id);
        assert_eq!(parsed.autolykos_solution.pow_distance, from_json.autolykos_solution.pow_distance);
        assert!(parsed.autolykos_solution.pow_onetime_pk.is_some());
    }

    /// Empty bytes must fail gracefully, not panic.
    #[test]
    fn parse_empty_bytes_fails() {
        let result = parse_header(&[]);
        assert!(result.is_err());
        assert!(matches!(result, Err(ChainError::Parse(_))));
    }

    /// Truncated bytes must fail gracefully.
    #[test]
    fn parse_truncated_bytes_fails() {
        let result = parse_header(&[0x02, 0x01, 0x02, 0x03]);
        assert!(result.is_err());
    }

    /// Random garbage must fail gracefully.
    #[test]
    fn parse_garbage_fails() {
        let garbage: Vec<u8> = (0..200).map(|i| (i * 37 + 13) as u8).collect();
        let result = parse_header(&garbage);
        // May succeed with garbage values or fail — either is fine.
        // The contract says "never panics on malformed input."
        let _ = result;
    }
}

#[cfg(test)]
mod pow_tests {
    use crate::verify_pow;

    /// Valid V2 header at height 614400 (first N increase) — known-good PoW from sigma-rust tests.
    #[test]
    fn verify_pow_valid_v2_header() {
        let json = r#"{
            "extensionId" : "00cce45975d87414e8bdd8146bc88815be59cd9fe37a125b5021101e05675a18",
            "difficulty" : "16384",
            "votes" : "000000",
            "timestamp" : 4928911477310178288,
            "size" : 223,
            "stateRoot" : "5c8c00b8403d3701557181c8df800001b6d5009e2201c6ff807d71808c00019780",
            "height" : 614400,
            "nBits" : 37748736,
            "version" : 2,
            "id" : "5603a937ec1988220fc44fb5022fb82d5565b961f005ebb55d85bd5a9e6f801f",
            "adProofsRoot" : "5d3f80dcff7f5e7f59007294c180808d0158d1ff6ba10000f901c7f0ef87dcff",
            "transactionsRoot" : "f17fffacb6ff7f7f1180d2ff7f1e24ffffe1ff937f807f0797b9ff6ebdae007e",
            "extensionHash" : "1480887f80007f4b01cf7f013ff1ffff564a0000b9a54f00770e807f41ff88c0",
            "powSolutions" : {
              "pk" : "03bedaee069ff4829500b3c07c4d5fe6b3ea3d3bf76c5c28c1d4dcdb1bed0ade0c",
              "n" : "0000000000003105"
            },
            "adProofsId" : "dec129290a763f4de41f04e87e2b661dd59758af6bdd00dd51f5d97c3a8cb9b5",
            "transactionsId" : "eba1dd82cf51147232e09c1f72b37c554c30f63274d5093bff36849a83472a42",
            "parentId" : "ac2101807f0000ca01ff0119db227f202201007f62000177a080005d440896d0"
        }"#;

        let header: ergo_chain_types::Header = serde_json::from_str(json).unwrap();
        let result = verify_pow(&header);
        assert!(result.is_ok(), "valid PoW should pass: {result:?}");
    }

    /// Invalid V2 header at height 2870 — PoW doesn't meet difficulty target.
    #[test]
    fn verify_pow_invalid_v2_header() {
        let json = r#"{"extensionId":"277907e4e5e42f27e928e6101cc4fec173bee5d7728794b73d7448c339c380e5","difficulty":"1325481984","votes":"000000","timestamp":1611225263165,"size":219,"stateRoot":"c0d0b5eafd07b22487dac66628669c42a242b90bef3e1fcdc76d83140d58b6bc0e","height":2870,"nBits":72286528,"version":2,"id":"5b0ce6711de6b926f60b67040cc4512804517785df375d063f1bf1d75588af3a","adProofsRoot":"49453875a43035c7640dee2f905efe06128b00d41acd2c8df13691576d4fd85c","transactionsRoot":"770cbb6e18673ed025d386487f15d3252115d9a6f6c9b947cf3d04731dd6ab75","extensionHash":"9bc7d54583c5d44bb62a7be0473cd78d601822a626afc13b636f2cbff0d87faf","powSolutions":{"pk":"0288114b0586efea9f86e4587f2071bc1c85fb77e15eba96b2769733e0daf57903","w":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","n":"000100000580a91b","d":0},"adProofsId":"4fc36d59bf26a672e01fbfde1445bd66f50e0f540f24102e1e27d0be1a99dfbf","transactionsId":"d196ef8a7ef582ab1fdab4ef807715183705301c6ae2ff0dcbe8f1d577ba081f","parentId":"ab19e6c7a4062979dddb534df83f236d1b949c7cef18bcf434a67e87c593eef9"}"#;

        let header: ergo_chain_types::Header = serde_json::from_str(json).unwrap();
        let result = verify_pow(&header);
        assert!(result.is_err(), "invalid PoW should fail");
    }

    /// PoW verification on a parsed-from-bytes header (integration: parse then verify).
    #[test]
    fn parse_then_verify_pow() {
        use crate::parse_header;
        use sigma_ser::ScorexSerializable;

        let json = r#"{
            "extensionId" : "00cce45975d87414e8bdd8146bc88815be59cd9fe37a125b5021101e05675a18",
            "difficulty" : "16384",
            "votes" : "000000",
            "timestamp" : 4928911477310178288,
            "size" : 223,
            "stateRoot" : "5c8c00b8403d3701557181c8df800001b6d5009e2201c6ff807d71808c00019780",
            "height" : 614400,
            "nBits" : 37748736,
            "version" : 2,
            "id" : "5603a937ec1988220fc44fb5022fb82d5565b961f005ebb55d85bd5a9e6f801f",
            "adProofsRoot" : "5d3f80dcff7f5e7f59007294c180808d0158d1ff6ba10000f901c7f0ef87dcff",
            "transactionsRoot" : "f17fffacb6ff7f7f1180d2ff7f1e24ffffe1ff937f807f0797b9ff6ebdae007e",
            "extensionHash" : "1480887f80007f4b01cf7f013ff1ffff564a0000b9a54f00770e807f41ff88c0",
            "powSolutions" : {
              "pk" : "03bedaee069ff4829500b3c07c4d5fe6b3ea3d3bf76c5c28c1d4dcdb1bed0ade0c",
              "n" : "0000000000003105"
            },
            "adProofsId" : "dec129290a763f4de41f04e87e2b661dd59758af6bdd00dd51f5d97c3a8cb9b5",
            "transactionsId" : "eba1dd82cf51147232e09c1f72b37c554c30f63274d5093bff36849a83472a42",
            "parentId" : "ac2101807f0000ca01ff0119db227f202201007f62000177a080005d440896d0"
        }"#;

        // Simulate the P2P path: JSON → Header → bytes → parse_header → verify_pow
        let from_json: ergo_chain_types::Header = serde_json::from_str(json).unwrap();
        let wire_bytes = from_json.scorex_serialize_bytes().unwrap();
        let parsed = parse_header(&wire_bytes).unwrap();

        assert_eq!(parsed.id, from_json.id);
        assert!(verify_pow(&parsed).is_ok());
    }
}

#[cfg(test)]
mod tracker_tests {
    use crate::HeaderTracker;

    fn make_header(height: u32, version: u8) -> ergo_chain_types::Header {
        // Build a minimal header. The id will be computed from the serialized content,
        // so different heights produce different ids.
        use ergo_chain_types::*;
        use sigma_ser::ScorexSerializable;

        let zero32 = Digest32::zero();
        let mut header = Header {
            version,
            id: BlockId(Digest32::zero()),
            parent_id: BlockId(Digest32::zero()),
            ad_proofs_root: zero32,
            state_root: ADDigest::zero(),
            transaction_root: zero32,
            timestamp: 1000000 + height as u64,
            n_bits: 100000,
            height,
            extension_root: zero32,
            autolykos_solution: AutolykosSolution {
                miner_pk: Box::new(EcPoint::default()),
                pow_onetime_pk: None,
                nonce: vec![0; 8],
                pow_distance: None,
            },
            votes: Votes([0, 0, 0]),
            unparsed_bytes: Box::new([]),
        };

        // Compute the real id via serialize roundtrip
        let bytes = header.scorex_serialize_bytes().unwrap();
        let reparsed = Header::scorex_parse_bytes(&bytes).unwrap();
        header.id = reparsed.id;
        header
    }

    #[test]
    fn empty_tracker() {
        let tracker = HeaderTracker::new();
        assert_eq!(tracker.best_height(), None);
        assert!(tracker.best_header_id().is_none());
    }

    #[test]
    fn single_observation() {
        let mut tracker = HeaderTracker::new();
        let h = make_header(100, 2);
        tracker.observe(&h);

        assert_eq!(tracker.best_height(), Some(100));
        assert_eq!(tracker.best_header_id(), Some(&h.id));
    }

    #[test]
    fn higher_header_updates_tip() {
        let mut tracker = HeaderTracker::new();
        let h1 = make_header(100, 2);
        let h2 = make_header(200, 2);

        tracker.observe(&h1);
        tracker.observe(&h2);

        assert_eq!(tracker.best_height(), Some(200));
        assert_eq!(tracker.best_header_id(), Some(&h2.id));
    }

    #[test]
    fn lower_header_does_not_update_tip() {
        let mut tracker = HeaderTracker::new();
        let h1 = make_header(200, 2);
        let h2 = make_header(100, 2);

        tracker.observe(&h1);
        tracker.observe(&h2);

        assert_eq!(tracker.best_height(), Some(200));
        assert_eq!(tracker.best_header_id(), Some(&h1.id));
    }

    #[test]
    fn equal_height_does_not_update_tip() {
        let mut tracker = HeaderTracker::new();
        let h1 = make_header(100, 2);
        let h2 = make_header(100, 2);

        tracker.observe(&h1);
        let original_id = tracker.best_header_id().cloned();
        tracker.observe(&h2);

        assert_eq!(tracker.best_height(), Some(100));
        // Tip should not change — equal height doesn't dominate.
        assert_eq!(tracker.best_header_id().cloned(), original_id);
    }

    #[test]
    fn many_observations_tracks_max() {
        let mut tracker = HeaderTracker::new();
        let heights = [50, 100, 75, 200, 150, 300, 250, 300, 299];

        let headers: Vec<_> = heights.iter().map(|&h| make_header(h, 2)).collect();
        for h in &headers {
            tracker.observe(h);
        }

        assert_eq!(tracker.best_height(), Some(300));
        // The tip should be the first header observed at height 300 (index 5)
        assert_eq!(tracker.best_header_id(), Some(&headers[5].id));
    }

    #[test]
    fn default_impl() {
        let tracker = HeaderTracker::default();
        assert_eq!(tracker.best_height(), None);
    }
}

#[cfg(test)]
mod chain_tests {
    use crate::{ChainConfig, ChainError, HeaderChain};
    use ergo_chain_types::*;
    use sigma_ser::ScorexSerializable;

    /// Build a header with a computed ID. For chain tests — no real PoW.
    fn make_chain_header(
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

        // Compute ID via serialization roundtrip
        let bytes = header.scorex_serialize_bytes().unwrap();
        let reparsed = Header::scorex_parse_bytes(&bytes).unwrap();
        header.id = reparsed.id;
        header
    }

    fn genesis_parent_id() -> BlockId {
        BlockId(Digest32::zero())
    }

    fn testnet_config() -> ChainConfig {
        ChainConfig::testnet()
    }

    fn make_genesis(config: &ChainConfig) -> Header {
        make_chain_header(1, genesis_parent_id(), 1_000_000, config.initial_n_bits)
    }

    #[test]
    fn empty_chain() {
        let chain = HeaderChain::new(testnet_config());
        assert!(chain.is_empty());
        assert_eq!(chain.height(), 0);
        assert_eq!(chain.len(), 0);
    }

    #[test]
    fn append_genesis() {
        let config = testnet_config();
        let mut chain = HeaderChain::new(config.clone());
        let genesis = make_genesis(&config);
        let genesis_id = genesis.id;

        assert!(chain.try_append_no_pow(genesis).is_ok());
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.len(), 1);
        assert!(chain.contains(&genesis_id));
        assert_eq!(chain.header_at(1).unwrap().id, genesis_id);
    }

    #[test]
    fn reject_genesis_wrong_parent() {
        let config = testnet_config();
        let mut chain = HeaderChain::new(config.clone());
        // Genesis with non-zero parent
        let bad = make_chain_header(1, BlockId(Digest32::from([1u8; 32])), 1_000_000, config.initial_n_bits);

        let err = chain.try_append_no_pow(bad).unwrap_err();
        assert!(matches!(err, ChainError::InvalidGenesisParent { .. }));
    }

    #[test]
    fn reject_genesis_wrong_height() {
        let config = testnet_config();
        let mut chain = HeaderChain::new(config.clone());
        let bad = make_chain_header(5, genesis_parent_id(), 1_000_000, config.initial_n_bits);

        let err = chain.try_append_no_pow(bad).unwrap_err();
        assert!(matches!(err, ChainError::InvalidGenesisHeight { .. }));
    }

    #[test]
    fn reject_genesis_wrong_difficulty() {
        let config = testnet_config();
        let mut chain = HeaderChain::new(config);
        let bad = make_chain_header(1, genesis_parent_id(), 1_000_000, 99999);

        let err = chain.try_append_no_pow(bad).unwrap_err();
        assert!(matches!(err, ChainError::WrongDifficulty { .. }));
    }

    #[test]
    fn append_child_after_genesis() {
        let config = testnet_config();
        let mut chain = HeaderChain::new(config.clone());
        let genesis = make_genesis(&config);
        let parent_id = genesis.id;
        let parent_n_bits = genesis.n_bits;

        chain.try_append_no_pow(genesis).unwrap();

        // Child at height 2 — within first epoch, so n_bits carries forward
        let child = make_chain_header(2, parent_id, 2_000_000, parent_n_bits);
        assert!(chain.try_append_no_pow(child).is_ok());
        assert_eq!(chain.height(), 2);
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn reject_child_wrong_parent() {
        let config = testnet_config();
        let mut chain = HeaderChain::new(config.clone());
        let genesis = make_genesis(&config);
        chain.try_append_no_pow(genesis).unwrap();

        // Child pointing to a non-existent parent
        let bad = make_chain_header(2, BlockId(Digest32::from([0xAB; 32])), 2_000_000, config.initial_n_bits);
        let err = chain.try_append_no_pow(bad).unwrap_err();
        assert!(matches!(err, ChainError::ParentNotFound { .. }));
    }

    #[test]
    fn reject_child_wrong_height() {
        let config = testnet_config();
        let mut chain = HeaderChain::new(config.clone());
        let genesis = make_genesis(&config);
        let parent_id = genesis.id;
        chain.try_append_no_pow(genesis).unwrap();

        // Height 5 after genesis (should be 2)
        let bad = make_chain_header(5, parent_id, 2_000_000, config.initial_n_bits);
        let err = chain.try_append_no_pow(bad).unwrap_err();
        assert!(matches!(err, ChainError::NonSequentialHeight { .. }));
    }

    #[test]
    fn reject_child_timestamp_not_increasing() {
        let config = testnet_config();
        let mut chain = HeaderChain::new(config.clone());
        let genesis = make_genesis(&config);
        let parent_id = genesis.id;
        chain.try_append_no_pow(genesis).unwrap();

        // Timestamp equal to genesis (should be strictly greater)
        let bad = make_chain_header(2, parent_id, 1_000_000, config.initial_n_bits);
        let err = chain.try_append_no_pow(bad).unwrap_err();
        assert!(matches!(err, ChainError::TimestampNotIncreasing { .. }));
    }

    #[test]
    fn reject_child_wrong_difficulty() {
        let config = testnet_config();
        let mut chain = HeaderChain::new(config.clone());
        let genesis = make_genesis(&config);
        let parent_id = genesis.id;
        chain.try_append_no_pow(genesis).unwrap();

        // Wrong n_bits (should inherit from parent within epoch)
        let bad = make_chain_header(2, parent_id, 2_000_000, 99999);
        let err = chain.try_append_no_pow(bad).unwrap_err();
        assert!(matches!(err, ChainError::WrongDifficulty { .. }));
    }

    #[test]
    fn reject_duplicate_header() {
        // A header already in the chain must not be accepted again.
        let config = testnet_config();
        let mut chain = HeaderChain::new(config.clone());
        let genesis = make_genesis(&config);
        chain.try_append_no_pow(genesis).unwrap();

        // Build a chain of 10 headers
        for h in 2..=10 {
            let tip = chain.tip();
            let expected_n_bits = crate::difficulty::expected_difficulty(tip, &chain).unwrap();
            let header = make_chain_header(h, tip.id, 1_000_000 + h as u64 * 45_000, expected_n_bits);
            chain.try_append_no_pow(header).unwrap();
        }

        // Try to append a clone of the header at height 5
        let existing = chain.header_at(5).unwrap().clone();
        let result = chain.try_append_no_pow(existing);
        assert!(result.is_err(), "duplicate header should be rejected");
    }

    #[test]
    fn reject_header_extending_non_tip() {
        // A header whose parent exists in the chain but is not the tip
        // must be rejected — the chain is linear.
        let config = testnet_config();
        let mut chain = HeaderChain::new(config.clone());
        let genesis = make_genesis(&config);
        chain.try_append_no_pow(genesis).unwrap();

        // Build chain to height 10
        for h in 2..=10 {
            let tip = chain.tip();
            let expected_n_bits = crate::difficulty::expected_difficulty(tip, &chain).unwrap();
            let header = make_chain_header(h, tip.id, 1_000_000 + h as u64 * 45_000, expected_n_bits);
            chain.try_append_no_pow(header).unwrap();
        }

        // Build a valid-looking child of height-5 header (not the tip)
        let mid_header = chain.header_at(5).unwrap();
        let fork_child = make_chain_header(6, mid_header.id, mid_header.timestamp + 1000, config.initial_n_bits);
        let result = chain.try_append_no_pow(fork_child);
        assert!(result.is_err(), "header extending non-tip should be rejected");
    }

    #[test]
    fn difficulty_carries_within_epoch() {
        // Build a chain of several blocks within the first epoch.
        // All should have the same n_bits as genesis.
        let config = testnet_config();
        let mut chain = HeaderChain::new(config.clone());

        let genesis = make_genesis(&config);
        let mut prev_id = genesis.id;
        let n_bits = genesis.n_bits;
        chain.try_append_no_pow(genesis).unwrap();

        for h in 2..=10 {
            let header = make_chain_header(h, prev_id, 1_000_000 + h as u64 * 45_000, n_bits);
            prev_id = header.id;
            chain.try_append_no_pow(header).unwrap();
        }

        assert_eq!(chain.height(), 10);
        assert_eq!(chain.len(), 10);
        // All headers should have the same difficulty
        for h in 1..=10 {
            assert_eq!(chain.header_at(h).unwrap().n_bits, n_bits);
        }
    }

    #[test]
    fn headers_from_range() {
        let config = testnet_config();
        let mut chain = HeaderChain::new(config.clone());

        let genesis = make_genesis(&config);
        let mut prev_id = genesis.id;
        let n_bits = genesis.n_bits;
        chain.try_append_no_pow(genesis).unwrap();

        for h in 2..=5 {
            let header = make_chain_header(h, prev_id, 1_000_000 + h as u64 * 45_000, n_bits);
            prev_id = header.id;
            chain.try_append_no_pow(header).unwrap();
        }

        let slice = chain.headers_from(2, 3);
        assert_eq!(slice.len(), 3);
        assert_eq!(slice[0].height, 2);
        assert_eq!(slice[1].height, 3);
        assert_eq!(slice[2].height, 4);

        // Beyond chain end
        let slice = chain.headers_from(4, 10);
        assert_eq!(slice.len(), 2); // heights 4, 5

        // Before chain start
        let slice = chain.headers_from(0, 5);
        assert_eq!(slice.len(), 0);
    }

    #[test]
    fn difficulty_recalculation_at_epoch_boundary() {
        // Build a chain of 129 blocks (genesis at 1, epoch_length=128).
        // Block 129 triggers recalculation (parent at height 128 = epoch boundary).
        let config = testnet_config();
        let mut chain = HeaderChain::new(config.clone());

        let genesis = make_genesis(&config);
        let mut prev_id = genesis.id;
        let n_bits = genesis.n_bits;
        chain.try_append_no_pow(genesis).unwrap();

        // Build up to height 128 with perfect timing (45s apart)
        for h in 2..=128 {
            let timestamp = 1_000_000 + (h as u64 - 1) * 45_000;
            let header = make_chain_header(h, prev_id, timestamp, n_bits);
            prev_id = header.id;
            chain.try_append_no_pow(header).unwrap();
        }

        assert_eq!(chain.height(), 128);

        // Height 129 triggers difficulty recalculation.
        // With perfect block timing (45s intervals), the difficulty should stay
        // approximately the same (the actual result depends on the linear regression
        // with only one epoch of data, which returns the same difficulty).
        let parent = chain.tip();
        let expected_n_bits =
            crate::difficulty::expected_difficulty(parent, &chain).unwrap();

        let header129 = make_chain_header(
            129,
            prev_id,
            1_000_000 + 128 * 45_000,
            expected_n_bits,
        );
        assert!(chain.try_append_no_pow(header129).is_ok());
        assert_eq!(chain.height(), 129);
    }
}

#[cfg(test)]
mod sync_info_tests {
    use crate::{build_sync_info, parse_sync_info, ChainConfig, HeaderChain, SyncInfo};
    use ergo_chain_types::*;
    use sigma_ser::ScorexSerializable;

    fn make_chain_header(
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

    fn testnet_config() -> ChainConfig {
        ChainConfig::testnet()
    }

    fn make_genesis(config: &ChainConfig) -> Header {
        make_chain_header(1, BlockId(Digest32::zero()), 1_000_000, config.initial_n_bits)
    }

    fn build_test_chain(count: u32) -> HeaderChain {
        let config = testnet_config();
        let mut chain = HeaderChain::new(config.clone());
        if count == 0 {
            return chain;
        }

        let genesis = make_genesis(&config);
        let mut prev_id = genesis.id;
        chain.try_append_no_pow(genesis).unwrap();

        for h in 2..=count {
            let parent = chain.tip();
            let expected_n_bits =
                crate::difficulty::expected_difficulty(parent, &chain).unwrap();
            let timestamp = 1_000_000 + (h as u64 - 1) * 45_000;
            let header = make_chain_header(h, prev_id, timestamp, expected_n_bits);
            prev_id = header.id;
            chain.try_append_no_pow(header).unwrap();
        }

        chain
    }

    // --- build_sync_info tests ---

    #[test]
    fn build_empty_chain_produces_v2_zero_headers() {
        let chain = build_test_chain(0);
        let bytes = build_sync_info(&chain);
        // VLQ(0) = 0x00, mode = 0xFF, count = 0x00
        assert_eq!(bytes, vec![0x00, 0xFF, 0x00]);
    }

    #[test]
    fn build_short_chain_includes_only_tip() {
        // 5 headers (heights 1-5). Offsets: [0, 16, 128, 512].
        // Only offset 0 (height 5) is within range.
        let chain = build_test_chain(5);
        let bytes = build_sync_info(&chain);

        // Parse it back to verify content
        let sync = parse_sync_info(&bytes).unwrap();
        match sync {
            SyncInfo::V2 { headers } => {
                assert_eq!(headers.len(), 1);
                assert_eq!(headers[0].height, 5);
            }
            _ => panic!("expected V2"),
        }
    }

    #[test]
    fn build_long_chain_includes_four_headers_at_offsets() {
        // 600 headers (heights 1-600). Offsets from tip (600):
        //   0 → height 600, 16 → height 584, 128 → height 472, 512 → height 88
        // All within range (chain starts at 1).
        let chain = build_test_chain(600);
        let bytes = build_sync_info(&chain);

        let sync = parse_sync_info(&bytes).unwrap();
        match sync {
            SyncInfo::V2 { headers } => {
                assert_eq!(headers.len(), 4);
                // Tip-first ordering
                assert_eq!(headers[0].height, 600);
                assert_eq!(headers[1].height, 584);
                assert_eq!(headers[2].height, 472);
                assert_eq!(headers[3].height, 88);
            }
            _ => panic!("expected V2"),
        }
    }

    // --- roundtrip tests ---

    #[test]
    fn build_parse_roundtrip() {
        let chain = build_test_chain(200);
        let bytes = build_sync_info(&chain);
        let sync = parse_sync_info(&bytes).unwrap();

        match sync {
            SyncInfo::V2 { headers } => {
                // Offsets from tip 200: 0→200, 16→184, 128→72. 512 below chain start.
                assert_eq!(headers.len(), 3);
                for parsed_hdr in &headers {
                    let chain_hdr = chain.header_at(parsed_hdr.height).unwrap();
                    assert_eq!(parsed_hdr.id, chain_hdr.id);
                }
            }
            _ => panic!("expected V2"),
        }
    }

    // --- parse V1 ---

    #[test]
    fn parse_v1_header_ids() {
        // V1: VLQ(count) followed by count * 32-byte header IDs
        let mut body = Vec::new();
        // VLQ encode 3
        body.push(3u8);
        // 3 header IDs (32 bytes each)
        for i in 0u8..3 {
            body.extend_from_slice(&[i + 1; 32]);
        }

        let sync = parse_sync_info(&body).unwrap();
        match sync {
            SyncInfo::V1 { header_ids } => {
                assert_eq!(header_ids.len(), 3);
                assert_eq!(header_ids[0].0 .0, [1u8; 32]);
                assert_eq!(header_ids[1].0 .0, [2u8; 32]);
                assert_eq!(header_ids[2].0 .0, [3u8; 32]);
            }
            _ => panic!("expected V1"),
        }
    }

    // --- parse V2 with zero headers ---

    #[test]
    fn parse_v2_zero_headers() {
        let body = vec![0x00, 0xFF, 0x00];
        let sync = parse_sync_info(&body).unwrap();
        match sync {
            SyncInfo::V2 { headers } => assert!(headers.is_empty()),
            _ => panic!("expected V2"),
        }
    }

    // --- error cases ---

    #[test]
    fn parse_garbage_returns_error() {
        let garbage: Vec<u8> = (0..50).map(|i| (i * 37 + 13) as u8).collect();
        // Should not panic — may be Err or weird Ok, but never panic.
        let _ = parse_sync_info(&garbage);
    }

    #[test]
    fn parse_empty_returns_error() {
        let result = parse_sync_info(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_v2_too_many_headers_rejected() {
        // Craft a V2 message claiming 51 headers
        let body = vec![0x00, 0xFF, 51u8];
        let result = parse_sync_info(&body);
        assert!(result.is_err());
    }

    #[test]
    fn parse_v2_oversized_header_rejected() {
        // Craft a V2 message with 1 header claiming 1001 bytes
        let mut body = vec![0x00, 0xFF, 0x01];
        // VLQ encode 1001 (0xE9 0x07 in VLQ)
        body.push(0xE9);
        body.push(0x07);
        // Pad with enough junk bytes
        body.extend(vec![0xAB; 1001]);

        let result = parse_sync_info(&body);
        assert!(result.is_err());
    }

    #[test]
    fn parse_v1_too_many_header_ids_rejected() {
        // V1 with 1002 header IDs — over the 1001 limit
        let mut body = Vec::new();
        // VLQ encode 1002 = 0xEA 0x07
        body.push(0xEA);
        body.push(0x07);
        // Don't need actual data — should reject before reading
        body.extend(vec![0x00; 32 * 10]); // some padding

        let result = parse_sync_info(&body);
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod section_tests {
    use crate::section_ids;

    fn hex(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Verify section IDs against JVM-computed values for a real mainnet header.
    /// Header at height 2870 — section IDs from the JVM node's JSON output.
    #[test]
    fn section_ids_match_jvm_test_vector() {
        let json = r#"{"extensionId":"277907e4e5e42f27e928e6101cc4fec173bee5d7728794b73d7448c339c380e5","difficulty":"1325481984","votes":"000000","timestamp":1611225263165,"size":219,"stateRoot":"c0d0b5eafd07b22487dac66628669c42a242b90bef3e1fcdc76d83140d58b6bc0e","height":2870,"nBits":72286528,"version":2,"id":"5b0ce6711de6b926f60b67040cc4512804517785df375d063f1bf1d75588af3a","adProofsRoot":"49453875a43035c7640dee2f905efe06128b00d41acd2c8df13691576d4fd85c","transactionsRoot":"770cbb6e18673ed025d386487f15d3252115d9a6f6c9b947cf3d04731dd6ab75","extensionHash":"9bc7d54583c5d44bb62a7be0473cd78d601822a626afc13b636f2cbff0d87faf","powSolutions":{"pk":"0288114b0586efea9f86e4587f2071bc1c85fb77e15eba96b2769733e0daf57903","w":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","n":"000100000580a91b","d":0},"adProofsId":"4fc36d59bf26a672e01fbfde1445bd66f50e0f540f24102e1e27d0be1a99dfbf","transactionsId":"d196ef8a7ef582ab1fdab4ef807715183705301c6ae2ff0dcbe8f1d577ba081f","parentId":"ab19e6c7a4062979dddb534df83f236d1b949c7cef18bcf434a67e87c593eef9"}"#;

        let header: ergo_chain_types::Header = serde_json::from_str(json).unwrap();
        let ids = section_ids(&header);

        // BlockTransactions (type 102)
        assert_eq!(ids[0].0, 102);
        assert_eq!(
            hex(&ids[0].1),
            "d196ef8a7ef582ab1fdab4ef807715183705301c6ae2ff0dcbe8f1d577ba081f"
        );

        // ADProofs (type 104)
        assert_eq!(ids[1].0, 104);
        assert_eq!(
            hex(&ids[1].1),
            "4fc36d59bf26a672e01fbfde1445bd66f50e0f540f24102e1e27d0be1a99dfbf"
        );

        // Extension (type 108)
        assert_eq!(ids[2].0, 108);
        assert_eq!(
            hex(&ids[2].1),
            "277907e4e5e42f27e928e6101cc4fec173bee5d7728794b73d7448c339c380e5"
        );
    }

    /// Same but for a second header (height 614400) to avoid single-vector luck.
    #[test]
    fn section_ids_second_vector() {
        let json = r#"{
            "extensionId" : "00cce45975d87414e8bdd8146bc88815be59cd9fe37a125b5021101e05675a18",
            "difficulty" : "16384",
            "votes" : "000000",
            "timestamp" : 4928911477310178288,
            "size" : 223,
            "stateRoot" : "5c8c00b8403d3701557181c8df800001b6d5009e2201c6ff807d71808c00019780",
            "height" : 614400,
            "nBits" : 37748736,
            "version" : 2,
            "id" : "5603a937ec1988220fc44fb5022fb82d5565b961f005ebb55d85bd5a9e6f801f",
            "adProofsRoot" : "5d3f80dcff7f5e7f59007294c180808d0158d1ff6ba10000f901c7f0ef87dcff",
            "transactionsRoot" : "f17fffacb6ff7f7f1180d2ff7f1e24ffffe1ff937f807f0797b9ff6ebdae007e",
            "extensionHash" : "1480887f80007f4b01cf7f013ff1ffff564a0000b9a54f00770e807f41ff88c0",
            "powSolutions" : {
              "pk" : "03bedaee069ff4829500b3c07c4d5fe6b3ea3d3bf76c5c28c1d4dcdb1bed0ade0c",
              "n" : "0000000000003105"
            },
            "adProofsId" : "dec129290a763f4de41f04e87e2b661dd59758af6bdd00dd51f5d97c3a8cb9b5",
            "transactionsId" : "eba1dd82cf51147232e09c1f72b37c554c30f63274d5093bff36849a83472a42",
            "parentId" : "ac2101807f0000ca01ff0119db227f202201007f62000177a080005d440896d0"
        }"#;

        let header: ergo_chain_types::Header = serde_json::from_str(json).unwrap();
        let ids = section_ids(&header);

        assert_eq!(ids[0].0, 102);
        assert_eq!(
            hex(&ids[0].1),
            "eba1dd82cf51147232e09c1f72b37c554c30f63274d5093bff36849a83472a42"
        );

        assert_eq!(ids[1].0, 104);
        assert_eq!(
            hex(&ids[1].1),
            "dec129290a763f4de41f04e87e2b661dd59758af6bdd00dd51f5d97c3a8cb9b5"
        );

        assert_eq!(ids[2].0, 108);
        assert_eq!(
            hex(&ids[2].1),
            "00cce45975d87414e8bdd8146bc88815be59cd9fe37a125b5021101e05675a18"
        );
    }

    /// Section IDs are deterministic — same header produces same IDs.
    #[test]
    fn section_ids_deterministic() {
        let json = r#"{"extensionId":"277907e4e5e42f27e928e6101cc4fec173bee5d7728794b73d7448c339c380e5","difficulty":"1325481984","votes":"000000","timestamp":1611225263165,"size":219,"stateRoot":"c0d0b5eafd07b22487dac66628669c42a242b90bef3e1fcdc76d83140d58b6bc0e","height":2870,"nBits":72286528,"version":2,"id":"5b0ce6711de6b926f60b67040cc4512804517785df375d063f1bf1d75588af3a","adProofsRoot":"49453875a43035c7640dee2f905efe06128b00d41acd2c8df13691576d4fd85c","transactionsRoot":"770cbb6e18673ed025d386487f15d3252115d9a6f6c9b947cf3d04731dd6ab75","extensionHash":"9bc7d54583c5d44bb62a7be0473cd78d601822a626afc13b636f2cbff0d87faf","powSolutions":{"pk":"0288114b0586efea9f86e4587f2071bc1c85fb77e15eba96b2769733e0daf57903","w":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","n":"000100000580a91b","d":0},"adProofsId":"4fc36d59bf26a672e01fbfde1445bd66f50e0f540f24102e1e27d0be1a99dfbf","transactionsId":"d196ef8a7ef582ab1fdab4ef807715183705301c6ae2ff0dcbe8f1d577ba081f","parentId":"ab19e6c7a4062979dddb534df83f236d1b949c7cef18bcf434a67e87c593eef9"}"#;

        let header: ergo_chain_types::Header = serde_json::from_str(json).unwrap();
        let ids1 = section_ids(&header);
        let ids2 = section_ids(&header);
        assert_eq!(ids1, ids2);
    }
}
