# Fix gen_indexes panic in ergoplatform/sigma-rust

You are working in a fork of `ergoplatform/sigma-rust`. Your job is to fix a bug, add a regression test, and open a PR against upstream `develop`.

## Coding conventions

This crate has strict lint rules enforced via `lib.rs` deny attributes. Your changes MUST NOT introduce:
- `unwrap()` or `expect()` in non-test code (`clippy::unwrap_used`, `clippy::expect_used` are denied)
- `panic!()`, `todo!()`, `unimplemented!()`, `unreachable!()` in non-test code
- `unsafe` code (forbidden crate-wide)
- Missing doc comments on public items (`missing_docs` is denied)
- Wildcard enum match arms (`clippy::wildcard_enum_match_arm` is denied)

Test code is covered by the existing `#[allow(clippy::unwrap_used)]` on the `mod tests` block.

Use default `rustfmt` — no project-level overrides exist.

## Setup

1. Ensure your fork's `develop` branch is up to date with `ergoplatform/sigma-rust:develop`.
2. Create a feature branch off `develop`:
   ```
   git checkout develop && git pull upstream develop && git checkout -b fix/gen-indexes-zero-modulo
   ```
   (If `upstream` isn't configured, add it: `git remote add upstream https://github.com/ergoplatform/sigma-rust.git`)

## The Bug

File: `ergo-chain-types/src/autolykos_pow_scheme.rs`, method `gen_indexes` (~line 248).

This line panics when the modulo result is zero:

```rust
.to_u32_digits()
.1[0],
```

`BigInt::to_u32_digits()` returns `(NoSign, vec![])` for zero. Indexing `.1[0]` on an empty vec is a panic.

The JVM reference (`AutolykosPowScheme.scala`) returns 0 correctly via `BigInt.toInt`.

### Impact

Consensus-affecting crash. Any valid block where one of 32 index computations yields an exact multiple of N crashes the node. With N ~67M and 32 indices per header, roughly 25% cumulative probability of hitting this across all mainnet blocks during initial sync.

## Apply the Fix

In `ergo-chain-types/src/autolykos_pow_scheme.rs`, in the `gen_indexes` method, change:

```rust
.1[0],
```

to:

```rust
.1.first().copied().unwrap_or(0),
```

That's it. One line. Do NOT change anything else in this method — keep the diff minimal.

## Add the Regression Test

In the same file, inside the existing `#[cfg(test)] mod tests` block, add this test:

```rust
#[test]
fn test_gen_indexes_zero_modulo() {
    // Regression: gen_indexes must not panic when a 4-byte window
    // in the seed hash is an exact multiple of N, producing index 0.
    // JVM reference AutolykosPowScheme.genIndexes handles this correctly.
    let pow = AutolykosPowScheme::default();
    let n_base = pow.big_n_base.get(); // 2^26 = 67108864 = 0x04000000

    // Seed hash where bytes[0..4] == N, so N % N == 0
    let mut seed_hash = [0u8; 32];
    seed_hash[0..4].copy_from_slice(&n_base.to_be_bytes());

    let indexes = pow.gen_indexes(&seed_hash, n_base);
    assert_eq!(indexes.len(), 32);
    assert_eq!(indexes[0], 0);

    // All-zero seed: every 4-byte window is 0, and 0 % N == 0
    let zero_seed = [0u8; 32];
    let indexes = pow.gen_indexes(&zero_seed, n_base);
    assert_eq!(indexes.len(), 32);
    assert!(indexes.iter().all(|&idx| idx == 0));
}
```

## Verify

Run all three — every one must pass with zero warnings:

```bash
cargo fmt --all -- --check
cargo clippy -p ergo-chain-types --all-targets
cargo test -p ergo-chain-types
```

If `cargo fmt` modifies anything, re-stage and re-check. Do not commit unformatted code.

## Commit

```
git add ergo-chain-types/src/autolykos_pow_scheme.rs
git commit -m "Fix panic in gen_indexes when index modulo N equals zero

to_u32_digits() returns an empty vec for BigInt(0). Accessing .1[0]
panics. Replace with .first().copied().unwrap_or(0) to match the JVM
reference behavior (BigInt.toInt returns 0)."
```

## Open the PR

Target: `ergoplatform/sigma-rust:develop`

PR title:
```
Fix panic in gen_indexes when index modulo N equals zero
```

PR body:
```
## Summary

`gen_indexes` panics when any of the 32 extracted 4-byte hash windows,
interpreted as an unsigned big-endian integer, is an exact multiple of N.
The modulo result is zero, `BigInt::to_u32_digits()` returns an empty
digit vector, and `.1[0]` panics with index out of bounds.

The JVM reference (`AutolykosPowScheme.scala`) handles this correctly
via `BigInt.toInt`, which returns 0 for `BigInt(0)`.

## Fix

Replace `.1[0]` with `.1.first().copied().unwrap_or(0)` — returns 0
when the digit vector is empty, matching JVM behavior.

## Risk

With 32 indices per header and N starting at ~67M, there is a non-trivial
cumulative probability that some mainnet block triggers this during
initial chain sync. The fix is a one-line change with no behavioral
difference for non-zero results.

## Test plan

- [x] Added regression test `test_gen_indexes_zero_modulo` that triggers
  the exact panic condition (seed hash with 4-byte window equal to N)
- [x] All existing tests pass unchanged
- [x] `cargo clippy` clean
- [x] `cargo fmt` clean
```

Push and create the PR:
```bash
git push -u origin fix/gen-indexes-zero-modulo
gh pr create --repo ergoplatform/sigma-rust --base develop --title "Fix panic in gen_indexes when index modulo N equals zero" --body "$(cat <<'EOF'
<paste PR body from above>
EOF
)"
```

## After the PR

Report back the PR URL. Do not delete this prompt file — the enr-chain session will handle cleanup after the fix is merged and the dependency is updated.
