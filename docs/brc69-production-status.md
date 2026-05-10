# BRC-69 Method 2 Whole-Statement ZK

Last updated: 2026-05-10.

This is the single authoritative document for the BRC-69 Method 2 ZK system in
this branch. The wallet-facing production path is proof type `1` and proves the
whole statement in one STARK segment named `whole`.

## Statement

The proof establishes the whole Method 2 specific key-linkage statement:

```text
exists a:
  A = aG
  S = aB
  linkage = HMAC-SHA256(compress(S), invoice)
```

The HMAC is inside the proof. The proof binds scalar derivation, EC
multiplication for both public `A` and private `S`, compression of `S`, and
HMAC-SHA256 over the public invoice.

## Current Code Path

Wallet proof generation uses proof type `1` by default. Proof type `0` remains
only for no-proof payloads.

Production defaults:

```text
proof type: 1
transcript domain: BRC69_METHOD2_WHOLE_STATEMENT_AIR
segments in proof: whole
cross proofs: none
constant-column proofs: none
```

Generation path:

1. `ProtoWallet.revealSpecificKeyLinkage` defaults omitted `proofType` to `1`.
2. `createSpecificKeyLinkageProof` checks the requested statement and builds the
   whole-statement witness.
3. `buildBRC69Method2WholeStatement` builds scalar, lookup, bridge, EC,
   compression, and compact-HMAC traces.
4. The bus-wrapped segment columns are concatenated into one `whole` trace.
5. `proveBRC69Method2WholeStatement` proves that one same-domain trace.
6. `serializeSpecificKeyLinkageProofPayload` emits the proof type `1` envelope.

Verification path:

1. `parseSpecificKeyLinkageProofPayload` accepts proof type `1` and rejects
   malformed or trailing proof bytes.
2. `verifySpecificKeyLinkageProof` checks the proof type `1` payload and public
   statement.
3. `verifyBRC69Method2WholeStatement` validates public inputs, recomputes public
   roots and bus challenge digest, and verifies the single `whole` STARK segment.

Standalone scalar, lookup, EC, compression, HMAC, or bus proofs are diagnostic
and metrics helpers. Lookup-batched HMAC remains as standalone code, but it is
not accepted in the proof type `1` wallet proof.

## Production Proof Shape

The committed `whole` trace concatenates these bus-wrapped components in order:

| Component | Role |
| --- | --- |
| `scalar` | Canonical 24-window signed radix-11 scalar digits, non-zero scalar, and range below secp256k1 `n`. |
| `lookup` | Deterministic dual-base point table and selected point-pair lookup rows. |
| `bridge` | Links scalar digits and lookup outputs to selected `G` and `B` points consumed by EC. |
| `ec` | Fixed-schedule affine EC accumulator, producing public `A` and private `S`. |
| `compression` | Links private `S` to compressed secp256k1 key bytes. |
| `hmac` | Compact SHA/HMAC AIR proving `HMAC-SHA256(compress(S), invoice) = linkage`. |

The old cross-trace bus endpoint checks are same-proof constraints in the
`whole` AIR. The scalar bus start and HMAC bus end are public zero endpoints, so
the hidden bus must balance across the whole relation.

The production STARK parameters are unchanged:

```text
blowup factor: 16
queries: 48
max remainder size: 16
mask degree: 2
coset offset: 7
```

## Production Runs

### Full Whole-Statement Run

Latest full production run:

```text
artifact base:
  artifacts/brc69-full-production-96gb-6h-20260510T202402Z

command:
  npm run brc69:metrics -- \
    --json artifacts/brc69-full-production-96gb-6h-20260510T202402Z/report.json \
    --markdown artifacts/brc69-full-production-96gb-6h-20260510T202402Z/report.md
```

Run result:

| Metric | Value |
| --- | ---: |
| invoice bytes | 1,233 |
| SHA/HMAC blocks | 23 |
| whole proof verified | true |
| diagnostic result | ok |
| prove time | 2,247.197s |
| verify time | 2.311s |
| total metrics run time | 2,260.180s |
| proof bytes during run | 3,184,437 |
| current compact-encoded proof bytes | 2,738,411 |
| proof-size acceptance cap | 1,500,000 |
| whole active rows | 30,688 |
| whole padded rows | 32,768 |
| whole committed width | 1,208 |
| whole committed cells | 39,583,744 |
| whole LDE cells | 633,339,904 |

The process exited nonzero only after verification because the proof-size gate
still fails. Current compact encoding reduces the same saved proof artifact to
2,738,411 bytes, which is still above the 1.5 MB cap.

Compared with the previous lookup/multi-proof implementation on this branch:

| Metric | previous lookup/multi-proof | current compact/single-proof | Change |
| --- | ---: | ---: | ---: |
| prove time | 3,840.064s | 2,247.197s | 1.71x faster |
| verify time | 5.037s | 2.311s | 2.18x faster |
| proof bytes | 10,938,748 | 2,738,411 | 3.99x smaller |
| committed width | 1,127 | 1,208 | +81 |
| LDE cells | 590,872,576 | 633,339,904 | +42,467,328 |

The first performance landing gate is not met yet: proving is improved, but the
target is `<= 900s`.

### HMAC-Only Run

Compact HMAC-only production-parameter run:

```text
artifact base:
  artifacts/brc69-compact-hmac-production-20260510T202241Z
```

| Metric | Value |
| --- | ---: |
| active rows | 1,495 |
| padded rows | 2,048 |
| committed width | 551 |
| committed cells | 1,128,448 |
| LDE cells | 18,055,168 |
| prove time | 48.117s |
| verify time | 0.194s |
| proof bytes during run | 1,689,125 |
| current compact-encoded proof bytes | 1,348,751 |
| verified | true |

## Measured Shape

| Segment | Active Rows | Padded Rows | Width | Committed Cells | LDE Cells |
| --- | ---: | ---: | ---: | ---: | ---: |
| scalar digits | 24 | 32 | 49 | 1,568 | 25,088 |
| radix-11 lookup | 23,608 | 32,768 | 85 | 2,785,280 | 44,564,480 |
| EC arithmetic | 5,280 | 8,192 | 174 | 1,425,408 | 22,806,528 |
| compression/key binding | 257 | 512 | 78 | 39,936 | 638,976 |
| max-invoice compact HMAC | 1,495 | 2,048 | 551 | 1,128,448 | 18,055,168 |
| lookup/equality bus accounting | 260 | 196,608 | 2 | 393,216 | 6,291,456 |
| whole statement | 30,688 | 32,768 | 1,208 | 39,583,744 | 633,339,904 |

## Measured Bottlenecks

The bottleneck is now the single wide whole trace, not multi-proof overhead.
The largest phases from the current progress log are:

| Phase | Duration |
| --- | ---: |
| whole `trace.lde` | 907.644s |
| whole `stark.composition-oracle` | 899.298s |
| whole `stark.composition-context` | 178.251s |
| whole `stark.trace-combination` | 96.714s |
| whole `trace.merkle` / leaf serialization | 84.555s |

Most remaining proving time is CPU work over 633M LDE cells and 524,288
composition-oracle rows. Memory is not the binding limit: RSS stayed far below
the 96 GB heap ceiling.

The current highest-value performance work is:

- move whole-trace LDE and composition evaluation to a column-major typed backend
  that avoids row-array reconstruction in the hot loops;
- reduce committed width, especially compact-HMAC width and same-proof public
  boundary columns, without changing the relation or STARK parameters;
- keep bus endpoint checks same-proof, but make them offset-aware typed
  constraints instead of generic row slicing;
- continue canonical proof encoding work beyond Merkle-node deduplication,
  because the proof remains above the 1.5 MB cap.

## Cryptographic Soundness and Correctness

Validated in the current code path:

- The relation is unchanged: `A = aG`, `S = aB`, and
  `linkage = HMAC-SHA256(compress(S), invoice)`.
- Performance changes are structural only: compact HMAC AIR, same-domain trace
  concatenation, and proof encoding.
- STARK parameters are unchanged: 16 blowup, 48 queries, max remainder 16,
  mask degree 2, coset offset 7.
- The only wallet-facing proof selector for this ZK system is proof type `1`;
  proof type `0` remains the no-proof path.
- The verifier reconstructs public-input digests, deterministic table roots, bus
  challenge digest, proof parameters, and the `whole` AIR from public inputs.
- HMAC is compact SHA/HMAC AIR in proof type `1`.
- Compression-to-HMAC key-byte bus linkage is preserved.
- EC formulas and windows were not changed in this performance pass.
- The compact proof encoder only deduplicates serialized Merkle authentication
  nodes; it does not change Merkle roots, FRI queries, AIR constraints, Fiat-
  Shamir inputs, or verifier checks.

Soundness gaps and required review:

- No independent cryptographic audit has been completed for this proof system.
- A full soundness calculation is still needed for AIR degrees, FRI parameters,
  Fiat-Shamir challenges, masking, bus compression challenges, and the compact
  HMAC AIR.
- The segment bus uses two Goldilocks-field compression challenges; the collision
  bound and whether production should use extension-field challenges need a
  written analysis.
- The zero-knowledge argument must enumerate every unmasked schedule/public
  column and prove that masking hides `a`, `S`, compressed `S`, HMAC internals,
  and private bus endpoints.
- The EC exceptional-branch policy remains fail-closed for this slice. Broader
  production use needs either complete exceptional-branch constraints or a
  verifier-checkable proof that rejected branches are unreachable for accepted
  inputs.
- Verifier resource limits and denial-of-service behavior need a production
  policy beyond the current payload and proof-size caps.

## Acceptance Status

Current status: proof type `1` defaults to the whole-statement path, the
max-invoice production proof verifies, and proving is materially faster than the
previous lookup/multi-proof implementation. Production acceptance is still
blocked by proving time above 900s, proof size
above 1.5 MB, and the soundness review items above.
