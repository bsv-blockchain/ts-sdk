# BRC-69 Method 2 Whole-Statement ZK

Last updated: 2026-05-11.

This is the single authoritative document for the BRC-69 Method 2 ZK system in
this branch. The wallet-facing production path is proof type `1` and proves the
whole statement with phased STARK segments named `base` and `bus`.

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
segments in proof: base, bus
cross proofs: lookup-accumulator, segment-bus-accumulator
constant-column proofs: none
```

Generation path:

1. `ProtoWallet.revealSpecificKeyLinkage` defaults omitted `proofType` to `1`.
2. `createSpecificKeyLinkageProof` checks the requested statement and builds the
   whole-statement witness.
3. `buildBRC69Method2WholeStatement` builds scalar, lookup, bridge, EC,
   compression, and compact-HMAC traces.
4. The raw witness-bearing columns are concatenated into the `base` trace and
   committed first.
5. Bus challenges are derived from the public-input digest and committed `base`
   trace root.
6. The challenge-dependent lookup and segment-bus accumulator columns are
   committed in the `bus` trace.
7. `proveBRC69Method2WholeStatement` proves both segments plus the cross-trace
   accumulator constraints.
8. `serializeSpecificKeyLinkageProofPayload` emits the proof type `1` envelope.

Verification path:

1. `parseSpecificKeyLinkageProofPayload` accepts proof type `1` and rejects
   malformed or trailing proof bytes.
2. `verifySpecificKeyLinkageProof` checks the proof type `1` payload and public
   statement.
3. `verifyBRC69Method2WholeStatement` validates public inputs, recomputes public
   roots and post-base-root bus challenge digests, then verifies the `base` and
   `bus` STARK segments and their cross-trace accumulator constraints.

The verifier derives all proof type `1` STARK metadata from verifier-owned
inputs: AIR shape, public input, trace length, and the production profile. The
serialized proof still carries metadata for parsing and compatibility, but the
verifier treats trace degree bounds, composition degree bounds, FRI remainder
size, and public-input digest as values to compare against verifier-derived
expectations. They are not used as verifier policy.

Standalone scalar, lookup, EC, compression, HMAC, or bus trace/AIR builders are
diagnostic and metrics helpers only. Legacy lookup/log-bus proof APIs with
public-input-derived challenges fail closed and are not accepted by the proof
type `1` wallet verifier.

## Counterparty Policy

Proof type `1` models BRC-69 Method 2 as a relation against a specified
counterparty public key. `ProtoWallet.revealSpecificKeyLinkage` therefore
requires `counterparty` to be an explicit compressed public key when proof type
`1` is used. Sentinel `self` and `anyone` requests remain supported only through
explicit proof type `0`, which is the legacy no-proof payload. This avoids
treating sentinel derivation modes as ordinary Method 2 proof statements.

## Production Proof Shape

Proof type `1` is now a phased two-segment STARK:

1. The prover commits the witness-bearing `base` trace first.
2. The verifier/prover derive lookup and segment-bus compression challenges from
   the public-input digest, STARK domain, and committed `base` trace root.
3. The prover commits the challenge-dependent `bus` accumulator trace.
4. Cross-trace composition constraints bind the `bus` accumulator updates to the
   already-committed raw base rows.

The `base` trace concatenates these raw components in order:

| Component | Role |
| --- | --- |
| `scalar` | Canonical 24-window signed radix-11 scalar digits, non-zero scalar, and range below secp256k1 `n`. |
| `lookup` | Deterministic dual-base point table and selected point-pair lookup rows, without challenge-dependent accumulator columns. |
| `bridge` | Links scalar digits and lookup outputs to selected `G` and `B` points consumed by EC. |
| `ec` | Fixed-schedule affine EC accumulator, producing public `A` and private `S`. |
| `compression` | Links private `S` to compressed secp256k1 key bytes. |
| `hmac` | Compact SHA/HMAC AIR proving `HMAC-SHA256(compress(S), invoice) = linkage`. |

The `bus` trace contains only lookup accumulator columns and segment-bus
accumulator columns/selectors. The scalar bus start and HMAC bus end are public
zero endpoints, so the hidden segment bus must balance across the whole
relation. The lookup accumulator starts and ends at the public neutral product.

The production STARK parameters are:

```text
blowup factor: 16
queries: 48
max remainder size: 16
mask degree: 192
coset offset: 7
```

The EC arithmetic segment now includes explicit per-row bit decompositions for
the selected 52-bit linear limbs, selected 26-bit multiplication and quotient
limbs, signed carry columns, and canonical `< p` borrow-chain witnesses. The
multiplication carry bound is 32 bits, so the checked per-limb identities cannot
wrap modulo the Goldilocks STARK field.
The wallet-facing whole-statement mask degree covers the maximum number of
trace-root openings per committed column at 48 queries: 96 rows from trace FRI
plus current/next rows for 48 composition FRI queries.

## Production Runs

### Full Whole-Statement Run

Latest full production run after EC range hardening and the phased bus challenge
redesign:

```text
artifact base:
  artifacts/brc69-full-production-phased-96gb-12h-20260511T035508Z-rerun

command:
  npm run brc69:metrics -- \
    --json artifacts/brc69-full-production-phased-96gb-12h-20260511T035508Z-rerun/report.json \
    --markdown artifacts/brc69-full-production-phased-96gb-12h-20260511T035508Z-rerun/report.md \
    --progress-jsonl artifacts/brc69-full-production-phased-96gb-12h-20260511T035508Z-rerun/progress.jsonl \
    --partial-json artifacts/brc69-full-production-phased-96gb-12h-20260511T035508Z-rerun/partial.json \
    --proof-json artifacts/brc69-full-production-phased-96gb-12h-20260511T035508Z-rerun/whole-proof.json \
    --diagnostic-json artifacts/brc69-full-production-phased-96gb-12h-20260511T035508Z-rerun/diagnostic.json
```

Run result:

| Metric | Value |
| --- | ---: |
| invoice bytes | 1,233 |
| SHA/HMAC blocks | 23 |
| whole proof verified | true |
| diagnostic result | ok |
| prove time | 3,283.895s |
| verify time | 6.276s |
| total metrics run time | 3,311.072s |
| proof bytes | 6,519,722 |
| proof-size acceptance cap | 1,500,000 |
| whole active rows | 30,688 |
| whole padded rows | 32,768 |
| whole committed width | 1,561 |
| whole committed cells | 51,150,848 |
| whole LDE cells | 818,413,568 |
| peak RSS | 19.699 GiB |
| peak heap used | 9.915 GiB |

The process exited nonzero only after proof generation, verification,
diagnostics, and report generation because the proof-size gate still fails. This
is not a correctness failure: the whole proof verified and the diagnostic result
was `ok`. The production run stayed well below the requested 96 GB Node heap
ceiling; runtime was CPU-bound rather than memory-bound.

The same full command was first run before compacting cross-proof Merkle path
serialization. That saved proof verified and measured 6,581,476 bytes. Compact
cross-proof and constant-column Merkle dictionaries reduced the current encoded
proof to 6,519,722 bytes. The small reduction confirms that current proof size
is dominated by full row openings, not repeated Merkle authentication nodes.

Compared with the previous compact single-proof baseline before EC range
hardening and the phased bus redesign:

| Metric | previous compact/single-proof | current phased/hardened | Change |
| --- | ---: | ---: | ---: |
| prove time | 2,247.197s | 3,283.895s | 1.46x slower |
| verify time | 2.311s | 6.276s | 2.72x slower |
| proof bytes | 2,738,411 | 6,519,722 | 2.38x larger |
| committed width | 1,208 | 1,561 | +353 |
| LDE cells | 633,339,904 | 818,413,568 | +185,073,664 |

The first performance landing gate is not met yet: proving is 3,283.895s and
the target is `<= 900s`. The proof-size gate is also not met: the current proof
is 6,519,722 bytes and the target is `<= 1,500,000`.

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
| radix-11 lookup base | 23,608 | 32,768 | 72 | 2,359,296 | 37,748,736 |
| EC arithmetic | 5,280 | 8,192 | 526 | 4,308,992 | 68,943,872 |
| compression/key binding | 257 | 512 | 78 | 39,936 | 638,976 |
| max-invoice compact HMAC | 1,495 | 2,048 | 551 | 1,128,448 | 18,055,168 |
| phased base trace | 30,688 | 32,768 | 1,344 | 44,040,192 | 704,643,072 |
| phased bus trace | 30,688 | 32,768 | 217 | 7,110,656 | 113,770,496 |
| phased total | 30,688 | 32,768 | 1,561 | 51,150,848 | 818,413,568 |

## Measured Bottlenecks

The bottleneck is the wide base trace plus the challenge-dependent bus phase,
not memory capacity. The current phased shape has 818M LDE cells and peaked at
19.699 GiB RSS / 9.915 GiB heap under a 96 GB heap ceiling.

| Phase | Duration |
| --- | ---: |
| whole-statement prove | 3,283.895s |
| base `trace.lde` | 1,062.047s |
| base `stark.composition-oracle` | 668.412s |
| segment-bus-accumulator cross composition | 615.285s |
| base `stark.composition-context` | 204.583s |
| bus `trace.lde` | 165.112s |
| base `stark.trace-combination` | 165.075s |
| base `trace.merkle` / leaf serialization | 97.235s |
| lookup-accumulator cross composition | 89.813s |
| bus `stark.composition-oracle` | 38.077s |

The base segment is the dominant CPU cost because it commits width 1,344 across
32,768 rows and evaluates over 524,288 LDE rows. The segment-bus cross proof is
the next major cost because it evaluates relation-specific accumulator
constraints against the committed base and bus traces. FRI and verifier time are
visible but are not the primary runtime limit.

The current highest-value performance work is:

- move whole-trace LDE and composition evaluation to a column-major typed backend
  that avoids row-array reconstruction in the hot loops;
- reduce committed width, especially compact-HMAC width and same-proof public
  boundary columns, without changing the relation or STARK parameters;
- reduce opened row width through columnar commitments, narrower subtrace
  commitments, or an equivalent opening scheme;
- optimize the cross-trace bus accumulator composition, which now carries the
  lookup and segment-bus challenge-dependent work;
- continue canonical proof encoding work beyond Merkle-node deduplication,
  because the proof remains above the 1.5 MB cap.

## Proof Size Analysis

The current encoded proof is 6,519,722 bytes against a 1,500,000 byte
acceptance cap. The largest pieces are:

| Piece | Size / Shape |
| --- | ---: |
| base segment proof | 2,957,420 bytes |
| bus segment proof | 1,226,808 bytes |
| lookup-accumulator cross proof FRI | 390,414 bytes |
| segment-bus-accumulator cross proof FRI | 395,090 bytes |
| lookup-accumulator cross trace openings | 85,344 field elements |
| segment-bus-accumulator cross trace openings | 85,344 field elements |

The segment proofs also carry large full-row openings. The base segment opens
129,024 low-degree trace field elements, 64,512 current trace field elements,
and 64,512 next-trace field elements. Each cross proof opens full rows from the
`base`, `bus`, and next `bus` traces for 48 queries, so each cross proof carries
48 * (1,344 + 217 + 217) = 85,344 trace field elements.

Merkle-path dictionary compaction is implemented for segment, cross, and
constant-column openings, but it only removes repeated authentication nodes. The
remaining proof-size problem is structural: row-Merkle commitments force
opening whole wide rows even when a constraint needs only a narrower slice.
Meeting the 1.5 MB cap requires reducing opened row width, for example with
columnar commitments, narrower subtrace commitments, fewer committed columns, or
a different opening scheme. Reducing proof parameters or mask degree is not an
acceptable proof-size fix because it would weaken the soundness or
zero-knowledge margin.

## Cryptographic Soundness and Correctness

Validated in the current code path:

- The relation is unchanged: `A = aG`, `S = aB`, and
  `linkage = HMAC-SHA256(compress(S), invoice)`.
- Recent implementation changes preserve the relation while changing proof
  plumbing and hardening: compact HMAC AIR, phased base/bus commitments,
  proof encoding, EC range checks, and stronger whole-statement masking.
- The latest full production run generated and verified a proof for the
  phased/hardened path. The diagnostic result was `ok`; the remaining acceptance
  failure is proof size, not relation correctness or STARK verification.
- STARK parameters are 16 blowup, 48 queries, max remainder 16, mask degree 192,
  coset offset 7.
- The only wallet-facing proof selector for this ZK system is proof type `1`;
  proof type `0` remains the no-proof path.
- The verifier reconstructs public-input digests, deterministic table roots,
  post-base-root bus challenge digests, proof parameters, the `base` AIR, the
  `bus` AIR, and cross-trace accumulator constraints from public inputs and the
  proof's committed base root.
- HMAC is compact SHA/HMAC AIR in proof type `1`.
- Compression-to-HMAC key-byte bus linkage is preserved.
- EC formulas and windows are unchanged. The production EC AIR now range-checks
  selected 52-bit linear limbs, selected 26-bit multiplication and quotient
  limbs, signed carries, and canonical `< p` field encodings.
- The compact proof encoder only deduplicates serialized Merkle authentication
  nodes; it does not change Merkle roots, FRI queries, AIR constraints, Fiat-
  Shamir inputs, or verifier checks.

Soundness gaps and required review:

- No independent cryptographic audit has been completed for this proof system.
- A full soundness calculation is still needed for AIR degrees, FRI parameters,
  Fiat-Shamir challenges, masking, bus compression challenges, and the compact
  HMAC AIR.
- EC field arithmetic now has bounded limb, carry, quotient-limb, and canonical
  `< p` borrow-chain constraints in the production AIR. It still needs a written
  proof that those constraints imply the intended secp256k1 field operations for
  every bound metadata value.
- Segment and lookup bus tuple compression use two Goldilocks-field challenges.
  The challenges are now derived after the witness-bearing base trace root is
  committed, so the standard non-adaptive tuple-collision argument applies to
  the committed base polynomials rather than to prover-chosen post-challenge
  tuples. For arity 23, the base-field Schwartz-Zippel estimate is about
  119 bits. Extension-field challenges remain a possible future margin increase,
  but they are no longer a substitute for transcript ordering.
- The whole-statement mask degree now covers the verifier's worst-case
  trace-root openings per column at 48 queries. A final zero-knowledge write-up
  must still enumerate every unmasked schedule/public column and prove that
  masking hides `a`, `S`, compressed `S`, HMAC internals, and private bus
  endpoints.
- The EC exceptional-branch policy remains fail-closed for this slice. Broader
  production use needs either complete exceptional-branch constraints or a
  verifier-checkable proof that rejected branches are unreachable for accepted
  inputs.
- The BRC-69 Method 2 parser now rejects public input above 16 MiB, STARK proof
  sections above 16 MiB, and whole payloads above 34 MiB before expensive
  section parsing. A final production DoS policy should still be tied to the
  post-optimization proof encoding.

## Acceptance Status

Current status: proof type `1` defaults to the phased whole-statement path. The
base and bus challenge ordering now matches the standard lookup/permutation
shape. The latest production run verifies and passes diagnostics, but production
acceptance is still blocked by proving time above 900s, proof size above 1.5 MB,
and the remaining soundness review items above.
