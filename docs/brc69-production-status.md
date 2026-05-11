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

## Formal Security Argument

This section is the audit target for proof type `1`. It states what the proof
establishes, which assumptions it uses, and which failures are outside the
algebraic proof model.

### Relation

For public inputs `(A, B, invoice, linkage)` the accepted statement is:

```text
exists a in [1, n - 1]:
  A = aG
  S = aB
  K = compress(S)
  linkage = HMAC-SHA256(K, invoice)
```

`G` is the secp256k1 generator, `n` is the secp256k1 group order, and accepted
`A` and `B` are non-infinity curve points. Since secp256k1 has cofactor one,
every accepted non-infinity point has order `n`.

### Encoding and Transcript Binding

The wallet payload is a versioned binary envelope:

```text
proofType = 1
magic = BRC69_KEY_LINKAGE_PROOF_PAYLOAD
version = 1
publicInput = BRC69_METHOD2_WHOLE_STATEMENT_PUBLIC_INPUT version 1
proof = binary multi-trace STARK proof
```

The public input is no longer JSON-revived. Points are compressed SEC1 points,
field elements are canonical 8-byte Goldilocks encodings, byte vectors and row
counts have explicit length prefixes, and the parser rejects trailing bytes,
unknown versions, payloads above 34 MiB, public input above 16 MiB, and proof
sections above 16 MiB. STARK and FRI transcript parameters are checked before
`u32` packing, including explicit `<= 0xffffffff` bounds and Goldilocks
two-adicity caps for evaluation domains.

The verifier recomputes deterministic public-input digests, deterministic table
roots, AIR metadata, degree bounds, proof parameters, and bus challenge inputs.
Proof-carried metadata is accepted only if it equals verifier-derived metadata.

### AIR Soundness Lemmas

1. Scalar lemma: the scalar AIR range-checks the 24 signed radix-11 windows,
   reconstructs the scalar, rejects zero, enforces `a < n`, and enforces the
   production final-window bound. Therefore any accepted scalar segment commits
   to one canonical `a in [1, n - 1]`.
2. Lookup lemma: the lookup base schedule binds requests to the deterministic
   dual-base table rooted by `B`. The phased lookup accumulator uses challenges
   derived after the base trace root, so committed lookup rows cannot be chosen
   adaptively after seeing compression challenges.
3. Bridge lemma: the bridge consumes scalar digit bus tuples and lookup output
   bus tuples, applies the digit sign, and emits selected `G` and `B` points.
   Segment-bus balance forces the EC segment to consume exactly those selected
   points.
4. EC lemma: for each distinct-add row, the production EC AIR constrains
   `dx`, `dy`, `dx^{-1}`, slope, `x3`, and `y3` through secp256k1 field
   additions/subtractions/multiplications. Each field operation has selected
   limb range checks, signed carry bounds, quotient-limb range checks, and
   canonical `< p` borrow-chain checks, so the Goldilocks identities lift to
   integer identities over secp256k1 field elements without wraparound.
5. Compression lemma: the compression AIR bit-decomposes `S.x`, reconstructs
   each compressed-key byte, and binds the prefix to the parity of `S.y`.
6. HMAC lemma: the compact SHA/HMAC AIR constrains the SHA-256 schedules,
   boolean helpers, modular word additions, inner digest carry, outer digest,
   and public `linkage`. The segment bus binds its 33 key-byte inputs to the
   compression segment outputs.
7. Composition lemma: concatenating the base trace and proving the second-phase
   bus trace with cross-trace accumulator constraints preserves each component
   AIR and additionally proves lookup/segment-bus balance against the already
   committed base rows.

Together these lemmas reduce an accepted proof to the relation above, except
with the negligible STARK/FRI and randomized bus-collision probabilities below.

### Bus Collision Bounds

Lookup and segment buses compress tuples with two Goldilocks challenges. For
arity `23`, a fixed unequal tuple pair collides with probability at most
`23 / (p - 1)` per challenge, so two independent challenges give about
`2 * (log2(p - 1) - log2(23))`, or greater than 118 bits, for non-adaptive
committed tuples. Challenges are sampled after the base trace root, so this is
the applicable non-adaptive bound for proof type `1`.

### EC Exceptional Branches

The production EC AIR intentionally supports only selected-infinity,
accumulator-infinity, and distinct-add rows. It constrains doubling and
opposite-add selectors to zero. This is sound for accepted radix-11 inputs:

- At window `i`, the accumulator is `P_i = sum_{j<i} d_j r^j` and the selected
  point is `d_i r^i` times the lane base, with `r = 2^11`.
- Doubling would require `P_i ≡ d_i r^i (mod n)`.
- Opposite-add would require `P_i ≡ -d_i r^i (mod n)`.
- The builder and validator reconstruct these exact integers from the canonical
  scalar digits and reject if either congruence holds.
- Because both `G` and any accepted non-infinity `B` have order `n`, these
  scalar congruences are exactly the group equalities that would cause
  doubling or opposite-add in either lane.

Tests exercise deterministic edge scalars and randomized fixtures, assert zero
doubling/opposite selectors in the aggregate EC trace, and mutate a distinct-add
row into a doubling row to confirm the AIR fails closed.

### STARK and Fiat-Shamir Assumptions

The STARK security argument assumes collision resistance of SHA-256 for Merkle
commitments and Fiat-Shamir transcript binding, plus the standard random-oracle
heuristic for Fiat-Shamir challenge sampling. With blowup `16`, `48` queries,
and max remainder `16`, verifier policy is fixed by proof type `1`; proofs with
weaker query counts, different degree bounds, altered public-input digests, or
different transcript domains fail before or during STARK verification.

### Zero-Knowledge and Local Secret Handling

The whole-statement profile uses mask degree `192`, covering the verifier's
worst-case trace-root openings per committed column at 48 queries. Public and
schedule columns are intentionally unmasked only when their values are
verifier-derived or public metadata. Witness-bearing columns for `a`, selected
points, `S`, compressed key bytes, HMAC key material, digest internals, and
private bus endpoints are masked in committed traces.

This is an algebraic zero-knowledge claim, not a local-process side-channel
claim. The prover now avoids a duplicate pre-proof `aB` scalar multiplication,
does not retain separate compact-HMAC key/message/digest convenience copies,
and wipes the witness-bearing whole-statement traces after wallet proof
generation. JavaScript execution is still not constant-time; deployments that
must defend against local timing/cache/process-memory observers need isolated
prover execution or a constant-time native prover boundary.

### Audit Status

The code path now has a written formal argument and verifier-enforced format,
parameter, branch, and profile checks. No independent third-party
cryptographic audit has been completed; such an audit remains a release
governance requirement, not an undocumented proof-system gap.

## Acceptance Status

Current status: proof type `1` defaults to the phased whole-statement path. The
base and bus challenge ordering now matches the standard lookup/permutation
shape, public input/proof payloads are versioned binary encodings, the
standalone Method 2 lookup/HMAC/scalar/compression helpers use the
production-strength profile, and EC exceptional branches are covered by the
radix scalar argument above plus fail-closed AIR selectors. The latest
production run verifies and passes diagnostics, but production acceptance is
still blocked by proving time above 900s and proof size above 1.5 MB.
