# BRC-69 Method 2 Whole-Statement ZK

Last updated: 2026-05-10.

This is the single authoritative document for the BRC-69 Method 2 ZK system in
this branch. Historical strategy notes have been collapsed into this page so
there is one proof relation, one production proof path, and one place to audit
current status.

## Statement

The proof establishes the whole Method 2 specific key-linkage statement:

```text
exists a:
  A = aG
  S = aB
  linkage = HMAC-SHA256(compress(S), invoice)
```

Where:

- `a` is the prover's private root scalar.
- `A` is the public prover identity key.
- `G` is the secp256k1 generator.
- `B` is the public counterparty key.
- `invoice = computeInvoiceNumber(protocolID, keyID)`.
- `linkage` is the public Method 2 specific linkage value.

It is not sufficient for the prover to check HMAC outside the proof. The whole
statement proof must bind scalar derivation, EC multiplication for both public
`A` and private `S`, compression of `S`, and HMAC-SHA256 over the invoice.

## Public and Private Values

Public verifier inputs:

- prover identity key `A`;
- counterparty key `B`;
- invoice bytes;
- linkage bytes;
- deterministic radix-11 table root for `G` and `B`;
- fixed production STARK profile and proof metadata;
- segment public inputs needed to reconstruct verifier AIRs.

Private witness values:

- scalar `a`;
- shared point `S = aB`;
- compressed `S` bytes used as the HMAC key;
- HMAC internal state;
- intermediate bus accumulator endpoints except the public zero start and end.

## One Production Code Path

Wallet proof generation uses proof type `1` by default. Proof type `0` remains
only for legacy no-proof payloads.

Generation path:

1. `ProtoWallet.revealSpecificKeyLinkage` defaults omitted `proofType` to `1`.
2. `createSpecificKeyLinkageProof` normalizes `self` and `anyone`, checks that
   the private scalar matches public `A`, recomputes the public linkage relation,
   and builds the whole-statement witness.
3. `buildBRC69Method2WholeStatement` builds all production traces.
4. `proveBRC69Method2WholeStatement` produces one multi-trace STARK proof.
5. `serializeSpecificKeyLinkageProofPayload` wraps the whole-statement proof in
   the BRC-69 proof type `1` envelope.

Verification path:

1. `parseSpecificKeyLinkageProofPayload` accepts proof type `1` and rejects
   malformed or trailing proof bytes.
2. `verifySpecificKeyLinkageProof` checks the payload profile, matches public
   input to the requested statement, and calls the whole-statement verifier.
3. `verifyBRC69Method2WholeStatement` validates public inputs, recomputes the bus
   challenge digest, enforces the production profile, and verifies the multi-trace
   proof.

Standalone scalar, lookup, EC, compression, HMAC, or bus proofs are diagnostic
and metrics helpers. They are not the wallet-facing production proof.

## Production Proof Shape

The production proof is a single multi-trace Fiat-Shamir transcript containing
six committed segments:

| Segment | Role |
| --- | --- |
| `scalar` | Proves canonical 24-window signed radix-11 scalar digits, non-zero scalar, and scalar range below secp256k1 `n`. |
| `lookup` | Supplies the deterministic dual-base point table and proves selected point-pair lookup rows. |
| `bridge` | Links scalar digit rows and lookup outputs to the selected `G` and `B` points consumed by EC. |
| `ec` | Proves the fixed-schedule affine EC accumulator, producing public `A` and private `S`. |
| `compression` | Links private `S` to compressed secp256k1 key bytes. |
| `hmac` | Proves lookup-batched HMAC-SHA256 from compressed `S` and public invoice to public linkage. |

The segment-local bus embeds hidden accumulator columns in each segment. Adjacent
segment endpoints are linked by a cross-trace quotient constraint in the same
multi-trace transcript. The scalar segment has a public zero bus start and the
HMAC segment has a public zero bus end, so the whole bus must balance.

The production profile is fixed:

```text
blowup factor: 16
queries: 48
max remainder size: 16
mask degree: 2
coset offset: 7
proof type: 1
profile id: 1
```

## Current Production Run

The latest full production run completed proof generation and verification with
a 96 GB Node heap. The process exited nonzero only after verification because
the production acceptance gate rejected the proof size.

```text
artifact base:
  artifacts/brc69-full-production-96gb-6h-20260510T171500Z

completed:
  2026-05-10T18:19:30.224Z

environment:
  node: v22.21.1
  platform: darwin arm64
  cpu count: 16
  git commit: 57d5c60708b8effcfb394330c03c624c38ef95d5

command:
  npm run build:ts
  node --max-old-space-size=98304 scripts/brc69-metrics.js \
    --json artifacts/brc69-full-production-96gb-6h-20260510T171500Z/report.json \
    --markdown artifacts/brc69-full-production-96gb-6h-20260510T171500Z/report.md \
    --progress-jsonl artifacts/brc69-full-production-96gb-6h-20260510T171500Z/progress.jsonl \
    --partial-json artifacts/brc69-full-production-96gb-6h-20260510T171500Z/partial.json \
    --proof-json artifacts/brc69-full-production-96gb-6h-20260510T171500Z/whole-proof.json \
    --diagnostic-json artifacts/brc69-full-production-96gb-6h-20260510T171500Z/diagnostic.json
```

Run result:

| Metric | Value |
| --- | ---: |
| invoice bytes | 1,233 |
| SHA/HMAC blocks | 23 |
| radix-11 table rows | 23,584 |
| whole-statement proof verified | true |
| diagnostic result | ok |
| proof bytes | 10,938,748 |
| proof-size acceptance cap | 1,500,000 |
| prove time | 3,840.064s |
| verify time | 5.037s |
| total metrics run time | 3,868.488s |
| committed width across bus-wrapped segments | 1,127 |
| committed cells | 36,929,536 |
| LDE cells | 590,872,576 |
| peak RSS observed in progress log | 16,599,744,512 bytes |
| peak heap used observed in progress log | 8,344,265,376 bytes |

Acceptance status for this run: **proof verified, production acceptance failed**.
The failure is:

```text
BRC69 production acceptance gate failed: wholeStatement proof bytes 10938748 exceeds 1500000
```

Measured segment shape:

| Segment | Rows | Width | Committed Cells | LDE Cells |
| --- | ---: | ---: | ---: | ---: |
| scalar digits | 32 | 49 | 1,568 | 25,088 |
| radix-11 lookup | 32,768 | 85 | 2,785,280 | 44,564,480 |
| EC arithmetic | 8,192 | 174 | 1,425,408 | 22,806,528 |
| compression/key binding | 512 | 78 | 39,936 | 638,976 |
| max-invoice lookup HMAC | 32,768 | 470 | 15,400,960 | 246,415,360 |
| lookup/equality bus accounting | 196,608 | 2 | 393,216 | 6,291,456 |
| whole statement | 32,768 max segment rows | 1,127 total | 36,929,536 | 590,872,576 |

## Measured Bottlenecks

The primary cost center is lookup-batched HMAC/SHA. The HMAC segment is the
widest segment, has the largest committed and LDE cell counts, and dominates both
trace preparation and STARK composition evaluation.

Largest observed phases from `progress.jsonl`:

| Phase | Duration |
| --- | ---: |
| HMAC `stark.composition-oracle` | 1,416.791s |
| HMAC `stark.committed-prove` total | 1,670.424s |
| HMAC `trace.commit` total | 455.391s |
| HMAC `trace.lde` | 401.541s |
| EC `stark.committed-prove` total | 314.389s |
| bridge `stark.committed-prove` total | 295.871s |
| bridge `stark.composition-oracle` | 253.009s |
| EC `stark.composition-oracle` | 209.913s |
| EC `trace.lde` | 186.492s |
| HMAC `stark.composition-context` | 165.352s |
| lookup `stark.committed-prove` total | 161.007s |
| compression `stark.committed-prove` total | 134.875s |

The proof-size failure is the other blocking production issue. The verified proof
is about 7.29x the 1.5 MB cap.

The main optimization targets are:

- reduce HMAC/SHA trace width and composition degree cost;
- move deterministic radix-11 table work toward fixed/preprocessed commitments;
- finish and validate the typed-array column-major prover path as the
  wallet-facing production path;
- reduce proof bytes below the 1.5 MB max-invoice acceptance cap.

## Cryptographic Soundness and Correctness

Validated by the current code path:

- The verifier reconstructs all public-input digests from public inputs rather
  than accepting proof-selected AIRs.
- The whole-statement verifier rejects non-production profiles, wrong transcript
  domains, missing segments, unexpected constant-column proofs, and missing
  cross-trace proofs.
- Public input validation checks `A` and `B` are valid non-infinity secp256k1
  points, validates invoice and linkage bytes, forces lookup HMAC mode, checks
  the deterministic lookup table root, and recomputes the segment-bus challenge.
- The scalar segment constrains radix-11 digit decomposition, canonical signed
  digit shape, non-zero scalar, and range below secp256k1 `n`.
- The lookup table is deterministically derived from public `B` and the fixed
  radix-11 profile.
- The bridge and segment bus bind scalar digits, lookup outputs, selected EC
  points, private `S`, compressed key bytes, and HMAC key bytes across segments.
- The EC segment currently rejects doubling and opposite accumulator branches and
  supports the selected-infinity, accumulator-infinity, and distinct-add cases
  used by this production slice.
- The HMAC segment checks the compressed key bytes, invoice schedule, lookup
  multiplicities, SHA helper relations, and final linkage.

Issues that still need explicit cryptographic review:

- No independent cryptographic audit has been completed for this proof system.
- The segment-bus lookup/equality argument uses two Goldilocks-field compression
  challenges. The collision bound and whether production should use extension
  field challenges need a written analysis.
- The fixed STARK profile has not yet been accompanied by a full soundness
  calculation covering AIR degrees, FRI parameters, Fiat-Shamir challenge
  derivation, cross-trace quotient constraints, and batched lookup arguments.
- The zero-knowledge argument needs to enumerate every unmasked public schedule
  column and prove that masking of witness columns hides `a`, `S`, compressed
  `S`, HMAC internals, and private bus endpoints.
- The EC exceptional-branch policy is fail-closed for this slice. Before broader
  wallet-facing production use, either prove all valid exceptional branches or
  keep and document a verifier-checkable condition showing they are unreachable
  for all accepted public inputs.
- The proof payload format caps public input and STARK proof sizes, but verifier
  resource limits and denial-of-service behavior need a production policy.

## Acceptance Status

The branch goal is to make proof type `1` the default and prove the whole
statement with one auditable code path. Wallet-facing production acceptance still
requires the whole-statement proof to fit the max-invoice proof-size budget,
prove within the target UX envelope, and complete the soundness review items
above.
