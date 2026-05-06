# BRC-69 Method 2 Production ZK Status

Last updated: 2026-05-04.

This page summarizes the current production proof architecture for BRC-69 key
linkage revelation Method 2. The exact statement is unchanged:

```text
exists a:
  A = aG
  S = aB
  linkage = HMAC-SHA256(compress(S), invoice)
```

The verifier receives public `A`, public `B`, public invoice bytes, public
`linkage`, production profile metadata, and the proof. The verifier must not
receive private scalar `a`, private shared point `S`, compressed `S`, HMAC key
bytes, or private bus tuples.

## Current Result

The latest full production-profile validation generated and verified the whole
Method 2 proof successfully.

```text
artifact base:
  artifacts/brc69-full-production-96gb-14h-narrow-hmac-20260504T012025Z

wholeStatement:
  verified: true
  proof bytes: 10,938,764
  prove time: 4,097.898s
  verify time: 5.030s
  committed width across traces: 1,127
  committed cells: 36,929,536
  LDE cells: 590,872,576

profile:
  blowup factor: 16
  queries: 48
  max remainder size: 16
  mask degree: 2
  coset offset: 7

resource use:
  Node heap limit: 96GB
  peak RSS: 17,359,044,608 bytes
```

This is a proof-verification success, not a production-acceptance success. The
production gate still fails because the proof is 10.94MB, above the 1.5MB
max-invoice cap, and proving currently takes about 68.3 minutes.

## Production Path

The following components are currently on the production proof path:

| Component | Status | Notes |
| --- | --- | --- |
| Multi-trace single transcript | Active | One whole Method 2 proof transcript. |
| Shared equality domain | Active | Cross-trace endpoint links are proven by quotient constraints. |
| Segment-local bus wrappers | Active | Bus emissions are derived from committed row values and fixed selectors. |
| Scalar digit segment | Active | 24 signed radix-11 windows. |
| Radix-11 dual-base point lookup | Active | Public table derived from `G`, public `B`, and the production profile. |
| Hardened affine EC accumulator AIR | Active | Produces public `A` and private `S` inside the proof. |
| Compression/key-binding bridge | Active | Links private `S` to compressed HMAC key bytes. |
| Lookup-centric max-invoice HMAC | Active | Replaces compact HMAC, but remains the largest cost. |
| Production metrics harness | Active | Default full run measures the same path a production user would run. |

## Not Production Path

The historical prototype implementations were removed from the production source
surface. They are useful context for old artifacts and branch history, but they
are no longer maintained as SDK code paths:

| Component | Status | Reason |
| --- | --- | --- |
| Row-serialized Method 2 VM | Removed | Not the production proving shape. |
| V2 6-bit fixed-window path | Removed | Superseded by signed radix-11 dual-base lookup. |
| Old row-expanded scalar control | Removed | Not used by the whole production proof. |
| 240-subproof affine EC field-op bundle | Removed | Replaced by the hardened EC accumulator AIR. |
| Standalone compact HMAC proof | Removed | Compact HMAC remains only as internal arithmetic used by lookup HMAC. |
| Standalone segment proofs | Removed from wallet surface | Real production users run the whole-statement proof. |
| Standalone lookup/equality bus proof | Removed | Production uses segment-local buses and shared equality domain. |
| Masked-opening endpoint links | Removed | Not sound for private equality across separately masked traces. |

## Current Bottleneck

HMAC/SHA dominates the full proof:

```text
maxInvoiceLookupHmac:
  active rows: 24,432
  padded rows: 32,768
  committed width: 470
  committed cells: 15,400,960
  LDE cells: 246,415,360

hmac stark.committed-prove: 1,847.659s
hmac stark.composition-oracle: 1,570.235s
hmac trace.commit: 462.120s
hmac trace.lde: 406.374s
```

The next production work should reduce HMAC width and composition cost, move the
public radix-11 table into fixed/preprocessed commitments, and finish the
typed-array column-major prover path while keeping the BigInt prover as the
correctness oracle.
