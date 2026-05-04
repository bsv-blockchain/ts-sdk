# BRC-69 Method 2 ZK Strategy

This document records the revised production strategy for proving BRC-69 Method
2 inside the SDK, without external proving dependencies and without broad
proof-system generality.

The exact statement remains unchanged:

```text
exists a:
  A = aG
  S = aB
  linkage = HMAC-SHA256(compress(S), invoice)
```

Where:

- `a` is the prover's private root scalar.
- `A` is the public prover identity key.
- `B` is the public counterparty key.
- `G` is the secp256k1 generator.
- `invoice = computeInvoiceNumber(protocolID, keyID)`.
- `linkage` is the public Method 2 specific linkage value.

The proof must establish the full relation. It is not sufficient for the honest
prover to check HMAC outside the proof. The verifier is not Bob, does not know
the counterparty scalar, and must not learn `S`.

## Current Production Validation Status: 2026-05-04

The current production path is a multi-trace, single-transcript Method 2 proof
with segment-local buses and a shared cross-trace equality domain. It proves the
exact statement under the production STARK profile:

```text
A = aG
S = aB
linkage = HMAC-SHA256(compress(S), invoice)
```

The 2026-05-04 full production validation run completed, generated the whole
statement proof, and verified it successfully. The previous whole-proof
`scalar composition-fri` failure is resolved. The remaining hard production gate
failure is performance/size, not proof verification:

```text
artifact base:
  artifacts/brc97-full-production-96gb-14h-narrow-hmac-20260504T012025Z

environment:
  Node: v22.21.1
  platform: darwin arm64
  CPU count: 16
  Node heap limit: 96GB (--max-old-space-size=98304)
  peak RSS: 17,359,044,608 bytes
  git commit: 7fe87f5ffc67f80bccc4656ff3cbac7e6540a12c

profile:
  blowup factor: 16
  queries: 48
  max remainder size: 16
  mask degree: 2
  coset offset: 7

inputs:
  invoice length: 1,233 bytes
  HMAC/SHA blocks: 23
  scalar: SECP256K1_N - 123456789
  B: scalarMultiply(7)
  signed radix: 11
  windows: 24
  dual-base point table rows: 23,584

wholeStatement:
  status: actual
  verified: true
  active rows: 53,625
  padded rows per major trace: 32,768
  committed width across traces: 1,127
  committed cells: 36,929,536
  LDE cells: 590,872,576
  proof bytes: 10,938,764
  prove time: 4,097.898s, about 68.3 minutes
  verify time: 5.030s
```

The production acceptance gate still rejects this proof because the proof is
10.94MB, above the 1.5MB max-invoice acceptance cap. Runtime is also far above
the production UX target. This means the current system is proof-complete for
the deterministic max-invoice fixture, but not wallet-facing production-ready.

Current segment shape from the same verified whole-proof run:

```text
scalarDigits:
  status: actual
  active rows: 24
  padded rows: 32
  committed width: 49
  committed cells: 1,568
  estimated proof bytes: 382,921

radix11PointLookup:
  status: actual
  active rows: 23,608
  padded rows: 32,768
  committed width: 85
  committed cells: 2,785,280
  LDE cells: 44,564,480
  estimated proof bytes: 1,466,443
  table generation: 1.018s

ecArithmetic:
  status: actual
  active rows: 5,280
  padded rows: 8,192
  committed width: 174
  committed cells: 1,425,408
  LDE cells: 22,806,528
  estimated proof bytes: 1,347,371

compressionAndKeyBinding:
  status: actual
  active rows: 257
  padded rows: 512
  committed width: 78
  committed cells: 39,936
  estimated proof bytes: 760,073

maxInvoiceLookupHmac:
  status: actual
  active rows: 24,432
  padded rows: 32,768
  committed width: 470
  committed cells: 15,400,960
  LDE cells: 246,415,360
  estimated proof bytes: 2,058,187

lookupEqualityBus:
  status: actual
  active rows: 260
  shared-domain padded rows: 196,608
  committed width: 2
  committed cells: 393,216
  verify time: 5.030s
  verified: true
```

The largest runtime bottleneck is still HMAC/SHA proving:

```text
hmac stark.committed-prove: 1,847.659s
hmac stark.composition-oracle: 1,570.235s
hmac trace.commit: 462.120s
hmac trace.lde: 406.374s
hmac stark.composition-context: 183.129s
```

### Production-Path Components

These components are now on the production proof path. They are included in the
whole statement proof and are not merely standalone projections:

| Component | Production-path status | Notes |
| --- | --- | --- |
| Multi-trace single transcript | Active | One whole Method 2 transcript with cross-trace equality proof. |
| Production metrics harness | Active | Default full run attempts the whole production statement; segment proofs are debug-only. |
| Shared equality domain | Active | Endpoint links are enforced by cross-trace quotient constraints, not masked-opening comparison. |
| Segment-local bus wrappers | Active | Bus emissions are computed from committed row values and committed fixed selectors. |
| Scalar digit segment | Active | Emits 24 signed radix-11 windows and range links. |
| Radix-11 dual-base point lookup | Active | Verifier-derived public table for fixed bases `G` and public `B`; 23,584 rows and 24 selected lookups. |
| Hardened affine EC accumulator AIR | Active | Produces public `A` and private `S` inside the proof path. |
| Compression/key-binding bridge | Active | Decomposes private `S` into compressed-key bytes and links those bytes to HMAC. |
| Lookup-centric max-invoice HMAC | Active | Replaces compact HMAC on the production path, but remains too wide and slow. |
| Production verifier parameter gate | Active | Rejects weak profiles and currently rejects the verified proof on size. |

### Non-Production And Oracle Components

These components remain useful for testing, diagnosis, or historical comparison,
but are not the production Method 2 proof architecture:

| Component | Status | Reason |
| --- | --- | --- |
| Row-serialized Method 2 VM | Prototype/oracle | Useful for trace/correctness work, not the production proving shape. |
| V2 6-bit fixed-window path | Prototype/oracle | Superseded by signed radix-11 dual-base lookup for production. |
| Old row-expanded scalar-control path | Prototype/oracle | Not used by the whole production proof. |
| 240-subproof affine EC field-op bundle | Oracle | Replaced on the production path by the hardened EC accumulator AIR. |
| Compact HMAC AIR | Oracle | Proves the correct relation but is no longer the production HMAC segment. |
| Standalone segment proofs | Debug/metrics only | Real users should produce the whole Method 2 statement proof. |
| Standalone lookup/equality bus prototype | Debug/metrics only | Production uses segment-local buses plus the shared equality domain. |
| Masked-opening endpoint links | Retired | Unsound for private equality across separately masked traces. |

## Prior Measurements

The original row-serialized Method 2 VM remains prototype/test scaffolding. It
is not the production proving architecture.

The previous V2 work established useful lower-level facts:

```text
V2 scalar-core control AIR:
  active rows: 2,747
  padded rows: 4,096
  trace width: 21
  LDE rows at blowup 16: 65,536
  reduced proof size: ~65KB
  reduced proof verifies: yes

V2 29-bit field multiplication AIR:
  active rows: 18
  padded rows: 32
  trace width: 95
  carry bits per row: 37
  reduced proof size: ~27.5KB
  larger reduced proof size at blowup 16 / 8 queries: ~75.9KB
  reduced proof verifies: yes

V2 one-row Jacobian mixed-add prototype:
  limb bits: 29
  limb count: 9
  field elements in one row: 26
  one-row width: 234
```

## Historical Production-Profile Metrics Run: 2026-04-28

This section is retained as historical context. It has been superseded by the
2026-05-04 full production proof above, where all production segments are actual
and the whole statement verifies. The projections below are not the current
production status.

The corrected full production-profile metrics run used the current SDK-only
metrics harness with the accepted radix-11 lookup and compact-HMAC proof
segments. A later EC wiring update changed `ecArithmetic` from a fixed
projection to an actual production radix-11 trace. The latest EC hardening adds
an aggregate EC AIR for the production radix-11 field operations. That AIR now
uses a fixed 48-lane schedule, so zero/init/distinct branch positions are not
revealed by the public operation schedule. It verifies all production
field-operation slots in one STARK proof, replacing the previous 240-subproof
affine field-op bundle as the default EC proof path.

```text
Node heap limit: 64GB (--max-old-space-size=65536)
Node: v22.21.1
platform: darwin arm64
CPU count: 16
git commit: 7fe87f5ffc67f80bccc4656ff3cbac7e6540a12c
STARK profile: blowup 16, 48 queries, max remainder 16, mask degree 2,
  coset offset 7
```

Deterministic inputs:

```text
invoice length: 1,233 bytes
HMAC/SHA blocks: 23 total
scalar: SECP256K1_N - 123456789
B: scalarMultiply(7)
radix profile: signed radix 11, 24 windows
dual-base point table rows: 23,584
selected point lookups: 24
```

Measured and projected segment data:

```text
scalarDigits:
  status: projection
  active rows: 64
  padded rows: 128
  committed width: 32
  committed cells: 4,096
  LDE cells: 65,536
  estimated proof bytes: 510,441

radix11PointLookup:
  status: actual, verified
  active rows: 23,608
  padded rows: 32,768
  committed width: 85
  fixed/preprocessed rows: 23,584
  committed cells: 2,785,280
  LDE cells: 44,564,480
  proof bytes: 1,459,001
  table generation: 2.688s
  prove time: 1,110.785s, about 18.51 minutes
  verify time: 51.684s
  after-proof heap used: about 1.1GiB
  after-proof RSS: about 14.0GiB

ecArithmetic:
  status: actual fixed-schedule aggregate EC AIR, verified
  active rows: 5,280
  padded rows: 8,192
  committed width: 83
  committed cells: 679,936
  LDE cells: 10,878,976
  zero signed-radix digits: 11
  negative signed-radix digits: 6
  signed point negations: 12
  accumulator initialization branches: 2
  selected-infinity branches: 22
  distinct affine-add branches: 24
  doubling fallback branches: 0 for this fixture
  cancellation fallback branches: 0 for this fixture
  scheduled affine lane additions: 48
  scheduled field linear operations: 288
  scheduled field multiplication operations: 192
  aggregate EC AIR proof bytes: 1,200,079
  aggregate EC AIR prove time: 112.757s
  aggregate EC AIR verify time: 5.794s
  note: one fixed-schedule proof replaces the 80.5MB field-op bundle;
    lookup-backed range/carry checks remain pending

compressionAndKeyBinding:
  status: projection
  active rows: 128
  padded rows: 128
  committed width: 48
  committed cells: 6,144
  LDE cells: 98,304
  estimated proof bytes: 535,017

maxInvoiceCompactHmac:
  status: actual, verified
  active rows: 1,495
  padded rows: 2,048
  committed width: 659
  committed cells: 1,349,632
  LDE cells: 21,594,112
  proof bytes: 1,855,053
  build time: 0.053s
  prove time: 264.475s, about 4.41 minutes
  verify time: 5.635s
  after-proof heap used: about 3.1GiB
  after-proof RSS: about 14.1GiB

lookupEqualityBus:
  status: projection
  active rows: 12,000
  padded rows: 16,384
  committed width: 48
  fixed/preprocessed rows: 65,536
  committed cells: 786,432
  LDE cells: 12,582,912
  estimated proof bytes: 1,278,555

wholeStatement:
  status: mixed actual/projection
  active rows: 42,575
  padded rows: 59,648
  max committed width: 659
  fixed/preprocessed rows: 89,136
  committed cells: 5,611,520
  LDE cells: 89,784,320
  actual proof bytes from measured segments: 4,514,133
  estimated full proof bytes: 6,838,146
  actual measured prove time from measured segments: 1,488.017s,
    about 24.80 minutes
  actual measured verify time from measured segments: 63.113s
```

At the time, these numbers were accepted proof data for the then-STARK-proved
actual segments. They are no longer the current state of the production path:
the production path now uses the multi-trace whole proof, hardened EC
accumulator AIR, compression/key-binding bridge, lookup-centric HMAC, and shared
cross-trace equality domain reported in the 2026-05-04 section.

This historical run changed the feasibility read:

- current proof sizes are well above the max-invoice target,
- the current radix-11 point lookup has the intended table shape and lookup
  count and now verifies under the production profile,
- the EC segment now consumes the production positive-magnitude radix-11 lookup,
  applies private signs outside the table, computes both `A` and hidden `S`,
  and feeds HMAC from EC-derived `compressedS`,
- the current BigInt-backed full-profile prover path is too slow for
  wallet-facing production use,
- the measured memory footprint stayed below the 64GB Node heap limit, but the
  observed multi-GiB footprint is still too high for the mobile target.

### Pre-Fix Radix-11 Lookup Failure Root Cause

The earlier full production-profile run rejected the radix-11 lookup proof. The
failure was not caused by an invalid point table, invalid selected rows, or a
bad production witness. The production radix-11 lookup trace itself evaluated
cleanly:

```text
trace rows: 32,768
trace width: 85
table rows: 23,584
selected lookups: 24
AIR transition failures: 0
AIR boundary failures: 0
```

The failure is in the lookup-bus STARK degree metadata. A small range16 lookup
proof using the same production STARK profile reproduces the failure:

```text
trace FRI verifies: yes
composition FRI verifies: no
verifyStark: no
```

For that small reproduction:

```text
trace length: 32
trace degree bound with mask degree 2: 34
declared lookup-bus transition degree: 9
derived composition degree bound: 283
measured composition polynomial degree: 332
```

Overriding the lookup-bus AIR transition degree to 11 gives:

```text
derived composition degree bound: 351
verifyStark: yes
```

The root cause was therefore that, during the failing run, `buildLookupBusAir`
declared `transitionDegree: 9`, while the implemented constraints had effective
degree 11. The high-degree terms come from the supply-row inverse constraints:

```text
supply_selector(kind) *
  (lookup_inverse * power_for_multiplicity(lookup_factor, multiplicity) - 1)
```

`supply_selector(kind)` is a degree-4 selector over row kinds.
`power_for_multiplicity` uses degree-3 multiplicity selectors and includes up
to `lookup_factor^3`. The resulting product reaches degree 11 in the committed
trace columns. Reduced profiles accidentally hid this because the composition
degree bound was capped near the whole LDE domain. The production profile has
enough room to expose the underdeclared degree, so FRI correctly rejects the
composition oracle.

The prototype AIR metadata has been corrected to use transition degree 11, and
the regression suite now includes a production-parameter lookup proof that must
verify. The full 64GB production profile was rerun after this fix, and the
metrics harness now fails hard if any proved actual segment is not verified.

### Pre-Fix EC Bundle Failure Root Cause

The first explicit `--prove-ec` metrics run proved the affine field-op bundle
but failed the hard metrics gate:

```text
ecArithmetic:
  proof bytes: 80,497,378
  prove time: 45.822s
  verify time: 0.027s
  verified: false
```

The failure was not a bad EC witness. The root cause was option leakage:
`proveSecp256k1FieldLinear` and `proveSecp256k1FieldMul` accepted the caller's
top-level production metrics `transcriptDomain`, while their verifiers
correctly used fixed field-op domains:

```text
BRC97_SECP256K1_FIELD_OPS_V1:linear
BRC97_SECP256K1_FIELD_OPS_V1:mul
```

The field-op provers now lock both transcript domain and public input digest
after applying caller-tunable proof parameters. A regression test proves an
affine addition while deliberately passing a bad caller domain and digest, and
verification still succeeds. The fixed explicit EC run verifies:

```text
ecArithmetic:
  proof bytes: 80,497,428
  prove time: 45.907s
  verify time: 15.573s
  verified: true
```

The main lesson has changed. Row count is not the first bottleneck. Private
committed width, bit decomposition, and non-native arithmetic plumbing are the
first bottlenecks.

The production design should therefore not be:

```text
row-expanded scalar selection
wide Jacobian mixed-add rows
wide SHA round rows
private limb selectors and private carry-bit columns
ad hoc cross-table equality checks
```

The revised design is:

```text
signed fixed-window scalar digits
indexed fixed-table point-pair lookups for public G and public B
affine EC additions with inverse witnesses and exceptional-case handling
lookup-centric SHA/HMAC
one global tagged lookup/equality bus
typed-array column-major STARK backend
```

This keeps the exact HMAC-over-hidden-ECDH relation, but moves as much work as
possible into verifier-derived public tables and reusable lookup/permutation
machinery.

## Security Posture

The implementation now has a verified full production-profile proof for the
deterministic max-invoice fixture, but it is not wallet-facing production-ready.
The current blocker is not a missing projected segment; it is proof size,
runtime, and final cryptographic hardening/review.

Reduced profiles, benchmark profiles, deterministic masks, unchecked AIR
variants, verifier-selected parameter flexibility, proof-selected schedules,
partial relation proofs, and unreviewed lookup arguments are test-only.
Production verifiers must reject them.

Production readiness requires:

- repeated full-proof validation on deterministic random real-key fixtures,
- proof size at or below the 1.5MB max-invoice acceptance cap,
- prover runtime reduced from minutes to the production target,
- a written constraint-soundness argument for every active table and row type,
- a written lookup/equality-bus and cross-trace equality-domain soundness
  argument,
- a written zero-knowledge leakage argument for the masking scheme and all
  opened values,
- a written STARK parameter and soundness analysis for the exact production
  profile,
- negative tests demonstrating rejection of malformed witnesses,
- independent cryptographic review before wallet-facing production use.

Production verification must accept exactly one production parameter family. Any
variable schedule, such as invoice block count, must be derived by the verifier
from public inputs and fixed profile rules, not selected by the proof.

## Backend Rearchitecture Findings: 2026-05-04

The multi-trace single-transcript architecture now proves and verifies the full
production statement, but the current BigInt-heavy backend and wide SHA/HMAC
composition path have not reached the business goal of production proofs in
seconds.

Implemented backend changes:

- composition denominators are batched across the LDE domain instead of inverted
  once per row,
- LDE domain points are advanced incrementally instead of recomputed with
  exponentiation per row,
- FRI folding uses one inverse per layer instead of one inverse per folded pair,
- large non-materialized traces reuse row buffers during composition evaluation,
- trace leaf serialization streams directly from column LDEs instead of
  allocating temporary row arrays,
- field-element serialization now preallocates fixed 8-byte slots,
- full public boundary columns are left unmasked because they contain no private
  witness data,
- public composition contexts are cached by AIR digest/domain parameters, which
  supports verifier/prover precomputation for repeated public shapes.

Measured reduced-profile whole-statement timing on the deterministic max-invoice
fixture:

```text
previous reduced multi-trace proof: about 37.9s
after denominator/FRI/serialization changes, cold proof: about 24.5s
same-process warm proof with public context cache: about 21.3s
```

The 2026-05-04 full production run gives the current structural bottlenecks:

```text
maxInvoiceLookupHmac:
  width: 470
  committed cells: 15,400,960
  LDE cells: 246,415,360
  hmac stark.composition-oracle: 1,570.235s
  hmac trace.commit: 462.120s
  hmac trace.lde: 406.374s

wholeStatement:
  width across traces: 1,127
  committed cells: 36,929,536
  LDE cells: 590,872,576
  proof bytes: 10,938,764
  prove time: 4,097.898s

shared equality domain:
  padded bus rows: 196,608
  proof contribution remains conservative but sound

backend:
  main FFT/LDE/composition loops still allocate and operate mostly through
  JavaScript/BigInt-oriented paths
```

A Goldilocks-specific BigInt reduction was tested and rejected because it was
slower in V8 than native BigInt modulo for this workload. This confirms the next
major speedup should not be another BigInt micro-optimization.

The path to production seconds remains:

- reduce the lookup-centric HMAC width and composition degree first, because it
  dominates proving time,
- move the fixed radix-11 table into a true preprocessed/fixed oracle instead of
  recommitting table columns per proof,
- port the proved relations to the typed-array column-major prover path with no
  BigInt hot loops,
- reduce shared equality-domain padding once the cross-trace soundness argument
  is frozen,
- keep the current BigInt backend as the correctness oracle until typed/WASM
  proof metadata and verifier results match.

## New Optimization Priorities

### 1. Replace Selection Rows With Fixed-Table Lookups

Both elliptic-curve bases are verifier-known:

- `G` is globally fixed.
- `B` is public in the statement.

The selected window point pair should come from a deterministic public dual-base
table:

```text
(window, magnitude) -> G affine point limbs, B affine point limbs
```

The prover must prove private membership in this table without revealing the
digit. The table entries should not be private committed witness columns.

The `G` side is globally fixed. The `B` side is dynamic public data derived
deterministically from the public counterparty key and the production profile:

```text
dual_point_table_root = TableRoot(profile_id, B)
```

The verifier must either compute and cache this root or verify it through a
reviewed deterministic table-generation path. A prover-supplied table root is
not sound unless the verifier independently binds it to `B`.

### 2. Use Signed Radix-11 Windows First

The primary scalar parameter target is signed radix 11:

```text
radix bits: 11
radix R: 2^11 = 2048
window count: 24
digit range: [-1024, 1023]
magnitude range: [0, 1024]
final window full table not required; final magnitude is <= 8 after recoding
```

The scalar witness should include canonical scalar limbs plus signed digits. The
scalar table proves:

```text
1 <= a < n
a = sum_i digit_i * R^i
digit_i = sign_i * magnitude_i
magnitude_i in [0, 1024]
sign_i is canonical, and sign_i = positive when magnitude_i = 0
```

The same signed digit stream feeds both fixed-base multiplications.

Expected point-table size:

```text
full windows: 23
full magnitudes per full window: 1025
final-window magnitudes: 9
dual-base table rows: 23 * 1025 + 9 = 23,584
equivalent point entries: 47,168
private selection lookups: 24
```

Expected EC additions:

```text
24 additions for A = aG
24 additions for S = aB
48 total scheduled additions
```

This is the preferred first production target. Radix 10 is the conservative
fallback if dynamic `B` table generation, lookup proof size, or verifier cache
cost is too high:

```text
radix bits: 10
window count: 26
dual-base rows: about 26k with unsigned tables, less with signed tables
additions: 52 total
```

Radix 12+ should not be the initial target. It saves only a few additions while
nearly doubling dynamic point-table size.

### 3. Defer GLV Until After Radix-11 Is Measured

GLV deserves consideration, but it is not the first-order optimization for this
exact fixed-base setting.

A useful GLV design needs joint tables of the form:

```text
(window, d1, d2) -> d1 * R^i * P + d2 * R^i * phi(P)
```

Separate `k1P` and `k2 phi(P)` scalar multiplications usually increase the
number of additions unless the windows become large. Joint GLV tables reduce
additions but grow approximately with the product of both digit ranges.

Initial GLV candidates, if EC remains the bottleneck:

```text
joint GLV radix 5:
  scalar halves: about 26 windows
  additions: about 52 total for both G and B
  table size: similar order to radix-11 without GLV
  likely not better enough

joint GLV radix 6:
  scalar halves: about 22 windows
  additions: about 44 total for both G and B
  table size: much larger
  only worth considering if EC rows dominate after SHA lookup work
```

The production baseline should therefore be non-GLV signed radix 11. GLV is a
phase-two benchmark, not a dependency for feasibility.

### 4. Use Affine EC Addition With Inverse Witnesses

For fixed-table additions, affine arithmetic is likely cheaper than Jacobian
mixed addition inside the proof because inversion can be supplied as a witness.

For a non-exceptional affine addition `R = P + Q`:

```text
dx = xQ - xP
dy = yQ - yP
inv * dx = 1
lambda * dx = dy
xR = lambda^2 - xP - xQ
yR = lambda * (xP - xR) - yP
```

This costs about four field multiplications:

```text
inv * dx
lambda * dx
lambda^2
lambda * (xP - xR)
```

The old Jacobian planning estimate used about 10-12 field multiplications per
mixed addition. The new target is therefore:

```text
48 additions * about 4 field multiplications = about 192 field multiplications
192 field multiplications * 18 convolution rows = about 3,456 mul rows
```

The EC table must still be complete for every valid scalar. Production cannot
silently assume that exceptional cases never happen.

Required EC row types:

- zero-digit copy,
- accumulator initialization from the first nonzero selected point,
- general affine addition with inverse witness,
- point doubling fallback,
- cancellation-to-infinity fallback,
- final non-infinity assertion for `A` and `S`.

The common path should be the four-multiplication affine addition. The fallback
paths are required for correctness and soundness even if they are rarely used.

The EC table should represent accumulator infinity explicitly with a boolean
flag. `S` is final non-infinity because `1 <= a < n`, `B` is valid non-infinity,
and secp256k1 has cofactor 1.

### 5. Remove Private Limb Selectors And Carry-Bit Columns

The current 29-bit multiplication prototype has width 95 largely because it
keeps one-hot limb selectors and carry bits in the private trace.

Production should move these out:

- limb index and row type are fixed public schedule columns,
- carry range is proved through the lookup/range bus,
- limb range is proved through reusable register-range lookups,
- field operation rows reuse the same register columns.

The target field multiplication row should be closer to:

```text
a limbs: 9
b limbs: 9
c limbs: 9
q limbs: 9
carry in/out: 2
small control/register columns: ~10-20
private width target: ~48-64
```

29-bit limbs remain the primary target:

```text
limb bits: 29
field limbs: 9
radix: 2^29
```

28-bit limbs remain the conservative fallback if the final range and carry
soundness analysis for 29-bit limbs is too tight.

### 6. Make SHA/HMAC Lookup-Centric

Exact HMAC-SHA256 remains mandatory:

```text
inner = SHA256((compress(S) padded to 64 bytes xor 0x36) || invoice)
outer = SHA256((compress(S) padded to 64 bytes xor 0x5c) || inner)
linkage = outer
```

The SHA/HMAC table should not use the current 1,616-column SHA layout. It should
also not try to keep one SHA round in a wide arithmetic row.

The revised target is a lookup-centric SHA table based on 16-bit chunks:

```text
global fixed table:
  dense16
  spread/even-bit form as needed by the SHA boolean formulas
  xor-with-0x3636 helpers
  xor-with-0x5c5c helpers
  byte/range helpers

SHA trace:
  narrow round micro-rows
  32-bit word values carried as two 16-bit chunks
  spread/range checks through lookup requests
  public schedule words for invoice blocks
  private schedule words only where compress(S) or inner digest is involved
```

For the maximum invoice currently modeled:

```text
absolute max invoice length: 1233
inner blocks: 21
outer blocks: 2
total blocks: 23
SHA rounds: 1,472
```

The important split is:

```text
private-derived message blocks:
  inner key block: compress(S) xor ipad
  outer key block: compress(S) xor opad
  outer digest block: inner digest plus fixed padding

public invoice blocks:
  all invoice bytes and SHA padding are verifier-derived
  message schedule words are public/preprocessed
  chaining state remains private and must be proven
```

The compressed `S` bytes should be bound directly from EC output limbs into the
SHA key block:

```text
compressed S:
  prefix byte = 0x02 or 0x03 from y parity
  x coordinate = canonical 32-byte big-endian field encoding

HMAC key block:
  bytes 0..32 from compressed S
  bytes 33..63 zero
  xor with ipad/opad inside the SHA/HMAC table
```

Do not create an unconstrained private `compressedS` blob. It must be linked
byte-for-byte to the EC output and then to the HMAC key schedule.

The target SHA/HMAC shape is now narrow rather than minimal-row:

```text
max-invoice active rows: ~6k-12k preferred
max-invoice padded rows: 16,384 preferred
max-invoice padded rows: 32,768 acceptable
private width: <= 64 preferred
private width: <= 96 acceptable
```

This is a deliberate change from the earlier rolling-round target. More rows are
acceptable if the private committed width stays low and the lookup table is
fixed/preprocessed.

### 7. Preserve The Remaining Small Wins

Several secondary optimizations should be kept in the production design because
they reduce proof size or avoid duplicated work without changing the statement:

- one dual-base point lookup per scalar digit should return both the `G` and `B`
  points, rather than proving two separate lookups,
- the EC schedule should process the two accumulators as a pair so digit,
  magnitude, sign, zero, and initialization flags are shared where sound,
- the inner and outer HMAC key-block schedule should share byte decomposition and
  spread/xor lookups for `compress(S)` wherever the SHA table allows it,
- public invoice schedule words should be fixed/preprocessed columns, not lookup
  requests and not private witness,
- row type, limb index, SHA round index, block index, and window index should be
  public schedule columns,
- the 16-bit SHA/range lookup table is the primary target; an 8-bit table is only
  a fallback if 65,536 fixed rows are too expensive in the SDK backend,
- dynamic public table roots should be cached by `(profile, B)` so repeated
  verification for the same counterparty does not regenerate the table.

## Production Architecture

The production proof should be a fixed-profile segmented STARK with a global
lookup/equality bus:

```text
scalar and digit table
EC arithmetic table
SHA/HMAC table
lookup/equality bus tables
public fixed tables
```

The purpose of each table is narrow and explicit.

### Table 1: Scalar And Digits

Purpose:

- prove `1 <= a < n`,
- decompose `a` into 24 signed radix-11 digits,
- prove canonical sign/magnitude encoding,
- prove the same digit stream feeds `aG` and `aB`,
- emit lookup requests for selected `G`/`B` point-table pairs.

Target:

```text
active rows: <= 64
padded rows: 64 or 128
private width: <= 32
```

The scalar table should use range and comparison lookups rather than bespoke
bit columns wherever possible.

### Table 2: Fixed Dual-Base Point Table

Purpose:

- provide a deterministic public lookup table for paired `G` and `B` points,
- bind table contents to the production profile and public `B`,
- let private scalar digits select both affine points without revealing digits.

Primary radix-11 target:

```text
dual-base rows: 23,584
equivalent point entries: 47,168
private selection lookups: 24
private width: 0
```

Each lookup row should be tagged and include enough information to prevent table
confusion:

```text
profile_id
window
magnitude
is_zero
G x limbs
G y limbs
B x limbs
B y limbs
```

Signed digits should use the positive-magnitude table plus one private sign bit.
The sign bit conditionally maps both `G.y` and `B.y` to `p - y`; `x` is
unchanged. Magnitude zero must force the canonical positive sign and an
infinity/zero selected-point flag for both bases.

### Table 3: EC Arithmetic

Purpose:

- consume selected table point pairs for `G` and `B`,
- apply signed-y selection,
- update two accumulators,
- prove final `A` equals public `A`,
- output private `S`.

Primary target:

```text
scheduled additions: 48
field multiplications: about 192 common-path
active rows: <= 6,000 preferred
padded rows: 8,192 preferred
padded rows: 16,384 acceptable
private width: <= 64 preferred
private width: <= 96 acceptable
```

The EC table should be phased around reusable field-register operations, not a
wide one-row mixed-add formula. Public schedule columns should identify row
type, operation slot, limb index, and base/window where applicable.

### Table 4: Compression And HMAC Input Binding

Purpose:

- prove `S` is a valid non-infinity affine secp256k1 point,
- prove canonical x-coordinate byte decomposition,
- prove y parity,
- form the exact 33-byte compressed point,
- bind those bytes into the inner and outer HMAC key blocks.

This table may be part of the EC table, part of the SHA/HMAC table, or a short
bridge segment. Its links are soundness-critical. The prover must not be able to
prove `S = aB` and HMAC a different key.

### Table 5: SHA/HMAC

Purpose:

- prove exact HMAC-SHA256 for the public invoice,
- use public/preprocessed invoice schedule words,
- use private schedule words only for key and digest-derived blocks,
- bind final outer digest to public `linkage`.

Primary max-invoice target:

```text
total SHA blocks: 23
SHA rounds: 1,472
active rows: <= 12,000 preferred
padded rows: 16,384 preferred
padded rows: 32,768 acceptable
private width: <= 64 preferred
private width: <= 96 acceptable
```

The verifier derives the exact SHA/HMAC schedule from public invoice bytes and
invoice length. A proof must not select a shorter or weaker schedule.

### Table 6: Global Lookup And Equality Bus

Purpose:

- range checks,
- byte decomposition,
- SHA spread lookups,
- SHA xor helpers,
- carry range checks,
- selected point-pair table lookups,
- scalar digit range checks,
- cross-table equality links.

The bus should use tagged tuple compression with verifier challenges:

```text
compressed_tuple = Compress(tag, value_0, value_1, ...)
```

Required links include:

- scalar digits to both EC multiplications,
- point-pair lookup outputs to EC selected points,
- final EC accumulator `A` to public `A`,
- final EC accumulator `S` to compression,
- compressed `S` bytes to HMAC key blocks,
- inner SHA digest to outer SHA input,
- final outer digest to public `linkage`.

Production lookup and equality batching should use extension-field challenges or
an equivalent multi-challenge construction. A single 64-bit Goldilocks base-field
challenge is not enough margin for production tuple compression and batching.

## Public And Private Data

Public inputs:

- `A`, the prover public key,
- `B`, the counterparty public key,
- `G`, fixed by secp256k1,
- `protocolID`,
- `keyID`,
- exact invoice bytes and invoice length,
- `linkage`,
- proof version/profile,
- curve, hash, HMAC, limb, window, lookup, table, and STARK profile identifiers,
- deterministic dual-base fixed-window table root derived from `G` and `B`,
- public SHA constants and public invoice schedule words.

Private witness:

- scalar `a`,
- signed scalar digits,
- selected point-pair lookup witnesses,
- EC accumulator states,
- `S = aB`,
- compressed `S` bytes as linked derived values,
- HMAC inner digest,
- SHA intermediate states,
- carry and range witnesses,
- lookup/equality bus witnesses,
- masking/blinding columns.

Public/preprocessed data should be verifier-derived whenever possible. Do not
commit known tables and constants as private witness columns.

## STARK Backend Requirements

The current BigInt row-array backend is useful for exploration, but not for the
production mobile target.

A production SDK-only backend likely requires:

- column-major trace storage,
- typed-array Goldilocks elements,
- `Uint32Array` low/high lanes or equivalent packed representation,
- specialized Goldilocks add/sub/mul without BigInt in hot loops,
- extension-field arithmetic for production batching challenges,
- column-wise LDE/FFT,
- streaming Merkle leaves from columns,
- row materialization only for queried openings,
- batched/deduped Merkle paths,
- fixed/preprocessed table commitments,
- dynamic public table caching keyed by `(profile, B)`,
- global lookup/equality bus support.

The production backend must remain inside the SDK and must not depend on an
external prover service, zkVM, native binary, or third-party proving library.

## Updated Size And Compute Targets

The new architecture intentionally trades some row count for much lower private
width and far fewer EC field operations.

Primary max-invoice target:

```text
scalar/digit table:
  padded rows: <= 128
  private width: <= 32

EC table:
  padded rows: 8,192 preferred
  padded rows: 16,384 acceptable
  private width: <= 64 preferred
  private width: <= 96 acceptable

SHA/HMAC table:
  padded rows: 16,384 preferred
  padded rows: 32,768 acceptable
  private width: <= 64 preferred
  private width: <= 96 acceptable

lookup/equality bus:
  padded rows: 16,384 preferred
  padded rows: 32,768 acceptable
  private width: <= 48 preferred
  private width: <= 80 acceptable

fixed point tables:
  dual-base radix-11 rows: 23,584
  equivalent point entries: 47,168
  private width: 0

global 16-bit SHA/range table:
  rows: 65,536
  private width: 0
```

Approximate private trace-area target at blowup 16:

```text
EC:       8,192 *  64 * 16 ~= 8.4M cells
SHA:     16,384 * 64 * 16 ~= 16.8M cells
bus:     16,384 * 48 * 16 ~= 12.6M cells
scalar:     128 * 32 * 16 ~= 0.1M cells
total:                       ~38M cells
```

Acceptable fallback area:

```text
EC:      16,384 *  96 * 16 ~= 25.2M cells
SHA:     32,768 *  96 * 16 ~= 50.3M cells
bus:     32,768 *  80 * 16 ~= 41.9M cells
scalar:     128 *  32 * 16 ~= 0.1M cells
total:                        ~117M cells
```

The preferred target is materially better than the previous segmented estimate
of about 75M cells because EC arithmetic shrinks and private width is lower. The
fallback is still heavy and should be treated as a warning sign for mobile JS.

Proof-size target:

```text
typical invoice: <= 750KB preferred, <= 1MB acceptable
max invoice: <= 1.25MB preferred, <= 1.5MB acceptable
```

These targets require actual multi-table lookup openings to be measured. They
should not be judged using the current BigInt row-array prover.

## Security Requirements

The production proof must enforce:

- `A` is a valid non-infinity secp256k1 point,
- `B` is a valid non-infinity secp256k1 point,
- `1 <= a < n`,
- signed digit decomposition reconstructs `a`,
- both scalar multiplications use the same digit stream,
- every selected point pair is in the verifier-derived table for `G` and `B`,
- selected point-pair signs are applied correctly,
- `A = aG`,
- `S = aB`,
- EC addition exceptional cases are soundly handled,
- `compress(S)` is correctly formed,
- `linkage = HMAC-SHA256(compress(S), invoice)`,
- exact invoice bytes and invoice length are bound,
- SHA/HMAC block schedules are verifier-derived from public inputs,
- all table/profile identifiers are bound,
- all limb/carry relations are range-bounded tightly enough to prevent
  Goldilocks wraparound false positives,
- all lookup and cross-table equality links are sound.

Production verification must reject proof-supplied or caller-supplied weaker
parameters, including alternate window size, alternate limb size, alternate
lookup table, lower blowup, fewer queries, lower mask degree, alternate
transcript domains, alternate table schemas, shorter SHA schedules, or debug
profiles.

Transcript domain separation must include:

- proof family: BRC-69 Method 2,
- proof version,
- table schema identifiers,
- lookup/equality bus identifier,
- secp256k1 identifier,
- SHA/HMAC identifiers,
- signed radix/window size,
- limb size,
- public input digest format,
- fixed table root format,
- STARK parameter profile.

## Zero Knowledge

Private columns include:

- scalar limbs,
- signed scalar digits,
- selected point-pair lookup witnesses,
- EC accumulators,
- `S`,
- compressed `S` bytes before public linkage,
- SHA/HMAC chaining state and digest state,
- carry/range witnesses,
- lookup/equality bus witness rows.

Production masks must be CSPRNG-derived. Deterministic mask seeds are test-only.
The masking argument must account for every table, every opened row, next-row
opening, composition opening, trace-combination value, FRI-linked value,
lookup-bus value, and cross-table equality argument.

Lookup arguments must not reveal selected digit indexes, selected table rows,
scalar digits, `S`, compressed `S`, or SHA intermediate state.

## Acceptance Criteria

The implementation has now passed the execution part of this gate for the
deterministic max-invoice fixture: a full harness proved and verified one
256-bit Method 2 statement with production parameters and a maximum invoice on
2026-05-04.

Wallet-facing production readiness remains blocked until the same production
path meets the size, runtime, zero-knowledge, soundness-analysis, and review
criteria below.

The harness must report per table and overall:

- active rows,
- padded rows,
- private committed width,
- public/preprocessed width,
- fixed table rows,
- lookup request counts by tag,
- LDE rows,
- estimated trace area,
- proof byte length,
- prove time,
- verify time,
- fixed table generation time,
- peak or approximate memory,
- invoice length,
- SHA block count.

Updated production-oriented targets:

```text
scalar/digit table:
  signed radix: 11
  windows: 24
  padded rows <= 128
  private width <= 32

fixed point tables:
  dual-base rows <= 23,584 for radix 11
  equivalent point entries <= 47,168
  verifier-derived from profile and B

EC table:
  scheduled additions = 48
  padded rows <= 8,192 preferred
  padded rows <= 16,384 acceptable
  private width <= 64 preferred
  private width <= 96 acceptable

SHA/HMAC table:
  max-invoice padded rows <= 16,384 preferred
  max-invoice padded rows <= 32,768 acceptable
  private width <= 64 preferred
  private width <= 96 acceptable

lookup/equality bus:
  padded rows <= 16,384 preferred
  padded rows <= 32,768 acceptable
  private width <= 48 preferred
  private width <= 80 acceptable

overall:
  proof size <= 750KB typical preferred
  proof size <= 1MB typical acceptable
  proof size <= 1.25MB max-invoice preferred
  proof size <= 1.5MB max-invoice acceptable
```

## Recommended Next Steps

1. Reduce HMAC/SHA proving cost.

   `maxInvoiceLookupHmac` is now on the production path, but it remains the
   dominant bottleneck: width 470, 246.4M LDE cells, and about 26.2 minutes in
   the composition oracle alone. The next HMAC work should reduce lane width,
   composition degree, and repeated SHA lookup plumbing without weakening the
   compressed-`S` key binding.

2. Reduce proof size below the production cap.

   The current verified whole proof is 10.94MB. The production gate requires
   <=1.5MB for max invoice. This likely needs fixed/preprocessed commitments for
   the radix-11 table, narrower HMAC composition, fewer opened columns, and
   tighter cross-trace bus openings.

3. Finish typed-array column-major proving for the active production relations.

   The current proof verifies, so the BigInt path should remain the correctness
   oracle while the hot FFT/LDE/composition/Merkle loops move to typed arrays.
   The typed path must match proof metadata, public input digests, and verifier
   behavior before it becomes the production performance path.

4. Freeze and document the soundness arguments.

   The architecture now avoids the retired masked-opening endpoint-link model,
   but production review still needs written arguments for every active AIR,
   lookup tuple, cross-trace equality constraint, masking rule, and verifier
   parameter gate.

5. Revisit GLV only after HMAC and backend costs are under control.

   The latest full run shows HMAC/SHA dominates. GLV should remain deferred
   unless EC becomes the limiting factor after HMAC and backend reductions.

## Current Feasibility Read

The old VM path is not feasible.

The old row-expanded scalar-control path is no longer the target.

The old monolithic Jacobian mixed-add path is not feasible.

The old wide SHA layout is not feasible for low-power mobile.

The new most promising design is:

```text
signed radix-11 scalar digits
verifier-derived dual-base point table for G and B
private indexed point-pair lookups
affine EC additions with inverse witnesses and fallback branches
lookup-centric SHA/HMAC over 16-bit chunks
global tagged lookup/equality bus
29-bit field limbs with public schedules and lookup range checks
typed-array column-major prover backend
```

This design now proves and verifies the exact max-invoice HMAC-over-hidden-ECDH
relation under the production profile. The remaining work is to make that proof
small, fast, formally documented, and independently reviewed enough for
wallet-facing production use.
