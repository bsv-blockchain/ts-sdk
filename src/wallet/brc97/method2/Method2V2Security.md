# BRC-69 Method 2 V2 Security Notes

This note describes the older V2 6-bit fixed-window prototype. It is not the
current production proof path. The current production path is the multi-trace,
single-transcript signed radix-11 Method 2 proof tracked in `zk-strat.md` and
`docs/brc97-production-status.md`.

This note tracks the production security obligations for the V2 Method 2 proof.
The current implementation includes the deterministic V2 fixed-window core and
public-input binding substrate. It is not a completed production STARK AIR until
the remaining items below are implemented and reviewed.

## Implemented Invariants

- The V2 profile is fixed to `BRC69_METHOD2_V2`, 6-bit windows, 43 scalar
  windows, 29-bit target limbs, SHA-256, HMAC-SHA256, and the named STARK
  parameter profile.
- The public input digest binds the V2 family, AIR identifier, digest format,
  curve/hash/HMAC identifiers, window and limb identifiers, STARK profile,
  prover key `A`, counterparty key `B`, exact invoice bytes and length, and
  public linkage bytes.
- Deterministic fixed-window tables are derived from public `G` and `B`.
- The shared digit stream reconstructs the same scalar used by both
  accumulations.
- Native V2 trace validation rejects digit tampering, wrong final `A`, wrong
  shared point `S`, malformed table selection, and wrong HMAC linkage.

## Limb And Carry Bounds

The V2 target limb size is 29 bits. The current V2 file records this profile
choice but does not yet replace the existing 16-bit AIR limb constraints.
Before production verification can be enabled, every V2 field, scalar, carry,
and reduction constraint must document:

- represented integer range for each limb and carry column,
- maximum intermediate convolution and reduction value,
- why the Goldilocks field equation cannot wrap and accept a false integer
  relation,
- canonical encoding constraints for field elements, scalars, points, bytes,
  and SHA digests.

If any 29-bit bound is too tight, the implementation may switch internally to
28-bit limbs, but the profile id and security note must be updated with the
reason and new bounds.

## EC Formula Completeness

The V2 core currently validates fixed-window accumulation natively using the
existing secp256k1 point operations. The production AIR must use projective or
Jacobian mixed-addition constraints and must document one of:

- complete formulas for every reachable transition, or
- every excluded exceptional case and the exact constraints or reachability
  argument that rules it out.

Public table validation alone is not sufficient; accumulator transition
constraints must also prevent exceptional witness escapes.

## Zero Knowledge

Production masking is not complete. Private V2 data includes scalar digits,
selected points, accumulators, `S`, compressed `S`, SHA/HMAC intermediate
state, and any carry columns. A production prover must use CSPRNG-derived masks.
Deterministic mask seeds remain test-only.

The leakage argument must account for opened trace rows, next rows, composition
rows, trace-combination values, and FRI-linked values.

## STARK Soundness

The current BigInt row-array STARK backend remains a prototype for this
production target. Production readiness requires a written soundness estimate
covering field size, blowup, query count, transition degree, composition degree,
FRI parameters, Fiat-Shamir derivation, batching, and whether base-field or
extension-field challenges are used.

## Review Gate

Production wallet-facing verification must stay disabled until:

- the full V2 AIR proves the complete relation,
- negative malformed-witness tests pass,
- internal implementation review is complete,
- independent cryptographic review is complete,
- all soundness, zero-knowledge, verifier-hardening, and malformed-witness
  findings are resolved.
