# BigNumber Benchmarks

The benchmark scripts measure extremely large number operations and script number serialization performance.

## BRC-69 Method 2 Production ZK

The current BRC-69 Method 2 production proof path is tracked separately in
[BRC-69 Method 2 Production ZK Status](./brc69-production-status.md).

As of the 2026-05-04 full production validation run, the whole statement proof
generates and verifies under the production STARK profile. It is not yet
production-acceptable for wallet-facing use because the proof is 10.94MB against
the 1.5MB max-invoice cap and proving takes about 68.3 minutes.

All results below were gathered on Node.js v22.16.0 using the `dist` build of the SDK. Each benchmark was executed with 200,000-digit inputs to stress the implementation.

## Addition and Multiplication

Command:

```bash
node benchmarks/bignumber-bench.js 200000 1 1
```

| Branch | mul large numbers | add large numbers |
| --- | --- | --- |
| master (pre-May-2025) | 6364.11ms | 13.04ms |
| fix-mem (May-2025) | 13.60ms | 2.64ms |

## Serialization

Command:

```bash
node benchmarks/serialization-bench.js 200000 1
```

| Branch | toSm big | toSm little | fromSm big | fromSm little | fromScriptNum |
| --- | --- | --- | --- | --- | --- |
| master (pre-May-2025) | 6.12ms | 10.11ms | 6.35ms | 12.56ms | 3.39ms |
| fix-mem (May-2025) | 8.46ms | 8.12ms | 27.77ms | 11.16ms | 10.31ms |

## Transaction Verification

Command:

```bash
node benchmarks/transaction-bench.js
```

| Branch | deep chain verify | wide transaction verify | large tx verify | nested inputs verify |
| --- | --- | --- | --- | --- |
| fix-mem (May-2025) | 3335.76ms | 2930.86ms | 1534.36ms | 1198.08ms |

## SymmetricKey Encryption/Decryption

Command:

```bash
node benchmarks/symmetric-key-bench.js
```

| Branch | encrypt large 2MB | decrypt large 2MB | encrypt 50 small | decrypt 50 small | encrypt 200 medium | decrypt 200 medium |
| --- | --- | --- | --- | --- | --- | --- |
| fix-mem baseline | 8609.78ms | 8372.23ms | 34.02ms | 48.58ms | 859.38ms | 960.16ms |
| optimized AESGCM (round 1) | 7678.65ms | 7619.82ms | 60.23ms | 35.21ms | 871.89ms | 763.13ms |
| optimized AESGCM (round 2) | 2026.89ms | 1793.35ms | 15.01ms | 7.88ms | 213.35ms | 169.37ms |

## Reader/Writer Operations

Command:

```bash
node benchmarks/reader-writer-bench.js
```

| Branch | mixed ops | large payloads | 3000 small payloads | 400 medium payloads |
| --- | --- | --- | --- | --- |
| fix-mem baseline | 9.93ms | 127.49ms | 27.86ms | 41.71ms |
| optimized utils.ts | 5.02ms | 91.93ms | 19.04ms | 53.80ms |
