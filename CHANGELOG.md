# CHANGELOG for `@bsv/sdk`

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec2.0.0.html).

## Table of Contents

- [Unreleased](#unreleased)
- [1.9.28 - 2025-12-11](#1928---2025-12-11)
- [1.9.27 - 2025-12-11](#1927---2025-12-11)
- [1.9.26 - 2025-12-10](#1926---2025-12-10)
- [1.9.25 - 2025-12-09](#1925---2025-12-09)
- [1.9.24 - 2025-12-09](#1924---2025-12-09)
- [1.9.23 - 2025-12-08](#1923---2025-12-08)
- [1.9.22 - 2025-12-05](#1922---2025-12-04)
- [1.9.21 - 2025-12-04](#1921---2025-12-04)
- [1.9.20 - 2025-12-02](#1920---2025-12-02)
- [1.9.19 - 2025-12-02](#1919---2025-12-02)
- [1.9.18 - 2025-12-02](#1918---2025-12-02)
- [1.9.17 - 2025-12-01](#1917---2025-12-01)
- [1.9.16 - 2025-12-01](#1916---2025-12-02)
- [1.9.15 - 2025-12-01](#1915---2025-12-01)
- [1.9.14 - 2025-12-01](#1914---2025-12-01)
- [1.9.13 - 2025-12-01](#1913---2025-12-01)
- [1.9.12 - 2025-12-01](#1912---2025-12-01)
- [1.9.11 - 2025-11-24](#1911---2025-11-24)
- [1.9.10 - 2025-11-17](#1910---2025-11-17)
- [1.9.9 - 2025-11-15](#199---2025-11-15)
- [1.9.8 - 2025-11-15](#198---2025-11-15)
- [1.9.7 - 2025-11-14](#197---2025-11-14)
- [1.9.6 - 2025-11-13](#196---2025-11-13)
- [1.9.5 - 2025-11-13](#195---2025-11-13)
- [1.9.3 - 2025-11-11](#193---2025-11-11)
- [1.9.2 - 2025-11-11](#192---2025-11-11)
- [1.9.1 - 2025-11-10](#191---2025-11-10)
- [1.9.0 - 2025-11-09](#190---2025-11-09)
- [1.8.13 - 2025-11-06](#1813---2025-11-06)
- [1.8.12 - 2025-11-06](#1812---2025-11-06)
- [1.8.11 - 2025-10-30](#1811---2025-10-30)
- [1.8.10 - 2025-10-28](#1810---2025-10-28)
- [1.8.9 - 2025-10-27](#189---2025-10-27)
- [1.8.8 - 2025-10-22](#188---2025-10-22)
- [1.8.7 - 2025-10-22](#187---2025-10-22)
- [1.8.5 - 2025-10-21](#185---2025-10-21)
- [1.8.4 - 2025-10-20](#184---2025-10-20)
- [1.8.3 - 2025-10-16](#183---2025-10-16)
- [1.8.2 - 2025-10-03](#182---2025-10-03)
- [1.8.1 - 2025-10-02](#181---2025-10-02)
- [1.8.0 - 2025-10-02](#180---2025-10-02)
- [1.7.8 - 2025-10-02](#178---2025-10-02)
- [1.7.6 - 2025-09-09](#176---2025-09-08)
- [1.7.5 - 2025-09-08](#175---2025-09-08)
- [1.7.4 - 2025-09-08](#174---2025-09-08)
- [1.7.3 - 2025-09-05](#173---2025-09-05)
- [1.7.2 - 2025-09-05](#172---2025-09-05)
- [1.7.1 - 2025-09-03](#171---2025-09-03)
- [1.7.0 - 2025-09-03](#170---2025-09-03)
- [1.6.26 - 2025-09-02](#1626---2025-09-02)
- [1.6.25 - 2025-09-02](#1625---2025-09-02)
- [1.6.24 - 2025-08-19](#1624---2025-08-19)
- [1.6.20 - 2025-07-22](#1620---2025-07-22)
- [1.6.19 - 2025-07-21](#1619---2025-07-21)
- [1.6.18 - 2025-07-20](#1618---2025-07-20)
- [1.6.17 - 2025-07-18](#1617---2025-07-18)
- [1.6.16 - 2025-07-17](#1616---2025-07-17)
- [1.6.14 - 2025-07-17](#1614---2025-07-17)
- [1.6.13 - 2025-07-17](#1613---2025-07-17)
- [1.6.12 - 2025-07-08](#1612---2025-07-08)
- [1.6.11 - 2025-07-05](#1611---2025-07-05)
- [1.6.10 - 2025-07-02](#1610---2025-07-02)
- [1.6.9 - 2025-07-02](#169---2025-07-02)
- [1.6.8 - 2025-06-26](#168---2025-06-26)
- [1.6.7 - 2025-06-25](#167---2025-06-25)
- [1.6.6 - 2025-06-25](#166---2025-06-25)
- [1.6.5 - 2025-06-21](#165---2025-06-21)
- [1.6.4 - 2025-06-20](#164---2025-06-20)
- [1.6.3 - 2025-06-20](#163---2025-06-20)
- [1.6.2 - 2025-06-18](#162---2025-06-18)
- [1.6.1 - 2025-06-16](#161---2025-06-16)
- [1.6.0 - 2025-05-29](#160---2025-05-29)
- [1.5.3 - 2025-05-29](#153---2025-05-29)
- [1.5.1 - 2025-05-13](#151---2025-05-13)
- [1.5.0 - 2025-05-09](#150---2025-05-09)
    - Hereon compatible with Metanet Mobile v0.0.1
- [1.4.23 - 2025-04-29](#1423---2025-04-29)
- [1.4.22 - 2025-04-27](#1422---2025-04-27)
- [1.4.21 - 2025-04-13](#1421---2025-04-17)
- [1.4.20 - 2025-04-23](#1420---2025-04-23)
- [1.4.19 - 2025-04-09](#1419---2025-04-09)
- [1.4.18 - 2025-04-02](#1418---2025-04-02)
- [1.4.17 - 2025-04-01](#1417---2025-04-01)
- [1.4.16 - 2025-04-01](#1416---2025-04-01)
- [1.4.15 - 2025-03-31](#1415---2025-03-31)
- [1.4.14 - 2025-03-31](#1414---2025-03-31)
- [1.4.13 - 2025-03-30](#1413---2025-03-30)
- [1.4.12 - 2025-03-28](#1412---2025-03-28)
- [1.4.11 - 2025-03-25](#1411---2025-03-25)
- [1.4.10 - 2025-03-24](#1410---2025-03-24)
- [1.4.8 - 2025-03-17](#148---2025-03-17)
- [1.4.7 - 2025-03-17](#147---2025-03-17)
- [1.4.6 - 2025-03-15](#146---2025-03-15)
- [1.4.5 - 2025-03-15](#145---2025-03-15)
- [1.4.4 - 2025-03-15](#144---2025-03-15)
- [1.4.3 - 2025-03-14](#143---2025-03-14)
- [1.4.2 - 2025-03-13](#142---2025-03-13)
- [1.4.1 - 2025-03-12](#141---2025-03-12)
- [1.4.0 - 2025-03-10](#140---2025-03-7)
    - Scope increase to include Identity, Storage, and Message Box client functionality
- [1.3.36 - 2025-03-07](#1336---2025-03-7)
- [1.3.35 - 2025-03-07](#1335---2025-03-7)
- [1.3.34 - 2025-03-06](#1334---2025-03-6)
- [1.3.33 - 2025-03-06](#1333---2025-03-6)
- [1.3.32 - 2025-03-06](#1332---2025-03-6)
- [1.3.30 - 2025-03-05](#1330---2025-03-5)
- [1.3.29 - 2025-03-05](#1329---2025-03-5)
- [1.3.28 - 2025-02-28](#1328---2025-02-28)
- [1.3.27 - 2025-02-28](#1327---2025-02-28)
- [1.3.26 - 2025-02-28](#1326---2025-02-28)
- [1.3.25 - 2025-02-27](#1325---2025-02-27)
- [1.3.24 - 2025-02-22](#1324---2025-02-22)
- [1.3.23 - 2025-02-21](#1323---2025-02-21)
- [1.3.22 - 2025-02-19](#1322---2025-02-19)
- [1.3.21 - 2025-02-17](#1321---2025-02-17)
- [1.3.20- 2025-02-11](#1320---2025-02-17)
- [1.3.19 - 2025-02-16](#1319---2025-02-16)
- [1.3.18 - 2025-02-12](#1318---2025-02-12)
- [1.3.17- 2025-02-11](#1317---2025-02-11)
- [1.3.15- 2025-02-07](#1315---2025-02-07)
- [1.3.14- 2025-02-07](#1314---2025-02-07)
- [1.3.12 - 2025-01-29](#139---2025-01-29)
- [1.3.11 - 2025-01-28](#139---2025-01-28)
- [1.3.10 - 2025-01-27](#139---2025-01-27)
- [1.3.9 - 2025-01-23](#139---2025-01-23)
- [1.3.8 - 2025-01-20](#138---2025-01-20)
- [1.3.7 - 2025-01-18](#137---2025-01-18)
- [1.3.6 - 2025-01-17](#136---2025-01-17)
- [1.3.4 - 2025-01-17](#134---2025-01-17)
- [1.3.3 - 2025-01-13](#133---2025-01-13)
- [1.3.2 - 2025-01-13](#132---2025-01-13)
- [1.3.1 - 2025-01-13](#131---2025-01-13)
- [1.3.0 - 2025-01-11](#130---2025-01-11)
    - Scope increase to include [auth](./src/auth/) Mutual Authentication and Monetization Framework
- [1.2.22 - 2025-01-06](#1222---2025-01-06)
- [1.2.21 - 2025-01-03](#1221---2025-01-03)
- [1.2.19 - 2024-12-19](#1219---2024-12-19)
- [1.2.18 - 2024-12-19](#1218---2024-12-19)
- [1.2.17 - 2024-12-18](#1217---2024-12-18)
- [1.2.15 - 2024-12-16](#1215---2024-12-16)
- [1.2.14 - 2024-12-14](#1214---2024-12-14)
- [1.2.13 - 2024-12-13](#1213---2024-12-13)
- [1.2.12 - 2024-12-12](#1212---2024-12-12)
- [1.2.11 - 2024-12-10](#1211---2024-12-10)
- [1.2.10 - 2024-12-10](#1210---2024-12-10)
- [1.2.9 - 2024-12-06](#129---2024-12-06)
- [1.2.8 - 2024-12-02](#128---2024-12-02)
- [1.2.7 - 2024-12-02](#127---2024-12-02)
- [1.2.6 - 2024-11-30](#126---2024-11-30)
- [1.2.5 - 2024-11-30](#125---2024-11-30)
- [1.2.4 - 2024-11-29](#124---2024-11-29)
- [1.2.3 - 2024-11-26](#123---2024-11-26)
- [1.2.2 - 2024-11-26](#122---2024-11-26)
- [1.2.1 - 2024-11-25](#121---2024-11-25)
- [1.2.0 - 2024-11-25](#120---2024-11-25)
    - Scope increase to include [wallet](./src/wallet/) and [overlay-tools](./src/overlay-tools/)
- [1.1.33 - 2024-11-22](#1133---2024-11-22)
- [1.1.32 - 2024-11-22](#1132---2024-11-22)
- [1.1.30 - 2024-11-02](#1130---2024-11-02)
- [1.1.29 - 2024-10-23](#1129---2024-10-23)
- [1.1.28 - 2024-10-23](#1128---2024-10-23)
- [1.1.26 - 2024-10-22](#1126---2024-10-22)
- [1.1.25 - 2024-10-21](#1125---2024-10-21)
- [1.1.24 - 2024-10-04](#1124---2024-10-04)
- [1.1.22 - 2024-09-02](#1122---2024-09-02)
- [1.1.21 - 2024-09-02](#1121---2024-09-02)
- [1.1.17 - 2024-08-21](#1117---2024-08-21)
- [1.1.14 - 2024-07-30](#1114---2024-07-30)
- [1.1.13 - 2024-07-19](#1113---2024-07-19)
- [1.1.10 - 2024-06-28](#1110---2024-06-28)
- [1.1.8 - 2024-06-19](#118---2024-06-19)
- [1.1.6 - 2024-06-12](#116---2024-06-12)
- [1.1.5 - 2024-06-11](#115---2024-06-11)
- [1.1.4 - 2024-05-10](#114---2024-05-10)
- [1.1.0 - 2024-05-06](#110---2024-05-06)
    - First changes from open source community
- [1.0.0 - 2024-02-10](#100---2024-02-10)
    - Open Source launch
- [Template for New Releases](#template-for-new-releases)

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

---

## [1.9.28] - 2025-12-11

### Added
- Add getBytes64 helper for 64-bit length fields.
- Added long ciphertext test case.

### Changed
- Changed AESGCM to use Uint8Arrays instead of number[] for all inputs and outputs for optimization.

### Fixed
- Use 64-bit length encoding for GHASH inputs.

---

## [1.9.27] - 2025-12-11

### Fixed
- Addressed TOB-24: hardened elliptic-curve point validation across `fromDER`, `fromX`, and `fromJSON`.
- Added bigint-secure curve equation checking to `Point.validate()`.
- Fixed modular sqrt and pow logic (`biModSqrt`, `biModPow`) to correctly detect invalid X coordinates.
- Ensured consistent `Invalid point` errors for malformed input.
- Added negative tests and roundtrip validation tests.

---

## [1.9.26] - 2025-12-10

### Security
- Addressed TOB-25 by adding explicit ECDSA and elliptic-curve regression tests
  ensuring correct propagation and handling of the point at infinity during
  scalar multiplication and signature verification.
  These tests prevent regressions where invalid infinity points could be
  incorrectly treated as valid curve points.

---

## [1.9.25] - 2025-12-09

### Added
- Documentation disclaimer for our specific AESGCM implementation of padding for additional authenticated data (AAD) and ciphertext.

### Removed
- Removed support for additional authenticated data (AAD) padding in AESGCM.

---

## [1.9.24] - 2025-12-09

### Fixed
- Addressed TOB-20: clarified and corrected byte-order helper behavior in
  `Hash.ts`.  
  - The original `htonl()` implementation (a byte-swap) is now formally
    exposed as `swapBytes32()` for clarity.  
  - Introduced `realHtonl()`, which applies true host-to-network conversion
    based on runtime endianness.  
  - Added `isHostLittleEndian` export to ensure deterministic behavior and 
    allow complete test coverage.

### Added
- Comprehensive unit tests for `swapBytes32()`, `realHtonl()`, and all
  32-bit edge cases, including simulated big-endian environments.

### Security
- TOB-20 remediation ensures byte-order correctness for PBKDF2, SHA-family
  padding, and any future code paths relying on word-level endian handling.

---

## [1.9.23] - 2025-12-08

### Fixed
- Implemented strict infinity normalization for JacobianPoint, ensuring
  all infinity representations (`null`, `"0"`, or BigNumber(0)) are treated
  canonically and compare equal (TOB-18).
- Gracefully handle encoding of the point at infinity (TOB-19).
  `Point.encode()` now returns the SEC1-compliant `0x00` encoding instead
  of triggering internal assertions when coordinates are null.

### Security
- Addressed TOB-18 and TOB-19: eliminated assertion failures and ensured
  standards-compliant behavior for malformed or edge-case elliptic curve
  point objects.
  
---

### [1.9.22] - 2025-12-04

### Changed

- Removed the export of DRBG from the package.
- Added disclaimer to DRBG documentation.

---

### [1.9.21] - 2025-12-04

### Security

- Implemented strict validation for hex string parsing across the codebase,
  addressing TOB-21.  
  Non-hex characters now cause an immediate error instead of being silently
  discarded, preventing message-forgery scenarios.

### Fixed

- Rewrote the `toArray` and `hexToArray` conversion logic to enforce strict
  hexadecimal input handling rather than permissive filtering.  
- Corrected UTF-8 decoding behavior to ensure invalid byte sequences produce
  a single `U+FFFD` replacement character as specified.  
- Updated all internal hash and array conversion utilities to maintain consistent
  behavior with strong input validation.

---

### [1.9.20] - 2025-12-02

### Security

- Corrected ECDSA nonce range validation to strictly follow the specification.
  The implementation now correctly accepts `k = 1` and `k = n-1` when generating or
  validating nonces, resolving the issue raised in TOB-23.

### Fixed

- Updated both locations in the ECDSA sign function where the incorrect bound
  check was performed, ensuring consistent and standards-compliant behavior.

---

### [1.9.19] - 2025-12-02

### Added

- Added DRBG checks for entropy and nonce length to ensure uniqueness of generated sequences.

### Changed

- Tests for DRBG was fully rewritten and expanded upon.

---

### [1.9.18] - 2025-12-02

### Added

- Added checks for messages that are too long for the hash function.

### Changed

- Changed the Hash class to use BigInt for padding.
- Changed the way padding is calculated for big endian and little endian.

---

### [1.9.17] - 2025-12-01

### Added

- Added bound checking in the toUTF8 function to prevent buffer overflows.

---

### [1.9.16] - 2025-12-01

### Added

- AES unpadding of keys.

---

### [1.9.15] - 2025-12-01

### Added

- AESGCM checks for initialization vector and key length for both encryption and decryption.

---

### [1.9.14] - 2025-12-01

### Added

- Added a standalone secp256r1 (P-256) BigInt implementation with ECDSA signing, verification, and tests.

---

### [1.9.13] - 2025-12-01

### Added

- Changed the toArray function to throw on invalid base64 strings.

---

### [1.9.12] - 2025-12-01

### Added

- Added decryption validation to SymmetricKey.

---

### [1.9.11] - 2025-11-24

### Removed

- Removed dependency on react-native-get-random-values polyfill from Random.ts


---

### [1.9.10] - 2025-11-17

### Added

- Added `Certificate.fromObject` method for creating Certificate instances from plain objects.

---

### [1.9.9] - 2025-11-15

### Fixed

- Ensured `OP_LSHIFT` and `OP_RSHIFT` maintain the original stack element endianness and added regression tests covering the bug.

---

### [1.9.8] - 2025-11-15

### Added

- Added WalletLoggerInterface with change to validationHelpers to inject logging into wallet requests.

---

### [1.9.7] - 2025-11-14

### Added

- Added handling of already spent transactions for the identity client's revoke method.
- Added originator checks for all methods that may try to create a new wallet.

---

### [1.9.6] - 2025-11-13

### Added

- Script interpreter now routes script numbers through bigint-only paths (stack indexing, bit shifts, split/num2bin sizing, and CHECKMULTISIG counters) to avoid JS safe-number limits while keeping checks accurate.

---

### [1.9.5] - 2025-11-13

### Added

- Added support for revoking certificate revelation.

---

### [1.9.3] - 2025-11-11

### Added

- Added `withDoubleSpendRetry` overlay tool to retry broadcast with resolved competing transactions.
- Updated GlobalKVStore to use `withDoubleSpendRetry` in set/remove operations.

---

### [1.9.2] - 2025-11-11

### Fixed

- Fixed bug with RegistryClient definition removal.
- Added support for updating existing registry definitions.

---

### [1.9.1] - 2025-11-10

### Fixed

- Added support for originator param in LocalKVStore wallet calls.

---

### [1.9.0] - 2025-11-09

### Added

- Faster serialization and caching improvements
- Use node- and browser-specific fast-paths opportunistically
- Cache signatures in Spend to avoid repeated verifications
- Cache serialized values and use Uint8Array in more places
- These changes are not intended to be breaking, but a minor version increment is performed out of an abundance of caution

---


### [1.8.13] - 2025-11-06

### Added

- LookupResolver: Support for custom overlay ranking to allow for expedited lookups and reputation tracking.

---

### [1.8.12] - 2025-11-06

### Fixed

- **WalletError**: unknownToJson now using isError and name rather than constructor.name

---

### [1.8.11] - 2025-10-30

### Fixed

- **Transaction**: Default sequence value changed from 0 to 0xffffffff (max sequence) for transaction inputs in serialization and script validation. This aligns with the default set within the preimage calculation. This change ensures that the transaction is marked as final by default, which is the expected behavior for most transactions. addInput had this build in already, this extends that to the constructor approach.

---

### [1.8.10] - 2025-10-28

### Added

- WalletClient argument validation methods to throw WERR_INVALID_PARAMETER errors.
- validationHelpers functions exported under Validation.
- Support for WERR_INVALID_PARAMETER and WERR_INSUFFICIENT_FUNDS errors through HTTPWalletJSON

---

### [1.8.9] - 2025-10-27

### Fixed

- Default fetch binding now works in more environments.

---

### [1.8.8] - 2025-10-22

### Added

- **GlobalKVStore**: Support for tags in set/get operations

---

### [1.8.7] - 2025-10-22

### Fixed

- **Auth**: Peer transport now preserves detailed `SimplifiedFetchTransport` errors instead of replacing them with generic peer send failures.
- Improved error handling when payments are involved

---

### [1.8.5] - 2025-10-21

### Added

- **LookupResolver**: Support compact binary return format

---

### [1.8.4] - 2025-10-20

### Added

- **LookupResolver**: Validate format of all host overrides.

### [1.8.3] - 2025-10-16

### Added

- **Random**: New random number generator that works across all JavaScript environments.

---

### [1.8.2] - 2025-10-03

### Added

- **GlobalKVStore**: Added import for GlobalKVStore.

---

### [1.8.1] - 2025-10-02

### Added

- **GlobalKVStore**: New global key-value storage system using overlay services to track key-value pairs
  - Full CRUD operations: `get()`, `set()`, `remove()` with PushDrop token outputs
  - Flexible query system supporting key, controller, and protocolID parameters
  - Optional history tracking with `Historian` integration for chronological value chains
  - Optional token data inclusion for transaction details and BEEF access
  - Atomic operations with key-based locking for concurrent safety
- **Historian**: Overlay tool for building chronological history by traversing transaction input ancestry and interpreting outputs with provided interpreter functions.

---

### [1.8.0] - 2025-10-02

### Added

- Added `secure-json-api` substrate to allow for HTTPS JSON API communication.

### Changed

- Changed the way in which the substrates attempt to connect to speed up the decision by 20x. Now all substrates are tried in parallel and the first successful one is used. XDM is attempted if all else fails because the delayed caused by absence would otherwise be 200ms.

---


### [1.7.8] - 2025-10-02

### Added

- **LivePolicy fee model**: New dynamic fee model that fetches current rates from ARC GorillaPool API (`https://arc.gorillapool.io/v1/policy`) with intelligent caching and fallback mechanisms


---

### [1.7.7] - 2025-09-19

### Added

- Atomic BEEF bemchmark for long chains
- Performance enhancements when dealing with long BEEF chains

---

### [1.7.6] - 2025-09-09

### Fixed

- Set the originator of AuthFetch within the constructor so it properly uses originator.

---

### [1.7.5] - 2025-09-08

### Fixed

- Plumbed originator through Peer and AuthFetch to pass to WalletInterface calls.
- Updated IdentityClient to support limit on getContacts, and only request locking scripts to increase performance.

---

### [1.7.4] - 2025-09-08

### Fixed

- Use shared lookup resolver to benefit from competent host caching.

---

### [1.7.3] - 2025-09-05

### Fixed

- Fixed bug with LookupResolver default fetch in browser.

---

### [1.7.2] - 2025-09-05

### Changed

- Cache lookup resolver state for faster overlay operations

---

### [1.7.1] - 2025-09-03

### Changed

- Support overriding identity resolution results with personal contacts in IdentityClient.discoverByIdentityKey and IdentityClient.discoverByAttributes

---

### [1.7.0] - 2025-09-03

### Changed

- Use Uint8Array for storage instead of number arrays
- Support chunked hashing for more efficient uploads and downloads of large data

---

### [1.6.26] - 2025-09-02

### Fixed

- Fixed bug with ContactsManager caching system.

---

### [1.6.25] - 2025-09-02

### Added

- IdentityClient now supports saving, getting, and removing encrypted personal contacts.
- SPV verification bugfix

---

### [1.6.24] - 2025-08-19

### Fixed

- Modified Script.writeBin so that when passed an empty array the chunk is correctly written as OP_0 when toASM() is called

---

### [1.6.23] - 2025-08-13

### Change

- ListOutputsArgs offset is now number, negative values sort newest first, newest output is offset -1.

---

### [1.6.22] - 2025-08-06

### Fixed

- TOB-BSV-2: Fix vulnerability in toKeyShares function which allowed for repeated x-coordinates and zeroed x-coordinates which would have lead to privateKey leaks and unrecoverable shares.
- Fix platform specific build errors on Apple Silicon

---

### [1.6.20] - 2025-07-22

### Fixed

- Small ECDSA optimizations
- Proper types for script evaluation errors (useful for programmatic access)
- Clear rspack errors and use latest version

### [1.6.19] - 2025-07-21

### Added

- Improve performance of PBKDF2-SHA512 by 5x
- Improve build performance by 5x with rspack
- ECDSA signature verification speed increased by 50%
- Improve performance for sha256, sha512, sha256hmac, and sha512hmac with native BigInt logic
- Fix remaining lint errors, removing final two files from the ignore-list

---

### [1.6.18] - 2025-07-20

### Added

- More default SLAP trackers (run by BSVA) to ensure redundancy and resiliency.

---

## [1.6.17] - 2025-07-18

### Fixed

- Increase ECDSA performance by 3x by using jacobian coordinates

---

## [1.6.16] - 2025-07-17

### Fixed

- Improved performance of point multiplication by 10x
- Make proper use of CachedKey deriver within ProtoWallet by default.
- Cache shared secret within BKDS

---

## [1.6.15] - 2025-07-17

### Added

- `signal` property to HttpClientRequestOptions for request aborting including timeouts.

### Fixed

- SymmetricKeyCompatibility.test.ts failed to compile with extra toBe argument.

---

## [1.6.14] - 2025-07-17

### Changed

- Default broadcaster changed to Gorilla Pool ARC because they do not enforce an api key.

## [1.6.13] - 2025-07-16

### Added

- Added new guides covering advanced SDK usage patterns
- Added markdown validation system with pre-commit hooks for documentation quality

### Fixed

- Fixed markdown formatting issues for improved Material MkDocs rendering

---

## [1.6.12] - 2025-07-08

### Fixed

- Fixed a bug where the WalletClient decrypt method was not first calling connectToSubstrate.

---

## [1.6.11] - 2025-07-05

### Fixed

- Fixed an edge-case where the originator header wasn't correctly set when in non-browser environments.

## [1.6.10] - 2025-07-02

### Added

- Comprehensive documentation overhaul with new tutorials, guides, and reference materials
- Interactive coding environment integration

### Changed

- Reorganized documentation structure

## [1.6.9] - 2025-07-02

### Fixed

- Fixed an edge-case where the originator header wasn't correctly set when in non-browser environments.

## [1.6.8] - 2025-06-26

### Change

- VarInt read and write methods will now handle negative numbers by writing them as Int64.
- `readVarIntNum` method now takes a signed argument to control whether to read as Int64 or Uint64.

### Added

- OverflowInt64 and OverflowUint64 constants.
- `readInt64LEBn` method to read Int64 values.

---

## [1.6.7] - 2025-06-25

### Change

To LocalKVStore:

- Extend locks to lockQueues and to get and remove operations.

---

## [1.6.6] - 2025-06-25

### Change

To LocalKVStore:

- Make the `set` method update each key value atomically.
- Add acceptDelayedBroadcast constructor argument, default false.

---

## [1.6.5] - 2025-06-21

### Added

- ChainTracker which relies on an instance of [Block Headers Service](https://github.com/bsv-blockchain/block-headers-service).

---

## [1.6.4] - 2025-06-20

### Change

- Export the type for `ScriptChunk` properly.

---

## [1.6.3] - 2025-06-20

### Change

- `SimplifiedFetchTransport`: Added more checks to ensure the connection at the transport layer is correct when sending certificates.

---

## [1.6.2] - 2025-06-18

### Change

- Use `OffChainValues` with TopicBroadcaster from `tx.metadata`
- Handle and return context explicitly in LookupResolver

---

## [1.6.1] - 2025-06-16

### Change

- New types for Private Overlay support

---

## [1.6.0] - 2025-05-29

### Fixed

- Align eval mem limits with current miner policy while stopping memory attacks at 100MB
- Use BigInt in BigNumber for faster performance
- Optimize script interpreter memory usage

## [1.5.3] - 2025-05-29

### Change

- Make verifyValid in Beef class public. It was private.

---

## [1.5.1] - 2025-05-13

### Fixed

- Stop parsing script chunks once we hit an op return out of a conditional block.

---

## [1.5.0] - 2025-05-09

### Added

- ReactNativeWebView substrate, intentionally keeping the JSON stringify simple option for seralization, not using base64 so that we can update JSON HTTP at the same time as ReactNativeWebView. Therefore NOT for production use yet. I'm keen to get this in here so that updating deps within apps will allow us to test many apps from within mobile context in these early days.

---

## [1.4.24] - 2025-05-01

### Added

- A binary body http client and Teranode HTTP broadcaster.

---

## [1.4.22] - 2025-04-27

### Added

- A helper function to create a VerifiableCertificate from a WalletCertificate for ease of use

---

## [1.4.22] - 2025-04-27

### Added

- Max Memory Allocation for script evaluation defaulting to 100 KB for practicality (concensus policy is 100 MB but this would kill a regular browser window for example, so users who want to do things like OP_PUSHTX with a massive ordinal in the input should explicitly set a higher limit as so:

```js
tx.verify('scripts only', new SatoshisPerKilobyte(1), 100000000)
```

Developers are encouraged to have this set to something pretty low if their app is just for P2PKH for example where allocation can be more like 35 bytes. That would prevent malicious actors sending high memory use transactions as an attack on the service.

### Changed

There was some slightly weird patterns in the Spend step method which. It was async, I think unnecessarily. It was also looping beyond the point of script execution failure. Noticable now that it will fail on exceeding the allowed memory allocation.

---

## [1.4.21] - 2025-04-17

### Fixed

- Transaction.test.js: addP2PKHOutput: removed repeated and incomplete test and added extra test to fulfill description

---

## [1.4.20] - 2025-04-23

### Fixed

- Export HTTPWalletJSON substrate.

---

## [1.4.19] - 2025-04-09

### Added

- find, list, and renew functions to the StorageUploader class along with tests for each

---

## [1.4.18] - 2025-04-02

### Changes

- LocalKVStore: Additional testing, passing.

### Added

- WERR_REVIEW_ACTIONS error class and support through HTTPWalletJson

---

## [1.4.17] - 2025-04-01

### Added

- Key value storage implementation

---

## [1.4.16] - 2025-04-01

### Fix

- Updating jest.config.js to remove warning of use of globals

### Security

- Updating dependencies

---

## [1.4.15] - 2025-03-31

### Change

- Simplified AuthFetch error handling to avoid intercepting external errors, improving the developer experience.

---

## [1.4.14] - 2025-03-31

### Change

- Tx fee update to 1 sat per kilobyte as default.

---

## [1.4.13] - 2025-03-30

### Fix

- Exported DRBG from Primitives
- Added Dev Dependencies @types/node and @jest/globals

---

## [1.4.12] - 2025-03-28

### Fix

- Removed registryOperator check from token parseLockingScript helper function.

---

## [1.4.11] - 2025-03-25

### Fix

- Sorts AuthFetch request and response headers by key before serialization to ensure a consistent order for signing and verification.

---

## [1.4.10] - 2025-03-24

### Fix

- Fix signature pre-image mismatch caused by browser-modified content-type header in AuthFetch.

---

## [1.4.9] - 2025-03-18

### Add

- Add action status 'failed' which is the result of abortAction.

---

## [1.4.8] - 2025-03-17

### Fixed

- Fix timeout in SHIP broadcaster

---

## [1.4.7] - 2025-03-17

### Fixed

- Fixed midding headers in StorageUploader
- Added check for expiryTime in StorageDownloader
- Fix timeout in lookup resolver

## [1.4.6] - 2025-03-15

### Fixed

- Fixed a bug in local-only broadcast mode

---

## [1.4.5] - 2025-03-15

### Fixed

- Fixed a bug in local-only broadcast mode

---

## [1.4.4] - 2025-03-15

### Fixed

- Fixed allow HTTP bug in broadcast facilitator

---

## [1.4.3] - 2025-03-14

### Fixed

- Bug fixes and removed ambiguity with the registration process in the RegistryClient.

---

## [1.4.2] - 2025-03-13

### Added

- Implement UHRP Storage Downloader

---

## [1.4.1] - 2025-03-12

### Added

- Implement IdentityClient
- Implement RegistryClient

---

## [1.4.0] - 2025-03-10

### Added

- Implement UHRP Storage Uploader
- Implement UHRP Storage Downloader
- Test coverage WIP

---

## [1.3.36] - 2025-03-7

### Fixed

- AuthFetch waits for pending certificate requests before exchanging data

---

## [1.3.35] - 2025-03-7

### Fixed

- Beef toBinary was missing a sortTxs() call.

---

## [1.3.34] - 2025-03-6

### Added

- Support for the Babbage testnet SLAP tracker
- Support for overlay network presets for mainnet, testnet, or local

---

## [1.3.33] - 2025-03-6

### Fixed

- Add support for privileged certificates in MasterCertificate and VerifiableCertificate classes.

---

## [1.3.32] - 2025-03-6

### Fixed

- Removed ambiguity with the keyID used in master and verifiable certificate field encryption.

---

## [1.3.31] - 2025-03-6

### Fixed

- Beef verify now checks that BUMPs contain required txids.

---

## [1.3.30] - 2025-03-5

### Fixed

- Re-handshake in AuthFetch if a server forgets about a session that the client maintained

---

## [1.3.29] - 2025-03-5

### Added

- Concurrent session management for the same peer across devices

---

## [1.3.28] - 2025-02-28

### Fixed

- Persisted payee derivation information in AuthFetch
- Use the first output index for AuthFetch payments

---

## [1.3.27] - 2025-02-28

### Fixed

- Added defaults for undefined AuthFetch request body (specifically for content-type of application/json).
- This prevents signature verification errors due to express defaults for requests with undefined body.

---

## [1.3.26] - 2025-02-28

### Fixed

- Fixed a bug with AuthFetch where when responding to error 402, the derivationSuffix was not sent to the server.
- Updated used createNonce for the derivationSuffix creation to link it to the sender.

---

## [1.3.25] - 2025-02-27

### Fixed

- Previously, the function split each character’s 16-bit code unit into two bytes (if the high byte was non-zero), which only worked for ASCII and failed on non-ASCII/multi-byte characters. Now emojis can be encoded correctly!

---

## [1.3.24] - 2025-02-22

### Added

- Originator support to PushDrop template

---

## [1.3.23] - 2025-02-21

### Fixed

- Fixed a bug with SHIPCast's default configuration.

---

## [1.3.22] - 2025-02-19

### Fixed

- Fixed a bug with how the HTTPWalletJSON response was parsed to check for errors.

---

## [1.3.21] - 2025-02-17

### Fixed

- Update type returned in Hash.SHA512._digestHex method so that it doesn't fail tsc builds.

---

## [1.3.20] - 2025-02-17

### Fixed

- ATOMIC BEEF should use little endian encoding of the txid, rather than big endian.

---

## [1.3.19] - 2025-02-16

### Change

- Make URL, httpClient, getHttpHeaders protected instead of private to support extending WhatsOnChain class.

---

## [1.3.18] - 2025-02-12

### Fixed

- Avoid collapsing doc details. Not supported by github pages.

---

## [1.3.17] - 2025-02-11

### Fixed

- Added error handling to HTTPWalletJSON

---

## [1.3.15] - 2025-02-07

### Fixed

- Hot fix for SimplifiedFetchTransport due to a bug introduced with linting fixes.

---

## [1.3.14] - 2025-02-07

### Changed

- Fixed build issue, and conformed to ts-standard

---

## [1.3.12] - 2025-01-29

### Changed

- Modified ProtoWallet to make the KeyDeriver optional, and to allow an optional originator argument on each supported method.
- This allows any Wallet that implements WalletInterface to be a ProtoWallet.

---

## [1.3.11] - 2025-01-28

### Changed

- Refactored certificate classes and helper functions based on usage requirements in the new acquireCertificate method via the issuance path.
- Changed certain MasterCertificate methods to static functions for use-cases where an instantiated class isn't convenient.

---

## [1.3.10] - 2025-01-27

### Changed

- Create and Verify Nonce utility functions now support optional counterparty param.
- This enables the verification of nonces created by a counterparty.

---

### Changed

- Export `WalletInterface` and `ProtoWallet` but not `Wallet`
- ProtoWallet does not deal with privilege or originators

---

## [1.3.8] - 2025-01-20

### Fixed

- Fixed the double export of Beef class as named and default which was messing up the constructor somehow. Now it's a named export and that means the BEEF_V1 and V2 constants are also available as exported values.

---

## [1.3.7] - 2025-01-18

### Fixed

- Fixed the double export of Beef class as named and default which was messing up the constructor somehow. Now it's a named export and that means the BEEF_V1 and V2 constants are also available as exported values.

---

## [1.3.6] - 2025-01-17

### Added

- Consolidated certificate functionality
- Added certificate tests

---

## [1.3.4] - 2025-01-17

### Changed

Changes to cleanup and normalize types in Wallet.interfaces.ts and dependent files.

- Wallet.interfaces.ts

- KeyDeriver.ts
- CachedKeyDeriver.ts
- ProtoWallet.ts

- WalletClient.ts
- HttpWalletJSON.ts
- WalletWireTranceiver.ts
- XDM.ts
- window.CWI.ts
  
### Added

- WalletCrypto.ts: Pulled out of ProtoWallet for reuse as a base class.

---

## [1.3.3] - 2025-01-13

### Changed

- Removed unnecessary length byte of signatures in the encoding of a Certificate in Binary.

---

## [1.3.2] - 2025-01-13

### Added

- Support for last session persistence in Peer

## [1.3.1] - 2025-01-13

### Fixed

- Updated the Auth SimplifiedFetchTransport to bind window.fetch in a browser context.

---

## [1.3.0] - 2025-01-11

### Changed

- Minor Version release (should have been done at 1.2.21 due to Mutual Authentication Scope increase)
- Renamed toBin => toBinary and fromBin => fromBinary so that the methods match other classes.

---

## [1.2.22] - 2025-01-06

### Fixed

- #158
- Export certificate helpers

---

## [1.2.21] - 2025-01-03

### Added

- Implemented a Mutual Authentication and Service Monetization Framework

---

## [1.2.19] - 2024-12-19

### Added

- new method on the interface for ChainTrackers which returns the current height of the blockchain.
- Implemented a Coinbase specific MerklePath .verify conditional block which ensures the input is spendable if it's a coinbase output.

---

## [1.2.18] - 2024-12-19

### Added

- Enumerated constants for the tx data type in beef encoded transaction lists.

### Removed

- Removed the idea of "V1" and "V2" beef. There is already a version number which is encoded in the bytes, I think it's clearer if we stick to one.
- Removed the V1 capability to use txidOnly.

### Fixed

- There was a slice of the BeefTxs array in Beef which should be a splice (remove a tx)

### Changed

- Refactored a bunch of functions on advice from Sonar Qube which suggested they were a little to dense for most people to follow.
- Refactored for loops into for-of loops where possible.
- Refactored loops where the loop counter is updated within the loop which is advised against.

---

## [1.2.17] - 2024-12-18

### Added

Beef addComputedLeaves
MerklePath.fromReader and MerklePath constructor legalOffsetsOnly optional argument

### Fixed

Beef toBinaryAtomic now prunes transactions newer than target txid.
Beef mergeBeefTx error if both isTxidOnly
Bug [#162](https://github.com/bsv-blockchain/ts-sdk/issues/162)

---

## [1.2.15] - 2024-12-16

### Added

- A helper function for most commonly used output type. `tx.addP2PKHOutput(address, satoshis)`
- Make sure to check the provided hash is 20 bytes.

---

## [1.2.14] - 2024-12-14

### Added

- fromCoinbaseTxidAndHeight method to the MerklePath class for that special case
- added test demonstrating how to validate scripts only for one tx even when you don't have a merkle path for the previous tx.

  ```js
  // merklePath just has to be set to any object.
  sourceTransaction.merklePath = { assumeValid: true }
  tx.inputs[0].sourceTransaction = sourceTransaction
  await tx.verify('scripts only')
  ```

---

## [1.2.13] - 2024-12-13

### Added

- JSON HTTP substrate, with corresponding swagger-ui documentation.
- Example args and responses to the swagger-ui

### Added

- PrivateKey test linter errors

---

## [1.2.12] - 2024-12-12

### Added

- Added optional broadcastMany to Broadcaster interface.

## [1.2.11] - 2024-12-10

### Added

- Added a fix to ensure PrivateKeys as hex are always 64 chars in length ensuring 256 bit keys.

## [1.2.10] - 2024-12-10

### Added

Beef makeTxidOnly

### Fixed

Beef sortTx fix for partially valid and txidOnly data.

### Security

---

## [1.2.9] - 2024-12-06

### Added

- Added support for returning coinsRemoved in an overlay Submitted Transaction Execution AcKnowledgment (STEAK) message.

---

## [1.2.8] - 2024-12-02

### Added

- Stop people inadvertently creating corrupted public keys.

---

## [1.2.7] - 2024-12-02

### Added

- Define the security level of protocolIDs as a type so that we can attach a JSDoc explaining what each value means.

### Added

- Use a default value in the async fee() function when no args are used rather than requiring a value and then setting if undefined.

---

## [1.2.6] - 2024-11-30

### Added

- revealSpecificKeyLinkage requires a counterparty.
- ProtoWallet now correctly implements the wallet interface.

---

## [1.2.5] - 2024-11-30

### Added

- Testnet capabilities & config override for node to function without error to defaultBroadcaster
- broadcastMany function to ARCBroadcaster

---

## [1.2.4] - 2024-11-29

### Added

- A "random" distributioun mode for change allocation which approximates Benford's Law in attempt to distribute the remainder of: (inputSats - knownOutputSats - txFee) across the outputs marked "change: true".

---

## [1.2.3] - 2024-11-26

### Added

- Added support for Overlay broadcast and lookup timeouts.

---

## [1.2.2] - 2024-11-26

### Added

- Updated the default ShipBroadcast config, tests, and docs.

---

## [1.2.1] - 2024-11-25

### Added

- [NPM package provenance](https://github.blog/security/supply-chain-security/introducing-npm-package-provenance/) support

---

## [1.2.0] - 2024-11-25

### Added

- Implement BRC-100 wallet interface
- Add PushDrop token template
- SHIP and SLAP overlay tooling including broadcaster and lookup

---

## [1.1.33] - 2024-11-22

### Added

Beef.toBinaryAtomic(txid: string) to serialize Beef with AtomicBEEF header.

### Fixed

Transaction.fromAtomicBEEF

1. Test for all required dependencies was ignoring BUMP hashes.
2. Test for unused transactions required additional fix.

---

## [1.1.32] - 2024-11-22

### Added

1. allowPartial optional argument to Transaction toBEEF and toAtomicBEEF to avoid errors on missing sourceTransactions.
2. findBump, findTransactionForSigning, findAtomicTransaction to Beef class.
3. mergeBeefFromParty to BeefParty
4. isValid to BeefTx, used by new sortTx.
5. Add serialized AtomicBEEF deserialization to Beef class.
6. Add atomicTxid property to Beef class.

### Fixed

1. sortTxs of Beef class fixed to handle incompletely valid data, order now matches spec for isValid true BEEF.

### Removed

1. degree property from BeefTx class, was used only by original sortTxs algorithm.

---

## [1.1.30] - 2024-11-02

### Added

- Feature - Schorr class which allows ZKP creation and verification. BRC-94 and BRC-100 related.

### Changed

- electrumEncrypt correctly allows fromPrivateKey to be omitted

## [1.1.29] - 2024-10-23

### Fixed

- ECIES ElectrumDecrypt counterparty decryption bug

## [1.1.28] - 2024-10-23

### Added

- UMD support added for use in non-standard environments.

## [1.1.26] - 2024-10-22

### Added

- Atomic BEEF serializer and deserializer for `Transaction` class
- Ability to select a TXID from a BEEF when construction a `Transaction.fromBEEF()`

## [1.1.25] - 2024-10-21

### Added

- `Beef`, `BeefTx`, and `BeefParty` classes

## [1.1.24] - 2024-10-04

### Fixed

- Addressed #125
- Optimized SPV verification

## [1.1.22] - 2024-09-02

### Added

- Base64 mode support for BSM

## [1.1.21] - 2024-09-02

### Added

- Broadcaster types have been updated to better align with Arc
- Added some convenience functions for toDER and fromDER on the point and pubkey classes where missing.

### Changed

- In the PublicKey class pubkey.toDER() to defaults to return a number[] rather than string. If a string is desired .toString() or .toDER('hex') have equivalent functionality.

## [1.1.17] - 2024-08-21

### Added

Transaction static fromReader method is now public.

## [1.1.14] - 2024-07-30

### Added

Ability to split a private key into shares using Shamir's Secret Sharing Scheme. Use like this:

```javascript
const key = PrivateKey.fromRandom()
const recovery = key.split(2, 5)
const sameKey = PrivateKey.fromShares(recovery.shares, recovery.threshold)
```

## [1.1.13] - 2024-07-19

### Fixed

Transaction SPV verification now correctly returns true for "scripts only" verification when a merkle proof is found.

## [1.1.10] - 2024-06-28

### Fixed

ARC Broadcaster correctly parses status -> code, details -> description. Adds optional txid and more to error response if provided.

## [1.1.8] - 2024-06-19

### Added

TOTP class which allows the generation of time based pass codes. Use varies but originally included for validating shared secrets between remote counterparties over a secure channel.

## [1.1.6] - 2024-06-12

### Added

- Allow Fees in historic transaction to be validated against a FeeModel.

## [1.1.5] - 2024-06-11

### Fixed

- Unnecessary `Buffer.from` in pbkdf2 function has been removed.

## [1.1.4] - 2024-05-10

### Added

- MerklePath trim function which removes data if it can be calculated. Backported from go-sdk by tonesnotes. Only affects compound Merkle paths which are not yet widely used.

### Changed

- The corresponding error messages associated with invalid MerklePaths which no longer check empty levels if they are above level 0.

## [1.1.0] - 2024-05-06

### Added

- Ability to create TransactionInputs from a utxo, creating a partial sourceTransaction.
Use is like so:

```javascript
const input = fromUtxo({
    txid: '434555433eaca96dff6e71a4d02febd0dd3832e5ca4e5734623ca914522e17d5',
    vout: 0,
    script: '76a914d01b0b702ee90e00944342f97c772a8be83e42a288ac',
    satoshis: 1234
}, new P2PKH().unlock(key))

tx.addInput(input)
```

- Ability to create a transaction from Extended Format bytes or hex. The result being a partial sourceTransaction in each input.

```javascript
const tx = Transaction.fromHexEF('020000000000000000ef01b2faffe1e1d3c88f4092f34646c060ea2b6a93acc3010484c747ed4c051c2555080000006a4730440220392bcec91f190ce38db9bf53d03886ab63d9bd24fcf7174e8a8df21d23382ba7022038f20c1f3f6583951d01af0be30612a6c0b46d949b4aae60f42644ce513f3e55412103ea0ff49ec6fbb9cbc942d9c1fce9c04e12a91c1209b239466e0a29147da55db1ffffffff01f45500000000001976a914de337957f543c8d1fad2cfff0b57bb5b4264d91788ac0390010000000000001976a9144d255baa50a14bef4cce1eb8012a02768e8ffaa888acd3600000000000001976a91447e22d8011bb446cc3f606179e333f64a9b6206b88ac04915500000000001976a914d24cb016397008a85c88b1278a36434fdd4e801f88ac00000000')
```

### Removed

- Use of sourceSatoshis as a parameter of TransactionInput type.

### Fixed

- Increase default maxNumSize to MAX_SAFE_INJTEGER to resolve OP_BIN2NUM execution failures. by @tonesnotes in <https://github.com/bsv-blockchain/ts-sdk/pull/20>
- Docs examples by @ty-everett in <https://github.com/bsv-blockchain/ts-sdk/pull/21>
- Allow BigNumber constructor to accept a BigNumber. by @tonesnotes in <https://github.com/bsv-blockchain/ts-sdk/pull/22>
- Hash enc digest hex by @tonesnotes in <https://github.com/bsv-blockchain/ts-sdk/pull/27>
- [feature] helper function to allow Address => Locking Script by @sirdeggen in <https://github.com/bsv-blockchain/ts-sdk/pull/24>
- [chore] npm run doc by @sirdeggen in <https://github.com/bsv-blockchain/ts-sdk/pull/26>
- CRITICAL FIX for BigNumber fromSm by @tonesnotes in <https://github.com/bsv-blockchain/ts-sdk/pull/30>
- [feature]: Block Header Service api by @sirdeggen in <https://github.com/bsv-blockchain/ts-sdk/pull/23>
- Tone bug 31 by @tonesnotes in <https://github.com/bsv-blockchain/ts-sdk/pull/33>
- Low Level Docs by @ty-everett in <https://github.com/bsv-blockchain/ts-sdk/pull/32>
- push(...x) fails for large array x values by @tonesnotes in <https://github.com/bsv-blockchain/ts-sdk/pull/36>
- [fix] length must be that of the data, not the original argument. by @sirdeggen in <https://github.com/bsv-blockchain/ts-sdk/pull/37>
- [chore] ts-standard and linter stuff by @sirdeggen in <https://github.com/bsv-blockchain/ts-sdk/pull/38>
- [feature] compact sigs by @sirdeggen in <https://github.com/bsv-blockchain/ts-sdk/pull/39>
- controversial stuff by @sirdeggen in <https://github.com/bsv-blockchain/ts-sdk/pull/40>
- Avoid requiring sourceTransaction on inputs. by @tonesnotes in <https://github.com/bsv-blockchain/ts-sdk/pull/41>
- [fix] Enforce signature length in compact sigs by @sirdeggen in <https://github.com/bsv-blockchain/ts-sdk/pull/44>
- Concept-level documentation by @ty-everett in <https://github.com/bsv-blockchain/ts-sdk/pull/45>
- refactor: add more static factory methods to HD class and use them in examples by @dorzepowski in <https://github.com/bsv-blockchain/ts-sdk/pull/48>
- refactor: replace returned type union with method overloading for transaction id. by @dorzepowski in <https://github.com/bsv-blockchain/ts-sdk/pull/50>
- [docs] HOW_TX.md review and edits. Note: A topic worth discussing is c… by @jonesjBSV in <https://github.com/bsv-blockchain/ts-sdk/pull/53>
- [chore] remove redundant line by @sirdeggen in <https://github.com/bsv-blockchain/ts-sdk/pull/56>
- I suspect it should be this - see ts-paymail for more suggestions by @sirdeggen in <https://github.com/bsv-blockchain/ts-sdk/pull/60>
- [fix] adding startsWith OP_ seems to fix the ASM parsing bug by @sirdeggen in <https://github.com/bsv-blockchain/ts-sdk/pull/58>
- Add Transaction.parseScriptOffsets by @tonesnotes in <https://github.com/bsv-blockchain/ts-sdk/pull/59>
- [fix] Compact SIgnatures Pubkey Recovery function precision. by @sirdeggen in <https://github.com/bsv-blockchain/ts-sdk/pull/63>
- feat(#65): configure ARC with custom http client by @dorzepowski in <https://github.com/bsv-blockchain/ts-sdk/pull/66>
- feat: default broadcaster and chain tracker by @dorzepowski in <https://github.com/bsv-blockchain/ts-sdk/pull/67>
- Fixed fee model by @tiagolr in <https://github.com/bsv-blockchain/ts-sdk/pull/70>
- toAddress() string prefix support by @tiagolr in <https://github.com/bsv-blockchain/ts-sdk/pull/72>
- Addional input field sourceSatoshis to be used in fee calculation by @tiagolr in <https://github.com/bsv-blockchain/ts-sdk/pull/71>
- Tone key length by @tonesnotes in <https://github.com/bsv-blockchain/ts-sdk/pull/79>
- Improve JSON content type detection by @oskarszoon in <https://github.com/bsv-blockchain/ts-sdk/pull/80>
- example-utxos-tx.md by @tiagolr in <https://github.com/bsv-blockchain/ts-sdk/pull/75>
- Allow ARC config to set CallbackURL and other headers as required by @sirdeggen in <https://github.com/bsv-blockchain/ts-sdk/pull/81>
- Tone overlay1 by @tonesnotes in <https://github.com/bsv-blockchain/ts-sdk/pull/82>

### New Contributors

- @tonesnotes made their first contribution in <https://github.com/bsv-blockchain/ts-sdk/pull/20>
- @dorzepowski made their first contribution in <https://github.com/bsv-blockchain/ts-sdk/pull/48>
- @jonesjBSV made their first contribution in <https://github.com/bsv-blockchain/ts-sdk/pull/53>
- @tiagolr made their first contribution in <https://github.com/bsv-blockchain/ts-sdk/pull/70>
- @oskarszoon made their first contribution in <https://github.com/bsv-blockchain/ts-sdk/pull/80>

## [1.0.0] - 2024-02-10

### Added

- Initial release of the BSV Blockchain Libraries Project SDK.
- Sound Cryptographic Primitives for key management, signature computations, and encryption protocols.
- Script Level Constructs with network-compliant script interpreter.
- Comprehensive Transaction Construction and Signing API.
- Mechanisms for Transaction Broadcast Management.
- Tools for Merkle Proof Verification and representation.
- Structures and interfaces for full Serializable SPV Structures.
- Enhanced mechanisms for Secure Encryption and Signed Messages.

---

### Template for New Releases

Replace `X.X.X` with the new version number and `YYYY-MM-DD` with the release date:

```
## [X.X.X] - YYYY-MM-DD

### Added
- 

### Changed
- 

### Deprecated
- 

### Removed
- 

### Fixed
- 

### Security
- 
```

Use this template as the starting point for each new version. Always update the "Unreleased" section with changes as they're implemented, and then move them under the new version header when that version is released.
