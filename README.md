# BSV SDK

[![codecov](https://codecov.io/gh/bsv-blockchain/ts-sdk/branch/master/graph/badge.svg)](https://codecov.io/gh/bsv-blockchain/ts-sdk)
[![npm version](https://badge.fury.io/js/@bsv%2Fsdk.svg)](https://badge.fury.io/js/@bsv%2Fsdk)
[![Build Status](https://github.com/bsv-blockchain/ts-sdk/actions/workflows/push.yaml/badge.svg)](https://github.com/bsv-blockchain/ts-sdk/actions/workflows/push.yaml)

BSV BLOCKCHAIN | Software Development Kit for JavaScript and TypeScript

Welcome to the BSV Blockchain Libraries Project, the comprehensive TypeScript SDK designed to provide an updated and unified layer for developing scalable applications on the BSV Blockchain. This SDK addresses the limitations of previous tools by offering a fresh, peer-to-peer approach, adhering to SPV, and ensuring privacy and scalability.

For application-to-wallet integrations, the SDK exposes the BRC-100 `WalletClient` interface. BSV Desktop and BSV Browser are the BSV Association reference implementations for this interface; vendor distributions such as Babbage's Metanet Desktop / Metanet Explorer and Hudos Browser can implement the same interface with their own branding and service defaults.

## Table of Contents

1. [Objective](#objective)
2. [Getting Started](#getting-started)
3. [Features & Deliverables](#features--deliverables)
4. [Documentation](#documentation)
5. [Contribution Guidelines](#contribution-guidelines)
6. [Support & Contacts](#support--contacts)

## Objective

The BSV Blockchain Libraries Project aims to structure and maintain a middleware layer of the BSV Blockchain technology stack. By facilitating the development and maintenance of core libraries, it serves as an essential toolkit for developers looking to build on the BSV Blockchain.

## Getting Started

### Installation

To install the SDK, run:

```bash
npm install @bsv/sdk
```

### Basic Usage

Here's a simple example of using the SDK to create and sign a transaction:

```javascript
import { PrivateKey, P2PKH, Transaction, ARC } from '@bsv/sdk'

const privKey = PrivateKey.fromWif('L5EY1SbTvvPNSdCYQe1EJHfXCBBT4PmnF6CDbzCm9iifZptUvDGB')

const sourceTransaction = Transaction.fromHex('0200000001849c6419aec8b65d747cb72282cc02f3fc26dd018b46962f5de48957fac50528020000006a473044022008a60c611f3b48eaf0d07b5425d75f6ce65c3730bd43e6208560648081f9661b0220278fa51877100054d0d08e38e069b0afdb4f0f9d38844c68ee2233ace8e0de2141210360cd30f72e805be1f00d53f9ccd47dfd249cbb65b0d4aee5cfaf005a5258be37ffffffff03d0070000000000001976a914acc4d7c37bc9d0be0a4987483058a2d842f2265d88ac75330100000000001976a914db5b7964eecb19fcab929bf6bd29297ec005d52988ac809f7c09000000001976a914c0b0a42e92f062bdbc6a881b1777eed1213c19eb88ac00000000')

const version = 1
const input = {
  sourceTransaction,
  sourceOutputIndex: 0,
  unlockingScriptTemplate: new P2PKH().unlock(privKey),
}
const output = {
  lockingScript: new P2PKH().lock(privKey.toAddress()),
  change: true
}

const tx = new Transaction(version, [input], [output])
await tx.fee()
await tx.sign()

await tx.broadcast()
```

For a more detailed tutorial and advanced examples, check our [Documentation](#documentation).

## Features & Deliverables

- **Sound Cryptographic Primitives**: Secure key management, signature computations, and encryption protocols.

- **Script Level Constructs**: Network-compliant script interpreter with support for custom scripts and serialization formats.

- **Transaction Construction and Signing**: Comprehensive transaction builder API, ensuring versatile and secure transaction creation.

- **Transaction Broadcast Management**: Mechanisms to send transactions to both miners and overlays, ensuring extensibility and future-proofing.

- **Merkle Proof Verification**: Tools for representing and verifying merkle proofs, adhering to various serialization standards.

- **Serializable SPV Structures**: Structures and interfaces for full SPV verification.

- **Secure Encryption and Signed Messages**: Enhanced mechanisms for encryption and digital signatures, replacing outdated methods.

- **P2P Authentication**: Robust peer-to-peer authentication mechanisms to ensure secure connections between parties.

- **Identity**: Comprehensive identity management system supporting identity verification and certificate management.

- **Key Value Store**: Distributed key-value store for decentralized data storage and retrieval.

- **Distributed Storage**: Scalable and secure distributed data storage solutions to support blockchain applications.

- **Wallet Interface**: Standardized interface for wallet operations, supporting multiple cryptocurrencies and protocols.

- **Overlay Tools**: Advanced tools for overlay network management and optimization.

- **Distributed Protocol and Certificate Registration**: Efficient systems for registering and managing distributed protocols and certificates.

## Documentation

Comprehensive documentation is available in several formats:

- **[📚 Online Documentation](https://bsv-blockchain.github.io/ts-sdk)**: Our complete documentation:
    - **[🚀 Tutorials](https://bsv-blockchain.github.io/ts-sdk/tutorials/)**: Step-by-step lessons to learn by doing
    - **[🔧 How-To Guides](https://bsv-blockchain.github.io/ts-sdk/guides/)**: Practical solutions to specific problems
    - **[📚 Reference](https://bsv-blockchain.github.io/ts-sdk/reference/)**: Complete technical specifications and API documentation
    - **[🏗️ Concepts](https://bsv-blockchain.github.io/ts-sdk/concepts/)**: Architecture and design explanations
- **[⚡ Examples](https://docs.bsvblockchain.org/guides/sdks/ts/examples)**: Practical code examples
- **Code Annotations**: The SDK is richly documented with code-level annotations that show up in editors like VSCode

## Contribution Guidelines

We're always looking for contributors to help us improve the SDK. Whether it's bug reports, feature requests, or pull requests - all contributions are welcome.

1. **Fork & Clone**: Fork this repository and clone it to your local machine.
2. **Set Up**: Run `npm install` to install all dependencies.
3. **Make Changes**: Create a new branch and make your changes.
4. **Test**: Ensure all tests pass by running `npm test`.
5. **Commit**: Commit your changes and push to your fork.
6. **Pull Request**: Open a pull request from your fork to this repository.
For more details, check the [contribution guidelines](./CONTRIBUTING.md).

For information on past releases, check out the [changelog](./CHANGELOG.md). For future plans, check the [roadmap](./ROADMAP.md)!

## Support & Contacts

Project Owners: Thomas Giacomo and Darren Kellenschwiler

Development Team Lead: Ty Everett

For questions, bug reports, or feature requests, please open an issue on GitHub or contact us directly.

## License

The license for the code in this repository is the Open BSV License. Refer to [LICENSE.txt](./LICENSE.txt) for the license text.

Thank you for being a part of the BSV Blockchain Libraries Project. Let's build the future of BSV Blockchain together!
