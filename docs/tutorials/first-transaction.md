# Your First BSV Transaction

**Duration**: 15 minutes  
**Prerequisites**: Node.js, basic TypeScript knowledge  

## Learning Goals
- Install and configure the BSV TypeScript SDK
- Create a simple transaction using `WalletClient` interface on the mainnet network. This approach makes it easy to build transactions by abstracting away many of the low-level details. By the end, you'll understand the basic components of a BSV transaction and how to construct, sign, and broadcast one on the BSV blockchain.

> **📚 Related Concepts**: Before starting, you may want to review [Transaction Structure](../concepts/transaction-structure.md) and [Wallet Integration](../concepts/wallet-integration.md) to understand the fundamentals.

## Introduction

In this tutorial, you'll learn how to create your first Bitcoin SV transactions using the TypeScript SDK's `WalletClient` interface on the mainnet network. This approach makes it easy to build transactions by abstracting away many of the low-level details. By the end, you'll understand the basic components of a BSV transaction and how to construct, sign, and broadcast one on the BSV blockchain.

> **💡 Try It Interactive**: Want to experiment with the code examples from this tutorial? Check out our [Interactive BSV Coding Environment](https://fast.brc.dev/) where you can run SDK code directly in your browser without any setup!

## Precondition 

Install a BRC-100 compliant wallet such as the [Metanet Desktop Wallet](https://Metanet.bsvb.tech/). When you install it, you'll receive a small amount of funds to play with.

## Step 1: Setting Up Your Environment

First, create a new Node.js project and install the BSV SDK:

```bash
# Create a new directory for your project
mkdir my-first-bsv-tx
cd my-first-bsv-tx

# Initialize a new Node.js project
npm init -y

# Install TypeScript and ts-node (TypeScript execution engine)
npm install typescript ts-node @types/node --save-dev
# ts-node allows you to run TypeScript files directly without compiling them first

# Install the BSV SDK
npm install @bsv/sdk
```

Create a basic TypeScript configuration file (`tsconfig.json`):

```json
{
  "compilerOptions": {
    "target": "es2020",
    "module": "commonjs",
    "esModuleInterop": true,
    "strict": true,
    "outDir": "./dist"
  }
}
```

## Step 2: Understanding Transaction Components

Before we write any code, let's understand the basic components of a Bitcoin transaction:

- **Inputs**: References to previous transaction outputs that you're spending
- **Outputs**: New UTXOs (Unspent Transaction Outputs) that define who receives the bitcoins
- **Locking Scripts**: Scripts that determine the conditions for spending outputs
- **Unlocking Scripts**: Scripts that satisfy the conditions in locking scripts

### Additional Resources

For a deeper understanding of Bitcoin transactions, check out these resources:

- [Bitcoin SV Protocol Specifications](https://github.com/bitcoin-sv-specs/protocol) - Official Bitcoin SV protocol specifications
- [WhatsOnChain Explorer](https://whatsonchain.com/) - Standard block explorer for viewing BSV transactions
- [Bitcoin Developer Reference](https://developer.bitcoin.org/reference/transactions.html) - Comprehensive explanation of transaction structure

## Step 3: Your First Transactions - 3 Simple Steps

Now let's create your first BSV transactions using three clean, focused steps. Each step builds on the previous one, showing you the core workflow of BSV development.

We'll create three separate files to keep things organized and clear:

### Example 1: Create a Simple Transaction

**What you'll do**: Create your first transaction that stores a simple message on the BSV blockchain. This introduces you to the basic `createAction()` method and shows how data can be permanently stored on-chain.

Create a file called `step1-simple-transaction.ts`:

```typescript
import { WalletClient, Script } from '@bsv/sdk'

async function createSimpleTransaction() {
  // Connect to user's wallet
  const wallet = new WalletClient('auto', 'localhost')
  
  // Create a simple transaction with a data output
  const response = await wallet.createAction({
    description: 'My first BSV transaction',
    outputs: [{
      satoshis: 100,
      lockingScript: Script.fromASM(`OP_RETURN ${Buffer.from('Hello BSV!').toString('hex')}`).toHex(),
      outputDescription: 'My first data output'
    }]
  })
  
  console.log('Transaction created:', response)
  if (response.txid) {
    console.log(`View on WhatsOnChain: https://whatsonchain.com/tx/${response.txid}`)
  }
  
  return response
}

// Run the function
createSimpleTransaction().catch(console.error)
```

Run it as follows:

```bash
# Run the TypeScript file directly
npx ts-node step1-simple-transaction.ts
```


**What's happening here:**
- We connect to your BRC-100 wallet (like Metanet Desktop)
- Create a transaction with one output containing "Hello BSV!" data
- The wallet automatically handles inputs, change, and fees
- We get a transaction ID to view on the blockchain explorer

### Example 2: Create and Store a Token

**What you'll do**: Create a spendable token and organize it using wallet baskets. This shows you how to create UTXOs that can be spent later and how to use the wallet's organizational features.

Create a file called `step2-create-token.ts`:

```typescript
import { WalletClient, Script } from '@bsv/sdk'

async function createToken() {
  // Connect to user's wallet
  const wallet = new WalletClient('auto', 'localhost')
  
  // Create a token and store it in a specific basket
  const response = await wallet.createAction({
    description: 'Create my first token',
    outputs: [{
      satoshis: 1,
      lockingScript: Script.fromASM('OP_NOP').toHex(),
      basket: 'my-tokens',
      outputDescription: 'My first token'
    }]
  })
  
  console.log('Token created:', response)
  if (response.txid) {
    console.log(`Token transaction: https://whatsonchain.com/tx/${response.txid}`)
  }
  
  return response
}

// Run the function
createToken().catch(console.error)
```


Run it as follows:

```bash
# Run the TypeScript file directly
npx ts-node step2-create-token.ts
```


**What's happening here:**
- We create a minimal token (1 satoshi with OP_NOP script)
- Store it in a wallet basket called 'my-tokens' for organization
- This creates a spendable output we can use later

### Example 3: List and Spend Your Token

**What you'll do**: Retrieve your stored token (created in the previous example) and spend it in a new transaction. This demonstrates the complete UTXO lifecycle and shows how to work with transaction inputs using the BEEF format.

Create a file called `step3-spend-token.ts`:

```typescript
import { WalletClient, Script } from '@bsv/sdk'

async function spendToken() {
  // Connect to user's wallet
  const wallet = new WalletClient('auto', 'localhost')
  
  // First, list our tokens
  const tokenList = await wallet.listOutputs({
    basket: 'my-tokens',
    include: 'entire transactions'
  })
  
  console.log('Available tokens:', tokenList.outputs.length)
  
  let response;
  if (tokenList.outputs.length > 0) {
    // Spend the first token
    response = await wallet.createAction({
      description: 'Spend my first token',
      inputBEEF: tokenList.BEEF,
      inputs: [{
        outpoint: tokenList.outputs[0].outpoint,
        unlockingScript: Script.fromASM('OP_TRUE').toHex(),
        inputDescription: 'My token being spent'
      }]
    })
    
    console.log('Token spent:', response)
    if (response.txid) {
      console.log(`Spending transaction: https://whatsonchain.com/tx/${response.txid}`)
    }
  } else {
    console.log('No tokens available to spend. Run step2-create-token.ts first!')
    response = null;
  }
  
  return response
}

// Run the function
spendToken().catch(console.error)
```


Run it as follows:

```bash
# Run the TypeScript file directly
npx ts-node step3-spend-token.ts
```


**What's happening here:**
- We list tokens from our 'my-tokens' basket
- Spend the first available token by providing its outpoint
- Create a new output with proof that we spent the token
- The BEEF (Blockchain Exchange Format) provides the transaction history



## What You've Learned

Congratulations! You've successfully created your first BSV transactions. Here's what you accomplished:

### Core Concepts Mastered

1. **WalletClient Usage**: Connected to your BRC-100 wallet and created transactions
2. **Script Construction**: Used `Script.fromASM()` to create clean, readable Bitcoin scripts
3. **Transaction Outputs**: Created both data storage and spendable token outputs
4. **Wallet Baskets**: Organized your tokens using the basket system
5. **UTXO Management**: Listed and spent existing outputs using BEEF format

### Key WalletClient Methods

- `createAction()`: Creates transactions with specified outputs and inputs
- `listOutputs()`: Retrieves spendable outputs from wallet baskets
- The wallet automatically handles signing, fees, and broadcasting

### Script Types You Used

- `OP_RETURN "data"`: Store arbitrary data on the blockchain
- `OP_NOP`: Create simple tokens that can be spent later  
- `OP_TRUE`: Unlock scripts that always validate (for simple spending)

## Next Steps

- Learn about [Key Management and Cryptography](./key-management.md)
- Prefer lower-level control? Check out [First Transaction (Low-level API)](./first-transaction-low-level.md)

## Additional Resources

- [Wallet API Reference](../reference/wallet.md)
- [BSV Wallet Protocols](https://projectbabbage.com/docs/guides/wallet/transactions)
- [Transaction Broadcasting](https://projectbabbage.com/docs/guides/wallet/signing)
