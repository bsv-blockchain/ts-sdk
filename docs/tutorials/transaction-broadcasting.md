# Transaction Broadcasting

**Duration**: 25 minutes  
**Prerequisites**: Completed "Your First BSV Transaction" tutorial, Node.js, basic TypeScript knowledge  

## Learning Goals
- Understand how transaction broadcasting works in BSV
- Learn the difference between `WalletClient` and direct broadcasting approaches
- Configure broadcasting for testnet vs mainnet
- Implement custom broadcasters for different services (ARC, WhatsOnChain)
- Handle broadcasting errors and responses

> **📚 Related Concepts**: Review [Chain Tracking](../concepts/chain-tracking.md), [Transaction Fees](../concepts/fees.md), and [Wallet Integration](../concepts/wallet-integration.md) for background on network interaction.

## Introduction

Transaction broadcasting is the process of submitting your signed transaction to the Bitcoin SV network so it can be included in a block. The BSV TypeScript SDK provides multiple approaches for broadcasting transactions, each suited for different use cases and deployment scenarios.

In this tutorial, you'll learn about the two main broadcasting approaches:

1. **WalletClient Broadcasting**: Uses a BRC-100 compliant wallet as a proxy (such as the Metanet Desktop Wallet)
2. **Direct Broadcasting**: Connects directly to mining services and APIs

## Understanding Broadcasting Architecture

### WalletClient Broadcasting Flow

When you use `WalletClient`, the broadcasting flow looks like this:

```
Your App → WalletClient → Wallet → Mining Services → BSV Network
```

The Wallet acts as a proxy that:
- Manages your broadcasting preferences 
- Handles fallback logic between different services
- Provides a consistent API regardless of the underlying service

Due to its simplicity, this is the recommended approach. 

### Direct Broadcasting Flow

With direct broadcasting, your application connects directly to mining services:

```
Your App → Custom Broadcaster → Mining Service API → BSV Network
```

This approach gives you:
- Full control over which service to use
- Direct error handling and response processing
- Ability to implement custom retry logic
- No dependency on external wallet software

Due to its complexity and need to handle the low-level details of the broadcasting process, this is the less recommended approach.

## Step 1: WalletClient Broadcasting

Let's start with the `WalletClient` approach, which is the simplest for most applications. This is the same approach we have seen in the previous tutorials, where we used the `WalletClient` to create and broadcast transactions. 

### Basic WalletClient Setup

First, create a new project for our broadcasting examples:

```bash
# Create a new directory
mkdir bsv-broadcasting-tutorial
cd bsv-broadcasting-tutorial

# Initialize project
npm init -y

# Install dependencies
npm install typescript ts-node @types/node --save-dev
npm install @bsv/sdk
```

Create a basic TypeScript configuration (`tsconfig.json`):

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

### WalletClient Broadcasting Example

Create `wallet-broadcasting.ts`:

```typescript
import { WalletClient } from '@bsv/sdk'

async function walletClientBroadcasting() {
  try {
    // Initialize the `WalletClient`, using localhost as wallet substrate
    const wallet = new WalletClient('auto', 'localhost')
    
    // Check if we're authenticated with the wallet
    const { authenticated } = await wallet.isAuthenticated()
    if (!authenticated) {
      console.log('Please authenticate with your wallet')
      await wallet.waitForAuthentication()
      console.log('Successfully authenticated!')
    }
    
    // Get wallet version
    const { version } = await wallet.getVersion()
    console.log(`Wallet version: ${version}`)
    
    // For this tutorial, we'll create a transaction with a simple OP_RETURN data output
    // The wallet will handle input selection, change outputs and fees
    console.log('\n🚀 Creating transaction...')
    const actionResult = await wallet.createAction({
      description: 'Broadcasting tutorial transaction',
      outputs: [
        {
          satoshis: 100, // Amount in satoshis (very small amount)
          // For this basic example, we'll use a standard OP_RETURN script
          // Here we use a pre-defined script for simplicity (OP_RETURN with simple data)
          lockingScript: '006a0461626364', // OP_RETURN with data 'abcd'
          outputDescription: 'Broadcasting tutorial data'
        }
      ]
    })
    
    console.log('Transaction created:')
    
    if (actionResult.txid) {
      // If the wallet auto-signed and broadcast the transaction
      console.log('Full action result:', JSON.stringify(actionResult, null, 2))
      console.log(`Transaction ID: ${actionResult.txid}`)
      console.log(`View on explorer: https://whatsonchain.com/tx/${actionResult.txid}`)
      console.log('Transaction was automatically signed and broadcast!')
    } 
    else if (actionResult.signableTransaction) {
      console.log('Created transaction that needs signing')
      // Get the reference needed for signing
      const txReference = actionResult.signableTransaction.reference
      
      // Now sign the transaction
      // Note: In a real application, you might prompt the user to sign
      const signResult = await wallet.signAction({
        // The wallet knows which inputs need to be spent based on the reference
        spends: {},
        // Use the reference from the createAction result
        reference: txReference,
        options: {
          acceptDelayedBroadcast: true
        }
      })

      console.log(`Transaction signed and broadcast!`)
      console.log(`Transaction ID: ${signResult.txid}`)
      console.log(`View on explorer: https://whatsonchain.com/tx/${signResult.txid}`)
    }
    else {
      console.log('Transaction created but no actionable result returned')
    }
    
  } catch (error) {
    console.error('❌ Broadcasting failed:', error)
    console.log('Note: Make sure you have a compatible wallet running and are authenticated.')
  }
}

// Run the example
walletClientBroadcasting()
```

### How `WalletClient` Broadcasting Works

When you use `WalletClient`:

1. **Connection**: Your app connects to the BRC-100 wallet's local HTTP API (usually `http://localhost:3321` for Metanet Desktop Wallet)
2. **Transaction Creation**: The wallet helps construct the transaction using your available UTXOs
3. **Signing**: The wallet signs the transaction with your private keys
4. **Broadcasting**: The wallet submits the transaction to whatever broadcast service is configured in its settings
5. **Response**: You receive either a transaction ID (success) or an error message

The key advantage is that **you don't control the broadcasting directly** - the BRC-100 wallet handles it based on its configuration. This means:
- ✅ Easy to use - no need to manage API keys or endpoints
- ✅ Fallback logic built-in
- ✅ User can configure preferred services through the wallet UI



## Step 2: Direct Broadcasting with Custom Broadcasters

The `WalletClient` approach in step 1 is the recommended approach. However, if you need more control, you can broadcast transactions directly using custom broadcaster implementations. We will demonstrate the main broadcaster implementations in the SDK: ARC and WhatsOnChain.

### Automatic vs Manual Broadcasting

**Important**: By default, `wallet.createAction()` automatically broadcasts transactions through the wallet's configured broadcaster. To demonstrate manual broadcasting with specific services, you need to:

1. **Prevent automatic broadcast**: Use `options: { noSend: true }` in `createAction()`
2. **Convert to Transaction**: Convert the returned `AtomicBEEF` to a `Transaction` object
3. **Manual broadcast**: Use your chosen broadcaster to submit the transaction

This approach is useful when you need to:
- Use a specific broadcasting service (ARC, WhatsOnChain, etc.)
- Implement custom retry logic or error handling
- Broadcast to multiple services for redundancy
- Control exactly when and how transactions are broadcast

### Understanding Broadcaster Interface

All broadcasters in the SDK implement the `Broadcaster` interface:

```typescript
interface Broadcaster {
  broadcast(tx: Transaction): Promise<BroadcastResponse | BroadcastFailure>
}
```

The response types are:

```typescript
interface BroadcastResponse {
  status: 'success'
  txid: string
  message?: string
}

interface BroadcastFailure {
  status: 'error'
  code: string
  description: string
}
```

### ARC Broadcasting

ARC (Application Resource Component) is TAAL's enterprise-grade transaction processing service. Create `arc-broadcasting.ts`:

```typescript
import { WalletClient, ARC, NodejsHttpClient, Transaction } from '@bsv/sdk'
import https from 'https'

async function arcBroadcasting() {
  try {
    // 1. Set up wallet connection
    const wallet = new WalletClient('auto', 'localhost')
    
    // Check if wallet is connected
    const isAuthenticated = await wallet.isAuthenticated()
    if (!isAuthenticated) {
      console.log('Please authenticate with your BRC-100 wallet first')
      return
    }
    
    // 2. Create a transaction action WITHOUT automatic broadcasting
    const actionResult = await wallet.createAction({
      description: 'ARC broadcasting tutorial transaction',
      outputs: [
        {
          satoshis: 100, // Small payment amount
          lockingScript: '76a914f1c075a01882ae0972f95d3a4177c86c852b7d9188ac', // P2PKH script to a test address
          outputDescription: 'ARC broadcasting tutorial payment'
        }
      ],
      options: {
        noSend: true // Prevent automatic broadcasting - we'll broadcast manually with ARC
      }
    })
    
    console.log('Transaction created successfully (not broadcast yet)')
    console.log(`Transaction ID: ${actionResult.txid}`)
    
    // 3. Convert AtomicBEEF to Transaction for manual broadcasting
    if (!actionResult.tx) {
      throw new Error('Transaction creation failed - no transaction returned')
    }
    const tx = Transaction.fromAtomicBEEF(actionResult.tx)
    
    // 4. Set up ARC broadcaster for testnet
    // You need to provide your Taal API key here
    // Get it by signing up at https://console.taal.com
    const apiKey = process.env.TAAL_API_KEY || 'your_taal_api_key_here'
    const httpClient = new NodejsHttpClient(https)
    
    const arc = new ARC('https://arc.taal.com', {
      apiKey,
      httpClient,
      deploymentId: 'broadcasting-tutorial'
    })
    
    // 5. Manually broadcast the transaction using ARC
    console.log('Broadcasting transaction with ARC...')
    const result = await tx.broadcast(arc)
    
    if (result.status === 'success') {
      console.log('✅ Transaction broadcast successful!')
      console.log(`Transaction ID: ${result.txid}`)
      console.log(`View on explorer: https://www.whatsonchain.com/tx/${result.txid}`)
    } else {
      console.log('❌ Broadcasting failed:', result)
    }
    
  } catch (error: any) {
    console.error('❌ Error during ARC broadcasting:', error)
    
    // Common troubleshooting
    if (error.message?.includes('Insufficient funds')) {
      console.log('💡 Make sure your wallet has sufficient testnet coins')
    } else if (error.message?.includes('no header should have returned false')) {
      console.log('💡 Try restarting your wallet application and ensure it is fully synced')
    }
  }
}

// Run the example
arcBroadcasting()
```

### WhatsOnChain Broadcasting

WhatsOnChain provides a free broadcasting service. Create `whatsonchain-broadcasting.ts`:

```typescript
import { WalletClient, WhatsOnChainBroadcaster, NodejsHttpClient, Transaction } from '@bsv/sdk'
import https from 'https'

async function whatsOnChainBroadcasting() {
  try {
    // 1. Set up wallet connection
    const wallet = new WalletClient('auto', 'localhost')
    
    // Check if wallet is connected
    const isAuthenticated = await wallet.isAuthenticated()
    if (!isAuthenticated) {
      console.log('Please authenticate with your BRC-100 wallet first')
      return
    }
    
    // 2. Create a transaction action WITHOUT automatic broadcasting
    const actionResult = await wallet.createAction({
      description: 'WhatsOnChain broadcasting tutorial transaction',
      outputs: [
        {
          satoshis: 100, // Small payment amount
          lockingScript: '76a914f1c075a01882ae0972f95d3a4177c86c852b7d9188ac', // P2PKH script to a test address
          outputDescription: 'WhatsOnChain broadcasting tutorial payment'
        }
      ],
      options: {
        noSend: true // Prevent automatic broadcasting - we'll broadcast manually with WhatsOnChain
      }
    })
    
    console.log('Transaction created successfully (not broadcast yet)')
    console.log(`Transaction ID: ${actionResult.txid}`)
    
    // 3. Convert AtomicBEEF to Transaction for manual broadcasting
    if (!actionResult.tx) {
      throw new Error('Transaction creation failed - no transaction returned')
    }
    const tx = Transaction.fromAtomicBEEF(actionResult.tx)
    
    // 4. Set up WhatsOnChain broadcaster for mainnet
    const httpClient = new NodejsHttpClient(https)
    const broadcaster = new WhatsOnChainBroadcaster('main', httpClient)
    
    // 5. Manually broadcast the transaction using WhatsOnChain
    console.log('Broadcasting transaction with WhatsOnChain...')
    const result = await tx.broadcast(broadcaster)
    
    if (result.status === 'success') {
      console.log('✅ Transaction broadcast successful!')
      console.log(`Transaction ID: ${result.txid}`)
      console.log(`View on explorer: https://www.whatsonchain.com/tx/${result.txid}`)
    } else {
      console.log('❌ Broadcasting failed:', result)
    }
    
  } catch (error: any) {
    console.error('❌ Error during WhatsOnChain broadcasting:', error)
    
    // Common troubleshooting
    if (error.message?.includes('Insufficient funds')) {
      console.log('💡 Make sure your wallet has sufficient mainnet coins')
    } else if (error.message?.includes('no header should have returned false')) {
      console.log('💡 Try restarting your wallet application and ensure it is fully synced')
    }
  }
}

// Run the example
whatsOnChainBroadcasting()
```

## Step 3: Network Configuration (Testnet vs Mainnet)

For advanced broadcasting scenarios like custom broadcaster implementations, see the [Custom Broadcasters Guide](../guides/custom-broadcasters.md).

**Important**: When using manual broadcasting, ensure your wallet and broadcasters are configured for the same network. If your BRC-100 wallet is connected to testnet, use testnet broadcasters. If it's on mainnet, use mainnet broadcasters. Mismatched networks will cause broadcasting failures.

Different networks require different broadcaster configurations:

```typescript
import { ARC, WhatsOnChainBroadcaster, Broadcaster } from '@bsv/sdk'

interface NetworkConfig {
  name: string
  arc: Broadcaster
  whatsOnChain: Broadcaster
}

// Network configurations
const networks: Record<string, NetworkConfig> = {
  testnet: {
    name: 'BSV Testnet',
    arc: new ARC('https://arc-test.taal.com'),
    whatsOnChain: new WhatsOnChainBroadcaster('test')
  },
  
  mainnet: {
    name: 'BSV Mainnet',
    arc: new ARC('https://arc.taal.com', {
      apiKey: process.env.TAAL_API_KEY // Use environment variable for production
    }),
    whatsOnChain: new WhatsOnChainBroadcaster('main')
  }
}
```

## Step 4: Monitoring and Verification

After broadcasting, you should verify that your transaction was accepted:

```typescript
import { Transaction } from '@bsv/sdk'

async function verifyTransaction(txid: string, network: 'test' | 'main' = 'test') {
  const baseUrl = network === 'test' 
    ? 'https://api.whatsonchain.com/v1/bsv/test'
    : 'https://api.whatsonchain.com/v1/bsv/main'
  
  try {
    // Check if transaction exists
    const response = await fetch(`${baseUrl}/tx/${txid}`)
    
    if (response.ok) {
      const txData = await response.json()
      
      console.log('✅ Transaction found on network')
      console.log('Transaction ID:', txData.txid)
      console.log('Block height:', txData.blockheight || 'Unconfirmed')
      console.log('Confirmations:', txData.confirmations || 0)
      
      return txData
    } else if (response.status === 404) {
      console.log('⏳ Transaction not yet visible on network')
      return null
    } else {
      throw new Error(`API error: ${response.status}`)
    }
    
  } catch (error) {
    console.error('❌ Error verifying transaction:', error)
    throw error
  }
}

async function waitForTransaction(
  txid: string, 
  network: 'test' | 'main' = 'test',
  timeoutMs: number = 30000
): Promise<any> {
  const startTime = Date.now()
  
  while (Date.now() - startTime < timeoutMs) {
    const txData = await verifyTransaction(txid, network)
    
    if (txData) {
      return txData
    }
    
    // Transactions can take a few seconds to show up in WhatsOnChain
    // Wait 2 seconds before checking again
    await new Promise(resolve => setTimeout(resolve, 2000))
  }
  
  throw new Error(`Transaction ${txid} not found within ${timeoutMs}ms`)
}

// Example usage
async function monitoringExample(txid: string) {
  try {
    console.log('Waiting for transaction to appear on network...')
    const txData = await waitForTransaction(txid, 'main')
    
    console.log('✅ Transaction confirmed:', txData)
    
  } catch (error) {
    console.error('❌ Transaction monitoring failed:', error)
  }
}

// Run the example
monitoringExample('your-transaction-id-here')
```

## Summary

In this tutorial, you learned about the two main approaches to transaction broadcasting in BSV:

### `WalletClient` Approach
- ✅ **Simple**: Easy to use with BRC-100 wallets
- ✅ **Managed**: Wallet handles service selection and fallbacks
- ✅ **User Control**: Users can configure preferred services


### Direct Broadcasting Approach
- ✅ **Full Control**: Choose exactly which service to use
- ✅ **No Dependencies**: Works without external wallet software
- ✅ **Custom Logic**: Implement your own retry and fallback logic
- ✅ **Error Handling**: Direct access to service responses
- ❌ **More Complex**: Requires more setup and configuration


### Next Steps

- Experiment with different broadcaster configurations
- Implement custom broadcasters for other services  
- Build monitoring dashboards for your applications
- Explore advanced features like batch broadcasting
- Implement robust error handling: See the [Error Handling and Edge Cases Tutorial](./error-handling.md) for comprehensive patterns and the [Custom Broadcasters Guide](../guides/custom-broadcasters.md) for advanced retry logic and failover strategies

The broadcasting approach you choose depends on your application's requirements, deployment environment, and control needs. Both approaches are valid and can be used effectively in different scenarios.
