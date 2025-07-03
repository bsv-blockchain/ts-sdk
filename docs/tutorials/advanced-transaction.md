**Duration**: 75 minutes  
**Prerequisites**: Completed "Transaction Types and Data" tutorial, Node.js, basic TypeScript knowledge  

## Learning Goals
- Master multi-input/multi-output transaction construction
- Implement advanced fee calculation and optimization strategies
- Handle change outputs efficiently
- Use advanced `WalletClient` options for transaction control
- Implement UTXO selection and management strategies
- Handle complex transaction scenarios and error recovery

## Introduction

This tutorial builds on your knowledge of basic `WalletClient` usage to explore advanced transaction construction patterns. You'll learn how to create sophisticated transactions that handle multiple inputs and outputs, optimize fees, and manage UTXOs effectively for production applications.

## Prerequisites

- Complete the [Transaction Types and Data](./transaction-types.md) tutorial
- Have a BRC-100 compliant wallet (such as the [Metanet Desktop Wallet](https://Metanet.bsvb.tech/)) installed and configured
- Some BSV in your wallet
- Understanding of Bitcoin transaction fundamentals

## Advanced `WalletClient` Options

The `createAction` method supports many advanced options through the `options` parameter. Let's explore these capabilities:

```typescript
import { WalletClient } from '@bsv/sdk'

async function exploreAdvancedOptions() {
  try {
    const wallet = new WalletClient('auto', 'localhost')
    
    // Authenticate with the wallet
    const { authenticated } = await wallet.isAuthenticated()
    if (!authenticated) {
      await wallet.waitForAuthentication()
    }

    // Create a transaction with advanced options
    const actionResult = await wallet.createAction({
      description: 'Advanced options demonstration',
      outputs: [
        {
          satoshis: 100,
          lockingScript: '006a0e416476616e636564206f7074696f6e73', // OP_RETURN "Advanced options"
          outputDescription: 'Advanced options demo'
        }
      ],
      options: {
        // Don't automatically sign and process - gives you more control
        signAndProcess: false,
        
        // Accept delayed broadcast for better fee optimization
        acceptDelayedBroadcast: true,
        
        // Return only the transaction ID to save bandwidth
        returnTXIDOnly: false,
        
        // Don't send the transaction immediately
        noSend: true,
        
        // Randomize output order for privacy
        randomizeOutputs: true
      }
    })

    console.log('Transaction created with advanced options:')
    console.log('Signable transaction available for manual processing')
    
    if (actionResult.signableTransaction) {
      console.log('Transaction reference:', actionResult.signableTransaction.reference)
      console.log('Transaction ready for signing')
    }

  } catch (error: any) {
    console.error('Error:', error)
    
    // Provide helpful troubleshooting
    if (error.message?.includes('unlockingScript')) {
      console.log('\nTroubleshooting: When specifying custom inputs, you must provide:')
      console.log('- unlockingScript (valid hexadecimal string, not empty)')
      console.log('- unlockingScriptLength (typically 107 for P2PKH)')
      console.log('\nRecommendation: Let the wallet auto-select inputs by omitting the inputs array')
    }
  }
}

exploreAdvancedOptions().catch(console.error)
```

## Multi-Input Transaction Construction

Multi-input transactions combine multiple UTXOs to fund larger outputs. The BSV TypeScript SDK provides two approaches:

1. **Automatic Input Selection (Recommended)**: Let the wallet automatically select UTXOs by creating outputs that require more satoshis than any single UTXO can provide.

2. **Manual Input Specification (Advanced)**: Explicitly specify which UTXOs to use as inputs. This requires providing complete unlocking script information and is typically only needed for specialized use cases.

```typescript
import { WalletClient } from '@bsv/sdk'

async function createMultiInputTransaction() {
  try {
    const wallet = new WalletClient('auto', 'localhost')
    
    const { authenticated } = await wallet.isAuthenticated()
    if (!authenticated) {
      await wallet.waitForAuthentication()
    }

    // First, let's see what UTXOs we have available (basket name is 'bsv-tutorial' for consistency with previous tutorials, where we created some outputs)
    const { outputs } = await wallet.listOutputs({
      basket: 'bsv-tutorial',
      include: 'locking scripts',
      limit: 10
    })

    console.log(`Found ${outputs.length} available outputs:`)
    outputs.forEach((output, index) => {
      console.log(`  ${index + 1}. ${output.outpoint}: ${output.satoshis} satoshis (spendable: ${output.spendable})`)
    })

    // Check if we have enough UTXOs for a multi-input transaction
    const spendableOutputs = outputs.filter(output => output.spendable && output.satoshis >= 100)
    
    if (spendableOutputs.length < 2) {
      console.log('Need at least 2 spendable outputs for this demo')
      return
    }

    // Method 1: Automatic Input Selection (Recommended)
    
    // Create a transaction that requires multiple inputs by using a large output amount
    // The wallet will automatically select multiple UTXOs if needed
    const totalAvailable = spendableOutputs.reduce((sum, output) => sum + output.satoshis, 0)
    const largeAmount = Math.min(1500, Math.floor(totalAvailable * 0.8)) // Use 80% of available funds
    
    console.log(`Creating transaction requiring ${largeAmount} satoshis (should trigger multi-input selection)`)
    
    const actionResult = await wallet.createAction({
      description: 'Multi-input transaction example',
      outputs: [
        {
          satoshis: largeAmount,
          lockingScript: '006a0c4d756c74692d696e707574', // OP_RETURN "Multi-input"
          outputDescription: 'Multi-input demo output'
        }
      ]
      // No inputs specified - let wallet auto-select
    })

    console.log('Transaction created successfully!')
    console.log('Transaction ID:', actionResult.txid)
    console.log(`View on explorer: https://whatsonchain.com/tx/${actionResult.txid}`)

    // Method 2: Manual Input Specification (Advanced)
    // Manual input specification requires unlocking script details
    // This is commented out as it requires proper unlocking script construction
    /*
    const manualActionResult = await wallet.createAction({
      description: 'Manual multi-input transaction',
      inputs: [
        {
          outpoint: spendableOutputs[0].outpoint,
          unlockingScript: '00', // Placeholder - would need actual unlocking script
          unlockingScriptLength: 107, // Typical P2PKH unlocking script length
          inputDescription: 'First manually selected input'
        },
        {
          outpoint: spendableOutputs[1].outpoint,
          unlockingScript: '00', // Placeholder - would need actual unlocking script
          unlockingScriptLength: 107, // Typical P2PKH unlocking script length
          inputDescription: 'Second manually selected input'
        }
      ],
      outputs: [
        {
          satoshis: 150,
          lockingScript: '006a104d616e75616c2d6d756c74692d696e707574', // OP_RETURN "Manual-multi-input"
          outputDescription: 'Manual multi-input demo output'
        }
      ]
    })
    */

  } catch (error: any) {
    console.error('Error:', error)
    
    // Provide helpful troubleshooting
    if (error.message?.includes('unlockingScript')) {
      console.log('\nTroubleshooting: When specifying custom inputs, you must provide:')
      console.log('- unlockingScript (valid hexadecimal string, not empty)')
      console.log('- unlockingScriptLength (typically 107 for P2PKH)')
      console.log('\nRecommendation: Let the wallet auto-select inputs by omitting the inputs array')
    }
  }
}

createMultiInputTransaction().catch(console.error)
```

## Batch Processing Multiple Payments

For businesses and applications that need to send multiple payments efficiently, batch processing reduces fees and blockchain footprint:

```typescript
import { WalletClient } from '@bsv/sdk'

async function createBatchPayment() {
  try {
    const wallet = new WalletClient('auto', 'localhost')
    
    const { authenticated } = await wallet.isAuthenticated()
    if (!authenticated) {
      await wallet.waitForAuthentication()
    }

    // Simulate multiple payment recipients
    const payments = [
      { amount: 100, description: 'Payment to Alice', data: 'Invoice #001' },
      { amount: 150, description: 'Payment to Bob', data: 'Invoice #002' },
      { amount: 200, description: 'Payment to Carol', data: 'Invoice #003' }
    ]

    // Create outputs for each payment
    const outputs = payments.map((payment, index) => {
      // Create OP_RETURN with payment data
      const dataHex = Buffer.from(payment.data).toString('hex')
      const dataLength = Buffer.from(payment.data).length
      const dataLengthHex = dataLength.toString(16).padStart(2, '0')
      const lockingScript = `006a${dataLengthHex}${dataHex}`

      return {
        satoshis: payment.amount,
        lockingScript: lockingScript,
        outputDescription: payment.description,
        basket: 'payments', // Organize outputs in a specific basket
        tags: ['batch-payment', `invoice-${index + 1}`] // Tag for easy tracking
      }
    })

    // Create the batch transaction
    const actionResult = await wallet.createAction({
      description: 'Batch payment transaction',
      outputs: outputs,
      labels: ['batch-processing', 'business-payments'], // Labels for transaction tracking
      options: {
        randomizeOutputs: false // Keep payment order for accounting
      }
    })

    if (actionResult.txid) {
      console.log(`Batch payment transaction created: ${actionResult.txid}`)
      console.log(`Processed ${payments.length} payments in a single transaction`)
      console.log(`Total amount: ${payments.reduce((sum, p) => sum + p.amount, 0)} satoshis`)
      console.log(`View on explorer: https://whatsonchain.com/tx/${actionResult.txid}`)
    }

  } catch (error: unknown) {
    console.error('Error:', error)
  }
}

createBatchPayment().catch(console.error)
```

## Advanced UTXO Management with Baskets

Baskets provide powerful UTXO organization capabilities. Here's how to use them for advanced transaction patterns:

```typescript
import { WalletClient } from '@bsv/sdk'

async function advancedBasketManagement() {
  try {
    const wallet = new WalletClient('auto', 'localhost')
    
    const { authenticated } = await wallet.isAuthenticated()
    if (!authenticated) {
      await wallet.waitForAuthentication()
    }

    // Create outputs in different baskets for different purposes
    console.log('Creating specialized UTXO baskets...')
    
    const actionResult = await wallet.createAction({
      description: 'UTXO organization with baskets',
      outputs: [
        {
          satoshis: 500,
          lockingScript: '006a0c48696768207072696f72697479', // OP_RETURN "High priority"
          outputDescription: 'High priority reserve',
          basket: 'high-priority',
          tags: ['reserve', 'urgent-use'],
          customInstructions: 'Reserved for urgent transactions'
        },
        {
          satoshis: 300,
          lockingScript: '006a0d4d656469756d207072696f72697479', // OP_RETURN "Medium priority"
          outputDescription: 'Medium priority operations',
          basket: 'medium-priority',
          tags: ['operations', 'daily-use']
        },
        {
          satoshis: 200,
          lockingScript: '006a0b4c6f77207072696f72697479', // OP_RETURN "Low priority"
          outputDescription: 'Low priority batch',
          basket: 'low-priority',
          tags: ['batch', 'bulk-operations']
        }
      ]
    })

    if (actionResult.txid) {
      console.log(`Basket organization transaction: ${actionResult.txid}`)
      console.log('Note: OP_RETURN outputs are unspendable by design (for data storage)')
      console.log('Waiting for wallet to process new outputs...')
      // Give the wallet a moment to process the new outputs
      await new Promise(resolve => setTimeout(resolve, 2000))
    }

    // Now let's examine our organized UTXOs
    console.log('\nExamining basket organization...')
    console.log('Note: OP_RETURN outputs show spendable: false because they are data-only outputs')
    const baskets = ['high-priority', 'medium-priority', 'low-priority']
    
    for (const basketName of baskets) {
      const { outputs, totalOutputs } = await wallet.listOutputs({
        basket: basketName,
        includeTags: true,
        includeCustomInstructions: true,
        limit: 10
      })

      console.log(`\n${basketName.toUpperCase()} Basket:`)
      console.log(`  Total outputs: ${totalOutputs}`)
      
      if (totalOutputs === 0) {
        console.log(`  Note: No outputs found. This could be because:`)
        console.log(`    - Outputs need confirmation time`)
        console.log(`    - Wallet needs time to process new baskets`)
        console.log(`    - OP_RETURN outputs might not be tracked as spendable UTXOs`)
      }
      
      outputs.forEach((output, index) => {
        console.log(`  Output ${index + 1}:`)
        console.log(`    Outpoint: ${output.outpoint}`)
        console.log(`    Amount: ${output.satoshis} satoshis`)
        console.log(`    Spendable: ${output.spendable}`)
        if (output.tags) {
          console.log(`    Tags: ${output.tags.join(', ')}`)
        }
        if (output.customInstructions) {
          console.log(`    Instructions: ${output.customInstructions}`)
        }
      })
    }

    // Add processing delay
    await new Promise(resolve => setTimeout(resolve, 5000));

  } catch (error: unknown) {
    console.error('Error:', error)
  }
}

advancedBasketManagement().catch(console.error)
```

## Transaction Chaining and Dependencies

Sometimes you need to create transactions that depend on previous ones. Here's how to handle transaction chaining:

```typescript
import { WalletClient } from '@bsv/sdk'

async function createTransactionChain() {
  try {
    const wallet = new WalletClient('auto', 'localhost')
    
    const { authenticated } = await wallet.isAuthenticated()
    if (!authenticated) {
      await wallet.waitForAuthentication()
    }

    console.log('Creating transaction chain...')
    console.log('Transaction chaining allows you to create a series of transactions that depend on each other.')
    console.log('This is useful for scenarios where you need to ensure that a transaction is only processed after a previous one has been confirmed.')
    console.log('In this example, we will create two transactions: the first one creates an output, and the second one spends that output.')

    // First transaction - creates outputs for the chain
    const firstTx = await wallet.createAction({
      description: 'Chain starter transaction',
      outputs: [
        {
          satoshis: 400,
          lockingScript: '006a0d436861696e207374617274657220', // OP_RETURN "Chain starter"
          outputDescription: 'Chain starter output',
          basket: 'chain-demo',
          tags: ['chain', 'step-1']
        }
      ],
      options: {
        acceptDelayedBroadcast: true // Allow some delay for better fee optimization
      }
    })

    if (!firstTx.txid) {
      console.log('First transaction failed')
      return
    }

    console.log(`First transaction: ${firstTx.txid}`)

    // Wait a moment for the transaction to be processed
    await new Promise(resolve => setTimeout(resolve, 2000))

    // Second transaction - demonstrates chaining with sendWith option
    // Note: We use automatic input selection rather than manual specification
    // Manual input specification requires unlockingScript and unlockingScriptLength
    // which adds complexity for tutorial purposes
    const secondTx = await wallet.createAction({
      description: 'Chain continuation transaction',
      outputs: [
        {
          satoshis: 150,
          lockingScript: '006a0c436861696e20636f6e74696e756174696f6e', // OP_RETURN "Chain continuation"
          outputDescription: 'Chain continuation output',
          basket: 'chain-demo',
          tags: ['chain', 'step-2']
        }
      ],
      options: {
        sendWith: [firstTx.txid] // Ensure this transaction is sent with the first one
      }
    })

    if (secondTx.txid) {
      console.log(`Second transaction: ${secondTx.txid}`)
      console.log('Transaction chain completed successfully')
    }

  } catch (error: unknown) {
    console.error('Error in transaction chain:', error)
  }
}

createTransactionChain().catch(console.error)
```


## Performance Optimization Strategies

For high-throughput applications, consider these optimization techniques:

```typescript
import { WalletClient } from '@bsv/sdk'

async function optimizedTransactionPatterns() {
  try {
    const wallet = new WalletClient('auto', 'localhost')
    
    const { authenticated } = await wallet.isAuthenticated()
    if (!authenticated) {
      await wallet.waitForAuthentication()
    }

    // Strategy 1: Pre-allocate UTXOs for different purposes
    console.log('Pre-allocating UTXOs for optimal performance...')
    
    const allocationTx = await wallet.createAction({
      description: 'UTXO pre-allocation for performance',
      outputs: [
        // Create multiple small UTXOs for frequent operations
        ...Array(5).fill(null).map((_, i) => ({
          satoshis: 200,
          lockingScript: `006a0f507265616c6c6f636174656420${i.toString(16).padStart(2, '0')}`, // "Preallocated" + index
          outputDescription: `Pre-allocated UTXO ${i + 1}`,
          basket: 'pre-allocated',
          tags: ['performance', 'ready-to-use']
        }))
      ],
      options: {
        acceptDelayedBroadcast: true
      }
    })

    if (allocationTx.txid) {
      console.log(`Pre-allocation transaction: ${allocationTx.txid}`)
    }

    // Strategy 2: Batch multiple operations efficiently
    await new Promise(resolve => setTimeout(resolve, 3000))

    const operations = [
      { type: 'data', content: 'Operation 1' },
      { type: 'data', content: 'Operation 2' },
      { type: 'data', content: 'Operation 3' }
    ]

    const batchOutputs = operations.map((op, index) => {
      const dataHex = Buffer.from(op.content).toString('hex')
      const dataLength = Buffer.from(op.content).length
      const dataLengthHex = dataLength.toString(16).padStart(2, '0')
      
      return {
        satoshis: 100,
        lockingScript: `006a${dataLengthHex}${dataHex}`,
        outputDescription: `Batch operation ${index + 1}`,
        basket: 'operations',
        tags: ['batch', `op-${index + 1}`]
      }
    })

    // Use pre-allocated UTXOs for the batch
    const { outputs: preAllocated } = await wallet.listOutputs({
      basket: 'pre-allocated',
      limit: 3
    })

    console.log(`Found ${preAllocated.length} pre-allocated UTXOs`)

    if (preAllocated.length > 0) {
      // Let the wallet automatically select inputs instead of manual specification
      const batchTx = await wallet.createAction({
        description: 'Optimized batch operation',
        outputs: batchOutputs,
        options: {
          randomizeOutputs: false, // Maintain order for processing
          acceptDelayedBroadcast: true
        }
      })

      if (batchTx.txid) {
        console.log(`Optimized batch transaction: ${batchTx.txid}`)
        console.log(`Processed ${operations.length} operations efficiently`)
      }
    }

  } catch (error: unknown) {
    console.error('Optimization error:', error)
  }
}

optimizedTransactionPatterns().catch(console.error)
```



## Conclusion

You've now mastered advanced transaction construction with the BSV TypeScript SDK's `WalletClient`. You can:

- Create sophisticated multi-input/multi-output transactions
- Implement robust error handling and retry strategies
- Optimize transaction patterns for performance
- Use advanced `WalletClient` features like baskets, tags, and options
- Handle complex scenarios like transaction chaining and batch processing

These techniques enable you to build production-ready applications that efficiently manage Bitcoin transactions while maintaining reliability and performance.

## Next Steps

- Review the [Transaction Signing Methods](../guides/transaction-signing-methods.md) for custom signing scenarios
- Check out specialized tutorials for your specific use case

- Advanced transaction construction requires robust error handling for production applications. For comprehensive coverage of error handling patterns, retry mechanisms, and recovery strategies, see the dedicated [Error Handling Tutorial](./error-handling.md).


## Additional Resources

- [Wallet Reference](../reference/wallet.md)
- [BSV Blockchain Documentation](https://docs.bsvblockchain.org/)
- [Metanet Desktop Wallet](https://Metanet.bsvb.tech/)
