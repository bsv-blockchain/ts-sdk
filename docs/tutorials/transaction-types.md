# Transaction Types and Data

**Duration**: 30 minutes  
**Prerequisites**: Completed "Your First BSV Transaction" tutorial, Node.js, basic TypeScript knowledge  

## Learning Goals
- Create transactions with multiple outputs
- Add data to transactions
- Work with different output types
- Use advanced `WalletClient` features

## Introduction

In the previous tutorial, you created a simple transaction that sent BSV to a single address. In this tutorial, you'll expand your knowledge by learning how to create more complex transactions using the `WalletClient` interface. You'll learn how to send to multiple recipients, include data in transactions, and explore more advanced `WalletClient` features.

## Prerequisites

- Complete the [Your First BSV Transaction](./first-transaction.md) tutorial
- Have a BRC-100 compliant wallet (such as [Metanet Desktop Wallet](https://Metanet.bsvb.tech/)) installed and configured
- Some BSV in your wallet

## Transaction with Multiple Outputs

One powerful feature of Bitcoin transactions is the ability to send to multiple recipients in a single transaction. Let's create a transaction that sends to two different recipients:

```typescript
import { WalletClient } from '@bsv/sdk'

async function createMultiOutputTransaction() {
  try {
    // Initialize the WalletClient (use localhost as wallet originator)
    const wallet = new WalletClient('auto', 'localhost')
    
    // Authenticate with the wallet if needed
    const { authenticated } = await wallet.isAuthenticated()
    if (!authenticated) {
      console.log('Please authenticate with your wallet')
      await wallet.waitForAuthentication()
    }
    
    // Get network information
    const { network } = await wallet.getNetwork()
    console.log(`Connected to ${network} network`)
    
    // Get our own public key for sending back to ourselves
    const { publicKey } = await wallet.getPublicKey({ identityKey: true })
    
    // Create a transaction with multiple outputs
    const actionResult = await wallet.createAction({
      description: 'Multi-output transaction example',
      outputs: [
        {
          // First output - uses simple OP_RETURN with data
          satoshis: 100,
          lockingScript: '006a0461626364', // OP_RETURN with data 'abcd'
          outputDescription: 'First data output'
        },
        {
          // Second output - also uses OP_RETURN with different data
          satoshis: 100,
          lockingScript: '006a04656667', // OP_RETURN with data 'efgh'
          outputDescription: 'Second data output'
        }
      ]
    })
    
    console.log('Transaction created:')
    
    let txReference
    let txid
    
    // If the wallet auto-signed and broadcast the transaction (otherwise, refer to the examples in our first tutorial to see how to explicitly sign it and broadcast it)
    if (actionResult.txid) {
      
      console.log(`Transaction ID: ${actionResult.txid}`)
      console.log(`View on explorer: https://whatsonchain.com/tx/${actionResult.txid}`)
      console.log('Transaction was automatically signed and broadcast!')
      txid = actionResult.txid
    } 
    else {
      console.log('Transaction created but no actionable result returned')
    }
    
    console.log(`Transaction ID: ${txid}`)
    console.log(`View on explorer: https://whatsonchain.com/tx/${txid}`)
    
  } catch (error) {
    console.error('Error:', error)
  }
}

createMultiOutputTransaction().catch(console.error)
```

This transaction creates two outputs, both sending funds back to your own wallet but with different amounts and descriptions. In a real-world scenario, you could send to different recipients by specifying different addresses or public keys.

## Adding Data to Transactions

Another powerful capability of Bitcoin SV is the ability to store data on-chain. Let's create a transaction that includes some data:

```typescript
import { WalletClient } from '@bsv/sdk'

async function createDataTransaction() {
  try {
    // Initialize the WalletClient
    const wallet = new WalletClient('auto', 'localhost')
    
    // Authenticate with the wallet if needed
    const { authenticated } = await wallet.isAuthenticated()
    if (!authenticated) {
      await wallet.waitForAuthentication()
    }
    
    // Data to store on-chain (in this case, a simple text message)
    const message = 'Hello, Bitcoin SV!'
    
    // Convert the message to a hex string
    const messageHex = Buffer.from(message).toString('hex')
    console.log(`Message as hex: ${messageHex}`)
    
    // Create the OP_RETURN script - start with OP_FALSE (00) + OP_RETURN (6a)
    // Then add the length of the data as a single byte (hex encoded)
    // Our message length is 16 bytes (0x10 in hex)
    const dataLength = Buffer.from(message).length
    const dataLengthHex = dataLength.toString(16).padStart(2, '0')
    
    // Complete lockingScript: OP_FALSE + OP_RETURN + data length + data
    const lockingScript = `006a${dataLengthHex}${messageHex}`
    console.log(`Complete lockingScript: ${lockingScript}`)
    
    // Create a transaction with an OP_RETURN output containing our data
    const actionResult = await wallet.createAction({
      description: 'Store data on-chain',
      outputs: [
        {
          satoshis: 100, // Small amount of satoshis
          lockingScript: lockingScript, // Dynamic OP_RETURN with our message data
          outputDescription: 'Data storage'
        }
      ]
    })
    
    console.log('Transaction created:')
    
    let txReference
    let txid
    
    if (actionResult.txid) {
      // If the wallet auto-signed and broadcast the transaction
      console.log(`Transaction ID: ${actionResult.txid}`)
      console.log(`View on explorer: https://whatsonchain.com/tx/${actionResult.txid}`)
      console.log('Transaction was automatically signed and broadcast!')
      txid = actionResult.txid
    } 
    else {
      console.log('Transaction created but no actionable result returned')
    }
    
    console.log(`Transaction ID: ${txid}`)
    console.log(`View on explorer: https://whatsonchain.com/tx/${txid}`)
    console.log(`Data stored on-chain: "${message}"`)
    
  } catch (error) {
    console.error('Error:', error)
  }
}

createDataTransaction().catch(console.error)
```

This transaction includes an OP_RETURN output, which is a special type of output that can contain arbitrary data but cannot be spent. This is a common way to store data on the Bitcoin SV blockchain.

## Combining Payment and Data

You can also combine regular payment outputs with data outputs in the same transaction:

```typescript
import { WalletClient } from '@bsv/sdk'

async function createCombinedTransaction() {
  try {
    // Initialize the WalletClient
    const wallet = new WalletClient('auto', 'localhost')
    
    // Authenticate with the wallet if needed
    const { authenticated } = await wallet.isAuthenticated()
    if (!authenticated) {
      await wallet.waitForAuthentication()
    }
    
    // Get our own public key for sending back to ourselves
    const { publicKey } = await wallet.getPublicKey({ identityKey: true })
    
    // Message data for our OP_RETURN outputs
    const receipt = 'Payment receipt'
    const orderRef = 'Order #12345'
    
    // Convert messages to hex
    const receiptHex = Buffer.from(receipt).toString('hex')
    const orderHex = Buffer.from(orderRef).toString('hex')
    
    // Build the OP_RETURN scripts with correct lengths
    // Format: OP_FALSE (00) + OP_RETURN (6a) + length byte + data in hex
    const receiptLength = Buffer.from(receipt).length
    const receiptLengthHex = receiptLength.toString(16).padStart(2, '0') // Ensure even length
    const receiptScript = `006a${receiptLengthHex}${receiptHex}`
    
    const orderLength = Buffer.from(orderRef).length
    const orderLengthHex = orderLength.toString(16).padStart(2, '0') // Ensure even length
    const orderScript = `006a${orderLengthHex}${orderHex}`
    
    console.log(`Receipt script: ${receiptScript}`)
    console.log(`Order script: ${orderScript}`)
    
    // Create a transaction with both outputs containing different data
    const actionResult = await wallet.createAction({
      description: 'Multi-data transaction',
      outputs: [
        {
          // First data output
          satoshis: 100,
          lockingScript: receiptScript, // OP_RETURN with payment receipt data
          outputDescription: 'Payment receipt data'
        },
        {
          // Second data output with different content
          satoshis: 100,
          lockingScript: orderScript, // OP_RETURN with order reference data
          outputDescription: 'Order reference data'
        }
      ]
    })
    
    console.log('Transaction created:')
    
    let txReference
    let txid
    
    if (actionResult.txid) {
      // If the wallet auto-signed and broadcast the transaction
      console.log(`Transaction ID: ${actionResult.txid}`)
      console.log(`View on explorer: https://whatsonchain.com/tx/${actionResult.txid}`)
      console.log('Transaction was automatically signed and broadcast!')
      txid = actionResult.txid
    } 
    else {
      console.log('Transaction created but no actionable result returned')
    }
    
    console.log(`Transaction ID: ${txid}`)
    console.log(`View on explorer: https://whatsonchain.com/tx/${txid}`)
    
  } catch (error) {
    console.error('Error:', error)
  }
}

createCombinedTransaction().catch(console.error)
```

This pattern of combining payments with data is very powerful for business applications, allowing you to create an immutable record of a payment that includes metadata about the purpose of the payment.

## Working with Transaction History

The `WalletClient` also allows you to retrieve your transaction history:

```typescript
import { WalletClient } from '@bsv/sdk'

async function viewTransactionHistory() {
  try {
    // Initialize the WalletClient
    const wallet = new WalletClient('auto', 'localhost')
    
    // Authenticate with the wallet if needed
    const { authenticated } = await wallet.isAuthenticated()
    if (!authenticated) {
      await wallet.waitForAuthentication()
    }
    
    // Get transaction history
    const { totalActions, actions } = await wallet.listActions({
      limit: 10, // Limit to the 10 first transactions
      offset: 0  // Start from the beginning
    })
    
    console.log(`Found ${totalActions} total transactions`)
    console.log('Recent transactions:')
    
    // Display transaction details
    actions.forEach((action, index) => {
      console.log(`\nTransaction #${index + 1}:`)
      console.log(`  TXID: ${action.txid}`)
      console.log(`  Description: ${action.description}`)
      console.log(`  Amount: ${action.satoshis} satoshis`)
      console.log(`  Status: ${action.status}`)
      console.log(`  Is Outgoing: ${action.isOutgoing ? 'Yes' : 'No'}`)
    })
    
  } catch (error) {
    console.error('Error:', error)
  }
}

viewTransactionHistory().catch(console.error)
```

This code retrieves and displays your recent transaction history, showing transaction IDs, descriptions, amounts, statuses, and whether each transaction was outgoing or incoming.

## Advanced Features: Working with Baskets

In the BSV SDK, "baskets" are a powerful UTXO management concept that allows you to organize and categorize your unspent transaction outputs (UTXOs) for better control over how they're used in transactions. Think of baskets as labeled containers for your UTXOs. Each basket can have its own purpose - for example, you might have a "savings" basket for long-term storage, a "spending" basket for daily transactions, or special baskets for specific applications or smart contracts.

Baskets help with:

* **UTXO organization**: Group outputs for different purposes or applications
* **Transaction optimization**: Control which UTXOs are used for specific transaction types
* **Privacy enhancement**: Segregate UTXOs from different sources or uses
* **Application-specific management**: Maintain dedicated UTXOs for particular applications

The `WalletClient` provides methods for working with baskets to give you fine-grained control over your UTXO management:

```typescript
import { WalletClient } from '@bsv/sdk'

async function workWithBaskets() {
  try {
    // Initialize the WalletClient
    const wallet = new WalletClient('auto', 'localhost')
    
    // Authenticate with the wallet if needed
    const { authenticated } = await wallet.isAuthenticated()
    if (!authenticated) {
      await wallet.waitForAuthentication()
    }
    
    // Basket name for our example
    const basketName = 'bsv-tutorial'
    
    // Let's create a transaction that explicitly uses this basket
    
    console.log('\nCreating a transaction with outputs assigned to our basket...')
    
    // Get our own public key for the transaction
    const { publicKey } = await wallet.getPublicKey({ identityKey: true })
    
    // Create a transaction with outputs assigned to a specific basket
    const actionResult = await wallet.createAction({
      description: 'Transaction with basket assignment',
      outputs: [
        {
          satoshis: 100,
          lockingScript: '006a0c426173746b657420746573742e', // Simple OP_RETURN
          outputDescription: 'Basket demonstration',
          basket: basketName // Assign this output to our basket
        }
      ]
    })
    
    if (actionResult.txid) {
      console.log(`Created transaction with ID: ${actionResult.txid}`)
      console.log(`Output has been assigned to the "${basketName}" basket`)
    }
    
    // List outputs in the specified basket
    const { outputs } = await wallet.listOutputs({
      basket: basketName,
      include: 'all' // use 'spendable' if you only want to see UTXOs that can be spent
    })
    
    console.log(`Found ${outputs.length} outputs in the "${basketName}" basket`)
    
    // Display output details
    outputs.forEach((output, index) => {
      console.log(`\nOutput #${index + 1}:`)
      console.log(`  Outpoint: ${output.outpoint}`)
      console.log(`  Value: ${output.satoshis} satoshis`)
      console.log(`  Spendable: ${output.spendable ? 'Yes' : 'No'}`)
    })
    
  } catch (error) {
    console.error('Error:', error)
  }
}

workWithBaskets().catch(console.error)
```

> **Important**::
>
> - The `basket` parameter is set at the individual output level, not at the transaction level
> - Each output can be assigned to a different basket if needed
> - The `include` parameter in `listOutputs()` can filter for 'all', 'spendable', or 'unspendable' outputs
> - For a UTXO to appear in a basket, the output must explicitly have a `basket` property when it's created

## Conclusion

Congratulations! You've now learned how to create more complex transactions using the `WalletClient` interface. You can:

- Send to multiple recipients in a single transaction
- Store data on the blockchain using OP_RETURN outputs
- Combine payments with data in the same transaction
- Retrieve and view your transaction history
- Work with baskets to organize your UTXOs

These capabilities form the foundation for building sophisticated applications on Bitcoin SV. With the `WalletClient` interface, you can focus on your application logic rather than the low-level details of transaction construction.

## Next Steps

- Learn about [Key Management and Cryptography](./key-management.md)
- Explore [Advanced Transaction Signing](../guides/advanced-transaction-signing.md)
- If you need more control over transaction construction, check out the [Direct Transaction Creation Guide](../guides/direct-transaction-creation.md)

## Additional Resources

- [WalletClient API Reference](../reference/wallet.md#class-walletclient)
- [BSV Transaction Types](https://wiki.bitcoinsv.io/index.php/Bitcoin_Transaction_Types)
- [Data Storage on BSV](https://wiki.bitcoinsv.io/index.php/Data_Insertion_in_Bitcoin)
