import Transaction from '../transaction/Transaction.js'
import * as Utils from '../primitives/utils.js'
import { TopicBroadcaster, LookupResolver, withDoubleSpendRetry } from '../overlay-tools/index.js'
import { BroadcastResponse, BroadcastFailure } from '../transaction/Broadcaster.js'
import { WalletInterface, WalletProtocol, CreateActionInput, OutpointString, PubKeyHex, CreateActionOutput, HexString } from '../wallet/Wallet.interfaces.js'
import { PushDrop } from '../script/index.js'
import WalletClient from '../wallet/WalletClient.js'
import { Beef } from '../transaction/Beef.js'
import { Historian } from '../overlay-tools/Historian.js'
import { KVContext, kvStoreInterpreter } from './kvStoreInterpreter.js'
import { ProtoWallet } from '../wallet/ProtoWallet.js'
import { kvProtocol, KVStoreConfig, KVStoreQuery, KVStoreEntry, KVStoreGetOptions, KVStoreSetOptions, KVStoreRemoveOptions } from './types.js'

/**
 * Default configuration values for GlobalKVStore operations.
 * Provides sensible defaults for overlay connection and protocol settings.
 */
const DEFAULT_CONFIG: KVStoreConfig = {
  protocolID: [1, 'kvstore'],
  serviceName: 'ls_kvstore',
  tokenAmount: 1,
  topics: ['tm_kvstore'],
  networkPreset: 'mainnet',
  acceptDelayedBroadcast: false,
  overlayBroadcast: false, // Use overlay broadcasting to prevent UTXO spending on broadcast rejection.
  tokenSetDescription: '', // Will be set dynamically
  tokenUpdateDescription: '', // Will be set dynamically
  tokenRemovalDescription: '' // Will be set dynamically
}

/**
 * Implements a global key-value storage system which uses an overlay service to track key-value pairs.
 * Each key-value pair is represented by a PushDrop token output.
 * Allows getting, setting, and removing key-value pairs with optional fetching by protocolID and history tracking.
 */
export class GlobalKVStore {
  /**
   * The wallet interface used to create transactions and perform cryptographic operations.
   * @readonly
   */
  private readonly wallet: WalletInterface

  /**
   * Configuration for the KVStore instance containing all runtime options.
   * @private
   * @readonly
   */
  private readonly config: KVStoreConfig

  /**
   * Historian instance used to extract history from transaction outputs.
   * @private
   */
  private readonly historian: Historian<string, KVContext>

  /**
   * Lookup resolver used to query the overlay for transaction outputs.
   * @private
   */
  private readonly lookupResolver: LookupResolver

  /**
   * Topic broadcaster used to broadcast transactions to the overlay.
   * @private
   */
  private readonly topicBroadcaster: TopicBroadcaster

  /**
   * A map to store locks for each key to ensure atomic updates.
   * @private
   */
  private readonly keyLocks: Map<string, Array<(value: void | PromiseLike<void>) => void>> = new Map()

  /**
   * Cached user identity key
   * @private
   */
  private cachedIdentityKey: PubKeyHex | null = null

  /**
   * Creates an instance of the GlobalKVStore.
   *
   * @param {KVStoreConfig} [config={}] - Configuration options for the KVStore. Defaults to empty object.
   * @param {WalletInterface} [config.wallet] - Wallet to use for operations. Defaults to WalletClient.
   * @throws {Error} If the configuration contains invalid parameters.
   */
  constructor (config: KVStoreConfig = {}) {
    // Merge with defaults to create a fully resolved config
    this.config = { ...DEFAULT_CONFIG, ...config }
    this.wallet = config.wallet ?? new WalletClient()
    this.historian = new Historian<string, KVContext>(kvStoreInterpreter)
    this.lookupResolver = new LookupResolver({
      networkPreset: this.config.networkPreset
    })
    this.topicBroadcaster = new TopicBroadcaster(this.config.topics as string[], {
      networkPreset: this.config.networkPreset
    })
  }

  /**
   * Retrieves data from the KVStore.
   * Can query by key+controller (single result), protocolID, controller, or key (multiple results).
   *
   * @param {KVStoreQuery} query - Query parameters sent to overlay
   * @param {KVStoreGetOptions} [options={}] - Configuration options for the get operation
   * @returns {Promise<KVStoreEntry | KVStoreEntry[] | undefined>} Single entry for key+controller queries, array for all other queries
   */
  async get (query: KVStoreQuery, options: KVStoreGetOptions = {}): Promise<KVStoreEntry | KVStoreEntry[] | undefined> {
    this.validateQuerySelectors(query)
    if (query.key != null && query.controller != null) {
      // Specific key+controller query - return single entry
      const entries = await this.queryOverlay(query, options)
      return entries.length > 0 ? entries[0] : undefined
    }
    return await this.queryOverlay(query, options)
  }

  /**
   * Ensures lookup pagination and ordering options are only used with a real KV selector.
   *
   * @param {KVStoreQuery} query - Query parameters sent to overlay.
   * @throws {Error} If the query does not include a valid selector.
   */
  private validateQuerySelectors (query: KVStoreQuery): void {
    const hasSelector =
      (typeof query.key === 'string' && query.key.length > 0) ||
      (typeof query.controller === 'string' && query.controller.length > 0) ||
      (Array.isArray(query.protocolID) && query.protocolID.length === 2) ||
      (Array.isArray(query.tags) && query.tags.length > 0)

    if (!hasSelector) {
      throw new Error('Must specify at least one selector: key, controller, protocolID, or tags')
    }
  }

  /**
   * Sets a key-value pair. The current user (wallet identity) becomes the controller.
   *
   * @param {string} key - The key to set (user computes this however they want)
   * @param {string} value - The value to store
   * @param {KVStoreSetOptions} [options={}] - Configuration options for the set operation
   * @returns {Promise<OutpointString>} The outpoint of the created token
   */
  async set (key: string, value: string, options: KVStoreSetOptions = {}): Promise<OutpointString> {
    if (typeof key !== 'string' || key.length === 0) {
      throw new Error('Key must be a non-empty string.')
    }
    if (typeof value !== 'string') {
      throw new Error('Value must be a string.')
    }

    const controller = await this.getIdentityKey()
    const lockQueue = await this.queueOperationOnKey(key)
    const protocolID = options.protocolID ?? this.config.protocolID
    const tokenSetDescription = (options.tokenSetDescription != null && options.tokenSetDescription !== '') ? options.tokenSetDescription : `Create KVStore value for ${key}`
    const tokenUpdateDescription = (options.tokenUpdateDescription != null && options.tokenUpdateDescription !== '') ? options.tokenUpdateDescription : `Update KVStore value for ${key}`
    const tokenAmount = options.tokenAmount ?? this.config.tokenAmount
    const tags = options.tags ?? []

    try {
      // Create PushDrop locking script (reusable across retries)
      const pushdrop = new PushDrop(this.wallet, this.config.originator)
      const lockingScriptFields = [
        Utils.toArray(JSON.stringify(protocolID), 'utf8'),
        Utils.toArray(key, 'utf8'),
        Utils.toArray(value, 'utf8'),
        Utils.toArray(controller, 'hex')
      ]

      // Add tags as optional 5th field for backwards compatibility
      if (tags.length > 0) {
        lockingScriptFields.push(Utils.toArray(JSON.stringify(tags), 'utf8'))
      }

      const lockingScript = await pushdrop.lock(
        lockingScriptFields,
        protocolID ?? this.config.protocolID as WalletProtocol,
        Utils.toUTF8(Utils.toArray(key, 'utf8')),
        'anyone',
        true
      )

      // Wrap entire operation in double-spend retry, including overlay query
      const outpoint = await withDoubleSpendRetry(async () => {
        // Re-query overlay on each attempt to get fresh token state
        const existingEntries = await this.queryOverlay({ key, controller }, { includeToken: true })
        const existingToken = existingEntries.length > 0 ? existingEntries[0].token : undefined

        if (existingToken != null) {
          // Update existing token
          const inputs: CreateActionInput[] = [{
            outpoint: `${existingToken.txid}.${existingToken.outputIndex}`,
            unlockingScriptLength: 74,
            inputDescription: 'Previous KVStore token'
          }]
          const inputBEEF = existingToken.beef

          const { signableTransaction } = await this.wallet.createAction({
            description: tokenUpdateDescription,
            inputBEEF: inputBEEF.toBinary(),
            inputs,
            outputs: [{
              satoshis: tokenAmount ?? this.config.tokenAmount as number,
              lockingScript: lockingScript.toHex(),
              outputDescription: 'KVStore token'
            }],
            options: {
              acceptDelayedBroadcast: this.config.acceptDelayedBroadcast,
              noSend: this.config.overlayBroadcast,
              randomizeOutputs: false
            }
          }, this.config.originator)

          if (signableTransaction == null) {
            throw new Error('Unable to create update transaction')
          }

          const tx = Transaction.fromAtomicBEEF(signableTransaction.tx)
          const unlocker = pushdrop.unlock(
            this.config.protocolID as WalletProtocol,
            key,
            'anyone'
          )
          const unlockingScript = await unlocker.sign(tx, 0)

          const { tx: finalTx } = await this.wallet.signAction({
            reference: signableTransaction.reference,
            spends: { 0: { unlockingScript: unlockingScript.toHex() } },
            options: {
              acceptDelayedBroadcast: this.config.acceptDelayedBroadcast,
              noSend: this.config.overlayBroadcast
            }
          }, this.config.originator)

          if (finalTx == null) {
            throw new Error('Unable to finalize update transaction')
          }

          const transaction = Transaction.fromAtomicBEEF(finalTx)
          await this.submitToOverlay(transaction)
          return `${transaction.id('hex')}.0`
        } else {
          // Create new token
          const { tx } = await this.wallet.createAction({
            description: tokenSetDescription,
            outputs: [{
              satoshis: tokenAmount ?? this.config.tokenAmount as number,
              lockingScript: lockingScript.toHex(),
              outputDescription: 'KVStore token'
            }],
            options: {
              acceptDelayedBroadcast: this.config.acceptDelayedBroadcast,
              noSend: this.config.overlayBroadcast,
              randomizeOutputs: false
            }
          }, this.config.originator)

          if (tx == null) {
            throw new Error('Failed to create transaction')
          }

          const transaction = Transaction.fromAtomicBEEF(tx)
          await this.submitToOverlay(transaction)
          return `${transaction.id('hex')}.0`
        }
      }, this.topicBroadcaster)

      return outpoint
    } finally {
      if (lockQueue.length > 0) {
        this.finishOperationOnKey(key, lockQueue)
      }
    }
  }

  /**
   * Removes the key-value pair associated with the given key from the overlay service.
   *
   * @param {string} key - The key to remove.
   * @param {CreateActionOutput[] | undefined} [outputs=undefined] - Additional outputs to include in the removal transaction.
   * @param {KVStoreRemoveOptions} [options=undefined] - Optional parameters for the removal operation.
   * @returns {Promise<HexString>} A promise that resolves to the txid of the removal transaction if successful.
   * @throws {Error} If the key is invalid.
   * @throws {Error} If the key does not exist in the store.
   * @throws {Error} If the overlay service is unreachable or the transaction fails.
   * @throws {Error} If there are existing tokens that cannot be unlocked.
   */
  async remove (key: string, outputs?: CreateActionOutput[], options: KVStoreRemoveOptions = {}): Promise<HexString> {
    if (typeof key !== 'string' || key.length === 0) {
      throw new Error('Key must be a non-empty string.')
    }

    const controller = await this.getIdentityKey()
    const lockQueue = await this.queueOperationOnKey(key)

    const protocolID = options.protocolID ?? this.config.protocolID
    const tokenRemovalDescription = (options.tokenRemovalDescription != null && options.tokenRemovalDescription !== '') ? options.tokenRemovalDescription : `Remove KVStore value for ${key}`

    try {
      const pushdrop = new PushDrop(this.wallet, this.config.originator)

      // Remove token with double-spend retry
      const txid = await withDoubleSpendRetry(async () => {
        // Re-query overlay on each attempt to get fresh token state
        const existingEntries = await this.queryOverlay({ key, controller }, { includeToken: true })

        if (existingEntries.length === 0 || existingEntries[0].token == null) {
          throw new Error('The item did not exist, no item was deleted.')
        }

        const existingToken = existingEntries[0].token
        const inputs: CreateActionInput[] = [{
          outpoint: `${existingToken.txid}.${existingToken.outputIndex}`,
          unlockingScriptLength: 74,
          inputDescription: 'KVStore token to remove'
        }]

        const { signableTransaction } = await this.wallet.createAction({
          description: tokenRemovalDescription,
          inputBEEF: existingToken.beef.toBinary(),
          inputs,
          outputs,
          options: {
            acceptDelayedBroadcast: this.config.acceptDelayedBroadcast,
            randomizeOutputs: false,
            noSend: this.config.overlayBroadcast
          }
        }, this.config.originator)

        if (signableTransaction == null) {
          throw new Error('Unable to create removal transaction')
        }

        const tx = Transaction.fromAtomicBEEF(signableTransaction.tx)
        const unlocker = pushdrop.unlock(
          protocolID ?? this.config.protocolID as WalletProtocol,
          key,
          'anyone'
        )
        const unlockingScript = await unlocker.sign(tx, 0)

        const { tx: finalTx } = await this.wallet.signAction({
          reference: signableTransaction.reference,
          spends: { 0: { unlockingScript: unlockingScript.toHex() } },
          options: {
            acceptDelayedBroadcast: this.config.acceptDelayedBroadcast,
            noSend: this.config.overlayBroadcast
          }
        }, this.config.originator)

        if (finalTx == null) {
          throw new Error('Unable to finalize removal transaction')
        }

        const transaction = Transaction.fromAtomicBEEF(finalTx)
        await this.submitToOverlay(transaction)
        return transaction.id('hex')
      }, this.topicBroadcaster)

      return txid
    } finally {
      if (lockQueue.length > 0) {
        this.finishOperationOnKey(key, lockQueue)
      }
    }
  }

  /**
   * Queues an operation on a specific key to ensure atomic updates.
   * Prevents concurrent operations on the same key from interfering with each other.
   *
   * @param {string} key - The key to queue an operation for.
   * @returns {Promise<Array<(value: void | PromiseLike<void>) => void>>} The lock queue for cleanup.
   * @private
   */
  private async queueOperationOnKey (key: string): Promise<Array<(value: void | PromiseLike<void>) => void>> {
    // Check if a lock exists for this key and wait for it to resolve
    let lockQueue = this.keyLocks.get(key)
    if (lockQueue == null) {
      lockQueue = []
      this.keyLocks.set(key, lockQueue)
    }

    let resolveNewLock: () => void = () => { }
    const newLock = new Promise<void>((resolve) => {
      resolveNewLock = resolve
      if (lockQueue != null) { lockQueue.push(resolve) }
    })

    // If we are the only request, resolve the lock immediately, queue remains at 1 item until request ends.
    if (lockQueue.length === 1) {
      resolveNewLock()
    }

    await newLock
    return lockQueue
  }

  /**
   * Finishes an operation on a key and resolves the next waiting operation.
   *
   * @param {string} key - The key to finish the operation for.
   * @param {Array<(value: void | PromiseLike<void>) => void>} lockQueue - The lock queue from queueOperationOnKey.
   * @private
   */
  private finishOperationOnKey (key: string, lockQueue: Array<(value: void | PromiseLike<void>) => void>): void {
    lockQueue.shift() // Remove the current lock from the queue
    if (lockQueue.length > 0) {
      // If there are more locks waiting, resolve the next one
      lockQueue[0]()
    } else {
      // Clean up empty queue to prevent memory leak
      this.keyLocks.delete(key)
    }
  }

  /**
   * Helper function to fetch and cache user identity key
   *
   * @returns {Promise<PubKeyHex>} The identity key of the current user
   * @private
   */
  private async getIdentityKey (): Promise<PubKeyHex> {
    if (this.cachedIdentityKey == null) {
      this.cachedIdentityKey = (await this.wallet.getPublicKey({ identityKey: true }, this.config.originator)).publicKey
    }
    return this.cachedIdentityKey
  }

  /**
   * Queries the overlay service for KV entries.
   *
   * @param {KVStoreQuery} query - Query parameters sent to overlay
   * @param {KVStoreGetOptions} options - Configuration options for the query
   * @returns {Promise<KVStoreEntry[]>} Array of matching KV entries
   * @private
   */
  private async queryOverlay (query: KVStoreQuery, options: KVStoreGetOptions = {}): Promise<KVStoreEntry[]> {
    const answer = await this.lookupResolver.query({
      service: options.serviceName ?? this.config.serviceName as string,
      query
    })

    if (answer.type !== 'output-list' || answer.outputs.length === 0) {
      return []
    }

    const entries: KVStoreEntry[] = []

    for (const result of answer.outputs) {
      try {
        const tx = Transaction.fromBEEF(result.beef)
        const output = tx.outputs[result.outputIndex]
        const decoded = PushDrop.decode(output.lockingScript)

        // Support backwards compatibility: old format without tags, new format with tags
        const expectedFieldCount = Object.keys(kvProtocol).length
        const hasTagsField = decoded.fields.length === expectedFieldCount
        const isOldFormat = decoded.fields.length === expectedFieldCount - 1

        if (!isOldFormat && !hasTagsField) {
          continue
        }

        // Verify signature
        const anyoneWallet = new ProtoWallet('anyone')
        const signature = decoded.fields.pop() as number[]
        try {
          await anyoneWallet.verifySignature({
            data: decoded.fields.reduce((a, e) => [...a, ...e], []),
            signature,
            counterparty: Utils.toHex(decoded.fields[kvProtocol.controller]),
            protocolID: JSON.parse(Utils.toUTF8(decoded.fields[kvProtocol.protocolID])),
            keyID: Utils.toUTF8(decoded.fields[kvProtocol.key])
          })
        } catch (error) {
          // Skip all outputs that fail signature verification
          continue
        }

        // Extract tags if present (backwards compatible)
        let tags: string[] | undefined
        if (hasTagsField && decoded.fields[kvProtocol.tags] != null) {
          try {
            tags = JSON.parse(Utils.toUTF8(decoded.fields[kvProtocol.tags]))
          } catch (e) {
            // If tags parsing fails, continue without tags
            tags = undefined
          }
        }

        const entry: KVStoreEntry = {
          key: Utils.toUTF8(decoded.fields[kvProtocol.key]),
          value: Utils.toUTF8(decoded.fields[kvProtocol.value]),
          controller: Utils.toHex(decoded.fields[kvProtocol.controller]),
          protocolID: JSON.parse(Utils.toUTF8(decoded.fields[kvProtocol.protocolID])),
          tags
        }

        if (options.includeToken === true) {
          entry.token = {
            txid: tx.id('hex'),
            outputIndex: result.outputIndex,
            beef: Beef.fromBinary(result.beef),
            satoshis: output.satoshis ?? 1
          }
        }

        if (options.history === true) {
          entry.history = await this.historian.buildHistory(tx, {
            key: entry.key,
            protocolID: entry.protocolID
          })
        }

        entries.push(entry)
      } catch (error) {
        continue
      }
    }

    return entries
  }

  /**
   * Submits a transaction to an overlay service using TopicBroadcaster.
   * Broadcasts the transaction to the configured topics for network propagation.
   *
   * @param {Transaction} transaction - The transaction to broadcast.
   * @returns {Promise<BroadcastResponse | BroadcastFailure>} The broadcast result.
   * @throws {Error} If the broadcast fails or the network is unreachable.
   * @private
   */
  private async submitToOverlay (transaction: Transaction): Promise<BroadcastResponse | BroadcastFailure> {
    return await this.topicBroadcaster.broadcast(transaction)
  }
}

export default GlobalKVStore
