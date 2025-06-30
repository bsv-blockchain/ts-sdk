import LockingScript from '../script/LockingScript.js'
import PushDrop from '../script/templates/PushDrop.js'
import * as Utils from '../primitives/utils.js'
import { WalletInterface, OutpointString, CreateActionInput, SignActionSpend, WalletProtocol, ListOutputsResult, WalletOutput, AtomicBEEF } from '../wallet/Wallet.interfaces.js'
import WalletClient from '../wallet/WalletClient.js'
import Transaction from '../transaction/Transaction.js'
import { Beef } from '../transaction/Beef.js'

/**
 * Implements a key-value storage system backed by transaction outputs managed by a wallet.
 * Each key-value pair is represented by a PushDrop token output in a specific context (basket).
 * Allows setting, getting, and removing key-value pairs, with optional encryption.
 */
export default class LocalKVStore {
  /**
   * The wallet interface used to manage outputs and perform cryptographic operations.
   * @private
   * @readonly
   */
  private readonly wallet: WalletInterface
  /**
   * The context (basket name) used to namespace the key-value pairs within the wallet.
   * @private
   * @readonly
   */
  private readonly context: string
  /**
   * Flag indicating whether values should be encrypted before storing.
   * @private
   * @readonly
   */
  private readonly encrypt: boolean

  /**
   * An originator to use with PushDrop and the wallet.
   * @private
   * @readonly
   */
  private readonly originator?: string

  acceptDelayedBroadcast: boolean = false

  /**
   * A map to store locks for each key to ensure atomic updates.
   * @private
   */
  private readonly keyLocks: Map<string, Array<(value: void | PromiseLike<void>) => void>> = new Map()

  /**
   * Creates an instance of the localKVStore.
   *
   * @param {WalletInterface} [wallet=new WalletClient()] - The wallet interface to use. Defaults to a new WalletClient instance.
   * @param {string} [context='kvstoredefault'] - The context (basket) for namespacing keys. Defaults to 'kvstore default'.
   * @param {boolean} [encrypt=true] - Whether to encrypt values. Defaults to true.
   * @param {string} [originator] — An originator to use with PushDrop and the wallet, if provided.
   * @throws {Error} If the context is missing or empty.
   */
  constructor (
    wallet: WalletInterface = new WalletClient(),
    context = 'kvstore default',
    encrypt = true,
    originator?: string,
    acceptDelayedBroadcast = false
  ) {
    if (typeof context !== 'string' || context.length < 1) {
      throw new Error('A context in which to operate is required.')
    }
    this.wallet = wallet
    this.context = context
    this.encrypt = encrypt
    this.originator = originator
    this.acceptDelayedBroadcast = acceptDelayedBroadcast
  }

  private async queueOperationOnKey (key: string): Promise<Array<(value: void | PromiseLike<void>) => void>> {
    // Check if a lock exists for this key and wait for it to resolve
    let lockQueue = this.keyLocks.get(key)
    if (lockQueue == null) {
      lockQueue = []
      this.keyLocks.set(key, lockQueue)
    }

    let resolveNewLock: () => void = () => {}
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

  private finishOperationOnKey (key: string, lockQueue: Array<(value: void | PromiseLike<void>) => void>): void {
    lockQueue.shift() // Remove the current lock from the queue
    if (lockQueue.length > 0) {
      // If there are more locks waiting, resolve the next one
      lockQueue[0]()
    }
  }

  private getProtocol (key: string): { protocolID: WalletProtocol, keyID: string } {
    return { protocolID: [2, this.context], keyID: key }
  }

  private async getOutputs (key: string, limit?: number): Promise<ListOutputsResult> {
    const results = await this.wallet.listOutputs({
      basket: this.context,
      tags: [key],
      tagQueryMode: 'all',
      include: 'entire transactions',
      limit
    })
    return results
  }

  /**
   * Retrieves the value associated with a given key.
   *
   * @param {string} key - The key to retrieve the value for.
   * @param {string | undefined} [defaultValue=undefined] - The value to return if the key is not found.
   * @returns {Promise<string | undefined>} A promise that resolves to the value as a string,
   *   the defaultValue if the key is not found, or undefined if no defaultValue is provided.
   * @throws {Error} If too many outputs are found for the key (ambiguous state).
   * @throws {Error} If the found output's locking script cannot be decoded or represents an invalid token format.
   */
  async get (key: string, defaultValue: string | undefined = undefined): Promise<string | undefined> {
    const lockQueue = await this.queueOperationOnKey(key)

    try {
      const r = await this.lookupValue(key, defaultValue, 5)
      return r.value
    } finally {
      this.finishOperationOnKey(key, lockQueue)
    }
  }

  private getLockingScript (output: WalletOutput, beef: Beef): LockingScript {
    const [txid, vout] = output.outpoint.split('.')
    const tx = beef.findTxid(txid)?.tx
    if (tx == null) { throw new Error(`beef must contain txid ${txid}`) }
    const lockingScript = tx.outputs[Number(vout)].lockingScript
    return lockingScript
  }

  private async lookupValue (key: string, defaultValue: string | undefined, limit?: number): Promise<LookupValueResult> {
    const lor = await this.getOutputs(key, limit)
    const r: LookupValueResult = { value: defaultValue, outpoint: undefined, lor }
    const { outputs } = lor
    if (outputs.length === 0) {
      return r
    }
    const output = outputs.slice(-1)[0]
    r.outpoint = output.outpoint
    let field: number[]
    try {
      if (lor.BEEF === undefined) { throw new Error('entire transactions listOutputs option must return valid BEEF') }
      const lockingScript = this.getLockingScript(output, Beef.fromBinary(lor.BEEF))
      const decoded = PushDrop.decode(lockingScript)
      if (decoded.fields.length < 1 || decoded.fields.length > 2) {
        throw new Error('Invalid token.')
      }
      field = decoded.fields[0]
    } catch (_) {
      throw new Error(`Invalid value found. You need to call set to collapse the corrupted state (or relinquish the corrupted ${outputs[0].outpoint} output from the ${this.context} basket) before you can get this value again.`)
    }
    if (!this.encrypt) {
      r.value = Utils.toUTF8(field)
    } else {
      const { plaintext } = await this.wallet.decrypt({
        ...this.getProtocol(key),
        ciphertext: field
      })
      r.value = Utils.toUTF8(plaintext)
    }
    return r
  }

  private getInputs (outputs: WalletOutput[]): CreateActionInput[] {
    const inputs: CreateActionInput[] = []
    for (let i = 0; i < outputs.length; i++) {
      inputs.push({
        outpoint: outputs[i].outpoint,
        unlockingScriptLength: 74,
        inputDescription: 'Previous key-value token'
      })
    }
    return inputs
  }

  private async getSpends (key: string, outputs: WalletOutput[], pushdrop: PushDrop, atomicBEEF: AtomicBEEF): Promise<Record<number, SignActionSpend>> {
    const p = this.getProtocol(key)
    const tx = Transaction.fromAtomicBEEF(atomicBEEF)
    const spends: Record<number, SignActionSpend> = {}
    for (let i = 0; i < outputs.length; i++) {
      const unlocker = pushdrop.unlock(p.protocolID, p.keyID, 'self')
      const unlockingScript = await unlocker.sign(tx, i)
      spends[i] = {
        unlockingScript: unlockingScript.toHex()
      }
    }
    return spends
  }

  /**
   * Sets or updates the value associated with a given key atomically.
   * If the key already exists (one or more outputs found), it spends the existing output(s)
   * and creates a new one with the updated value. If multiple outputs exist for the key,
   * they are collapsed into a single new output.
   * If the key does not exist, it creates a new output.
   * Handles encryption if enabled.
   * If signing the update/collapse transaction fails, it relinquishes the original outputs and starts over with a new chain.
   * Ensures atomicity by locking the key during the operation, preventing concurrent updates
   * to the same key from missing earlier changes.
   *
   * @param {string} key - The key to set or update.
   * @param {string} value - The value to associate with the key.
   * @returns {Promise<OutpointString>} A promise that resolves to the outpoint string (txid.vout) of the new or updated token output.
   */
  async set (key: string, value: string): Promise<OutpointString> {
    const lockQueue = await this.queueOperationOnKey(key)

    try {
      const current = await this.lookupValue(key, undefined, 10)
      if (current.value === value) {
        if (current.outpoint === undefined) {
          throw new Error('outpoint must be valid when value is valid and unchanged')
        }
        // Don't create a new transaction if the value doesn't need to change
        return current.outpoint
      }

      const protocol = this.getProtocol(key)
      let valueAsArray = Utils.toArray(value, 'utf8')
      if (this.encrypt) {
        const { ciphertext } = await this.wallet.encrypt({
          ...protocol,
          plaintext: valueAsArray
        })
        valueAsArray = ciphertext
      }

      const pushdrop = new PushDrop(this.wallet, this.originator)
      const lockingScript = await pushdrop.lock(
        [valueAsArray],
        protocol.protocolID,
        protocol.keyID,
        'self'
      )

      const { outputs, BEEF: inputBEEF } = current.lor
      let outpoint: OutpointString
      try {
        const inputs = this.getInputs(outputs)
        const { txid, signableTransaction } = await this.wallet.createAction({
          description: `Update ${key} in ${this.context}`,
          inputBEEF,
          inputs,
          outputs: [{
            basket: this.context,
            tags: [key],
            lockingScript: lockingScript.toHex(),
            satoshis: 1,
            outputDescription: 'Key-value token'
          }],
          options: {
            acceptDelayedBroadcast: this.acceptDelayedBroadcast,
            randomizeOutputs: false
          }
        })

        if (outputs.length > 0 && typeof signableTransaction !== 'object') {
          throw new Error('Wallet did not return a signable transaction when expected.')
        }

        if (signableTransaction == null) {
          outpoint = `${txid as string}.0`
        } else {
          const spends = await this.getSpends(key, outputs, pushdrop, signableTransaction.tx)
          const { txid } = await this.wallet.signAction({
            reference: signableTransaction.reference,
            spends
          })
          outpoint = `${txid as string}.0`
        }
      } catch (_) {
        throw new Error(`There are ${outputs.length} outputs with tag ${key} that cannot be unlocked.`)
      }

      return outpoint
    } finally {
      this.finishOperationOnKey(key, lockQueue)
    }
  }

  /**
   * Removes the key-value pair associated with the given key.
   * It finds the existing output(s) for the key and spends them without creating a new output.
   * If multiple outputs exist, they are all spent in the same transaction.
   * If the key does not exist, it does nothing.
   * If signing the removal transaction fails, it relinquishes the original outputs instead of spending.
   *
   * @param {string} key - The key to remove.
   * @returns {Promise<string[]>} A promise that resolves to the txids of the removal transactions if successful.
   */
  async remove (key: string): Promise<string[]> {
    const lockQueue = await this.queueOperationOnKey(key)

    try {
      const txids: string[] = []
      for (; ;) {
        const { outputs, BEEF: inputBEEF, totalOutputs } = await this.getOutputs(key)
        if (outputs.length > 0) {
          const pushdrop = new PushDrop(this.wallet, this.originator)
          try {
            const inputs = this.getInputs(outputs)
            const { signableTransaction } = await this.wallet.createAction({
              description: `Remove ${key} in ${this.context}`,
              inputBEEF,
              inputs,
              options: {
                acceptDelayedBroadcast: this.acceptDelayedBroadcast
              }
            })
            if (typeof signableTransaction !== 'object') {
              throw new Error('Wallet did not return a signable transaction when expected.')
            }
            const spends = await this.getSpends(key, outputs, pushdrop, signableTransaction.tx)
            const { txid } = await this.wallet.signAction({
              reference: signableTransaction.reference,
              spends
            })
            if (txid === undefined) { throw new Error('signAction must return a valid txid') }
            txids.push(txid)
          } catch (_) {
            throw new Error(`There are ${totalOutputs} outputs with tag ${key} that cannot be unlocked.`)
          }
        }
        if (outputs.length === totalOutputs) { break }
      }
      return txids
    } finally {
      this.finishOperationOnKey(key, lockQueue)
    }
  }
}

interface LookupValueResult {
  value: string | undefined
  outpoint: OutpointString | undefined
  lor: ListOutputsResult
}
