// @ts-nocheck
import TransactionInput from './TransactionInput.js'
import TransactionOutput from './TransactionOutput.js'
import UnlockingScript from '../script/UnlockingScript.js'
import LockingScript from '../script/LockingScript.js'
import { Reader, Writer, toHex, toArray, ReaderUint8Array, toUint8Array, WriterUint8Array } from '../primitives/utils.js'
import { hash256 } from '../primitives/Hash.js'
import FeeModel from './FeeModel.js'
import LivePolicy from './fee-models/LivePolicy.js'
import { Broadcaster, BroadcastResponse, BroadcastFailure } from './Broadcaster.js'
import MerklePath from './MerklePath.js'
import Spend from '../script/Spend.js'
import ChainTracker from './ChainTracker.js'
import { defaultBroadcaster } from './broadcasters/DefaultBroadcaster.js'
import { defaultChainTracker } from './chaintrackers/DefaultChainTracker.js'
import { Beef, BEEF_V1 } from './Beef.js'
import P2PKH from '../script/templates/P2PKH.js'

/**
 * Represents a complete Bitcoin transaction. This class encapsulates all the details
 * required for creating, signing, and processing a Bitcoin transaction, including
 * inputs, outputs, and various transaction-related methods.
 *
 * @class Transaction
 * @property {number} version - The version number of the transaction. Used to specify
 *           which set of rules this transaction follows.
 * @property {TransactionInput[]} inputs - An array of TransactionInput objects, representing
 *           the inputs for the transaction. Each input references a previous transaction's output.
 * @property {TransactionOutput[]} outputs - An array of TransactionOutput objects, representing
 *           the outputs for the transaction. Each output specifies the amount of satoshis to be
 *           transferred and the conditions under which they can be spent.
 * @property {number} lockTime - The lock time of the transaction. If non-zero, it specifies the
 *           earliest time or block height at which the transaction can be added to the block chain.
 * @property {Record<string, any>} metadata - A key-value store for attaching additional data to
 *           the transaction object, not included in the transaction itself. Useful for adding descriptions, internal reference numbers, or other information.
 * @property {MerkleProof} [merklePath] - Optional. A merkle proof demonstrating the transaction's
 *           inclusion in a block. Useful for transaction verification using SPV.
 *
 * @example
 * // Creating a new transaction
 * let tx = new Transaction();
 * tx.addInput(...);
 * tx.addOutput(...);
 * await tx.fee();
 * await tx.sign();
 * await tx.broadcast();
 *
 * @description
 * The Transaction class provides comprehensive
 * functionality to handle various aspects of transaction creation, including
 * adding inputs and outputs, computing fees, signing the transaction, and
 * generating its binary or hexadecimal representation.
 */
export default class Transaction {
  version: number
  inputs: TransactionInput[]
  outputs: TransactionOutput[]
  lockTime: number
  metadata: Record<string, any>
  merklePath?: MerklePath
  private cachedHash?: number[]
  private rawBytesCache?: Uint8Array
  private hexCache?: string

  // Recursive function for adding merkle proofs or input transactions
  private static addPathOrInputs (
    obj: { pathIndex?: number, tx: Transaction },
    transactions: Record<
    string,
    {
      pathIndex?: number
      tx: Transaction
    }
    >,
    BUMPs: MerklePath[]
  ): void {
    if (typeof obj.pathIndex === 'number') {
      const path = BUMPs[obj.pathIndex]
      if (typeof path !== 'object') {
        throw new Error('Invalid merkle path index found in BEEF!')
      }
      obj.tx.merklePath = path
    } else {
      for (const input of obj.tx.inputs) {
        if (input.sourceTXID === undefined) {
          throw new Error('Input sourceTXID is undefined')
        }
        const sourceObj = transactions[input.sourceTXID]
        if (typeof sourceObj !== 'object') {
          throw new Error(
            `Reference to unknown TXID in BEEF: ${input.sourceTXID ?? 'undefined'}`
          )
        }
        input.sourceTransaction = sourceObj.tx
        this.addPathOrInputs(sourceObj, transactions, BUMPs)
      }
    }
  }

  /**
   * Creates a new transaction, linked to its inputs and their associated merkle paths, from a BEEF V1, V2 or Atomic.
   * Optionally, you can provide a specific TXID to retrieve a particular transaction from the BEEF data.
   * If the TXID is provided but not found in the BEEF data, an error will be thrown.
   * If no TXID is provided, the last transaction in the BEEF data is returned, or the atomic txid.
   * @param beef A binary representation of transactions in BEEF format.
   * @param txid Optional TXID of the transaction to retrieve from the BEEF data.
   * @returns An anchored transaction, linked to its associated inputs populated with merkle paths.
   */
  static fromBEEF (beef: number[] | Uint8Array, txid?: string): Transaction {
    const { tx } = Transaction.fromAnyBeef(beef, txid)
    return tx
  }

  /**
   * Creates a new transaction from an Atomic BEEF (BRC-95) structure.
   * Extracts the subject transaction and supporting merkle path and source transactions contained in the BEEF data
   *
   * @param beef A binary representation of an Atomic BEEF structure.
   * @returns The subject transaction, linked to its associated inputs populated with merkle paths.
   */
  static fromAtomicBEEF (beef: number[] | Uint8Array): Transaction {
    const { tx, txid, beef: b } = Transaction.fromAnyBeef(beef)
    if (txid !== b.atomicTxid) {
      if (b.atomicTxid != null) {
        throw new Error(`Transaction with TXID ${b.atomicTxid} not found in BEEF data.`)
      } else {
        throw new Error('beef must conform to BRC-95 and must contain the subject txid.')
      }
    }
    return tx
  }

  private static fromAnyBeef (beef: number[] | Uint8Array, txid?: string): { tx: Transaction, beef: Beef, txid: string } {
    const b = Beef.fromBinary(beef)
    if (b.txs.length < 1) {
      throw new Error('beef must include at least one transaction.')
    }
    const target = txid ?? b.atomicTxid ?? b.txs.slice(-1)[0].txid
    const tx = b.findAtomicTransaction(target)
    if (tx == null) {
      if (txid != null) {
        throw new Error(`Transaction with TXID ${target} not found in BEEF data.`)
      } else {
        throw new Error('beef does not contain transaction for atomic txid.')
      }
    }
    return { tx, beef: b, txid: target }
  }

  /**
   * Creates a new transaction, linked to its inputs and their associated merkle paths, from a EF (BRC-30) structure.
   * @param ef A binary representation of a transaction in EF format.
   * @returns An extended transaction, linked to its associated inputs by locking script and satoshis amounts only.
   */
  static fromEF (ef: number[] | Uint8Array): Transaction {
    const br = ReaderUint8Array.makeReader(ef)
    const version = br.readUInt32LE()
    if (toHex(br.read(6)) !== '0000000000ef') { throw new Error('Invalid EF marker') }
    const inputsLength = br.readVarIntNum()
    const inputs: TransactionInput[] = []
    for (let i = 0; i < inputsLength; i++) {
      const sourceTXID = toHex(br.readReverse(32))
      const sourceOutputIndex = br.readUInt32LE()
      const scriptLength = br.readVarIntNum()
      const scriptBin = br.read(scriptLength)
      const unlockingScript = UnlockingScript.fromBinary(scriptBin)
      const sequence = br.readUInt32LE()
      const satoshis = br.readUInt64LEBn().toNumber()
      const lockingScriptLength = br.readVarIntNum()
      const lockingScriptBin = br.read(lockingScriptLength)
      const lockingScript = LockingScript.fromBinary(lockingScriptBin)
      const sourceTransaction = new Transaction(undefined, [], [], undefined)
      sourceTransaction.outputs = Array(sourceOutputIndex + 1).fill(null)
      sourceTransaction.outputs[sourceOutputIndex] = {
        satoshis,
        lockingScript
      }
      inputs.push({
        sourceTransaction,
        sourceTXID,
        sourceOutputIndex,
        unlockingScript,
        sequence
      })
    }
    const outputsLength = br.readVarIntNum()
    const outputs: TransactionOutput[] = []
    for (let i = 0; i < outputsLength; i++) {
      const satoshis = br.readUInt64LEBn().toNumber()
      const scriptLength = br.readVarIntNum()
      const scriptBin = br.read(scriptLength)
      const lockingScript = LockingScript.fromBinary(scriptBin)
      outputs.push({
        satoshis,
        lockingScript
      })
    }
    const lockTime = br.readUInt32LE()
    return new Transaction(version, inputs, outputs, lockTime)
  }

  /**
   * Since the validation of blockchain data is atomically transaction data validation,
   * any application seeking to validate data in output scripts must store the entire transaction as well.
   * Since the transaction data includes the output script data, saving a second copy of potentially
   * large scripts can bloat application storage requirements.
   *
   * This function efficiently parses binary transaction data to determine the offsets and lengths of each script.
   * This supports the efficient retreival of script data from transaction data.
   *
   * @param bin binary transaction data
   * @returns {
   *   inputs: { vin: number, offset: number, length: number }[]
   *   outputs: { vout: number, offset: number, length: number }[]
   * }
   */
  static parseScriptOffsets (bin: number[] | Uint8Array): {
    inputs: Array<{ vin: number, offset: number, length: number }>
    outputs: Array<{ vout: number, offset: number, length: number }>
  } {
    const br = ReaderUint8Array.makeReader(bin)
    const inputs: Array<{ vin: number, offset: number, length: number }> = []
    const outputs: Array<{ vout: number, offset: number, length: number }> = []

    br.pos += 4 // version
    const inputsLength = br.readVarIntNum()
    for (let i = 0; i < inputsLength; i++) {
      br.pos += 36 // txid and vout
      const scriptLength = br.readVarIntNum()
      inputs.push({ vin: i, offset: br.pos, length: scriptLength })
      br.pos += scriptLength + 4 // script and sequence
    }
    const outputsLength = br.readVarIntNum()
    for (let i = 0; i < outputsLength; i++) {
      br.pos += 8 // satoshis
      const scriptLength = br.readVarIntNum()
      outputs.push({ vout: i, offset: br.pos, length: scriptLength })
      br.pos += scriptLength
    }
    return { inputs, outputs }
  }

  static fromReader (br: Reader | ReaderUint8Array): Transaction {
    const version = br.readUInt32LE()
    const inputsLength = br.readVarIntNum()
    const inputs: TransactionInput[] = []
    for (let i = 0; i < inputsLength; i++) {
      const sourceTXID = toHex(br.readReverse(32))
      const sourceOutputIndex = br.readUInt32LE()
      const scriptLength = br.readVarIntNum()
      const scriptBin = br.read(scriptLength)
      const unlockingScript = UnlockingScript.fromBinary(scriptBin)
      const sequence = br.readUInt32LE()
      inputs.push({
        sourceTXID,
        sourceOutputIndex,
        unlockingScript,
        sequence
      })
    }
    const outputsLength = br.readVarIntNum()
    const outputs: TransactionOutput[] = []
    for (let i = 0; i < outputsLength; i++) {
      const satoshis = br.readUInt64LEBn().toNumber()
      const scriptLength = br.readVarIntNum()
      const scriptBin = br.read(scriptLength)
      const lockingScript = LockingScript.fromBinary(scriptBin)
      outputs.push({
        satoshis,
        lockingScript
      })
    }
    const lockTime = br.readUInt32LE()
    return new Transaction(version, inputs, outputs, lockTime)
  }

  /**
   * Creates a Transaction instance from a binary array.
   *
   * @static
   * @param {number[]} bin - The binary array representation of the transaction.
   * @returns {Transaction} - A new Transaction instance.
   */
  static fromBinary (bin: number[] | Uint8Array): Transaction {
    const copy = bin.slice()
    const rawBytes = Uint8Array.from(copy)
    const br = new ReaderUint8Array(rawBytes)
    const tx = Transaction.fromReader(br)
    tx.rawBytesCache = rawBytes
    return tx
  }

  /**
   * Creates a Transaction instance from a hexadecimal string.
   *
   * @static
   * @param {string} hex - The hexadecimal string representation of the transaction.
   * @returns {Transaction} - A new Transaction instance.
   */
  static fromHex (hex: string): Transaction {
    const rawBytes = toUint8Array(hex, 'hex')
    const br = new ReaderUint8Array(rawBytes)
    const tx = Transaction.fromReader(br)
    tx.rawBytesCache = rawBytes
    tx.hexCache = toHex(rawBytes)
    return tx
  }

  /**
   * Creates a Transaction instance from a hexadecimal string encoded EF.
   *
   * @static
   * @param {string} hex - The hexadecimal string representation of the transaction EF.
   * @returns {Transaction} - A new Transaction instance.
   */
  static fromHexEF (hex: string): Transaction {
    return Transaction.fromEF(toUint8Array(hex, 'hex'))
  }

  /**
   * Creates a Transaction instance from a hexadecimal string encoded BEEF.
   * Optionally, you can provide a specific TXID to retrieve a particular transaction from the BEEF data.
   * If the TXID is provided but not found in the BEEF data, an error will be thrown.
   * If no TXID is provided, the last transaction in the BEEF data is returned.
   *
   * @static
   * @param {string} hex - The hexadecimal string representation of the transaction BEEF.
   * @param {string} [txid] - Optional TXID of the transaction to retrieve from the BEEF data.
   * @returns {Transaction} - A new Transaction instance.
   */
  static fromHexBEEF (hex: string, txid?: string): Transaction {
    return Transaction.fromBEEF(toArray(hex, 'hex'), txid)
  }

  constructor (
    version: number = 1,
    inputs: TransactionInput[] = [],
    outputs: TransactionOutput[] = [],
    lockTime: number = 0,
    metadata: Record<string, any> = new Map(),
    merklePath?: MerklePath
  ) {
    this.version = version
    this.inputs = inputs
    this.outputs = outputs
    this.lockTime = lockTime
    this.metadata = metadata
    this.merklePath = merklePath
  }

  private invalidateSerializationCaches (): void {
    this.cachedHash = undefined
    this.rawBytesCache = undefined
    this.hexCache = undefined
  }

  /**
   * Adds a new input to the transaction.
   *
   * @param {TransactionInput} input - The TransactionInput object to add to the transaction.
   * @throws {Error} - If the input does not have a sourceTXID or sourceTransaction defined.
   */
  addInput (input: TransactionInput): void {
    if (
      typeof input.sourceTXID === 'undefined' &&
      typeof input.sourceTransaction === 'undefined'
    ) {
      throw new Error(
        'A reference to an an input transaction is required. If the input transaction itself cannot be referenced, its TXID must still be provided.'
      )
    }
    // If the input sequence number hasn't been set, the expectation is that it is final.
    if (typeof input.sequence === 'undefined') {
      input.sequence = 0xffffffff
    }
    this.invalidateSerializationCaches()
    this.inputs.push(input)
  }

  /**
   * Adds a new output to the transaction.
   *
   * @param {TransactionOutput} output - The TransactionOutput object to add to the transaction.
   */
  addOutput (output: TransactionOutput): void {
    this.cachedHash = undefined
    if (output.change !== true) {
      if (typeof output.satoshis === 'undefined') {
        throw new Error(
          'either satoshis must be defined or change must be set to true'
        )
      }
      if (output.satoshis < 0) { throw new Error('satoshis must be a positive integer or zero') }
    }
    if (output.lockingScript == null) throw new Error('lockingScript must be defined')
    this.outputs.push(output)
  }

  /**
   * Adds a new P2PKH output to the transaction.
   *
   * @param {number[] | string} address - The P2PKH address of the output.
   * @param {number} [satoshis] - The number of satoshis to send to the address - if not provided, the output is considered a change output.
   *
   */
  addP2PKHOutput (address: number[] | string, satoshis?: number): void {
    const lockingScript = new P2PKH().lock(address)
    if (typeof satoshis === 'undefined') {
      return this.addOutput({ lockingScript, change: true })
    }
    this.addOutput({
      lockingScript,
      satoshis
    })
  }

  /**
   * Updates the transaction's metadata.
   *
   * @param {Record<string, any>} metadata - The metadata object to merge into the existing metadata.
   */
  updateMetadata (metadata: Record<string, any>): void {
    this.metadata = {
      ...this.metadata,
      ...metadata
    }
  }

  /**
   * Computes fees prior to signing.
   * If no fee model is provided, uses a LivePolicy fee model that fetches current rates from ARC.
   * If fee is a number, the transaction uses that value as fee.
   *
   * @param modelOrFee - The initialized fee model to use or fixed fee for the transaction
   * @param changeDistribution - Specifies how the change should be distributed
   * amongst the change outputs
   *
   */
  async fee (
    modelOrFee: FeeModel | number = LivePolicy.getInstance(),
    changeDistribution: 'equal' | 'random' = 'equal'
  ): Promise<void> {
    this.invalidateSerializationCaches()
    if (typeof modelOrFee === 'number') {
      const sats = modelOrFee
      modelOrFee = {
        computeFee: async () => sats
      }
    }
    const fee = await modelOrFee.computeFee(this)
    const change = this.calculateChange(fee)
    if (change <= 0) {
      this.outputs = this.outputs.filter((output) => output.change !== true)
      return
    }
    this.distributeChange(change, changeDistribution)
  }

  private calculateChange (fee: number): number {
    let change = 0
    for (const input of this.inputs) {
      if (typeof input.sourceTransaction !== 'object') {
        throw new Error(
          'Source transactions are required for all inputs during fee computation'
        )
      }
      change +=
        input.sourceTransaction.outputs[input.sourceOutputIndex].satoshis ?? 0
    }
    change -= fee
    for (const out of this.outputs) {
      if (out.change !== true) {
        if (out.satoshis !== undefined) {
          change -= out.satoshis
        }
      }
    }
    return change
  }

  private distributeChange (
    change: number,
    changeDistribution: 'equal' | 'random'
  ): void {
    let distributedChange = 0
    const changeOutputs = this.outputs.filter((out) => out.change)
    if (changeDistribution === 'random') {
      distributedChange = this.distributeRandomChange(change, changeOutputs)
    } else if (changeDistribution === 'equal') {
      distributedChange = this.distributeEqualChange(change, changeOutputs)
    }
    if (distributedChange < change) {
      const lastOutput = this.outputs[this.outputs.length - 1]
      if (lastOutput.satoshis !== undefined) {
        lastOutput.satoshis += change - distributedChange
      } else {
        lastOutput.satoshis = change - distributedChange
      }
    }
  }

  private distributeRandomChange (
    change: number,
    changeOutputs: TransactionOutput[]
  ): number {
    let distributedChange = 0
    let changeToUse = change
    const benfordNumbers = Array(changeOutputs.length).fill(1)
    changeToUse -= changeOutputs.length
    distributedChange += changeOutputs.length
    for (let i = 0; i < changeOutputs.length - 1; i++) {
      const portion: number = this.benfordNumber(0, changeToUse)
      benfordNumbers[i] = (benfordNumbers[i] as number) + portion
      distributedChange += portion
      changeToUse -= portion
    }
    for (const output of this.outputs) {
      if (output.change === true) output.satoshis = benfordNumbers.shift()
    }
    return distributedChange
  }

  private distributeEqualChange (
    change: number,
    changeOutputs: TransactionOutput[]
  ): number {
    let distributedChange = 0
    const perOutput = Math.floor(change / changeOutputs.length)
    for (const out of changeOutputs) {
      distributedChange += perOutput
      out.satoshis = perOutput
    }
    return distributedChange
  }

  private benfordNumber (min: number, max: number): number {
    const d = Math.floor(Math.random() * 9) + 1
    return Math.floor(
      min + ((max - min) * Math.log10(1 + 1 / d)) / Math.log10(10)
    )
  }

  /**
   * Utility method that returns the current fee based on inputs and outputs
   *
   * @returns The current transaction fee
   */
  getFee (): number {
    let totalIn = 0
    for (const input of this.inputs) {
      if (typeof input.sourceTransaction !== 'object') {
        throw new Error(
          'Source transactions or sourceSatoshis are required for all inputs to calculate fee'
        )
      }
      totalIn +=
        input.sourceTransaction.outputs[input.sourceOutputIndex].satoshis ?? 0
    }
    let totalOut = 0
    for (const output of this.outputs) {
      totalOut += output.satoshis ?? 0
    }
    return totalIn - totalOut
  }

  /**
   * Signs a transaction, hydrating all its unlocking scripts based on the provided script templates where they are available.
   */
  async sign (): Promise<void> {
    this.invalidateSerializationCaches()
    for (const out of this.outputs) {
      if (typeof out.satoshis === 'undefined') {
        if (out.change === true) {
          throw new Error(
            'There are still change outputs with uncomputed amounts. Use the fee() method to compute the change amounts and transaction fees prior to signing.'
          )
        } else {
          throw new Error(
            'One or more transaction outputs is missing an amount. Ensure all output amounts are provided before signing.'
          )
        }
      }
    }
    const unlockingScripts = await Promise.all(
      this.inputs.map(async (x, i): Promise<UnlockingScript | undefined> => {
        if (typeof this.inputs[i].unlockingScriptTemplate === 'object') {
          return await this.inputs[i]?.unlockingScriptTemplate?.sign(this, i)
        } else {
          return await Promise.resolve(undefined)
        }
      })
    )
    for (let i = 0, l = this.inputs.length; i < l; i++) {
      if (typeof this.inputs[i].unlockingScriptTemplate === 'object') {
        this.inputs[i].unlockingScript = unlockingScripts[i]
      }
    }
  }

  /**
   * Broadcasts a transaction.
   *
   * @param broadcaster The Broadcaster instance wwhere the transaction will be sent
   * @returns A BroadcastResponse or BroadcastFailure from the Broadcaster
   */
  async broadcast (
    broadcaster: Broadcaster = defaultBroadcaster()
  ): Promise<BroadcastResponse | BroadcastFailure> {
    return await broadcaster.broadcast(this)
  }

  private writeTransactionBody (writer: Writer | WriterUint8Array): void {
    writer.writeUInt32LE(this.version)
    writer.writeVarIntNum(this.inputs.length)
    for (const i of this.inputs) {
      if (typeof i.sourceTXID === 'undefined') {
        if (i.sourceTransaction != null) {
          writer.write(i.sourceTransaction.hash() as number[])
        } else {
          throw new Error('sourceTransaction is undefined')
        }
      } else {
        writer.writeReverse(toArray(i.sourceTXID, 'hex'))
      }
      writer.writeUInt32LE(i.sourceOutputIndex)
      if (i.unlockingScript == null) {
        throw new Error('unlockingScript is undefined')
      }
      const scriptBin = i.unlockingScript.toUint8Array()
      writer.writeVarIntNum(scriptBin.length)
      writer.write(scriptBin)
      writer.writeUInt32LE(i.sequence ?? 0xffffffff)
    }
    writer.writeVarIntNum(this.outputs.length)
    for (const o of this.outputs) {
      writer.writeUInt64LE(o.satoshis ?? 0)
      const scriptBin = o.lockingScript.toUint8Array()
      writer.writeVarIntNum(scriptBin.length)
      writer.write(scriptBin)
    }
    writer.writeUInt32LE(this.lockTime)
  }

  private buildSerializedBytes (): Uint8Array {
    const writer = new WriterUint8Array()
    this.writeTransactionBody(writer)
    return writer.toUint8Array()
  }

  private getSerializedBytes (): Uint8Array {
    if (this.rawBytesCache == null) {
      this.rawBytesCache = this.buildSerializedBytes()
    }
    return this.rawBytesCache
  }

  /**
   * Converts the transaction to a binary array format.
   *
   * @returns {number[]} - The binary array representation of the transaction.
   */
  toBinary (): number[] {
    return Array.from(this.getSerializedBytes())
  }

  toUint8Array (): Uint8Array {
    return this.getSerializedBytes()
  }

  private writeEF (writer: Writer | WriterUint8Array): void {
    writer.writeUInt32LE(this.version)
    writer.write([0, 0, 0, 0, 0, 0xef])
    writer.writeVarIntNum(this.inputs.length)
    for (const i of this.inputs) {
      if (typeof i.sourceTransaction === 'undefined') {
        throw new Error(
          'All inputs must have source transactions when serializing to EF format'
        )
      }
      if (typeof i.sourceTXID === 'undefined') {
        writer.write(i.sourceTransaction.hash() as number[])
      } else {
        writer.write(toArray(i.sourceTXID, 'hex').reverse() as number[])
      }
      writer.writeUInt32LE(i.sourceOutputIndex)
      if (i.unlockingScript == null) {
        throw new Error('unlockingScript is undefined')
      }
      const scriptBin = i.unlockingScript.toBinary()
      writer.writeVarIntNum(scriptBin.length)
      writer.write(scriptBin)
      writer.writeUInt32LE(i.sequence ?? 0xffffffff) // default to max sequence
      writer.writeUInt64LE(
        i.sourceTransaction.outputs[i.sourceOutputIndex].satoshis ?? 0
      )
      const lockingScriptBin =
        i.sourceTransaction.outputs[
          i.sourceOutputIndex
        ].lockingScript.toBinary()
      writer.writeVarIntNum(lockingScriptBin.length)
      writer.write(lockingScriptBin)
    }
    writer.writeVarIntNum(this.outputs.length)
    for (const o of this.outputs) {
      writer.writeUInt64LE(o.satoshis ?? 0)
      const scriptBin = o.lockingScript.toBinary()
      writer.writeVarIntNum(scriptBin.length)
      writer.write(scriptBin)
    }
    writer.writeUInt32LE(this.lockTime)
  }

  /**
   * Converts the transaction to a BRC-30 EF format.
   *
   * @returns {number[]} - The BRC-30 EF representation of the transaction.
   */
  toEF (): number[] {
    const writer = new Writer()
    this.writeEF(writer)
    return writer.toArray()
  }

  /**
   * Converts the transaction to a BRC-30 EF format.
   *
   * @returns {Uint8Array} - The BRC-30 EF representation of the transaction.
   */
  toEFUint8Array (): Uint8Array {
    const writer = new WriterUint8Array()
    this.writeEF(writer)
    return writer.toUint8Array()
  }

  /**
   * Converts the transaction to a hexadecimal string EF.
   *
   * @returns {string} - The hexadecimal string representation of the transaction EF.
   */
  toHexEF (): string {
    return toHex(this.toEFUint8Array())
  }

  /**
   * Converts the transaction to a hexadecimal string format.
   *
   * @returns {string} - The hexadecimal string representation of the transaction.
   */
  toHex (): string {
    if (this.hexCache != null) {
      return this.hexCache
    }
    const bytes = this.getSerializedBytes()
    const hex = toHex(bytes)
    this.hexCache = hex
    return hex
  }

  /**
   * Converts the transaction to a hexadecimal string BEEF.
   *
   * @returns {string} - The hexadecimal string representation of the transaction BEEF.
   */
  toHexBEEF (): string {
    return toHex(this.toBEEF())
  }

  /**
   * Converts the transaction to a hexadecimal string Atomic BEEF.
   *
   * @returns {string} - The hexadecimal string representation of the transaction Atomic BEEF.
   */
  toHexAtomicBEEF (): string {
    return toHex(this.toAtomicBEEF())
  }

  /**
   * Calculates the transaction's hash.
   *
   * @param {'hex' | undefined} enc - The encoding to use for the hash. If 'hex', returns a hexadecimal string; otherwise returns a binary array.
   * @returns {string | number[]} - The hash of the transaction in the specified format.
   */
  hash (enc?: 'hex'): number[] | string {
    if (this.cachedHash == null) {
      this.cachedHash = hash256(this.getSerializedBytes())
    }
    if (enc === 'hex') {
      return toHex(this.cachedHash)
    }
    return this.cachedHash
  }

  /**
   * Calculates the transaction's ID in binary array.
   *
   * @returns {number[]} - The ID of the transaction in the binary array format.
   */
  id (): number[]
  /**
   * Calculates the transaction's ID in hexadecimal format.
   *
   * @param {'hex'} enc - The encoding to use for the ID. If 'hex', returns a hexadecimal string.
   * @returns {string} - The ID of the transaction in the hex format.
   */
  id (enc: 'hex'): string
  /**
   * Calculates the transaction's ID.
   *
   * @param {'hex' | undefined} enc - The encoding to use for the ID. If 'hex', returns a hexadecimal string; otherwise returns a binary array.
   * @returns {string | number[]} - The ID of the transaction in the specified format.
   */
  id (enc?: 'hex'): number[] | string {
    const id = [...(this.hash() as number[])]
    id.reverse()
    if (enc === 'hex') {
      return toHex(id)
    }
    return id
  }

  /**
   * Verifies the legitimacy of the Bitcoin transaction according to the rules of SPV by ensuring all the input transactions link back to valid block headers, the chain of spends for all inputs are valid, and the sum of inputs is not less than the sum of outputs.
   *
   * @param chainTracker - An instance of ChainTracker, a Bitcoin block header tracker. If the value is set to 'scripts only', headers will not be verified. If not provided then the default chain tracker will be used.
   * @param feeModel - An instance of FeeModel, a fee model to use for fee calculation. If not provided then the default fee model will be used.
   * @param memoryLimit - The maximum memory in bytes usage allowed for script evaluation. If not provided then the default memory limit will be used.
   *
   * @returns Whether the transaction is valid according to the rules of SPV.
   *
   * @example tx.verify(new WhatsOnChain(), LivePolicy.getInstance())
   */
  async verify (
    chainTracker: ChainTracker | 'scripts only' = defaultChainTracker(),
    feeModel?: FeeModel,
    memoryLimit?: number
  ): Promise<boolean> {
    const verifiedTxids = new Set<string>()
    const txQueue: Transaction[] = [this]

    while (txQueue.length > 0) {
      const tx = txQueue.shift()
      const txid = tx?.id('hex') ?? ''
      if (txid != null && txid !== '' && verifiedTxids.has(txid)) {
        continue
      }

      // If the transaction has a valid merkle path, verification is complete.
      if (typeof tx?.merklePath === 'object') {
        if (chainTracker === 'scripts only') {
          if (txid != null) {
            verifiedTxids.add(txid)
          }
          continue
        } else {
          const proofValid = await tx.merklePath.verify(txid, chainTracker)
          // If the proof is valid, no need to verify inputs.
          if (proofValid) {
            verifiedTxids.add(txid)
            continue
          } else {
            throw new Error(`Invalid merkle path for transaction ${txid}`)
          }
        }
      }

      // Verify fee if feeModel is provided
      if (typeof feeModel !== 'undefined') {
        if (tx === undefined) {
          throw new Error('Transaction is undefined')
        }
        const cpTx = Transaction.fromEF(tx.toEF())
        delete cpTx.outputs[0].satoshis
        cpTx.outputs[0].change = true
        await cpTx.fee(feeModel)
        if (tx.getFee() < cpTx.getFee()) {
          throw new Error(
            `Verification failed because the transaction ${txid} has an insufficient fee and has not been mined.`
          )
        }
      }

      // Verify each input transaction and evaluate the spend events.
      // Also, keep a total of the input amounts for later.
      let inputTotal = 0
      if (tx === undefined) {
        throw new Error('Transaction is undefined')
      }
      for (let i = 0; i < tx.inputs.length; i++) {
        const input = tx.inputs[i]
        if (typeof input.sourceTransaction !== 'object') {
          throw new Error(
            `Verification failed because the input at index ${i} of transaction ${txid} is missing an associated source transaction. This source transaction is required for transaction verification because there is no merkle proof for the transaction spending a UTXO it contains.`
          )
        }
        if (typeof input.unlockingScript !== 'object') {
          throw new Error(
            `Verification failed because the input at index ${i} of transaction ${txid} is missing an associated unlocking script. This script is required for transaction verification because there is no merkle proof for the transaction spending the UTXO.`
          )
        }
        const sourceOutput =
          input.sourceTransaction.outputs[input.sourceOutputIndex]
        inputTotal += sourceOutput.satoshis ?? 0

        const sourceTxid = input.sourceTransaction.id('hex')
        if (!verifiedTxids.has(sourceTxid)) {
          txQueue.push(input.sourceTransaction)
        }

        const otherInputs = tx.inputs.filter((_, idx) => idx !== i)
        if (typeof input.sourceTXID === 'undefined') {
          input.sourceTXID = sourceTxid
        }

        const spend = new Spend({
          sourceTXID: input.sourceTXID,
          sourceOutputIndex: input.sourceOutputIndex,
          lockingScript: sourceOutput.lockingScript,
          sourceSatoshis: sourceOutput.satoshis ?? 0,
          transactionVersion: tx.version,
          otherInputs,
          unlockingScript: input.unlockingScript,
          inputSequence: input.sequence ?? 0xffffffff, // default to max sequence
          inputIndex: i,
          outputs: tx.outputs,
          lockTime: tx.lockTime,
          memoryLimit
        })
        const spendValid = spend.validate()

        if (!spendValid) {
          return false
        }
      }

      // Total the outputs to ensure they don't amount to more than the inputs
      let outputTotal = 0
      for (const out of tx.outputs) {
        if (typeof out.satoshis !== 'number') {
          throw new Error(
            'Every output must have a defined amount during transaction verification.'
          )
        }
        outputTotal += out.satoshis
      }

      if (outputTotal > inputTotal) {
        return false
      }

      verifiedTxids.add(txid)
    }

    return true
  }

  /**
   * Serializes this transaction, together with its inputs and the respective merkle proofs, into the BEEF (BRC-62) format. This enables efficient verification of its compliance with the rules of SPV.
   *
   * @param allowPartial If true, error will not be thrown if there are any missing sourceTransactions.
   *
   * @returns The serialized BEEF structure
   * @throws Error if there are any missing sourceTransactions unless `allowPartial` is true.
   */
  writeSerializedBEEF (writer: Writer | WriterUint8Array, allowPartial?: boolean): void {
    writer.writeUInt32LE(BEEF_V1)
    const BUMPs: MerklePath[] = []
    const bumpIndexByInstance = new Map<MerklePath, number>()
    const bumpIndexByRoot = new Map<string, number>()
    const txs: Array<{ tx: Transaction, pathIndex?: number }> = []
    const seenTxids = new Set<string>()

    const getBumpIndex = (merklePath: MerklePath): number => {
      const existingByInstance = bumpIndexByInstance.get(merklePath)
      if (existingByInstance !== undefined) {
        return existingByInstance
      }

      const key = `${merklePath.blockHeight}:${merklePath.computeRoot()}`
      const existingByRoot = bumpIndexByRoot.get(key)
      if (existingByRoot !== undefined) {
        BUMPs[existingByRoot].combine(merklePath)
        bumpIndexByInstance.set(merklePath, existingByRoot)
        return existingByRoot
      }

      const newIndex = BUMPs.length
      BUMPs.push(merklePath)
      bumpIndexByInstance.set(merklePath, newIndex)
      bumpIndexByRoot.set(key, newIndex)
      return newIndex
    }

    // Recursive function to add paths and input transactions for a TX
    const addPathsAndInputs = (tx: Transaction): void => {
      const txid = tx.id('hex')
      if (seenTxids.has(txid)) {
        return
      }

      const obj: { tx: Transaction, pathIndex?: number } = { tx }
      const merklePath = tx.merklePath
      const hasProof = typeof merklePath === 'object'

      if (hasProof && merklePath != null) {
        obj.pathIndex = getBumpIndex(merklePath)
      }

      if (!hasProof) {
        for (let i = tx.inputs.length - 1; i >= 0; i--) {
          const input = tx.inputs[i]
          if (typeof input.sourceTransaction === 'object') {
            addPathsAndInputs(input.sourceTransaction)
          } else if (allowPartial === false) {
            throw new Error('A required source transaction is missing!')
          }
        }
      }

      seenTxids.add(txid)
      txs.push(obj)
    }

    addPathsAndInputs(this)

    writer.writeVarIntNum(BUMPs.length)
    for (const b of BUMPs) {
      writer.write(b.toBinary())
    }
    writer.writeVarIntNum(txs.length)
    for (const t of txs) {
      writer.write(t.tx.toBinary())
      if (typeof t.pathIndex === 'number') {
        writer.writeUInt8(1)
        writer.writeVarIntNum(t.pathIndex)
      } else {
        writer.writeUInt8(0)
      }
    }
    return writer.toArray()
  }

  /**
   * Serializes this transaction, together with its inputs and the respective merkle proofs, into the BEEF (BRC-62) format. This enables efficient verification of its compliance with the rules of SPV.
   *
   * @param allowPartial If true, error will not be thrown if there are any missing sourceTransactions.
   *
   * @returns {number[]} The serialized BEEF structure
   * @throws Error if there are any missing sourceTransactions unless `allowPartial` is true.
   */
  toBEEF (allowPartial?: boolean): number[] {
    const writer = new Writer()
    this.writeSerializedBEEF(writer, allowPartial)
    return writer.toArray()
  }

  /**
   * Serializes this transaction, together with its inputs and the respective merkle proofs, into the BEEF (BRC-62) format. This enables efficient verification of its compliance with the rules of SPV.
   *
   * @param allowPartial If true, error will not be thrown if there are any missing sourceTransactions.
   *
   * @returns {number[]} The serialized BEEF structure
   * @throws Error if there are any missing sourceTransactions unless `allowPartial` is true.
   */
  toBEEFUint8Array (allowPartial?: boolean): Uint8Array {
    const writer = new WriterUint8Array()
    this.writeSerializedBEEF(writer, allowPartial)
    return writer.toArray()
  }

  /**
   * Serializes this transaction and its inputs into the Atomic BEEF (BRC-95) format.
   * The Atomic BEEF format starts with a 4-byte prefix `0x01010101`, followed by the TXID of the subject transaction,
   * and then the BEEF data containing only the subject transaction and its dependencies.
   * This format ensures that the BEEF structure is atomic and contains no unrelated transactions.
   *
   * @param allowPartial If true, error will not be thrown if there are any missing sourceTransactions.
   *
   * @returns {number[]} - The serialized Atomic BEEF structure.
   * @throws Error if there are any missing sourceTransactions unless `allowPartial` is true.
   */
  toAtomicBEEF (allowPartial?: boolean): number[] {
    const prefix = [1, 1, 1, 1]
    const txHash = this.hash() as number[]
    const beefData = this.toBEEF(allowPartial)
    return prefix.concat(txHash, beefData)
  }

  /**
   * Serializes this transaction and its inputs into the Atomic BEEF (BRC-95) format.
   * The Atomic BEEF format starts with a 4-byte prefix `0x01010101`, followed by the TXID of the subject transaction,
   * and then the BEEF data containing only the subject transaction and its dependencies.
   * This format ensures that the BEEF structure is atomic and contains no unrelated transactions.
   *
   * @param allowPartial If true, error will not be thrown if there are any missing sourceTransactions.
   *
   * @returns {number[]} - The serialized Atomic BEEF structure.
   * @throws Error if there are any missing sourceTransactions unless `allowPartial` is true.
   */
  toAtomicBEEFUint8Array (allowPartial?: boolean): Uint8Array {
    const writer = new WriterUint8Array()
    const prefix = [1, 1, 1, 1]
    writer.write(prefix)
    const txHash = this.hash() as number[]
    writer.write(txHash)
    this.writeSerializedBEEF(writer, allowPartial)
    return writer.toUint8Array()
  }
}
