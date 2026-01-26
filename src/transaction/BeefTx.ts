import { hash256 } from '../primitives/Hash.js'
import { Reader, Writer, toHex, toArray, ReaderUint8Array, WriterUint8Array } from '../primitives/utils.js'
import Transaction from './Transaction.js'
import { BEEF_V2, TX_DATA_FORMAT } from './Beef.js'

/**
 * A single bitcoin transaction associated with a `Beef` validity proof set.
 *
 * Simple case is transaction data included directly, either as raw bytes or fully parsed data, or both.
 *
 * Supports 'known' transactions which are represented by just their txid.
 * It is assumed that intended consumer of this beef already has validity proof for such a transaction,
 * which they can merge if necessary to create a valid beef.
 */
export default class BeefTx {
  _bumpIndex?: number
  _tx?: Transaction
  _rawTx?: Uint8Array // ← changed to Uint8Array internally
  _txid?: string
  inputTxids: string[] = []
  /**
   * true if `hasProof` or all inputs chain to `hasProof`.
   *
   * Typically set by sorting transactions by proven dependency chains.
   */
  isValid?: boolean = undefined

  get bumpIndex (): number | undefined {
    return this._bumpIndex
  }

  set bumpIndex (v: number | undefined) {
    this._bumpIndex = v
    this.updateInputTxids()
  }

  get hasProof (): boolean {
    return this._bumpIndex !== undefined
  }

  get isTxidOnly (): boolean {
    return this._txid !== undefined && this._txid !== null && (this._rawTx == null) && (this._tx == null)
  }

  get txid (): string {
    if (this._txid !== undefined && this._txid !== null && this._txid !== '') return this._txid
    if (this._tx != null) {
      this._txid = this._tx.id('hex')
      return this._txid
    }
    if (this._rawTx != null) {
      this._txid = toHex(hash256(this._rawTx))
      return this._txid
    }
    throw new Error('Internal')
  }

  get tx (): Transaction | undefined {
    if (this._tx != null) return this._tx
    if (this._rawTx != null) {
      this._tx = Transaction.fromBinary(this._rawTx)
      return this._tx
    }
    return undefined
  }

  /**
   * Legacy compatibility getter — returns number[] (Byte[])
   */
  get rawTx (): number[] | undefined {
    if (this._rawTx != null) {
      return Array.from(this._rawTx)
    }
    if (this._tx != null) {
      const bytes = this._tx.toUint8Array()
      this._rawTx = bytes // cache
      return Array.from(bytes)
    }
    return undefined
  }

  /**
   * Preferred modern getter — returns Uint8Array (zero-copy where possible)
   */
  get rawTxUint8Array (): Uint8Array | undefined {
    if (this._rawTx != null) return this._rawTx
    if (this._tx != null) {
      this._rawTx = this._tx.toUint8Array()
      return this._rawTx
    }
    return undefined
  }

  /**
   * @param tx If string, must be a valid txid. If `number[]` must be a valid serialized transaction.
   * @param bumpIndex If transaction already has a proof in the beef to which it will be added.
   */
  constructor (tx: Transaction | Uint8Array | number[] | string, bumpIndex?: number) {
    if (typeof tx === 'string') {
      this._txid = tx
    } else if (tx instanceof Uint8Array) {
      this._rawTx = tx
    } else if (Array.isArray(tx)) {
      this._rawTx = new Uint8Array(tx)
    } else if (tx instanceof Transaction) {
      this._tx = tx
    } else {
      throw new Error('Invalid transaction data type')
    }
    this.bumpIndex = bumpIndex
    this.updateInputTxids()
  }

  static fromTx (tx: Transaction, bumpIndex?: number): BeefTx {
    return new BeefTx(tx, bumpIndex)
  }

  static fromRawTx (rawTx: Uint8Array | number[], bumpIndex?: number): BeefTx {
    return new BeefTx(rawTx, bumpIndex)
  }

  static fromTxid (txid: string, bumpIndex?: number): BeefTx {
    return new BeefTx(txid, bumpIndex)
  }

  private updateInputTxids (): void {
    if (this.hasProof || (this.tx == null)) {
      // If we have a proof, or don't have a parsed transaction
      this.inputTxids = []
    } else {
      const inputTxids: Set<string> = new Set() // minor perf improvement
      for (const input of this.tx.inputs) {
        if (input.sourceTXID !== undefined && input.sourceTXID !== null && input.sourceTXID !== '') {
          inputTxids.add(input.sourceTXID)
        }
      }
      this.inputTxids = Array.from(inputTxids)
    }
  }

  toWriter (writer: Writer | WriterUint8Array, version: number): void {
    const writeByte = (bb: number): void => {
      writer.writeUInt8(bb)
    }

    const writeTxid = (): void => {
      if (this._txid == null) {
        throw new Error('Transaction ID (_txid) is undefined')
      }
      writer.writeReverse(toArray(this._txid, 'hex'))
    }

    const writeTx = (): void => {
      const bytes = this.rawTxUint8Array
      if (bytes == null) {
        throw new Error('a valid serialized Transaction is expected')
      }
      writer.write(bytes)
    }

    const writeBumpIndex = (): void => {
      if (this.bumpIndex === undefined) {
        writeByte(TX_DATA_FORMAT.RAWTX) // 0
      } else {
        writeByte(TX_DATA_FORMAT.RAWTX_AND_BUMP_INDEX) // 1
        writer.writeVarIntNum(this.bumpIndex) // the index of the associated bump
      }
    }

    if (version === BEEF_V2) {
      if (this.isTxidOnly) {
        writeByte(TX_DATA_FORMAT.TXID_ONLY)
        writeTxid()
      } else if (this.bumpIndex !== undefined) {
        writeByte(TX_DATA_FORMAT.RAWTX_AND_BUMP_INDEX)
        writer.writeVarIntNum(this.bumpIndex)
        writeTx()
      } else {
        writeByte(TX_DATA_FORMAT.RAWTX)
        writeTx()
      }
    } else {
      writeTx()
      writeBumpIndex()
    }
  }

  static fromReader (br: Reader | ReaderUint8Array, version: number): BeefTx {
    let data: Transaction | undefined
    let bumpIndex: number | undefined
    let beefTx: BeefTx | undefined
    if (version === BEEF_V2) {
      // V2
      const format = br.readUInt8()
      if (format === TX_DATA_FORMAT.TXID_ONLY) {
        beefTx = BeefTx.fromTxid(toHex(br.readReverse(32)))
      } else {
        if (format === TX_DATA_FORMAT.RAWTX_AND_BUMP_INDEX) {
          bumpIndex = br.readVarIntNum()
        }
        data = Transaction.fromReader(br)
        beefTx = BeefTx.fromTx(data, bumpIndex)
      }
    } else {
      // V1
      data = Transaction.fromReader(br)
      bumpIndex = br.readUInt8() !== 0 ? br.readVarIntNum() : undefined
      beefTx = BeefTx.fromTx(data, bumpIndex)
    }

    return beefTx
  }
}
