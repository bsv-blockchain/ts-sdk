import ScriptChunk from './ScriptChunk.js'
import OP from './OP.js'
import { encode, toHex, toArray } from '../primitives/utils.js'
import BigNumber from '../primitives/BigNumber.js'

/**
 * The Script class represents a script in a Bitcoin SV transaction,
 * encapsulating the functionality to construct, parse, and serialize
 * scripts used in both locking (output) and unlocking (input) scripts.
 *
 * @property {ScriptChunk[]} chunks - An array of script chunks that make up the script.
 */
const BufferCtor =
  typeof globalThis !== 'undefined' ? (globalThis as any).Buffer : undefined

export default class Script {
  private _chunks: ScriptChunk[]
  private parsed: boolean
  private rawBytesCache?: Uint8Array
  private hexCache?: string

  /**
   * @method fromASM
   * Static method to construct a Script instance from an ASM (Assembly) formatted string.
   * @param asm - The script in ASM string format.
   * @returns A new Script instance.
   * @example
   * const script = Script.fromASM("OP_DUP OP_HASH160 abcd... OP_EQUALVERIFY OP_CHECKSIG")
   */
  static fromASM (asm: string): Script {
    const chunks: ScriptChunk[] = []
    const tokens = asm.split(' ')
    let i = 0
    while (i < tokens.length) {
      const token = tokens[i]
      let opCode
      let opCodeNum: number = 0
      if (token.startsWith('OP_') && typeof OP[token] !== 'undefined') {
        opCode = token
        opCodeNum = OP[token]
      }

      // we start with two special cases, 0 and -1, which are handled specially in
      // toASM. see _chunkToString.
      if (token === '0') {
        opCodeNum = 0
        chunks.push({
          op: opCodeNum
        })
        i = i + 1
      } else if (token === '-1') {
        opCodeNum = OP.OP_1NEGATE
        chunks.push({
          op: opCodeNum
        })
        i = i + 1
      } else if (opCode === undefined) {
        let hex = tokens[i]
        if (hex.length % 2 !== 0) {
          hex = '0' + hex
        }
        const arr = toArray(hex, 'hex')
        if (encode(arr, 'hex') !== hex) {
          throw new Error('invalid hex string in script')
        }
        const len = arr.length
        if (len >= 0 && len < OP.OP_PUSHDATA1) {
          opCodeNum = len
        } else if (len < Math.pow(2, 8)) {
          opCodeNum = OP.OP_PUSHDATA1
        } else if (len < Math.pow(2, 16)) {
          opCodeNum = OP.OP_PUSHDATA2
        } else if (len < Math.pow(2, 32)) {
          opCodeNum = OP.OP_PUSHDATA4
        }
        chunks.push({
          data: arr,
          op: opCodeNum
        })
        i = i + 1
      } else if (
        opCodeNum === OP.OP_PUSHDATA1 ||
        opCodeNum === OP.OP_PUSHDATA2 ||
        opCodeNum === OP.OP_PUSHDATA4
      ) {
        chunks.push({
          data: toArray(tokens[i + 2], 'hex'),
          op: opCodeNum
        })
        i = i + 3
      } else {
        chunks.push({
          op: opCodeNum
        })
        i = i + 1
      }
    }
    return new Script(chunks)
  }

  /**
   * @method fromHex
   * Static method to construct a Script instance from a hexadecimal string.
   * @param hex - The script in hexadecimal format.
   * @returns A new Script instance.
   * @example
   * const script = Script.fromHex("76a9...");
   */
  static fromHex (hex: string): Script {
    if (hex.length === 0) return Script.fromBinary([])
    if (hex.length % 2 !== 0) {
      throw new Error(
        'There is an uneven number of characters in the string which suggests it is not hex encoded.'
      )
    }
    if (!/^[0-9a-fA-F]+$/.test(hex)) {
      throw new Error('Some elements in this string are not hex encoded.')
    }
    const bin = toArray(hex, 'hex')
    const rawBytes = Uint8Array.from(bin)
    return new Script([], rawBytes, hex.toLowerCase(), false)
  }

  /**
   * @method fromBinary
   * Static method to construct a Script instance from a binary array.
   * @param bin - The script in binary array format.
   * @param legacyData - If true, arbitrary data following an OP_RETURN is parsed as a single data chunk.
   * @returns A new Script instance.
   * @example
   * const script = Script.fromBinary([0x76, 0xa9, ...])
   */
  static fromBinary (bin: number[]): Script {
    const rawBytes = Uint8Array.from(bin)
    return new Script([], rawBytes, undefined, false)
  }

  /**
   * @constructor
   * Constructs a new Script object.
   * @param chunks=[] - An array of script chunks to directly initialize the script.
   * @param rawBytesCache - Optional serialized bytes that can be reused instead of reserializing `chunks`.
   * @param hexCache - Optional lowercase hex string that matches the serialized bytes, used to satisfy `toHex` quickly.
   * @param parsed - When false the script defers parsing `rawBytesCache` until `chunks` is accessed; defaults to true.
   */
  constructor (chunks: ScriptChunk[] = [], rawBytesCache?: Uint8Array, hexCache?: string, parsed: boolean = true) {
    this._chunks = chunks
    this.parsed = parsed
    this.rawBytesCache = rawBytesCache
    this.hexCache = hexCache
  }

  get chunks (): ScriptChunk[] {
    this.ensureParsed()
    return this._chunks
  }

  set chunks (value: ScriptChunk[]) {
    this._chunks = value
    this.parsed = true
    this.invalidateSerializationCaches()
  }

  private ensureParsed (): void {
    if (this.parsed) return
    if (this.rawBytesCache != null) {
      this._chunks = Script.parseChunks(this.rawBytesCache)
    } else {
      this._chunks = []
    }
    this.parsed = true
  }

  /**
   * @method toASM
   * Serializes the script to an ASM formatted string.
   * @returns The script in ASM string format.
   */
  toASM (): string {
    let str = ''
    for (let i = 0; i < this.chunks.length; i++) {
      const chunk = this.chunks[i]
      str += this._chunkToString(chunk)
    }

    return str.slice(1)
  }

  /**
   * @method toHex
   * Serializes the script to a hexadecimal string.
   * @returns The script in hexadecimal format.
   */
  toHex (): string {
    if (this.hexCache != null) {
      return this.hexCache
    }
    if (this.rawBytesCache == null) {
      this.rawBytesCache = this.serializeChunksToBytes()
    }
    const hex =
      BufferCtor != null
        ? BufferCtor.from(this.rawBytesCache).toString('hex')
        : (encode(Array.from(this.rawBytesCache), 'hex') as string)
    this.hexCache = hex
    return hex
  }

  /**
   * @method toBinary
   * Serializes the script to a binary array.
   * @returns The script in binary array format.
   */
  toBinary (): number[] {
    return Array.from(this.toUint8Array())
  }

  toUint8Array (): Uint8Array {
    if (this.rawBytesCache == null) {
      this.rawBytesCache = this.serializeChunksToBytes()
    }
    return this.rawBytesCache
  }

  /**
   * @method writeScript
   * Appends another script to this script.
   * @param script - The script to append.
   * @returns This script instance for chaining.
   */
  writeScript (script: Script): Script {
    this.invalidateSerializationCaches()
    this.chunks = this.chunks.concat(script.chunks)
    return this
  }

  /**
   * @method writeOpCode
   * Appends an opcode to the script.
   * @param op - The opcode to append.
   * @returns This script instance for chaining.
   */
  writeOpCode (op: number): Script {
    this.invalidateSerializationCaches()
    this.chunks.push({ op })
    return this
  }

  /**
   * @method setChunkOpCode
   * Sets the opcode of a specific chunk in the script.
   * @param i - The index of the chunk.
   * @param op - The opcode to set.
   * @returns This script instance for chaining.
   */
  setChunkOpCode (i: number, op: number): Script {
    this.invalidateSerializationCaches()
    this.chunks[i] = { op }
    return this
  }

  /**
   * @method writeBn
   * Appends a BigNumber to the script as an opcode.
   * @param bn - The BigNumber to append.
   * @returns This script instance for chaining.
   */
  writeBn (bn: BigNumber): Script {
    this.invalidateSerializationCaches()
    if (bn.cmpn(0) === OP.OP_0) {
      this.chunks.push({
        op: OP.OP_0
      })
    } else if (bn.cmpn(-1) === 0) {
      this.chunks.push({
        op: OP.OP_1NEGATE
      })
    } else if (bn.cmpn(1) >= 0 && bn.cmpn(16) <= 0) {
      // see OP_1 - OP_16
      this.chunks.push({
        op: bn.toNumber() + OP.OP_1 - 1
      })
    } else {
      const buf = bn.toSm('little')
      this.writeBin(buf)
    }
    return this
  }

  /**
   * @method writeBin
   * Appends binary data to the script, determining the appropriate opcode based on length.
   * @param bin - The binary data to append.
   * @returns This script instance for chaining.
   * @throws {Error} Throws an error if the data is too large to be pushed.
   */
  writeBin (bin: number[]): Script {
    this.invalidateSerializationCaches()
    let op: number
    const data = bin.length > 0 ? bin : undefined
    if (bin.length > 0 && bin.length < OP.OP_PUSHDATA1) {
      op = bin.length
    } else if (bin.length === 0) {
      op = OP.OP_0
    } else if (bin.length < Math.pow(2, 8)) {
      op = OP.OP_PUSHDATA1
    } else if (bin.length < Math.pow(2, 16)) {
      op = OP.OP_PUSHDATA2
    } else if (bin.length < Math.pow(2, 32)) {
      op = OP.OP_PUSHDATA4
    } else {
      throw new Error("You can't push that much data")
    }
    this.chunks.push({
      data,
      op
    })
    return this
  }

  /**
   * @method writeNumber
   * Appends a number to the script.
   * @param num - The number to append.
   * @returns This script instance for chaining.
   */
  writeNumber (num: number): Script {
    this.invalidateSerializationCaches()
    this.writeBn(new BigNumber(num))
    return this
  }

  /**
   * @method removeCodeseparators
   * Removes all OP_CODESEPARATOR opcodes from the script.
   * @returns This script instance for chaining.
   */
  removeCodeseparators (): Script {
    this.invalidateSerializationCaches()
    const chunks: ScriptChunk[] = []
    for (let i = 0; i < this.chunks.length; i++) {
      if (this.chunks[i].op !== OP.OP_CODESEPARATOR) {
        chunks.push(this.chunks[i])
      }
    }
    this.chunks = chunks
    return this
  }

  /**
   * Deletes the given item wherever it appears in the current script.
   *
   * @param script - The script containing the item to delete from the current script.
   *
   * @returns This script instance for chaining.
   */
  findAndDelete (script: Script): Script {
    this.invalidateSerializationCaches()
    const buf = script.toHex()
    for (let i = 0; i < this.chunks.length;) {
      const script2 = new Script([this.chunks[i]])
      const buf2 = script2.toHex()
      if (buf === buf2) {
        this.chunks.splice(i, 1)
      } else {
        i++
      }
    }
    return this
  }

  /**
   * @method isPushOnly
   * Checks if the script contains only push data operations.
   * @returns True if the script is push-only, otherwise false.
   */
  isPushOnly (): boolean {
    for (let i = 0; i < this.chunks.length; i++) {
      const chunk = this.chunks[i]
      const opCodeNum = chunk.op
      if (opCodeNum > OP.OP_16) {
        return false
      }
    }
    return true
  }

  /**
   * @method isLockingScript
   * Determines if the script is a locking script.
   * @returns True if the script is a locking script, otherwise false.
   */
  isLockingScript (): boolean {
    throw new Error('Not implemented')
  }

  /**
   * @method isUnlockingScript
   * Determines if the script is an unlocking script.
   * @returns True if the script is an unlocking script, otherwise false.
   */
  isUnlockingScript (): boolean {
    throw new Error('Not implemented')
  }

  /**
   * @private
   * @method _chunkToString
   * Converts a script chunk to its string representation.
   * @param chunk - The script chunk.
   * @returns The string representation of the chunk.
   */
  private static computeSerializedLength (chunks: ScriptChunk[]): number {
    let total = 0
    for (const chunk of chunks) {
      total += 1
      if (chunk.data == null) continue
      const len = chunk.data.length
      if (chunk.op === OP.OP_RETURN) {
        total += len
        break
      }
      if (chunk.op < OP.OP_PUSHDATA1) {
        total += len
      } else if (chunk.op === OP.OP_PUSHDATA1) {
        total += 1 + len
      } else if (chunk.op === OP.OP_PUSHDATA2) {
        total += 2 + len
      } else if (chunk.op === OP.OP_PUSHDATA4) {
        total += 4 + len
      }
    }
    return total
  }

  private serializeChunksToBytes (): Uint8Array {
    const chunks = this.chunks
    const totalLength = Script.computeSerializedLength(chunks)
    const bytes = new Uint8Array(totalLength)
    let offset = 0

    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i]
      bytes[offset++] = chunk.op
      if (chunk.data == null) continue
      if (chunk.op === OP.OP_RETURN) {
        bytes.set(chunk.data, offset)
        offset += chunk.data.length
        break
      }
      offset = Script.writeChunkData(bytes, offset, chunk.op, chunk.data)
    }

    return bytes
  }

  private invalidateSerializationCaches (): void {
    this.rawBytesCache = undefined
    this.hexCache = undefined
  }

  private static writeChunkData (
    target: Uint8Array,
    offset: number,
    op: number,
    data: number[]
  ): number {
    const len = data.length
    if (op < OP.OP_PUSHDATA1) {
      target.set(data, offset)
      return offset + len
    } else if (op === OP.OP_PUSHDATA1) {
      target[offset++] = len & 0xff
      target.set(data, offset)
      return offset + len
    } else if (op === OP.OP_PUSHDATA2) {
      target[offset++] = len & 0xff
      target[offset++] = (len >> 8) & 0xff
      target.set(data, offset)
      return offset + len
    } else if (op === OP.OP_PUSHDATA4) {
      const size = len >>> 0
      target[offset++] = size & 0xff
      target[offset++] = (size >> 8) & 0xff
      target[offset++] = (size >> 16) & 0xff
      target[offset++] = (size >> 24) & 0xff
      target.set(data, offset)
      return offset + len
    }
    return offset
  }

  private static parseChunks (bytes: ArrayLike<number>): ScriptChunk[] {
    const chunks: ScriptChunk[] = []
    const length = bytes.length
    let pos = 0
    let inConditionalBlock = 0

    while (pos < length) {
      const op = bytes[pos++] ?? 0

      if (op === OP.OP_RETURN && inConditionalBlock === 0) {
        chunks.push({
          op,
          data: Script.copyRange(bytes, pos, length)
        })
        break
      }

      if (
        op === OP.OP_IF ||
        op === OP.OP_NOTIF ||
        op === OP.OP_VERIF ||
        op === OP.OP_VERNOTIF
      ) {
        inConditionalBlock++
      } else if (op === OP.OP_ENDIF) {
        inConditionalBlock--
      }

      if (op > 0 && op < OP.OP_PUSHDATA1) {
        const len = op
        const end = Math.min(pos + len, length)
        chunks.push({
          data: Script.copyRange(bytes, pos, end),
          op
        })
        pos = end
      } else if (op === OP.OP_PUSHDATA1) {
        const len = pos < length ? bytes[pos++] ?? 0 : 0
        const end = Math.min(pos + len, length)
        chunks.push({
          data: Script.copyRange(bytes, pos, end),
          op
        })
        pos = end
      } else if (op === OP.OP_PUSHDATA2) {
        const b0 = bytes[pos] ?? 0
        const b1 = bytes[pos + 1] ?? 0
        const len = b0 | (b1 << 8)
        pos = Math.min(pos + 2, length)
        const end = Math.min(pos + len, length)
        chunks.push({
          data: Script.copyRange(bytes, pos, end),
          op
        })
        pos = end
      } else if (op === OP.OP_PUSHDATA4) {
        const len =
          ((bytes[pos] ?? 0) |
            ((bytes[pos + 1] ?? 0) << 8) |
            ((bytes[pos + 2] ?? 0) << 16) |
            ((bytes[pos + 3] ?? 0) << 24)) >>>
          0
        pos = Math.min(pos + 4, length)
        const end = Math.min(pos + len, length)
        chunks.push({
          data: Script.copyRange(bytes, pos, end),
          op
        })
        pos = end
      } else {
        chunks.push({ op })
      }
    }

    return chunks
  }

  private static copyRange (
    bytes: ArrayLike<number>,
    start: number,
    end: number
  ): number[] {
    const size = Math.max(end - start, 0)
    const data = new Array(size)
    for (let i = 0; i < size; i++) {
      data[i] = bytes[start + i] ?? 0
    }
    return data
  }

  private _chunkToString (chunk: ScriptChunk): string {
    const op = chunk.op
    let str = ''
    if (typeof chunk.data === 'undefined') {
      const val = OP[op] as string
      str = `${str} ${val}`
    } else {
      str = `${str} ${toHex(chunk.data)}`
    }
    return str
  }
}
