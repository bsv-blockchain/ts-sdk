import BigNumber from './BigNumber.js'
import { Reader } from './utils.js'

/**
 * Reader for serialized Uint8Array binary data.
 */
export class ReaderUint8Array {
  public bin: Uint8Array
  public pos: number
  private readonly length: number

  static makeReader (bin: Uint8Array | number[], pos: number = 0): Reader | ReaderUint8Array {
    if (bin instanceof Uint8Array) {
      return new ReaderUint8Array(bin, pos)
    }
    if (Array.isArray(bin)) {
      return new Reader(bin, pos)
    }
    throw new Error('ReaderUint8Array.makeReader: bin must be Uint8Array or number[]')
  }

  constructor (bin: Uint8Array | number[] = new Uint8Array(0), pos: number = 0) {
    if (bin instanceof Uint8Array) {
      this.bin = bin
    } else if (Array.isArray(bin)) {
      this.bin = new Uint8Array(bin)
    } else {
      throw new Error('ReaderUint8Array constructor: bin must be Uint8Array or number[]')
    }
    this.pos = pos
    this.length = this.bin.length
  }

  public eof (): boolean {
    return this.pos >= this.length
  }

  public read (len = this.length): Uint8Array {
    const start = this.pos
    const end = this.pos + len
    this.pos = end
    return this.bin.slice(start, end)
  }

  public readReverse (len = this.length): Uint8Array {
    const buf2 = new Uint8Array(len)
    for (let i = 0; i < len; i++) {
      buf2[i] = this.bin[this.pos + len - 1 - i]
    }
    this.pos += len
    return buf2
  }

  public readUInt8 (): number {
    const val = this.bin[this.pos]
    this.pos += 1
    return val
  }

  public readInt8 (): number {
    const val = this.bin[this.pos]
    this.pos += 1
    // If the sign bit is set, convert to negative value
    return (val & 0x80) !== 0 ? val - 0x100 : val
  }

  public readUInt16BE (): number {
    const val = (this.bin[this.pos] << 8) | this.bin[this.pos + 1]
    this.pos += 2
    return val
  }

  public readInt16BE (): number {
    const val = this.readUInt16BE()
    // If the sign bit is set, convert to negative value
    return (val & 0x8000) !== 0 ? val - 0x10000 : val
  }

  public readUInt16LE (): number {
    const val = this.bin[this.pos] | (this.bin[this.pos + 1] << 8)
    this.pos += 2
    return val
  }

  public readInt16LE (): number {
    const val = this.readUInt16LE()
    // If the sign bit is set, convert to negative value
    const x = (val & 0x8000) !== 0 ? val - 0x10000 : val
    return x
  }

  public readUInt32BE (): number {
    const val =
      this.bin[this.pos] * 0x1000000 + // Shift the first byte by 24 bits
      ((this.bin[this.pos + 1] << 16) | // Shift the second byte by 16 bits
        (this.bin[this.pos + 2] << 8) | // Shift the third byte by 8 bits
        this.bin[this.pos + 3]) // The fourth byte
    this.pos += 4
    return val
  }

  public readInt32BE (): number {
    const val = this.readUInt32BE()
    // If the sign bit is set, convert to negative value
    return (val & 0x80000000) !== 0 ? val - 0x100000000 : val
  }

  public readUInt32LE (): number {
    const val =
      (this.bin[this.pos] |
        (this.bin[this.pos + 1] << 8) |
        (this.bin[this.pos + 2] << 16) |
        (this.bin[this.pos + 3] << 24)) >>>
      0
    this.pos += 4
    return val
  }

  public readInt32LE (): number {
    const val = this.readUInt32LE()
    // Explicitly check if the sign bit is set and then convert to a negative value
    return (val & 0x80000000) !== 0 ? val - 0x100000000 : val
  }

  public readUInt64BEBn (): BigNumber {
    const bin = Array.from(this.bin.slice(this.pos, this.pos + 8))
    const bn = new BigNumber(bin)
    this.pos = this.pos + 8
    return bn
  }

  public readUInt64LEBn (): BigNumber {
    const bin = Array.from(this.readReverse(8))
    const bn = new BigNumber(bin)
    return bn
  }

  public readInt64LEBn (): BigNumber {
    const OverflowInt64 = new BigNumber(2).pow(new BigNumber(63))
    const OverflowUint64 = new BigNumber(2).pow(new BigNumber(64))
    const bin = Array.from(this.readReverse(8))
    let bn = new BigNumber(bin)
    if (bn.gte(OverflowInt64)) {
      bn = bn.sub(OverflowUint64) // Adjust for negative numbers
    }
    return bn
  }

  public readVarIntNum (signed: boolean = true): number {
    const first = this.readUInt8()
    let bn: BigNumber
    switch (first) {
      case 0xfd:
        return this.readUInt16LE()
      case 0xfe:
        return this.readUInt32LE()
      case 0xff:
        bn = signed ? this.readInt64LEBn() : this.readUInt64LEBn()
        if (bn.lte(new BigNumber(2).pow(new BigNumber(53)))) {
          return bn.toNumber()
        } else {
          throw new Error('number too large to retain precision - use readVarIntBn')
        }
      default:
        return first
    }
  }

  public readVarInt (): Uint8Array {
    const first = this.bin[this.pos]
    switch (first) {
      case 0xfd:
        return this.read(1 + 2)
      case 0xfe:
        return this.read(1 + 4)
      case 0xff:
        return this.read(1 + 8)
      default:
        return this.read(1)
    }
  }

  public readVarIntBn (): BigNumber {
    const first = this.readUInt8()
    switch (first) {
      case 0xfd:
        return new BigNumber(this.readUInt16LE())
      case 0xfe:
        return new BigNumber(this.readUInt32LE())
      case 0xff:
        return this.readUInt64LEBn()
      default:
        return new BigNumber(first)
    }
  }
}
