import BigNumber from './BigNumber.js'
import { Writer } from './utils.js'

type WriterChunk = readonly number[] | Uint8Array

/**
 * WriterUint8Array is a utility class for writing binary data into a dynamically
 * growing Uint8Array buffer. It provides methods to write various integer types
 * and variable-length integers, similar to the Writer class but optimized for
 * Uint8Array usage.
 */
export class WriterUint8Array {
  private buffer: Uint8Array
  private pos: number
  private capacity: number

  constructor (bufs?: WriterChunk[], initialCapacity: number = 256) {
    if ((bufs != null) && bufs.length > 0) {
      const totalLength = bufs.reduce((sum, buf) => sum + buf.length, 0)
      initialCapacity = Math.max(initialCapacity, totalLength)
    }
    this.buffer = new Uint8Array(initialCapacity)
    this.pos = 0
    this.capacity = initialCapacity
    if (bufs != null) {
      for (const buf of bufs) {
        this.write(buf)
      }
    }
  }

  /**
   * Returns the current length of written data
   */
  getLength (): number {
    return this.pos
  }

  /**
   * @return the written data as Uint8Array copy of the internal buffer
   */
  toUint8Array (): Uint8Array {
    return this.buffer.slice(0, this.pos)
  }

  /**
   * Legacy compatibility method – returns number[] (Byte[])
   */
  toArray (): number[] {
    return Array.from(this.toUint8Array())
  }

  /**
   * @return the written data as Uint8Array. CAUTION: This is zero-copy subarray of the internal buffer).
   */
  toUint8ArrayZeroCopy (): Uint8Array {
    return this.buffer.subarray(0, this.pos)
  }

  private ensureCapacity (needed: number): void {
    if (this.pos + needed > this.capacity) {
      let newCapacity = this.capacity * 2
      while (this.pos + needed > newCapacity) {
        newCapacity *= 2
      }
      const newBuffer = new Uint8Array(newCapacity)
      newBuffer.set(this.buffer)
      this.buffer = newBuffer
      this.capacity = newCapacity
    }
  }

  write (bytes: WriterChunk): this {
    const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
    this.ensureCapacity(data.length)
    this.buffer.set(data, this.pos)
    this.pos += data.length
    return this
  }

  writeReverse (buf: WriterChunk): this {
    const data = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
    this.ensureCapacity(data.length)
    for (let i = data.length - 1; i >= 0; i--) {
      this.buffer[this.pos] = data[i]
      this.pos += 1
    }
    return this
  }

  writeUInt8 (value: number): this {
    this.ensureCapacity(1)
    this.buffer[this.pos] = value & 0xff
    this.pos += 1
    return this
  }

  writeInt8 (value: number): this {
    this.writeUInt8(value)
    return this
  }

  writeUInt16LE (value: number): this {
    this.ensureCapacity(2)
    this.buffer[this.pos] = value & 0xff
    this.buffer[this.pos + 1] = (value >> 8) & 0xff
    this.pos += 2
    return this
  }

  writeUInt16BE (value: number): this {
    this.ensureCapacity(2)
    this.buffer[this.pos] = (value >> 8) & 0xff
    this.buffer[this.pos + 1] = value & 0xff
    this.pos += 2
    return this
  }

  writeInt16LE (value: number): this {
    this.writeUInt16LE(value & 0xffff)
    return this
  }

  writeInt16BE (value: number): this {
    this.writeUInt16BE(value & 0xffff)
    return this
  }

  writeUInt32LE (value: number): this {
    this.ensureCapacity(4)
    this.buffer[this.pos] = value & 0xff
    this.buffer[this.pos + 1] = (value >> 8) & 0xff
    this.buffer[this.pos + 2] = (value >> 16) & 0xff
    this.buffer[this.pos + 3] = (value >> 24) & 0xff
    this.pos += 4
    return this
  }

  writeUInt32BE (value: number): this {
    this.ensureCapacity(4)
    this.buffer[this.pos] = (value >> 24) & 0xff
    this.buffer[this.pos + 1] = (value >> 16) & 0xff
    this.buffer[this.pos + 2] = (value >> 8) & 0xff
    this.buffer[this.pos + 3] = value & 0xff
    this.pos += 4
    return this
  }

  writeInt32LE (value: number): this {
    this.writeUInt32LE(value >>> 0)
    return this
  }

  writeInt32BE (value: number): this {
    this.writeUInt32BE(value >>> 0)
    return this
  }

  writeUInt64BEBn (bn: BigNumber): this {
    const buf = bn.toArray('be', 8)
    this.write(buf)
    return this
  }

  writeUInt64LEBn (bn: BigNumber): this {
    const buf = bn.toArray('be', 8)
    this.writeReverse(buf)
    return this
  }

  writeUInt64LE (n: number): this {
    const buf = new BigNumber(n).toArray('be', 8)
    this.writeReverse(buf)
    return this
  }

  writeVarIntNum (n: number): this {
    const buf = Writer.varIntNum(n)
    this.write(buf)
    return this
  }

  writeVarIntBn (bn: BigNumber): this {
    const buf = Writer.varIntBn(bn)
    this.write(buf)
    return this
  }

  /**
   * Resets the writer to empty state (reuses the buffer)
   */
  reset (): void {
    this.pos = 0
  }
}
