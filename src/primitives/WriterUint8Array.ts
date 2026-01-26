import { Writer } from './utils.js'

export class WriterUint8Array {
  private buffer: Uint8Array
  private pos: number
  private capacity: number

  constructor(initialCapacity: number = 256) {
    this.buffer = new Uint8Array(initialCapacity)
    this.pos = 0
    this.capacity = initialCapacity
  }

  private ensureCapacity(needed: number): void {
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

  write(bytes: Uint8Array | number[]): void {
    const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
    this.ensureCapacity(data.length)
    this.buffer.set(data, this.pos)
    this.pos += data.length
  }

  writeUInt8(value: number): void {
    this.ensureCapacity(1)
    this.buffer[this.pos] = value & 0xff
    this.pos += 1
  }

  writeInt8(value: number): void {
    this.writeUInt8(value < 0 ? value + 0x100 : value)
  }

  writeUInt16LE(value: number): void {
    this.ensureCapacity(2)
    this.buffer[this.pos]     = value & 0xff
    this.buffer[this.pos + 1] = (value >>> 8) & 0xff
    this.pos += 2
  }

  writeUInt16BE(value: number): void {
    this.ensureCapacity(2)
    this.buffer[this.pos]     = (value >>> 8) & 0xff
    this.buffer[this.pos + 1] = value & 0xff
    this.pos += 2
  }

  writeInt16LE(value: number): void {
    this.writeUInt16LE(value < 0 ? value + 0x10000 : value)
  }

  writeInt16BE(value: number): void {
    this.writeUInt16BE(value < 0 ? value + 0x10000 : value)
  }

  writeUInt32LE(value: number): void {
    this.ensureCapacity(4)
    this.buffer[this.pos]     = value & 0xff
    this.buffer[this.pos + 1] = (value >>> 8)  & 0xff
    this.buffer[this.pos + 2] = (value >>> 16) & 0xff
    this.buffer[this.pos + 3] = (value >>> 24) & 0xff
    this.pos += 4
  }

  writeUInt32BE(value: number): void {
    this.ensureCapacity(4)
    this.buffer[this.pos]     = (value >>> 24) & 0xff
    this.buffer[this.pos + 1] = (value >>> 16) & 0xff
    this.buffer[this.pos + 2] = (value >>> 8)  & 0xff
    this.buffer[this.pos + 3] = value & 0xff
    this.pos += 4
  }

  writeInt32LE(value: number): void {
    this.writeUInt32LE(value < 0 ? value + 0x100000000 : value)
  }

  writeInt32BE(value: number): void {
    this.writeUInt32BE(value < 0 ? value + 0x100000000 : value)
  }

  writeVarIntNum(value: number): void {
    if (value < 0xfd) {
      this.writeUInt8(value)
    } else if (value <= 0xffff) {
      this.writeUInt8(0xfd)
      this.writeUInt16LE(value)
    } else if (value <= 0xffffffff) {
      this.writeUInt8(0xfe)
      this.writeUInt32LE(value)
    } else {
      this.writeUInt8(0xff)
      // For values > 2^32-1 you'd normally need writeUInt64LE,
      // but since JS numbers are safe up to 2^53, we can approximate:
      this.writeUInt32LE(value & 0xffffffff)
      this.writeUInt32LE(Math.floor(value / 0x100000000))
    }
  }

  // ---------------------------------------------------------------------------
  // Output methods – prefer toUint8Array()
  // ---------------------------------------------------------------------------

  /**
   * Preferred modern method – returns the written data as Uint8Array
   * (zero-copy slice of the internal buffer)
   */
  toUint8Array(): Uint8Array {
    return this.buffer.subarray(0, this.pos)
  }

  /**
   * Legacy compatibility method – returns number[] (Byte[])
   */
  toArray(): number[] {
    return Array.from(this.toUint8Array())
  }

  /**
   * Returns the current length of written data
   */
  getLength(): number {
    return this.pos
  }

  /**
   * Resets the writer to empty state (reuses the buffer)
   */
  reset(): void {
    this.pos = 0
  }
}