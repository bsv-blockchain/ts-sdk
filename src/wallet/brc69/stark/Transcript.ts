import { sha256 } from '../../../primitives/Hash.js'
import { toArray } from '../../../primitives/utils.js'
import { F, FieldElement, GOLDILOCKS_MODULUS } from './Field.js'

export const STARK_CORE_TRANSCRIPT_PREFIX = 'BRC69_STARK_CORE_V1'

export class FiatShamirTranscript {
  private state: number[]
  private counter = 0

  constructor (domain: string) {
    const domainBytes = toArray(domain, 'utf8')
    this.state = sha256([
      ...toArray(STARK_CORE_TRANSCRIPT_PREFIX, 'utf8'),
      ...u32(domainBytes.length),
      ...domainBytes
    ])
  }

  absorb (label: string, data: number[]): void {
    assertBytes(data)
    const labelBytes = toArray(label, 'utf8')
    this.state = sha256([
      ...this.state,
      ...u32(labelBytes.length),
      ...labelBytes,
      ...u32(data.length),
      ...data
    ])
    this.counter = 0
  }

  absorbFieldElement (label: string, value: FieldElement): void {
    this.absorb(label, F.toBytesLE(value))
  }

  absorbFieldElements (label: string, values: FieldElement[]): void {
    const bytes: number[] = []
    for (const value of values) bytes.push(...F.toBytesLE(value))
    this.absorb(label, bytes)
  }

  challengeBytes (label: string, length: number): number[] {
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new Error('Challenge byte length must be a non-negative safe integer')
    }
    const out: number[] = []
    const labelBytes = toArray(label, 'utf8')
    while (out.length < length) {
      const block = sha256([
        ...this.state,
        ...u32(this.counter++),
        ...u32(labelBytes.length),
        ...labelBytes
      ])
      out.push(...block)
    }
    return out.slice(0, length)
  }

  challengeFieldElement (label: string): FieldElement {
    for (let attempt = 0; attempt < 1024; attempt++) {
      const value = readBigIntLE(
        this.challengeBytes(`${label}:field:${attempt}`, 8)
      )
      if (value < GOLDILOCKS_MODULUS) return value
    }
    throw new Error('Unable to sample field challenge')
  }

  challengeIndex (label: string, size: number): number {
    if (!Number.isSafeInteger(size) || size < 1) {
      throw new Error('Challenge index size must be positive')
    }
    const modulus = BigInt(size)
    const sampleSpace = 1n << 64n
    const limit = sampleSpace - (sampleSpace % modulus)
    for (let attempt = 0; attempt < 1024; attempt++) {
      const value = readBigIntLE(
        this.challengeBytes(`${label}:index:${attempt}`, 8)
      )
      if (value < limit) return Number(value % modulus)
    }
    throw new Error('Unable to sample index challenge')
  }
}

function u32 (value: number): number[] {
  assertU32(value)
  return [
    value & 0xff,
    (value >>> 8) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 24) & 0xff
  ]
}

function assertU32 (value: number): void {
  if (
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > 0xffffffff
  ) {
    throw new Error('Transcript length exceeds u32 range')
  }
}

function readBigIntLE (bytes: number[]): bigint {
  assertBytes(bytes)
  let value = 0n
  for (let i = 0; i < bytes.length; i++) {
    value |= BigInt(bytes[i]) << BigInt(i * 8)
  }
  return value
}

function assertBytes (bytes: number[]): void {
  for (const byte of bytes) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error('Invalid byte value')
    }
  }
}
