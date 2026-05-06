import { U16, U256Limbs } from './Types.js'

export const U16_BITS = 16
export const U16_RADIX = 1 << U16_BITS
export const U256_LIMBS = 16
export const U512_LIMBS = 32

export function assertU16 (value: number): U16 {
  if (!Number.isInteger(value) || value < 0 || value >= U16_RADIX) {
    throw new Error('Expected a canonical u16 limb')
  }
  return value
}

export function assertBit (value: number): 0 | 1 {
  if (value !== 0 && value !== 1) {
    throw new Error('Expected a bit')
  }
  return value
}

export function assertByte (value: number): number {
  if (!Number.isInteger(value) || value < 0 || value > 255) {
    throw new Error('Expected a byte')
  }
  return value
}

export function toBitsLE (value: bigint, width: number): number[] {
  if (value < 0n) throw new Error('Cannot decompose negative values')
  if (!Number.isSafeInteger(width) || width < 1) {
    throw new Error('Bit width must be positive')
  }
  if (value >= (1n << BigInt(width))) {
    throw new Error('Value exceeds bit width')
  }
  const bits = new Array<number>(width)
  let v = value
  for (let i = 0; i < width; i++) {
    bits[i] = Number(v & 1n)
    v >>= 1n
  }
  return bits
}

export function bitsToBigintLE (bits: number[]): bigint {
  let value = 0n
  for (let i = bits.length - 1; i >= 0; i--) {
    value = (value << 1n) | BigInt(assertBit(bits[i]))
  }
  return value
}

export function bigintToU16LimbsLE (
  value: bigint,
  limbCount: number
): U16[] {
  if (value < 0n) throw new Error('Cannot decompose negative values')
  assertLimbCount(limbCount)
  if (value >= (1n << BigInt(limbCount * U16_BITS))) {
    throw new Error('Value exceeds limb width')
  }
  const limbs = new Array<U16>(limbCount)
  let v = value
  for (let i = 0; i < limbCount; i++) {
    limbs[i] = Number(v & 0xffffn)
    v >>= 16n
  }
  return limbs
}

export function u16LimbsToBigintLE (limbs: number[]): bigint {
  assertU16Limbs(limbs)
  let value = 0n
  for (let i = limbs.length - 1; i >= 0; i--) {
    value = (value << 16n) | BigInt(limbs[i])
  }
  return value
}

export function assertU16Limbs (limbs: number[]): void {
  if (limbs.length < 1) throw new Error('Expected at least one limb')
  for (const limb of limbs) assertU16(limb)
}

export function compareLimbsLE (left: number[], right: number[]): -1 | 0 | 1 {
  assertU16Limbs(left)
  assertU16Limbs(right)
  const length = Math.max(left.length, right.length)
  for (let i = length - 1; i >= 0; i--) {
    const a = left[i] ?? 0
    const b = right[i] ?? 0
    if (a < b) return -1
    if (a > b) return 1
  }
  return 0
}

export function isCanonicalLimbsLE (
  limbs: number[],
  modulus: bigint
): boolean {
  assertPositiveModulus(modulus)
  return u16LimbsToBigintLE(limbs) < modulus
}

export function addLimbsLE (
  left: number[],
  right: number[],
  limbCount: number
): { limbs: U16[], carry: number } {
  assertU16Limbs(left)
  assertU16Limbs(right)
  assertLimbCount(limbCount)
  const limbs = new Array<U16>(limbCount)
  let carry = 0
  for (let i = 0; i < limbCount; i++) {
    const sum = (left[i] ?? 0) + (right[i] ?? 0) + carry
    limbs[i] = sum & 0xffff
    carry = sum >>> 16
  }
  return { limbs, carry }
}

export function subLimbsLE (
  left: number[],
  right: number[],
  limbCount: number
): { limbs: U16[], borrow: number } {
  assertU16Limbs(left)
  assertU16Limbs(right)
  assertLimbCount(limbCount)
  const limbs = new Array<U16>(limbCount)
  let borrow = 0
  for (let i = 0; i < limbCount; i++) {
    let diff = (left[i] ?? 0) - (right[i] ?? 0) - borrow
    if (diff < 0) {
      diff += U16_RADIX
      borrow = 1
    } else {
      borrow = 0
    }
    limbs[i] = diff
  }
  return { limbs, borrow }
}

export function mulLimbsLE (
  left: number[],
  right: number[]
): U16[] {
  assertU16Limbs(left)
  assertU16Limbs(right)
  const product = u16LimbsToBigintLE(left) * u16LimbsToBigintLE(right)
  return bigintToU16LimbsLE(product, left.length + right.length)
}

export function reduceLimbsLE (
  limbs: number[],
  modulus: bigint,
  limbCount: number = U256_LIMBS
): U256Limbs {
  assertPositiveModulus(modulus)
  assertLimbCount(limbCount)
  const value = u16LimbsToBigintLE(limbs) % modulus
  return bigintToU16LimbsLE(value, limbCount)
}

function assertLimbCount (limbCount: number): void {
  if (!Number.isSafeInteger(limbCount) || limbCount < 1) {
    throw new Error('Limb count must be positive')
  }
}

function assertPositiveModulus (modulus: bigint): void {
  if (modulus <= 0n) throw new Error('Modulus must be positive')
}
