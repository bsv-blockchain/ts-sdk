export type FieldElement = bigint

export const GOLDILOCKS_MODULUS = (1n << 64n) - (1n << 32n) + 1n
export const GOLDILOCKS_TWO_ADICITY = 32
export const GOLDILOCKS_TWO_ADIC_ROOT = 1753635133440165772n
export const MAX_TWO_ADIC_DOMAIN_SIZE = 2 ** GOLDILOCKS_TWO_ADICITY

export function isPowerOfTwo (n: number): boolean {
  return (
    Number.isSafeInteger(n) &&
    n > 0 &&
    2 ** Math.round(Math.log2(n)) === n
  )
}

export function assertPowerOfTwo (n: number): void {
  if (!isPowerOfTwo(n)) {
    throw new Error('Expected a positive power of two')
  }
}

export function bitLength (n: number): number {
  if (!Number.isInteger(n) || n < 1) {
    throw new Error('Expected a positive integer')
  }
  return Math.ceil(Math.log2(n))
}

export const F = {
  p: GOLDILOCKS_MODULUS,
  zero: 0n,
  one: 1n,

  normalize (value: bigint | number): FieldElement {
    const input = toBigInt(value)
    let v = input % GOLDILOCKS_MODULUS
    if (v < 0n) v += GOLDILOCKS_MODULUS
    return v
  },

  add (a: FieldElement, b: FieldElement): FieldElement {
    const r = a + b
    return r >= GOLDILOCKS_MODULUS ? r - GOLDILOCKS_MODULUS : r
  },

  sub (a: FieldElement, b: FieldElement): FieldElement {
    return a >= b ? a - b : GOLDILOCKS_MODULUS - (b - a)
  },

  neg (a: FieldElement): FieldElement {
    return a === 0n ? 0n : GOLDILOCKS_MODULUS - a
  },

  mul (a: FieldElement, b: FieldElement): FieldElement {
    return (a * b) % GOLDILOCKS_MODULUS
  },

  div (a: FieldElement, b: FieldElement): FieldElement {
    return F.mul(a, F.inv(b))
  },

  pow (base: FieldElement, exponent: bigint): FieldElement {
    if (exponent < 0n) {
      throw new Error('Negative exponents are not supported')
    }
    let result = 1n
    let x = base
    let e = exponent
    while (e > 0n) {
      if ((e & 1n) === 1n) result = F.mul(result, x)
      x = F.mul(x, x)
      e >>= 1n
    }
    return result
  },

  inv (value: FieldElement): FieldElement {
    if (value === 0n) {
      throw new Error('Cannot invert zero')
    }
    return F.pow(value, GOLDILOCKS_MODULUS - 2n)
  },

  eq (a: FieldElement, b: FieldElement): boolean {
    return a === b
  },

  fromBytesLE (bytes: number[]): FieldElement {
    if (bytes.length !== 8) {
      throw new Error('Goldilocks field elements serialize to 8 bytes')
    }
    assertBytes(bytes)
    let value = 0n
    for (let i = 0; i < 8; i++) {
      value |= BigInt(bytes[i]) << BigInt(i * 8)
    }
    if (value >= GOLDILOCKS_MODULUS) {
      throw new Error('Non-canonical Goldilocks field encoding')
    }
    return value
  },

  toBytesLE (value: FieldElement): number[] {
    const bytes = new Array<number>(8)
    let v = F.normalize(value)
    for (let i = 0; i < 8; i++) {
      bytes[i] = Number(v & 0xffn)
      v >>= 8n
    }
    return bytes
  },

  toString (value: FieldElement): string {
    return F.normalize(value).toString(10)
  },

  fromString (value: string): FieldElement {
    if (!/^-?[0-9]+$/.test(value)) {
      throw new Error('Invalid field element string')
    }
    return F.normalize(BigInt(value))
  },

  isCanonical (value: FieldElement): boolean {
    return typeof value === 'bigint' && value >= 0n && value < GOLDILOCKS_MODULUS
  },

  assertCanonical (value: FieldElement): void {
    if (!F.isCanonical(value)) {
      throw new Error('Field element is not canonical')
    }
  }
}

export function batchInvertFieldElements (
  values: FieldElement[]
): FieldElement[] {
  const length = values.length
  const prefixProducts = new Array<FieldElement>(length)
  const inverses = new Array<FieldElement>(length)
  let accumulator = 1n
  for (let i = 0; i < length; i++) {
    const value = F.normalize(values[i])
    if (value === 0n) {
      throw new Error('Cannot batch-invert zero')
    }
    prefixProducts[i] = accumulator
    accumulator = F.mul(accumulator, value)
  }
  let inverseAccumulator = F.inv(accumulator)
  for (let i = length - 1; i >= 0; i--) {
    const value = F.normalize(values[i])
    inverses[i] = F.mul(inverseAccumulator, prefixProducts[i])
    inverseAccumulator = F.mul(inverseAccumulator, value)
  }
  return inverses
}

export function getPowerOfTwoRootOfUnity (size: number): FieldElement {
  assertPowerOfTwo(size)
  if (size > MAX_TWO_ADIC_DOMAIN_SIZE) {
    throw new Error('Requested domain exceeds Goldilocks two-adicity')
  }
  const logSize = bitLength(size)
  if (logSize > GOLDILOCKS_TWO_ADICITY) {
    throw new Error('Requested domain exceeds Goldilocks two-adicity')
  }
  return F.pow(
    GOLDILOCKS_TWO_ADIC_ROOT,
    1n << BigInt(GOLDILOCKS_TWO_ADICITY - logSize)
  )
}

export function getPowerOfTwoDomain (size: number): FieldElement[] {
  const root = getPowerOfTwoRootOfUnity(size)
  const domain = new Array<FieldElement>(size)
  let x = 1n
  for (let i = 0; i < size; i++) {
    domain[i] = x
    x = F.mul(x, root)
  }
  return domain
}

export function getPowerOfTwoCosetDomain (
  size: number,
  offset: FieldElement
): FieldElement[] {
  offset = F.normalize(offset)
  F.assertCanonical(offset)
  if (offset === 0n) {
    throw new Error('Coset offset must be non-zero')
  }
  const base = getPowerOfTwoDomain(size)
  return base.map(x => F.mul(offset, x))
}

function toBigInt (value: bigint | number): bigint {
  if (typeof value === 'bigint') return value
  if (!Number.isSafeInteger(value)) {
    throw new Error('Field numbers must be safe integers')
  }
  return BigInt(value)
}

function assertBytes (bytes: number[]): void {
  for (const byte of bytes) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error('Invalid byte value')
    }
  }
}
