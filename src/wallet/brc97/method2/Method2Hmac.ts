import {
  F,
  FieldElement
} from '../stark/index.js'
import {
  hmacSha256,
  sha256Digest,
  sha256Pad,
  toBitsLE
} from '../circuit/index.js'

export interface Method2HmacLayout {
  invoiceLength: number
  sharedBits: number
  innerDigest: number
  linkage: number
  innerMessage: number
  innerMessageLength: number
  outerMessage: number
  outerMessageLength: number
  width: number
}

export interface Method2HmacWitnessPlan {
  innerMessage: number[]
  innerDigest: number[]
  outerMessage: number[]
  linkage: number[]
}

export const METHOD2_HMAC_BLOCK_SIZE = 64
export const METHOD2_HMAC_KEY_SIZE = 33
export const METHOD2_SHA256_DIGEST_SIZE = 32
export const METHOD2_HMAC_INNER_PAD = 0x36
export const METHOD2_HMAC_OUTER_PAD = 0x5c

export function method2HmacLayout (invoiceLength: number): Method2HmacLayout {
  if (
    !Number.isSafeInteger(invoiceLength) ||
    invoiceLength < 0
  ) {
    throw new Error('Method 2 HMAC invoice length is invalid')
  }
  const innerMessageLength = sha256Pad(new Array(METHOD2_HMAC_BLOCK_SIZE + invoiceLength).fill(0)).length
  const outerMessageLength = sha256Pad(new Array(METHOD2_HMAC_BLOCK_SIZE + METHOD2_SHA256_DIGEST_SIZE).fill(0)).length
  const sharedBits = 0
  const innerDigest = sharedBits + METHOD2_HMAC_KEY_SIZE * 8
  const linkage = innerDigest + METHOD2_SHA256_DIGEST_SIZE
  const innerMessage = linkage + METHOD2_SHA256_DIGEST_SIZE
  const outerMessage = innerMessage + innerMessageLength
  return {
    invoiceLength,
    sharedBits,
    innerDigest,
    linkage,
    innerMessage,
    innerMessageLength,
    outerMessage,
    outerMessageLength,
    width: outerMessage + outerMessageLength
  }
}

export function method2HmacWitnessPlan (
  shared: number[],
  invoice: number[],
  linkage: number[]
): Method2HmacWitnessPlan {
  assertBytes(shared, METHOD2_HMAC_KEY_SIZE, 'shared secret')
  assertBytes(invoice, undefined, 'invoice')
  assertBytes(linkage, METHOD2_SHA256_DIGEST_SIZE, 'linkage')
  const keyBlock = shared.slice()
  while (keyBlock.length < METHOD2_HMAC_BLOCK_SIZE) keyBlock.push(0)
  const innerPad = keyBlock.map(byte => byte ^ METHOD2_HMAC_INNER_PAD)
  const outerPad = keyBlock.map(byte => byte ^ METHOD2_HMAC_OUTER_PAD)
  const innerInput = [...innerPad, ...invoice]
  const innerDigest = sha256Digest(innerInput)
  const outerInput = [...outerPad, ...innerDigest]
  const expectedLinkage = hmacSha256(shared, invoice)
  if (!bytesEqual(expectedLinkage, linkage)) {
    throw new Error('Method 2 HMAC linkage witness does not match public linkage')
  }
  return {
    innerMessage: sha256Pad(innerInput),
    innerDigest,
    outerMessage: sha256Pad(outerInput),
    linkage: linkage.slice()
  }
}

export function writeMethod2HmacWitness (
  row: FieldElement[],
  offset: number,
  shared: number[],
  invoice: number[],
  linkage: number[]
): void {
  const layout = method2HmacLayout(invoice.length)
  const plan = method2HmacWitnessPlan(shared, invoice, linkage)
  for (let byteIndex = 0; byteIndex < shared.length; byteIndex++) {
    const bits = toBitsLE(BigInt(shared[byteIndex]), 8)
    for (let bit = 0; bit < 8; bit++) {
      row[offset + layout.sharedBits + byteIndex * 8 + bit] = BigInt(bits[bit])
    }
  }
  writeNumbers(row, offset + layout.innerDigest, plan.innerDigest)
  writeNumbers(row, offset + layout.linkage, plan.linkage)
  writeNumbers(row, offset + layout.innerMessage, plan.innerMessage)
  writeNumbers(row, offset + layout.outerMessage, plan.outerMessage)
}

export function evaluateMethod2HmacPlannerConstraints (
  row: FieldElement[],
  offset: number,
  sharedOffset: number,
  invoice: number[],
  linkage: number[]
): FieldElement[] {
  assertBytes(invoice, undefined, 'invoice')
  assertBytes(linkage, METHOD2_SHA256_DIGEST_SIZE, 'linkage')
  const layout = method2HmacLayout(invoice.length)
  const constraints: FieldElement[] = []

  for (let byteIndex = 0; byteIndex < METHOD2_HMAC_KEY_SIZE; byteIndex++) {
    let byteFromBits = 0n
    for (let bit = 0; bit < 8; bit++) {
      const bitValue = row[offset + layout.sharedBits + byteIndex * 8 + bit]
      constraints.push(booleanConstraint(bitValue))
      byteFromBits = F.add(byteFromBits, F.mul(bitValue, BigInt(1 << bit)))
    }
    constraints.push(F.sub(row[sharedOffset + byteIndex], byteFromBits))
    constraints.push(F.sub(
      row[offset + layout.innerMessage + byteIndex],
      xorByteWithConstantFromBits(row, offset + layout.sharedBits + byteIndex * 8, METHOD2_HMAC_INNER_PAD)
    ))
    constraints.push(F.sub(
      row[offset + layout.outerMessage + byteIndex],
      xorByteWithConstantFromBits(row, offset + layout.sharedBits + byteIndex * 8, METHOD2_HMAC_OUTER_PAD)
    ))
  }

  for (let byteIndex = METHOD2_HMAC_KEY_SIZE; byteIndex < METHOD2_HMAC_BLOCK_SIZE; byteIndex++) {
    constraints.push(F.sub(
      row[offset + layout.innerMessage + byteIndex],
      BigInt(METHOD2_HMAC_INNER_PAD)
    ))
    constraints.push(F.sub(
      row[offset + layout.outerMessage + byteIndex],
      BigInt(METHOD2_HMAC_OUTER_PAD)
    ))
  }

  const innerInput = new Array(METHOD2_HMAC_BLOCK_SIZE + invoice.length).fill(0)
  const innerPadded = sha256Pad(innerInput)
  for (let i = 0; i < invoice.length; i++) {
    constraints.push(F.sub(
      row[offset + layout.innerMessage + METHOD2_HMAC_BLOCK_SIZE + i],
      BigInt(invoice[i])
    ))
  }
  for (let i = METHOD2_HMAC_BLOCK_SIZE + invoice.length; i < innerPadded.length; i++) {
    constraints.push(F.sub(
      row[offset + layout.innerMessage + i],
      BigInt(innerPadded[i])
    ))
  }

  const outerInput = new Array(METHOD2_HMAC_BLOCK_SIZE + METHOD2_SHA256_DIGEST_SIZE).fill(0)
  const outerPadded = sha256Pad(outerInput)
  for (let i = 0; i < METHOD2_SHA256_DIGEST_SIZE; i++) {
    constraints.push(F.sub(
      row[offset + layout.outerMessage + METHOD2_HMAC_BLOCK_SIZE + i],
      row[offset + layout.innerDigest + i]
    ))
    constraints.push(F.sub(
      row[offset + layout.linkage + i],
      BigInt(linkage[i])
    ))
  }
  for (let i = METHOD2_HMAC_BLOCK_SIZE + METHOD2_SHA256_DIGEST_SIZE; i < outerPadded.length; i++) {
    constraints.push(F.sub(
      row[offset + layout.outerMessage + i],
      BigInt(outerPadded[i])
    ))
  }

  return constraints
}

function xorByteWithConstantFromBits (
  row: FieldElement[],
  bitsOffset: number,
  constant: number
): FieldElement {
  let value = 0n
  for (let bit = 0; bit < 8; bit++) {
    const bitValue = row[bitsOffset + bit]
    const weight = BigInt(1 << bit)
    const constantBit = (constant >> bit) & 1
    value = F.add(value, F.mul(
      constantBit === 0 ? bitValue : F.sub(1n, bitValue),
      weight
    ))
  }
  return value
}

function writeNumbers (
  row: FieldElement[],
  offset: number,
  values: number[]
): void {
  for (let i = 0; i < values.length; i++) row[offset + i] = BigInt(values[i])
}

function booleanConstraint (value: FieldElement): FieldElement {
  return F.mul(value, F.sub(value, 1n))
}

function assertBytes (
  bytes: number[],
  length: number | undefined,
  label: string
): void {
  if (length !== undefined && bytes.length !== length) {
    throw new Error(`Invalid ${label} length`)
  }
  for (const byte of bytes) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error(`Invalid ${label} byte`)
    }
  }
}

function bytesEqual (left: number[], right: number[]): boolean {
  if (left.length !== right.length) return false
  let diff = 0
  for (let i = 0; i < left.length; i++) diff |= left[i] ^ right[i]
  return diff === 0
}
