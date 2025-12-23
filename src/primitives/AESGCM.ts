
// @ts-nocheck
const Rcon = [
  [0x00, 0x00, 0x00, 0x00], [0x01, 0x00, 0x00, 0x00], [0x02, 0x00, 0x00, 0x00], [0x04, 0x00, 0x00, 0x00],
  [0x08, 0x00, 0x00, 0x00], [0x10, 0x00, 0x00, 0x00], [0x20, 0x00, 0x00, 0x00], [0x40, 0x00, 0x00, 0x00],
  [0x80, 0x00, 0x00, 0x00], [0x1b, 0x00, 0x00, 0x00], [0x36, 0x00, 0x00, 0x00]
].map(v => new Uint8Array(v))

function addRoundKey (
  state: number[][],
  roundKeyArray: number[][],
  offset: number
): void {
  for (let c = 0; c < 4; c++) {
    const keyCol = roundKeyArray[offset + c]
    for (let r = 0; r < 4; r++) {
      state[r][c] ^= keyCol[r]
    }
  }
}

function subBytes (state: number[][]): void {
  for (let r = 0; r < 4; r++) {
    for (let c = 0; c < 4; c++) {
      state[r][c] = aesSBox(state[r][c])
    }
  }
}

function subWord (value: number[]): void {
  for (let i = 0; i < 4; i++) {
    value[i] = aesSBox(value[i])
  }
}

function rotWord (value: number[]): void {
  const temp = value[0]

  value[0] = value[1]
  value[1] = value[2]
  value[2] = value[3]
  value[3] = temp
}

function shiftRows (state: number[][]): void {
  let tmp = state[1][0]
  state[1][0] = state[1][1]
  state[1][1] = state[1][2]
  state[1][2] = state[1][3]
  state[1][3] = tmp

  tmp = state[2][0]
  const tmp2 = state[2][1]
  state[2][0] = state[2][2]
  state[2][1] = state[2][3]
  state[2][2] = tmp
  state[2][3] = tmp2

  tmp = state[3][3]
  state[3][3] = state[3][2]
  state[3][2] = state[3][1]
  state[3][1] = state[3][0]
  state[3][0] = tmp
}

function mixColumns (state: number[][]): void {
  for (let c = 0; c < 4; c++) {
    const s0 = state[0][c]
    const s1 = state[1][c]
    const s2 = state[2][c]
    const s3 = state[3][c]

    const m0 = xtime(s0)
    const m1 = xtime(s1)
    const m2 = xtime(s2)
    const m3 = xtime(s3)

    state[0][c] = m0 ^ (m1 ^ s1) ^ s2 ^ s3
    state[1][c] = s0 ^ m1 ^ (m2 ^ s2) ^ s3
    state[2][c] = s0 ^ s1 ^ m2 ^ (m3 ^ s3)
    state[3][c] = (m0 ^ s0) ^ s1 ^ s2 ^ m3
  }
}

function keyExpansion (roundLimit: number, key: number[]): number[][] {
  const nK = key.length / 4
  const result: number[][] = []

  for (let i = 0; i < key.length; i++) {
    if (i % 4 === 0) result.push([])
    result[i >> 2].push(key[i])
  }

  for (let i = nK; i < 4 * roundLimit; i++) {
    result[i] = []
    const temp = result[i - 1].slice()

    if (i % nK === 0) {
      rotWord(temp)
      subWord(temp)
      const r = Rcon[i / nK]
      for (let j = 0; j < 4; j++) {
        temp[j] ^= r[j]
      }
    } else if (nK > 6 && (i % nK) === 4) {
      subWord(temp)
    }

    for (let j = 0; j < 4; j++) {
      result[i][j] = result[i - nK][j] ^ temp[j]
    }
  }

  return result
}

export function AES (input: number[], key: number[]): number[] {
  let i
  let j
  let round: number
  let roundLimit
  const state = [[], [], [], []]
  const output = []

  const ekey = Array.from(key)

  if (ekey.length === 16) {
    roundLimit = 11
  } else if (ekey.length === 24) {
    roundLimit = 13
  } else if (ekey.length === 32) {
    roundLimit = 15
  } else {
    throw new Error('Illegal key length: ' + String(ekey.length))
  }

  const w = keyExpansion(roundLimit, ekey)

  for (let c = 0; c < 4; c++) {
    state[0][c] = input[c * 4]
    state[1][c] = input[c * 4 + 1]
    state[2][c] = input[c * 4 + 2]
    state[3][c] = input[c * 4 + 3]
  }

  addRoundKey(state, w, 0)
  for (round = 1; round < roundLimit; round++) {
    subBytes(state)
    shiftRows(state)

    if (round + 1 < roundLimit) {
      mixColumns(state)
    }

    addRoundKey(state, w, round * 4)
  }

  for (i = 0; i < 4; i++) {
    for (j = 0; j < 4; j++) {
      output.push(state[j][i])
    }
  }

  return output
}

export const checkBit = function (
  byteArray: number[],
  byteIndex: number,
  bitIndex: number
): 1 | 0 {
  return (byteArray[byteIndex] & (0x01 << bitIndex)) !== 0 ? 1 : 0
}

export const getBytes = function (numericValue: number): number[] {
  return [
    (numericValue & 0xFF000000) >>> 24,
    (numericValue & 0x00FF0000) >> 16,
    (numericValue & 0x0000FF00) >> 8,
    numericValue & 0x000000FF
  ]
}

export const getBytes64 = function (numericValue: number): number[] {
  if (numericValue < 0 || numericValue > Number.MAX_SAFE_INTEGER) {
    throw new Error('getBytes64: value out of range')
  }

  const hi = Math.floor(numericValue / 0x100000000)
  const lo = numericValue >>> 0

  return [
    (hi >>> 24) & 0xFF,
    (hi >>> 16) & 0xFF,
    (hi >>> 8) & 0xFF,
    hi & 0xFF,
    (lo >>> 24) & 0xFF,
    (lo >>> 16) & 0xFF,
    (lo >>> 8) & 0xFF,
    lo & 0xFF
  ]
}

type Bytes = Uint8Array

const createZeroBlock = function (length: number): Bytes {
  // Uint8Array is already zero-filled
  return new Uint8Array(length)
}

// R = 0xe1 || 15 zero bytes
const R: Bytes = (() => {
  const r = new Uint8Array(16)
  r[0] = 0xe1
  return r
})()

const concatBytes = (...arrays: Bytes[]): Bytes => {
  let total = 0
  for (const a of arrays) total += a.length

  const out = new Uint8Array(total)
  let offset = 0
  for (const a of arrays) {
    out.set(a, offset)
    offset += a.length
  }
  return out
}

export const exclusiveOR = function (block0: Bytes, block1: Bytes): Bytes {
  const len = block0.length
  const result = new Uint8Array(len)
  for (let i = 0; i < len; i++) {
    result[i] = block0[i] ^ (block1[i] ?? 0)
  }
  return result
}

const xorInto = function (target: Bytes, block: Bytes): void {
  for (let i = 0; i < target.length; i++) {
    target[i] ^= block[i] ?? 0
  }
}

export const rightShift = function (block: Bytes): Bytes {
  let carry = 0
  let oldCarry = 0

  for (let i = 0; i < block.length; i++) {
    oldCarry = carry
    carry = block[i] & 0x01
    block[i] = block[i] >> 1

    if (oldCarry !== 0) {
      block[i] = block[i] | 0x80
    }
  }

  return block
}

export const multiply = function (block0: Bytes, block1: Bytes): Bytes {
  const v = block1.slice()
  const z = createZeroBlock(16)

  for (let i = 0; i < 16; i++) {
    for (let j = 7; j >= 0; j--) {
      // Conditionally xor v into z (branchless)
      const bit = (block0[i] >> j) & 1
      const mask = -bit
      for (let k = 0; k < 16; k++) {
        z[k] ^= v[k] & mask
      }

      // Shift v right and conditionally reduce (branchless)
      rightShiftReduce(v)
    }
  }

  return z
}


export const incrementLeastSignificantThirtyTwoBits = function (
  block: Bytes
): Bytes {
  const result = block.slice()

  for (let i = 15; i > 11; i--) {
    result[i] = (result[i] + 1) & 0xff // wrap explicitly

    if (result[i] !== 0) {
      break
    }
  }

  return result
}

export function ghash (input: Bytes, hashSubKey: Bytes): Bytes {
  let result = createZeroBlock(16)
  const block = new Uint8Array(16)

  for (let i = 0; i < input.length; i += 16) {
    block.set(result)
    for (let j = 0; j < 16; j++) {
      block[j] ^= input[i + j] ?? 0
    }
    result = multiply(block, hashSubKey)
  }

  return result
}

function gctr (
  input: Bytes,
  initialCounterBlock: Bytes,
  key: Bytes
): Bytes {
  if (input.length === 0) return new Uint8Array(0)

  const output = new Uint8Array(input.length)
  let counterBlock = initialCounterBlock.slice()
  let pos = 0
  const n = Math.ceil(input.length / 16)

  for (let i = 0; i < n; i++) {
    const counter = AES(counterBlock, key)
    const chunk = Math.min(16, input.length - pos)
    for (let j = 0; j < chunk; j++) {
      output[pos] = input[pos] ^ counter[j]
      pos++
    }

    if (i + 1 < n) {
      counterBlock = incrementLeastSignificantThirtyTwoBits(counterBlock)
    }
  }

  return output
}

function buildAuthInput (cipherText: Bytes): Bytes {
  const aadLenBits = 0
  const ctLenBits = cipherText.length * 8

  let padLen: number
  if (cipherText.length === 0) {
    padLen = 16
  } else if (cipherText.length % 16 === 0) {
    padLen = 0
  } else {
    padLen = 16 - (cipherText.length % 16)
  }

  const total =
    16 +
    cipherText.length +
    padLen +
    16

  const out = new Uint8Array(total)
  let offset = 0

  offset += 16

  out.set(cipherText, offset)
  offset += cipherText.length

  offset += padLen

  const aadLen = getBytes64(aadLenBits)
  out.set(aadLen, offset)
  offset += 8

  const ctLen = getBytes64(ctLenBits)
  out.set(ctLen, offset)

  return out
}

/**
 * SECURITY NOTE – NON-STANDARD AES-GCM PADDING
 *
 * This implementation intentionally deviates from NIST SP 800-38D’s AES-GCM
 * specification in how the GHASH input is formed when the additional
 * authenticated data (AAD) or ciphertext length is zero.
 *
 * In the standard, AAD and ciphertext are each padded with the minimum number
 * of zero bytes required to reach a multiple of 16 bytes; when the length is
 * already a multiple of 16 (including the case length = 0), no padding block
 * is added. In this implementation, when AAD.length === 0 or ciphertext.length
 * === 0, an extra 16-byte block of zeros is appended before the length fields
 * are processed. The same formatting logic is used symmetrically in both
 * AESGCM (encryption) and AESGCMDecrypt (decryption).
 *
 * As a result:
 *   - Authentication tags produced here are NOT compatible with tags produced
 *     by standards-compliant AES-GCM implementations in the cases where AAD
 *     or ciphertext are empty.
 *   - Ciphertexts generated by this code must be decrypted by this exact
 *     implementation (or one that reproduces the same GHASH formatting), and
 *     must not be mixed with ciphertexts produced by a strictly standard
 *     AES-GCM library.
 *
 * Cryptographic impact: this change alters only the encoding of the message
 * that is input to GHASH; it does not change the block cipher, key derivation,
 * IV handling, or the basic “encrypt-then-MAC over (AAD, ciphertext, lengths)”
 * structure of AES-GCM. Under the usual assumptions that AES is a secure block
 * cipher and GHASH with a secret subkey is a secure polynomial MAC, this
 * variant continues to provide confidentiality and integrity for data encrypted
 * and decrypted consistently with this implementation. We are not aware of any
 * attack that exploits the presence of this extra zero block when AAD or
 * ciphertext are empty.
 *
 * However, this padding behavior is non-compliant with NIST SP 800-38D and has
 * not been analyzed as extensively as standard AES-GCM. Code that requires
 * strict standards compliance or interoperability with external AES-GCM
 * implementations SHOULD NOT use this module as-is. Any future migration to a
 * fully compliant AES-GCM encoding will require a compatibility strategy, as
 * existing ciphertexts produced by this implementation will otherwise become
 * undecryptable.
 *
 * This non-standard padding behavior is retained intentionally for backward
 * compatibility: existing ciphertexts in production were generated with this
 * encoding, and changing it would render previously encrypted data
 * undecryptable by newer versions of the library.
 */
export function AESGCM (
  plainText: Bytes,
  initializationVector: Bytes,
  key: Bytes
): { result: Bytes, authenticationTag: Bytes } {
  if (initializationVector.length === 0) {
    throw new Error('Initialization vector must not be empty')
  }

  if (key.length === 0) {
    throw new Error('Key must not be empty')
  }

  const hashSubKey = new Uint8Array(AES(createZeroBlock(16), key))

  let preCounterBlock: Bytes

  if (initializationVector.length === 12) {
    preCounterBlock = concatBytes(initializationVector, createZeroBlock(3), new Uint8Array([0x01]))
  } else {
    let ivPadded = initializationVector
    if (ivPadded.length % 16 !== 0) {
      ivPadded = concatBytes(
        ivPadded,
        createZeroBlock(16 - (ivPadded.length % 16))
      )
    }

    const lenBlock = getBytes64(initializationVector.length * 8)
    const s = concatBytes(
      ivPadded,
      createZeroBlock(8),
      new Uint8Array(lenBlock)
    )

    preCounterBlock = ghash(s, hashSubKey)
  }

  const cipherText = gctr(
    plainText,
    incrementLeastSignificantThirtyTwoBits(preCounterBlock),
    key
  )

  const authInput = buildAuthInput(cipherText)

  const s = ghash(authInput, hashSubKey)
  const authenticationTag = gctr(s, preCounterBlock, key)

  return {
    result: cipherText,
    authenticationTag
  }
}

export function AESGCMDecrypt (
  cipherText: Bytes,
  initializationVector: Bytes,
  authenticationTag: Bytes,
  key: Bytes
): Bytes | null {
  if (cipherText.length === 0) {
    throw new Error('Cipher text must not be empty')
  }

  if (initializationVector.length === 0) {
    throw new Error('Initialization vector must not be empty')
  }

  if (key.length === 0) {
    throw new Error('Key must not be empty')
  }

  // Generate the hash subkey
  const hashSubKey = new Uint8Array(AES(createZeroBlock(16), key))

  let preCounterBlock: Bytes

  if (initializationVector.length === 12) {
    preCounterBlock = concatBytes(
      initializationVector,
      createZeroBlock(3),
      new Uint8Array([0x01])
    )
  } else {
    let ivPadded = initializationVector
    if (ivPadded.length % 16 !== 0) {
      ivPadded = concatBytes(
        ivPadded,
        createZeroBlock(16 - (ivPadded.length % 16))
      )
    }

    const lenBlock = getBytes64(initializationVector.length * 8)
    const s = concatBytes(
      ivPadded,
      createZeroBlock(8),
      new Uint8Array(lenBlock)
    )

    preCounterBlock = ghash(s, hashSubKey)
  }

  // Decrypt to obtain the plain text
  const plainText = gctr(
    cipherText,
    incrementLeastSignificantThirtyTwoBits(preCounterBlock),
    key
  )

  const authInput = buildAuthInput(cipherText)
  const s = ghash(authInput, hashSubKey)
  const calculatedTag = gctr(s, preCounterBlock, key)

  if (calculatedTag.length !== authenticationTag.length) {
    return null
  }

  let diff = 0
  for (let i = 0; i < calculatedTag.length; i++) {
    diff |= calculatedTag[i] ^ authenticationTag[i]
  }

  if (diff !== 0) {
    return null
  }

  return plainText
}

function aesSBox (x: number): number {
  x &= 0xff

  let inv = 1
  let isZero = ctIsZero8(x)

  // Compute x^254 for all x (safe even when x = 0)
  for (let i = 0; i < 254; i++) {
    inv = gfMul(inv, x)
  }

  // Force inv = 0 when x = 0 (constant-time)
  inv &= -(!isZero)

  let s =
    inv ^
    rotl8(inv, 1) ^
    rotl8(inv, 2) ^
    rotl8(inv, 3) ^
    rotl8(inv, 4) ^
    0x63

  return s & 0xff
}

function rotl8 (x: number, shift: number): number {
  return ((x << shift) | (x >>> (8 - shift))) & 0xff
}

function gfMul (a: number, b: number): number {
  let p = 0
  for (let i = 0; i < 8; i++) {
    p ^= a & -(b & 1)
    const hi = a & 0x80
    a = (a << 1) & 0xff
    a ^= 0x1b & -(hi >>> 7)
    b >>>= 1
  }
  return p
}

function xtime (x: number): number {
  // Multiply by 2 in GF(2^8), branchless
  const hi = x & 0x80
  return ((x << 1) ^ (0x1b & -(hi >>> 7))) & 0xff
}

function rightShiftReduce (v: Bytes): void {
  let carry = 0

  for (let i = 0; i < 16; i++) {
    const newCarry = v[i] & 1
    v[i] = (v[i] >>> 1) | (carry << 7)
    carry = newCarry
  }

  // If LSB of original v[15] was 1, xor with R
  const mask = -(carry & 1) // 0x00 or 0xFF
  for (let i = 0; i < 16; i++) {
    v[i] ^= R[i] & mask
  }
}

function ctIsZero8 (x: number): number {
  x &= 0xff
  let y = x | (x >> 4)
  y |= y >> 2
  y |= y >> 1
  return (y ^ 1) & 1
}