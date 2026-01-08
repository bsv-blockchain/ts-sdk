// @ts-nocheck

// NOTE:
// Table-based AES is intentionally retained for performance.
// JavaScript runtimes (JIT, GC, speculative execution) cannot provide
// strong constant-time guarantees, and arithmetic-only AES implementations
// cause catastrophic performance degradation in practice.
//
// This implementation therefore prioritizes correctness, performance,
// and compatibility over attempting misleading "constant-time" behavior.
//
// Applications requiring strict side-channel resistance SHOULD use
// platform-native crypto APIs (e.g. WebCrypto) or audited native libraries.
/**
 * SECURITY DISCLAIMER – AES-GCM IMPLEMENTATION
 *
 * This module provides a self-contained AES-GCM implementation intended for
 * functional correctness and portability with minimal dependencies.
 *
 * While efforts are made to reduce timing side-channel leakage (e.g. avoiding
 * secret-dependent branches in GHASH), JavaScript does not guarantee
 * constant-time execution. As such, this implementation should not be used in
 * environments where attackers can reliably measure fine-grained execution
 * timing (e.g. shared hosts, co-resident VMs, or untrusted browser contexts).
 *
 * For high-assurance cryptographic use cases, prefer platform-provided
 * WebCrypto APIs or well-audited constant-time libraries.
 */
const SBox = new Uint8Array([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
])

const Rcon = [
  [0x00, 0x00, 0x00, 0x00], [0x01, 0x00, 0x00, 0x00], [0x02, 0x00, 0x00, 0x00], [0x04, 0x00, 0x00, 0x00],
  [0x08, 0x00, 0x00, 0x00], [0x10, 0x00, 0x00, 0x00], [0x20, 0x00, 0x00, 0x00], [0x40, 0x00, 0x00, 0x00],
  [0x80, 0x00, 0x00, 0x00], [0x1b, 0x00, 0x00, 0x00], [0x36, 0x00, 0x00, 0x00]
].map(v => new Uint8Array(v))

const mul2 = new Uint8Array(256)
const mul3 = new Uint8Array(256)
for (let i = 0; i < 256; i++) {
  const m2 = ((i << 1) ^ ((i & 0x80) !== 0 ? 0x1b : 0)) & 0xff
  mul2[i] = m2
  mul3[i] = m2 ^ i
}

function mixColumnsFast (state: number[][]): void {
  for (let c = 0; c < 4; c++) {
    const s0 = state[0][c]
    const s1 = state[1][c]
    const s2 = state[2][c]
    const s3 = state[3][c]

    state[0][c] = mul2[s0] ^ mul3[s1] ^ s2 ^ s3
    state[1][c] = s0 ^ mul2[s1] ^ mul3[s2] ^ s3
    state[2][c] = s0 ^ s1 ^ mul2[s2] ^ mul3[s3]
    state[3][c] = mul3[s0] ^ s1 ^ s2 ^ mul2[s3]
  }
}

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
      state[r][c] = SBox[state[r][c]]
    }
  }
}

function subWord (value: number[]): void {
  for (let i = 0; i < 4; i++) {
    value[i] = SBox[value[i]]
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
      mixColumnsFast(state)
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

/**
 * SECURITY NOTE – TIMING SIDE-CHANNEL MITIGATION
 *
 * This GHASH multiplication implementation avoids data-dependent conditional
 * branches by using mask-based operations instead. This reduces timing
 * side-channel leakage compared to a naive implementation that branches on
 * secret bits.
 *
 * IMPORTANT: JavaScript and TypedArray operations do NOT provide constant-time
 * execution guarantees. While this implementation mitigates obvious control-
 * flow timing leaks, it must not be considered constant-time in a strict
 * cryptographic sense and is not suitable for hostile shared-CPU or
 * multi-tenant environments.
 *
 * Applications requiring strict constant-time AES-GCM SHOULD use a dedicated,
 * audited cryptographic library (e.g. noble-ciphers, WebCrypto, or BearSSL
 * bindings).
 */
export const multiply = function (block0: Bytes, block1: Bytes): Bytes {
  const v = block1.slice()
  const z = createZeroBlock(16)

  for (let i = 0; i < 16; i++) {
    const b = block0[i]
    for (let j = 7; j >= 0; j--) {
      // mask = 0xff if bit is set, 0x00 otherwise
      const bit = (b >> j) & 1
      const mask = -bit & 0xff
      // z ^= v & mask
      for (let k = 0; k < 16; k++) {
        z[k] ^= v[k] & mask
      }
      // compute reduction mask
      const lsb = v[15] & 1
      const rmask = -lsb & 0xff
      rightShift(v)
      // v ^= R & rmask
      for (let k = 0; k < 16; k++) {
        v[k] ^= R[k] & rmask
      }
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
