
// @ts-nocheck
/* eslint-disable @typescript-eslint/naming-convention */
import { assertValidHex, normalizeHex } from './hex.js'

const assert = (
  expression: unknown,
  message: string = 'Hash assertion failed'
): void => {
  if (!(expression as boolean)) {
    throw new Error(message)
  }
}

/**
 * The BaseHash class is an abstract base class for cryptographic hash functions.
 * It provides a common structure and functionality for hash function classes.
 *
 * @class BaseHash
 *
 * @property pending - Stores partially processed message segments.
 * @property pendingTotal - The total number of characters that are being stored in `pending`
 * @property blockSize - The size of each block to processed.
 * @property outSize - The size of the final hash output.
 * @property endian - The endianness used during processing, can either be 'big' or 'little'.
 * @property _delta8 - The block size divided by 8, useful in various computations.
 * @property _delta32 - The block size divided by 32, useful in various computations.
 * @property padLength - The length of padding to be added to finalize the computation.
 * @property hmacStrength - The HMAC strength value.
 *
 * @param blockSize - The size of the block to be hashed.
 * @param outSize - The size of the resulting hash.
 * @param hmacStrength - The strength of the HMAC.
 * @param padLength - The length of the padding to be added.
 *
 * @example
 * Sub-classes would extend this base BaseHash class like:
 * class RIPEMD160 extends BaseHash {
 *   constructor () {
 *     super(512, 160, 192, 64);
 *     // ...
 *   }
 *   // ...
 * }
 */
abstract class BaseHash {
  pending: number[] | null
  pendingTotal: number
  blockSize: number
  outSize: number
  endian: 'big' | 'little'
  _delta8: number
  _delta32: number
  padLength: number
  hmacStrength: number

  constructor (
    blockSize: number,
    outSize: number,
    hmacStrength: number,
    padLength: number
  ) {
    this.pending = null
    this.pendingTotal = 0
    this.blockSize = blockSize
    this.outSize = outSize
    this.hmacStrength = hmacStrength
    this.padLength = padLength / 8
    this.endian = 'big'

    this._delta8 = this.blockSize / 8
    this._delta32 = this.blockSize / 32
  }

  _update (msg: number[], start: number): void {
    throw new Error('Not implemented')
  }

  _digest (): number[] {
    throw new Error('Not implemented')
  }

  _digestHex (): string {
    throw new Error('Not implemented')
  }

  /**
   * Converts the input message into an array, pads it, and joins into 32bit blocks.
   * If there is enough data, it tries updating the hash computation.
   *
   * @method update
   * @param msg - The message segment to include in the hashing computation.
   * @param enc - The encoding of the message. If 'hex', the string will be treated as such, 'utf8' otherwise.
   *
   * @returns Returns the instance of the object for chaining.
   *
   * @example
   * sha256.update('Hello World', 'utf8');
   */
  update (msg: number[] | string, enc?: 'hex' | 'utf8'): this {
    // Convert message to array, pad it, and join into 32bit blocks
    msg = toArray(msg, enc)
    if (this.pending == null) {
      this.pending = msg
    } else {
      this.pending = this.pending.concat(msg)
    }
    this.pendingTotal += msg.length

    // Enough data, try updating
    if (this.pending.length >= this._delta8) {
      msg = this.pending

      // Process pending data in blocks
      const r = msg.length % this._delta8
      this.pending = msg.slice(msg.length - r, msg.length)
      if (this.pending.length === 0) {
        this.pending = null
      }

      msg = join32(msg, 0, msg.length - r, this.endian)
      for (let i = 0; i < msg.length; i += this._delta32) {
        this._update(msg, i)
      }
    }

    return this
  }

  /**
   * Finalizes the hash computation and returns the hash value/result.
   *
   * @method digest
   *
   * @returns Returns the final hash value.
   *
   * @example
   * const hash = sha256.digest();
   */
  digest (): number[] {
    this.update(this._pad())
    assert(this.pending === null)

    return this._digest()
  }

  /**
   * Finalizes the hash computation and returns the hash value/result as a hex string.
   *
   * @method digest
   *
   * @returns Returns the final hash value as a hex string.
   *
   * @example
   * const hash = sha256.digestHex();
   */
  digestHex (): string {
    this.update(this._pad())
    assert(this.pending === null)

    return this._digestHex()
  }

  /**
   * [Private Method] Used internally to prepare the padding for the final stage of the hash computation.
   *
   * @method _pad
   * @private
   *
   * @returns Returns an array denoting the padding.
   */
  private _pad (): number[] {
    const len = this.pendingTotal
    if (!Number.isSafeInteger(len) || len < 0) {
      throw new Error('Message too long for this hash function')
    }

    const bytes = this._delta8
    const k = bytes - ((len + this.padLength) % bytes)
    const res = new Array(k + this.padLength)
    res[0] = 0x80
    let i: number
    for (i = 1; i < k; i++) {
      res[i] = 0
    }
    const lengthBytes = this.padLength
    const maxBits = 1n << BigInt(lengthBytes * 8)
    let totalBits = BigInt(len) * 8n

    if (totalBits >= maxBits) {
      throw new Error('Message too long for this hash function')
    }

    if (this.endian === 'big') {
      const lenArray = new Array<number>(lengthBytes)

      for (let b = lengthBytes - 1; b >= 0; b--) {
        lenArray[b] = Number(totalBits & 0xffn)
        totalBits >>= 8n
      }

      for (let b = 0; b < lengthBytes; b++) {
        res[i++] = lenArray[b]
      }
    } else {
      for (let b = 0; b < lengthBytes; b++) {
        res[i++] = Number(totalBits & 0xffn)
        totalBits >>= 8n
      }
    }

    return res
  }
}

function isSurrogatePair (msg: string, i: number): boolean {
  if ((msg.charCodeAt(i) & 0xfc00) !== 0xd800) {
    return false
  }
  if (i < 0 || i + 1 >= msg.length) {
    return false
  }
  return (msg.charCodeAt(i + 1) & 0xfc00) === 0xdc00
}

/**
 *
 * @param msg
 * @param enc Optional. Encoding to use if msg is string. Default is 'utf8'.
 * @returns array of byte values from msg. If msg is an array, a copy is returned.
 */
export function toArray (
  msg: number[] | string,
  enc?: 'hex' | 'utf8'
): number[] {
  if (Array.isArray(msg)) {
    return msg.slice()
  }
  if (!(msg as unknown as boolean)) {
    return []
  }
  const res: number[] = []
  if (typeof msg === 'string') {
    if (enc !== 'hex') {
      // Inspired by stringToUtf8ByteArray() in closure-library by Google
      // https://github.com/google/closure-library/blob/8598d87242af59aac233270742c8984e2b2bdbe0/closure/goog/crypt/crypt#L117-L143
      // Apache License 2.0
      // https://github.com/google/closure-library/blob/master/LICENSE
      let p = 0
      for (let i = 0; i < msg.length; i++) {
        let c = msg.charCodeAt(i)
        if (c < 128) {
          res[p++] = c
        } else if (c < 2048) {
          res[p++] = (c >> 6) | 192
          res[p++] = (c & 63) | 128
        } else if (isSurrogatePair(msg, i)) {
          c = 0x10000 + ((c & 0x03ff) << 10) + (msg.charCodeAt(++i) & 0x03ff)
          res[p++] = (c >> 18) | 240
          res[p++] = ((c >> 12) & 63) | 128
          res[p++] = ((c >> 6) & 63) | 128
          res[p++] = (c & 63) | 128
        } else {
          res[p++] = (c >> 12) | 224
          res[p++] = ((c >> 6) & 63) | 128
          res[p++] = (c & 63) | 128
        }
      }
    } else {
      assertValidHex(msg)
      msg = normalizeHex(msg)
      for (let i = 0; i < msg.length; i += 2) {
        res.push(parseInt(msg[i] + msg[i + 1], 16))
      }
    }
  } else {
    msg = msg as number[]
    for (let i = 0; i < msg.length; i++) {
      res[i] = msg[i] | 0
    }
  }
  return res
}

/**
 * @deprecated
 * This function behaves differently from the standard C `htonl()`.
 * It always performs an unconditional 32-bit byte swap.
 * Use `swapBytes32()` for explicit byte swapping, or `realHtonl()` for
 * standards-compliant host-to-network conversion.
 */
export function htonl (w: number): number {
  return swapBytes32(w)
}

function toHex32 (msg: number[], endian?: 'little' | 'big'): string {
  let res = ''
  for (let i = 0; i < msg.length; i++) {
    let w = msg[i]
    if (endian === 'little') {
      w = htonl(w)
    }
    res += zero8(w.toString(16))
  }
  return res
}

function zero8 (word: string): string {
  if (word.length === 7) {
    return '0' + word
  } else if (word.length === 6) {
    return '00' + word
  } else if (word.length === 5) {
    return '000' + word
  } else if (word.length === 4) {
    return '0000' + word
  } else if (word.length === 3) {
    return '00000' + word
  } else if (word.length === 2) {
    return '000000' + word
  } else if (word.length === 1) {
    return '0000000' + word
  } else {
    return word
  }
}

function bytesToHex (data: Uint8Array): string {
  let res = ''
  for (const b of data) res += (b.toString(16).padStart(2, '0') as string)
  return res
}

function join32 (msg, start, end, endian): number[] {
  const len = end - start
  assert(len % 4 === 0)
  const res = new Array(len / 4)
  for (let i = 0, k: number = start; i < res.length; i++, k += 4) {
    let w
    if (endian === 'big') {
      w = (msg[k] << 24) | (msg[k + 1] << 16) | (msg[k + 2] << 8) | msg[k + 3]
    } else {
      w = (msg[k + 3] << 24) | (msg[k + 2] << 16) | (msg[k + 1] << 8) | msg[k]
    }
    res[i] = w >>> 0
  }
  return res
}

function split32 (msg: number[], endian: 'big' | 'little'): number[] {
  const res = new Array(msg.length * 4)
  for (let i = 0, k = 0; i < msg.length; i++, k += 4) {
    const m = msg[i]
    if (endian === 'big') {
      res[k] = m >>> 24
      res[k + 1] = (m >>> 16) & 0xff
      res[k + 2] = (m >>> 8) & 0xff
      res[k + 3] = m & 0xff
    } else {
      res[k + 3] = m >>> 24
      res[k + 2] = (m >>> 16) & 0xff
      res[k + 1] = (m >>> 8) & 0xff
      res[k] = m & 0xff
    }
  }
  return res
}

function rotr32 (w: number, b: number): number {
  return (w >>> b) | (w << (32 - b))
}

function rotl32 (w: number, b: number): number {
  return (w << b) | (w >>> (32 - b))
}

function sum32 (a: number, b: number): number {
  return (a + b) >>> 0
}

function SUM32_3 (a: number, b: number, c: number): number {
  return (a + b + c) >>> 0
}

function SUM32_4 (a: number, b: number, c: number, d: number): number {
  return (a + b + c + d) >>> 0
}

function SUM32_5 (
  a: number,
  b: number,
  c: number,
  d: number,
  e: number
): number {
  return (a + b + c + d + e) >>> 0
}

function FT_1 (s, x, y, z): number {
  if (s === 0) {
    return ch32(x, y, z)
  }
  if (s === 1 || s === 3) {
    return p32(x, y, z)
  }
  if (s === 2) {
    return maj32(x, y, z)
  }
  return 0
}

function ch32 (x, y, z): number {
  return (x & y) ^ (~x & z)
}

function maj32 (x, y, z): number {
  return (x & y) ^ (x & z) ^ (y & z)
}

function p32 (x, y, z): number {
  return x ^ y ^ z
}

function S0_256 (x): number {
  return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22)
}

function S1_256 (x): number {
  return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25)
}

function G0_256 (x): number {
  return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >>> 3)
}

function G1_256 (x): number {
  return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >>> 10)
}

const r = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15,
  3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11,
  5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7,
  12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
]

const rh = [
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5,
  10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0,
  4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1,
  5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
]

const s = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7,
  15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5,
  12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5,
  11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
]

const sh = [
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8,
  9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14,
  13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5,
  12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
]

function f (j, x, y, z): number {
  if (j <= 15) {
    return x ^ y ^ z
  } else if (j <= 31) {
    return (x & y) | (~x & z)
  } else if (j <= 47) {
    return (x | ~y) ^ z
  } else if (j <= 63) {
    return (x & z) | (y & ~z)
  } else {
    return x ^ (y | ~z)
  }
}

function K (j): number {
  if (j <= 15) {
    return 0x00000000
  } else if (j <= 31) {
    return 0x5a827999
  } else if (j <= 47) {
    return 0x6ed9eba1
  } else if (j <= 63) {
    return 0x8f1bbcdc
  } else {
    return 0xa953fd4e
  }
}

function Kh (j): number {
  if (j <= 15) {
    return 0x50a28be6
  } else if (j <= 31) {
    return 0x5c4dd124
  } else if (j <= 47) {
    return 0x6d703ef3
  } else if (j <= 63) {
    return 0x7a6d76e9
  } else {
    return 0x00000000
  }
}

/**
 * An implementation of RIPEMD160 cryptographic hash function. Extends the BaseHash class.
 * It provides a way to compute a 'digest' for any kind of input data; transforming the data
 * into a unique output of fixed size. The output is deterministic; it will always be
 * the same for the same input.
 *
 * @class RIPEMD160
 * @param None
 *
 * @constructor
 * Use the RIPEMD160 constructor to create an instance of RIPEMD160 hash function.
 *
 * @example
 * const ripemd160 = new RIPEMD160();
 *
 * @property h - Array that is updated iteratively as part of hashing computation.
 */
export class RIPEMD160 extends BaseHash {
  h: number[]

  constructor () {
    super(512, 160, 192, 64)
    this.endian = 'little'

    this.h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
    this.endian = 'little'
  }

  _update (msg: number[], start: number): void {
    let A = this.h[0]
    let B = this.h[1]
    let C = this.h[2]
    let D = this.h[3]
    let E = this.h[4]
    let Ah = A
    let Bh = B
    let Ch = C
    let Dh = D
    let Eh = E
    let T
    for (let j = 0; j < 80; j++) {
      T = sum32(
        rotl32(SUM32_4(A, f(j, B, C, D), msg[r[j] + start], K(j)), s[j]),
        E
      )
      A = E
      E = D
      D = rotl32(C, 10)
      C = B
      B = T
      T = sum32(
        rotl32(
          SUM32_4(Ah, f(79 - j, Bh, Ch, Dh), msg[rh[j] + start], Kh(j)),
          sh[j]
        ),
        Eh
      )
      Ah = Eh
      Eh = Dh
      Dh = rotl32(Ch, 10)
      Ch = Bh
      Bh = T
    }
    T = SUM32_3(this.h[1], C, Dh)
    this.h[1] = SUM32_3(this.h[2], D, Eh)
    this.h[2] = SUM32_3(this.h[3], E, Ah)
    this.h[3] = SUM32_3(this.h[4], A, Bh)
    this.h[4] = SUM32_3(this.h[0], B, Ch)
    this.h[0] = T
  }

  _digest (): number[] {
    return split32(this.h, 'little')
  }

  _digestHex (): string {
    return toHex32(this.h, 'little')
  }
}

/**
 * An implementation of SHA256 cryptographic hash function. Extends the BaseHash class.
 * It provides a way to compute a 'digest' for any kind of input data; transforming the data
 * into a unique output of fixed size. The output is deterministic; it will always be
 * the same for the same input.
 *
 * @class SHA256
 * @param None
 *
 * @constructor
 * Use the SHA256 constructor to create an instance of SHA256 hash function.
 *
 * @example
 * const sha256 = new SHA256();
 *
 * @property h - The initial hash constants
 * @property W - Provides a way to recycle usage of the array memory.
 * @property k - The round constants used for each round of SHA-256
 */
export class SHA256 {
  private readonly h: FastSHA256
  constructor () {
    this.h = new FastSHA256()
  }

  update (
    msg: Uint8Array | number[] | string,
    enc?: 'hex' | 'utf8'
  ): this {
    const data =
      msg instanceof Uint8Array ? msg : Uint8Array.from(toArray(msg, enc))
    this.h.update(data)
    return this
  }

  digest (): number[] {
    return Array.from(this.h.digest())
  }

  digestHex (): string {
    return bytesToHex(this.h.digest())
  }
}

/**
 * An implementation of SHA1 cryptographic hash function. Extends the BaseHash class.
 * It provides a way to compute a 'digest' for any kind of input data; transforming the data
 * into a unique output of fixed size. The output is deterministic; it will always be
 * the same for the same input.
 *
 * @class SHA1
 * @param None
 *
 * @constructor
 * Use the SHA1 constructor to create an instance of SHA1 hash function.
 *
 * @example
 * const sha1 = new SHA1();
 *
 * @property h - The initial hash constants.
 * @property W - Provides a way to recycle usage of the array memory.
 * @property k - The round constants used for each round of SHA-1.
 */
export class SHA1 extends BaseHash {
  h: number[]
  W: number[]
  k: number[]

  constructor () {
    super(512, 160, 80, 64)
    this.k = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6]
    this.h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
    this.W = new Array(80)
  }

  _update (msg: number[], start?: number): void {
    const W = this.W

    // Default start to 0
    if (start === undefined) {
      start = 0
    }

    let i: number
    for (i = 0; i < 16; i++) {
      W[i] = msg[start + i]
    }

    for (; i < W.length; i++) {
      W[i] = rotl32(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1)
    }

    let a = this.h[0]
    let b = this.h[1]
    let c = this.h[2]
    let d = this.h[3]
    let e = this.h[4]

    for (i = 0; i < W.length; i++) {
      const s = ~~(i / 20)
      const t = SUM32_5(rotl32(a, 5), FT_1(s, b, c, d), e, W[i], this.k[s])
      e = d
      d = c
      c = rotl32(b, 30)
      b = a
      a = t
    }

    this.h[0] = sum32(this.h[0], a)
    this.h[1] = sum32(this.h[1], b)
    this.h[2] = sum32(this.h[2], c)
    this.h[3] = sum32(this.h[3], d)
    this.h[4] = sum32(this.h[4], e)
  }

  _digest (): number[] {
    return split32(this.h, 'big')
  }

  _digestHex (): string {
    return toHex32(this.h, 'big')
  }
}

/**
 * An implementation of SHA512 cryptographic hash function. Extends the BaseHash class.
 * It provides a way to compute a 'digest' for any kind of input data; transforming the data
 * into a unique output of fixed size. The output is deterministic; it will always be
 * the same for the same input.
 *
 * @class SHA512
 * @param None
 *
 * @constructor
 * Use the SHA512 constructor to create an instance of SHA512 hash function.
 *
 * @example
 * const sha512 = new SHA512();
 *
 * @property h - The initial hash constants.
 * @property W - Provides a way to recycle usage of the array memory.
 * @property k - The round constants used for each round of SHA-512.
 */
export class SHA512 {
  private readonly h: FastSHA512
  constructor () {
    this.h = new FastSHA512()
  }

  update (msg: number[] | string, enc?: 'hex' | 'utf8'): this {
    const data = Uint8Array.from(toArray(msg, enc))
    this.h.update(data)
    return this
  }

  digest (): number[] {
    return Array.from(this.h.digest())
  }

  digestHex (): string {
    return bytesToHex(this.h.digest())
  }
}

/**
 * The `SHA256HMAC` class is used to create Hash-based Message Authentication Code (HMAC) using the SHA-256 cryptographic hash function.
 *
 * HMAC is a specific type of MAC involving a cryptographic hash function and a secret cryptographic key. It may be used to simultaneously verify both the data integrity and the authenticity of a message.
 *
 * This class also uses the SHA-256 cryptographic hash algorithm that produces a 256-bit (32-byte) hash value.
 *
 * @property inner - Represents the inner hash of SHA-256.
 * @property outer - Represents the outer hash of SHA-256.
 * @property blockSize - The block size for the SHA-256 hash function, in bytes. It's set to 64 bytes.
 * @property outSize - The output size of the SHA-256 hash function, in bytes. It's set to 32 bytes.
 */
export class SHA256HMAC {
  private readonly h: HMAC<FastSHA256>
  blockSize = 64
  outSize = 32

  /**
   * The constructor for the `SHA256HMAC` class.
   *
   * It initializes the `SHA256HMAC` object and sets up the inner and outer padded keys.
   * If the key size is larger than the blockSize, it is digested using SHA-256.
   * If the key size is less than the blockSize, it is padded with zeroes.
   *
   * @constructor
   * @param key - The key to use to create the HMAC. Can be a number array or a string in hexadecimal format.
   *
   * @example
   * const myHMAC = new SHA256HMAC('deadbeef');
   */
  constructor (key: Uint8Array | number[] | string) {
    const k =
      key instanceof Uint8Array
        ? key
        : Uint8Array.from(
          toArray(
            key,
            typeof key === 'string' ? 'hex' : undefined
          )
        )
    this.h = new HMAC(sha256Fast, k)
  }

  /**
   * Updates the `SHA256HMAC` object with part of the message to be hashed.
   *
   * @method update
   * @param msg - Part of the message to hash. Can be a number array or a string.
   * @param enc - If 'hex', then the input is encoded as hexadecimal. If undefined or not 'hex', then no encoding is performed.
   * @returns Returns the instance of `SHA256HMAC` for chaining calls.
   *
   * @example
   * myHMAC.update('deadbeef', 'hex');
   */
  update (msg: Uint8Array | number[] | string, enc?: 'hex'): SHA256HMAC {
    const data =
      msg instanceof Uint8Array ? msg : Uint8Array.from(toArray(msg, enc))
    this.h.update(data)
    return this
  }

  /**
   * Finalizes the HMAC computation and returns the resultant hash.
   *
   * @method digest
   * @returns Returns the digest of the hashed data. Can be a number array or a string.
   *
   * @example
   * let hashedMessage = myHMAC.digest();
   */
  digest (): number[] {
    return Array.from(this.h.digest())
  }

  /**
   * Finalizes the HMAC computation and returns the resultant hash as a hex string.
   *
   * @method digest
   * @returns Returns the digest of the hashed data as a hex string
   *
   * @example
   * let hashedMessage = myHMAC.digestHex();
   */
  digestHex (): string {
    return bytesToHex(this.h.digest())
  }
}

export class SHA1HMAC {
  inner: SHA1
  outer: SHA1
  blockSize = 64

  constructor (key: number[] | string) {
    key = toArray(key, 'hex')
    // Shorten key, if needed
    if (key.length > this.blockSize) {
      key = new SHA1().update(key).digest()
    }

    // Keys shorter than block size are padded with zeros on the right
    let i
    for (i = key.length; i < this.blockSize; i++) {
      key.push(0)
    }

    for (i = 0; i < key.length; i++) {
      key[i] ^= 0x36
    }
    this.inner = new SHA1().update(key)

    // 0x36 ^ 0x5c = 0x6a
    for (i = 0; i < key.length; i++) {
      key[i] ^= 0x6a
    }
    this.outer = new SHA1().update(key)
  }

  update (msg: number[] | string, enc?: 'hex'): SHA1HMAC {
    this.inner.update(msg, enc)
    return this
  }

  digest (): number[] {
    this.outer.update(this.inner.digest())
    return this.outer.digest()
  }

  digestHex (): string {
    this.outer.update(this.inner.digest())
    return this.outer.digestHex()
  }
}

/**
 * The `SHA512HMAC` class is used to create Hash-based Message Authentication Code (HMAC) using the SHA-512 cryptographic hash function.
 *
 * HMAC is a specific type of MAC involving a cryptographic hash function and a secret cryptographic key. It may be used to simultaneously verify both the data integrity and the authenticity of a message.
 *
 * This class also uses the SHA-512 cryptographic hash algorithm that produces a 512-bit (64-byte) hash value.
 *
 * @property inner - Represents the inner hash of SHA-512.
 * @property outer - Represents the outer hash of SHA-512.
 * @property blockSize - The block size for the SHA-512 hash function, in bytes. It's set to 128 bytes.
 * @property outSize - The output size of the SHA-512 hash function, in bytes. It's set to 64 bytes.
 */
export class SHA512HMAC {
  private readonly h: HMAC<FastSHA512>
  blockSize = 128
  outSize = 32

  /**
   * The constructor for the `SHA512HMAC` class.
   *
   * It initializes the `SHA512HMAC` object and sets up the inner and outer padded keys.
   * If the key size is larger than the blockSize, it is digested using SHA-512.
   * If the key size is less than the blockSize, it is padded with zeroes.
   *
   * @constructor
   * @param key - The key to use to create the HMAC. Can be a number array or a string in hexadecimal format.
   *
   * @example
   * const myHMAC = new SHA512HMAC('deadbeef');
   */
  constructor (key: Uint8Array | number[] | string) {
    const k =
      key instanceof Uint8Array
        ? key
        : Uint8Array.from(
          toArray(
            key,
            typeof key === 'string' ? 'hex' : undefined
          )
        )
    this.h = new HMAC(sha512Fast, k)
  }

  /**
   * Updates the `SHA512HMAC` object with part of the message to be hashed.
   *
   * @method update
   * @param msg - Part of the message to hash. Can be a number array or a string.
   * @param enc - If 'hex', then the input is encoded as hexadecimal. If undefined or not 'hex', then no encoding is performed.
   * @returns Returns the instance of `SHA512HMAC` for chaining calls.
   *
   * @example
   * myHMAC.update('deadbeef', 'hex');
   */
  update (msg: Uint8Array | number[] | string, enc?: 'hex' | 'utf8'): SHA512HMAC {
    const data =
      msg instanceof Uint8Array ? msg : Uint8Array.from(toArray(msg, enc))
    this.h.update(data)
    return this
  }

  /**
   * Finalizes the HMAC computation and returns the resultant hash.
   *
   * @method digest
   * @returns Returns the digest of the hashed data as a number array.
   *
   * @example
   * let hashedMessage = myHMAC.digest();
   */
  digest (): number[] {
    return Array.from(this.h.digest())
  }

  /**
   * Finalizes the HMAC computation and returns the resultant hash as a hex string.
   *
   * @method digest
   * @returns Returns the digest of the hashed data as a hex string
   *
   * @example
   * let hashedMessage = myHMAC.digestHex();
   */
  digestHex (): string {
    return bytesToHex(this.h.digest())
  }
}

/**
 * Computes RIPEMD160 hash of a given message.
 * @function ripemd160
 * @param msg - The message to compute the hash for.
 * @param enc - The encoding of msg if string. Default is 'utf8'.
 *
 * @returns the computed RIPEMD160 hash of the message.
 *
 * @example
 * const digest = ripemd160('Hello, world!');
 */
export const ripemd160 = (
  msg: number[] | string,
  enc?: 'hex' | 'utf8'
): number[] => {
  return new RIPEMD160().update(msg, enc).digest()
}

/**
 * Computes SHA1 hash of a given message.
 * @function sha1
 * @param msg - The message to compute the hash for.
 * @param enc - The encoding of msg if string. Default is 'utf8'.
 *
 * @returns the computed SHA1 hash of the message.
 *
 * @example
 * const digest = sha1('Hello, world!');
 */
export const sha1 = (
  msg: number[] | string,
  enc?: 'hex' | 'utf8'
): number[] => {
  return new SHA1().update(msg, enc).digest()
}

/**
 * Computes SHA256 hash of a given message.
 * @function sha256
 * @param msg - The message to compute the hash for.
 * @param enc - The encoding of msg if string. Default is 'utf8'.
 *
 * @returns the computed SHA256 hash of the message.
 *
 * @example
 * const digest = sha256('Hello, world!');
 */
export const sha256 = (
  msg: Uint8Array | number[] | string,
  enc?: 'hex' | 'utf8'
): number[] => {
  return new SHA256().update(msg, enc).digest()
}

/**
 * Computes SHA512 hash of a given message.
 * @function sha512
 * @param msg - The message to compute the hash for.
 * @param enc - The encoding of msg if string. Default is 'utf8'.
 *
 * @returns the computed SHA512 hash of the message.
 *
 * @example
 * const digest = sha512('Hello, world!');
 */
export const sha512 = (
  msg: number[] | string,
  enc?: 'hex' | 'utf8'
): number[] => {
  return new SHA512().update(msg, enc).digest()
}

/**
 * Performs a 'double hash' using SHA256. This means the data is hashed twice
 * with SHA256. First, the SHA256 hash of the message is computed, then the
 * SHA256 hash of the resulting hash is computed.
 * @function hash256
 * @param msg - The message to compute the hash for.
 * @param enc - The encoding of msg if string. Default is 'utf8'.
 *
 * @returns the double hashed SHA256 output.
 *
 * @example
 * const doubleHash = hash256('Hello, world!');
 */
export const hash256 = (
  msg: Uint8Array | number[] | string,
  enc?: 'hex' | 'utf8'
): number[] => {
  const first = new SHA256().update(msg, enc).digest()
  return new SHA256().update(first).digest()
}

/**
 * Computes SHA256 hash of a given message and then computes a RIPEMD160 hash of the result.
 *
 * @function hash160
 * @param msg - The message to compute the hash for.
 * @param enc - The encoding of msg if string. Default is 'utf8'.
 *
 * @returns the RIPEMD160 hash of the SHA256 hash of the input message.
 *
 * @example
 * const hash = hash160('Hello, world!');
 */
export const hash160 = (
  msg: Uint8Array | number[] | string,
  enc?: 'hex' | 'utf8'
): number[] => {
  const first = new SHA256().update(msg, enc).digest()
  return new RIPEMD160().update(first).digest()
}

/**
 * Computes SHA256 HMAC of a given message with a given key.
 * @function sha256hmac
 * @param key - The key used to compute the HMAC
 * @param msg - The message to compute the hash for.
 * @param enc - The encoding of msg if string. Default is 'utf8'.
 *
 * @returns the computed HMAC of the message.
 *
 * @example
 * const digest = sha256hmac('deadbeef', 'ffff001d');
 */
export const sha256hmac = (
  key: Uint8Array | number[] | string,
  msg: Uint8Array | number[] | string,
  enc?: 'hex'
): number[] => {
  return new SHA256HMAC(key).update(msg, enc).digest()
}

/**
 * Computes SHA512 HMAC of a given message with a given key.
 * @function sha512hmac
 * @param key - The key used to compute the HMAC
 * @param msg - The message to compute the hash for.
 * @param enc - The encoding of msg if string. Default is 'utf8'.
 *
 * @returns the computed HMAC of the message.
 *
 * @example
 * const digest = sha512hmac('deadbeef', 'ffff001d');
 */
export const sha512hmac = (
  key: Uint8Array | number[] | string,
  msg: Uint8Array | number[] | string,
  enc?: 'hex'
): number[] => {
  return new SHA512HMAC(key).update(msg, enc).digest()
}

// BEGIN fast-pbkdf2 helpers
// Utils
function isBytes (a: unknown): a is Uint8Array {
  return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array')
}
function anumber (n: number): void {
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new Error(`positive integer expected, got ${n}`)
  }
}
function abytes (b: Uint8Array | undefined, ...lengths: number[]): void {
  if (!isBytes(b)) throw new Error('Uint8Array expected')
  if (lengths.length > 0 && !lengths.includes(b.length)) {
    const lens = lengths.join(',')
    throw new Error(`Uint8Array expected of length ${lens}, got length=${b.length}`)
  }
}
function ahash (h: IHash): void {
  if (typeof h !== 'function' || typeof h.create !== 'function') { throw new Error('Hash should be wrapped by utils.createHasher') }
  anumber(h.outputLen)
  anumber(h.blockLen)
}
function aexists (instance: any, checkFinished = true): void {
  if (instance.destroyed === true) throw new Error('Hash instance has been destroyed')
  if (checkFinished && instance.finished === true) {
    throw new Error('Hash#digest() has already been called')
  }
}
function aoutput (out: any, instance: any): void {
  abytes(out)
  const min: number = instance.outputLen as number
  if (out.length < min) {
    throw new Error(`digestInto() expects output buffer of length at least ${min}`)
  }
}
type TypedArray =
  | Int8Array
  | Uint8ClampedArray
  | Uint8Array
  | Uint16Array
  | Int16Array
  | Uint32Array
  | Int32Array

function clean (...arrays: TypedArray[]): void {
  for (let i = 0; i < arrays.length; i++) arrays[i].fill(0)
}
function createView (arr: TypedArray): DataView {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength)
}
function toBytes (data: Input): Uint8Array {
  if (typeof data === 'string') data = utf8ToBytes(data)
  abytes(data)
  return data
}
function utf8ToBytes (str: string): Uint8Array {
  if (typeof str !== 'string') throw new Error('string expected')
  return new Uint8Array(new TextEncoder().encode(str))
}
type Input = string | Uint8Array
type KDFInput = string | Uint8Array
function kdfInputToBytes (data: KDFInput): Uint8Array {
  if (typeof data === 'string') data = utf8ToBytes(data)
  abytes(data)
  return data
}
interface IHash {
  (data: Uint8Array): Uint8Array
  blockLen: number
  outputLen: number
  create: any
}

interface Hasher<T extends Hash<T>> {
  (msg: Input): Uint8Array
  blockLen: number
  outputLen: number
  create: () => Hash<T>
}
abstract class Hash<T extends Hash<T>> {
  abstract blockLen: number
  abstract outputLen: number
  abstract update (buf: Input): this
  abstract digestInto (buf: Uint8Array): void
  abstract digest (): Uint8Array
  abstract destroy (): void
  abstract _cloneInto (to?: T): T
  abstract clone (): T
}
function createHasher<T extends Hash<T>> (hashCons: () => Hash<T>): Hasher<T> {
  const hashC = (msg: Input): Uint8Array => hashCons().update(toBytes(msg)).digest()
  const tmp = hashCons()
  hashC.outputLen = tmp.outputLen
  hashC.blockLen = tmp.blockLen
  hashC.create = () => hashCons()
  return hashC
}

// u64 helpers
const U32_MASK64 = BigInt(2 ** 32 - 1)
const _32n = BigInt(32)
function fromBig (n: bigint, le = false): { h: number, l: number } {
  if (le) return { h: Number(n & U32_MASK64), l: Number((n >> _32n) & U32_MASK64) }
  return { h: Number((n >> _32n) & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 }
}
function split (lst: bigint[], le = false): Uint32Array[] {
  const len = lst.length
  const Ah = new Uint32Array(len)
  const Al = new Uint32Array(len)
  for (let i = 0; i < len; i++) {
    const { h, l } = fromBig(lst[i], le)
    Ah[i] = h
    Al[i] = l
  }
  return [Ah, Al]
}
const shrSH = (h: number, _l: number, s: number): number => h >>> s
const shrSL = (h: number, l: number, s: number): number => (h << (32 - s)) | (l >>> s)
const rotrSH = (h: number, l: number, s: number): number => (h >>> s) | (l << (32 - s))
const rotrSL = (h: number, l: number, s: number): number => (h << (32 - s)) | (l >>> s)
const rotrBH = (h: number, l: number, s: number): number => (h << (64 - s)) | (l >>> (s - 32))
const rotrBL = (h: number, l: number, s: number): number => (h >>> (s - 32)) | (l << (64 - s))
function add (Ah: number, Al: number, Bh: number, Bl: number): { h: number, l: number } {
  const l = (Al >>> 0) + (Bl >>> 0)
  return { h: (Ah + Bh + ((l / 2 ** 32) | 0)) | 0, l: l | 0 }
}
const add3L = (Al: number, Bl: number, Cl: number): number => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0)
const add3H = (low: number, Ah: number, Bh: number, Ch: number): number => (Ah + Bh + Ch + ((low / 2 ** 32) | 0)) | 0
const add4L = (Al: number, Bl: number, Cl: number, Dl: number): number => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0)
const add4H = (low: number, Ah: number, Bh: number, Ch: number, Dh: number): number => (Ah + Bh + Ch + Dh + ((low / 2 ** 32) | 0)) | 0
const add5L = (Al: number, Bl: number, Cl: number, Dl: number, El: number): number =>
  (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0)
const add5H = (low: number, Ah: number, Bh: number, Ch: number, Dh: number, Eh: number): number =>
  (Ah + Bh + Ch + Dh + Eh + ((low / 2 ** 32) | 0)) | 0

// _md helpers
abstract class HashMD<T extends HashMD<T>> extends Hash<T> {
  readonly blockLen: number
  readonly outputLen: number
  readonly padOffset: number
  readonly isLE: boolean
  protected buffer: Uint8Array
  protected view: DataView
  protected finished = false
  protected length = 0
  protected pos = 0
  protected destroyed = false
  constructor (blockLen: number, outputLen: number, padOffset: number, isLE: boolean) {
    super()
    this.blockLen = blockLen
    this.outputLen = outputLen
    this.padOffset = padOffset
    this.isLE = isLE
    this.buffer = new Uint8Array(blockLen)
    this.view = createView(this.buffer)
  }

  protected abstract process (buf: DataView, offset: number): void
  protected abstract get (): number[]
  protected abstract set (...args: number[]): void
  abstract destroy (): void
  protected abstract roundClean (): void
  update (data: Input): this {
    aexists(this)
    data = toBytes(data)
    abytes(data)
    const { view, buffer, blockLen } = this
    const len = data.length
    for (let pos = 0; pos < len;) {
      const take = Math.min(blockLen - this.pos, len - pos)
      if (take === blockLen) {
        const dataView = createView(data)
        for (; blockLen <= len - pos; pos += blockLen) this.process(dataView, pos)
        continue
      }
      buffer.set(data.subarray(pos, pos + take), this.pos)
      this.pos += take
      pos += take
      if (this.pos === blockLen) {
        this.process(view, 0)
        this.pos = 0
      }
    }
    this.length += data.length
    this.roundClean()
    return this
  }

  digestInto (out: Uint8Array): void {
    aexists(this)
    aoutput(out, this)
    this.finished = true
    const { buffer, view, blockLen, isLE } = this
    let { pos } = this
    buffer[pos++] = 0b10000000
    clean(this.buffer.subarray(pos))
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0)
      pos = 0
    }
    for (let i = pos; i < blockLen; i++) buffer[i] = 0
    setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE)
    this.process(view, 0)
    const oview = createView(out)
    const len = this.outputLen
    if (len % 4 !== 0) throw new Error('_sha2: outputLen should be aligned to 32bit')
    const outLen = len / 4
    const state = this.get()
    if (outLen > state.length) throw new Error('_sha2: outputLen bigger than state')
    for (let i = 0; i < outLen; i++) oview.setUint32(4 * i, state[i], isLE)
  }

  digest (): Uint8Array {
    const { buffer, outputLen } = this
    this.digestInto(buffer)
    const res = buffer.slice(0, outputLen)
    this.destroy()
    return res
  }

  _cloneInto (to?: T): T {
    to ||= new (this.constructor as any)() as T
    to.set(...this.get())
    const { blockLen, buffer, length, finished, destroyed, pos } = this
    to.destroyed = destroyed
    to.finished = finished
    to.length = length
    to.pos = pos
    if (length % blockLen !== 0) to.buffer.set(buffer)
    return to
  }

  clone (): T {
    return this._cloneInto()
  }
}
function setBigUint64 (view: DataView, byteOffset: number, value: bigint, isLE: boolean): void {
  if (typeof view.setBigUint64 === 'function') return view.setBigUint64(byteOffset, value, isLE)
  const _32n = BigInt(32)
  const _u32_max = BigInt(0xffffffff)
  const wh = Number((value >> _32n) & _u32_max)
  const wl = Number(value & _u32_max)
  const h = isLE ? 4 : 0
  const l = isLE ? 0 : 4
  view.setUint32(byteOffset + h, wh, isLE)
  view.setUint32(byteOffset + l, wl, isLE)
}

// sha256 fast constants
const SHA256_IV = Uint32Array.from([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
])
const K256 = Uint32Array.from([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
])
const SHA256_W = new Uint32Array(64)

class FastSHA256 extends HashMD<FastSHA256> {
  protected A = SHA256_IV[0] | 0
  protected B = SHA256_IV[1] | 0
  protected C = SHA256_IV[2] | 0
  protected D = SHA256_IV[3] | 0
  protected E = SHA256_IV[4] | 0
  protected F = SHA256_IV[5] | 0
  protected G = SHA256_IV[6] | 0
  protected H = SHA256_IV[7] | 0
  constructor (outputLen = 32) {
    super(64, outputLen, 8, false)
  }

  protected get (): number[] {
    const { A, B, C, D, E, F, G, H } = this
    return [A, B, C, D, E, F, G, H]
  }

  protected set (
    A: number,
    B: number,
    C: number,
    D: number,
    E: number,
    F: number,
    G: number,
    H: number
  ): void {
    this.A = A | 0
    this.B = B | 0
    this.C = C | 0
    this.D = D | 0
    this.E = E | 0
    this.F = F | 0
    this.G = G | 0
    this.H = H | 0
  }

  protected process (view: DataView, offset: number): void {
    for (let i = 0; i < 16; i++, offset += 4) {
      SHA256_W[i] = view.getUint32(offset)
    }
    for (let i = 16; i < 64; i++) {
      const w15 = SHA256_W[i - 15]
      const w2 = SHA256_W[i - 2]
      const s0 = G0_256(w15)
      const s1 = G1_256(w2)
      SHA256_W[i] = sum32(sum32(s0, SHA256_W[i - 7]), sum32(s1, SHA256_W[i - 16]))
    }

    let { A, B, C, D, E, F, G, H } = this
    for (let i = 0; i < 64; i++) {
      const T1 = SUM32_5(H, S1_256(E), ch32(E, F, G), K256[i], SHA256_W[i])
      const T2 = sum32(S0_256(A), maj32(A, B, C))
      H = G
      G = F
      F = E
      E = sum32(D, T1)
      D = C
      C = B
      B = A
      A = sum32(T1, T2)
    }
    this.A = sum32(this.A, A)
    this.B = sum32(this.B, B)
    this.C = sum32(this.C, C)
    this.D = sum32(this.D, D)
    this.E = sum32(this.E, E)
    this.F = sum32(this.F, F)
    this.G = sum32(this.G, G)
    this.H = sum32(this.H, H)
  }

  protected roundClean (): void {
    clean(SHA256_W)
  }

  destroy (): void {
    clean(this.buffer)
    this.set(0, 0, 0, 0, 0, 0, 0, 0)
  }
}
const sha256Fast = createHasher(() => new FastSHA256())

// sha512
const SHA512_IV = Uint32Array.from([
  0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
  0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179
])
const K512 = (() =>
  split([
    '0x428a2f98d728ae22',
    '0x7137449123ef65cd',
    '0xb5c0fbcfec4d3b2f',
    '0xe9b5dba58189dbbc',
    '0x3956c25bf348b538',
    '0x59f111f1b605d019',
    '0x923f82a4af194f9b',
    '0xab1c5ed5da6d8118',
    '0xd807aa98a3030242',
    '0x12835b0145706fbe',
    '0x243185be4ee4b28c',
    '0x550c7dc3d5ffb4e2',
    '0x72be5d74f27b896f',
    '0x80deb1fe3b1696b1',
    '0x9bdc06a725c71235',
    '0xc19bf174cf692694',
    '0xe49b69c19ef14ad2',
    '0xefbe4786384f25e3',
    '0x0fc19dc68b8cd5b5',
    '0x240ca1cc77ac9c65',
    '0x2de92c6f592b0275',
    '0x4a7484aa6ea6e483',
    '0x5cb0a9dcbd41fbd4',
    '0x76f988da831153b5',
    '0x983e5152ee66dfab',
    '0xa831c66d2db43210',
    '0xb00327c898fb213f',
    '0xbf597fc7beef0ee4',
    '0xc6e00bf33da88fc2',
    '0xd5a79147930aa725',
    '0x06ca6351e003826f',
    '0x142929670a0e6e70',
    '0x27b70a8546d22ffc',
    '0x2e1b21385c26c926',
    '0x4d2c6dfc5ac42aed',
    '0x53380d139d95b3df',
    '0x650a73548baf63de',
    '0x766a0abb3c77b2a8',
    '0x81c2c92e47edaee6',
    '0x92722c851482353b',
    '0xa2bfe8a14cf10364',
    '0xa81a664bbc423001',
    '0xc24b8b70d0f89791',
    '0xc76c51a30654be30',
    '0xd192e819d6ef5218',
    '0xd69906245565a910',
    '0xf40e35855771202a',
    '0x106aa07032bbd1b8',
    '0x19a4c116b8d2d0c8',
    '0x1e376c085141ab53',
    '0x2748774cdf8eeb99',
    '0x34b0bcb5e19b48a8',
    '0x391c0cb3c5c95a63',
    '0x4ed8aa4ae3418acb',
    '0x5b9cca4f7763e373',
    '0x682e6ff3d6b2b8a3',
    '0x748f82ee5defb2fc',
    '0x78a5636f43172f60',
    '0x84c87814a1f0ab72',
    '0x8cc702081a6439ec',
    '0x90befffa23631e28',
    '0xa4506cebde82bde9',
    '0xbef9a3f7b2c67915',
    '0xc67178f2e372532b',
    '0xca273eceea26619c',
    '0xd186b8c721c0c207',
    '0xeada7dd6cde0eb1e',
    '0xf57d4f7fee6ed178',
    '0x06f067aa72176fba',
    '0x0a637dc5a2c898a6',
    '0x113f9804bef90dae',
    '0x1b710b35131c471b',
    '0x28db77f523047d84',
    '0x32caab7b40c72493',
    '0x3c9ebe0a15c9bebc',
    '0x431d67c49c100d4c',
    '0x4cc5d4becb3e42b6',
    '0x597f299cfc657e2a',
    '0x5fcb6fab3ad6faec',
    '0x6c44198c4a475817'
  ].map((n) => BigInt(n)))
)()
const SHA512_Kh = (() => K512[0])()
const SHA512_Kl = (() => K512[1])()
const SHA512_W_H = new Uint32Array(80)
const SHA512_W_L = new Uint32Array(80)

class FastSHA512 extends HashMD<FastSHA512> {
  protected Ah = SHA512_IV[0] | 0
  protected Al = SHA512_IV[1] | 0
  protected Bh = SHA512_IV[2] | 0
  protected Bl = SHA512_IV[3] | 0
  protected Ch = SHA512_IV[4] | 0
  protected Cl = SHA512_IV[5] | 0
  protected Dh = SHA512_IV[6] | 0
  protected Dl = SHA512_IV[7] | 0
  protected Eh = SHA512_IV[8] | 0
  protected El = SHA512_IV[9] | 0
  protected Fh = SHA512_IV[10] | 0
  protected Fl = SHA512_IV[11] | 0
  protected Gh = SHA512_IV[12] | 0
  protected Gl = SHA512_IV[13] | 0
  protected Hh = SHA512_IV[14] | 0
  protected Hl = SHA512_IV[15] | 0
  constructor (outputLen = 64) {
    super(128, outputLen, 16, false)
  }

  protected get (): number[] {
    const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this
    return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl]
  }

  protected set (
    Ah: number,
    Al: number,
    Bh: number,
    Bl: number,
    Ch: number,
    Cl: number,
    Dh: number,
    Dl: number,
    Eh: number,
    El: number,
    Fh: number,
    Fl: number,
    Gh: number,
    Gl: number,
    Hh: number,
    Hl: number
  ): void {
    this.Ah = Ah | 0
    this.Al = Al | 0
    this.Bh = Bh | 0
    this.Bl = Bl | 0
    this.Ch = Ch | 0
    this.Cl = Cl | 0
    this.Dh = Dh | 0
    this.Dl = Dl | 0
    this.Eh = Eh | 0
    this.El = El | 0
    this.Fh = Fh | 0
    this.Fl = Fl | 0
    this.Gh = Gh | 0
    this.Gl = Gl | 0
    this.Hh = Hh | 0
    this.Hl = Hl | 0
  }

  protected process (view: DataView, offset: number): void {
    for (let i = 0; i < 16; i++, offset += 4) {
      SHA512_W_H[i] = view.getUint32(offset)
      SHA512_W_L[i] = view.getUint32((offset += 4))
    }
    for (let i = 16; i < 80; i++) {
      const W15h = SHA512_W_H[i - 15] | 0
      const W15l = SHA512_W_L[i - 15] | 0
      const s0h = rotrSH(W15h, W15l, 1) ^ rotrSH(W15h, W15l, 8) ^ shrSH(W15h, W15l, 7)
      const s0l = rotrSL(W15h, W15l, 1) ^ rotrSL(W15h, W15l, 8) ^ shrSL(W15h, W15l, 7)
      const W2h = SHA512_W_H[i - 2] | 0
      const W2l = SHA512_W_L[i - 2] | 0
      const s1h = rotrSH(W2h, W2l, 19) ^ rotrBH(W2h, W2l, 61) ^ shrSH(W2h, W2l, 6)
      const s1l = rotrSL(W2h, W2l, 19) ^ rotrBL(W2h, W2l, 61) ^ shrSL(W2h, W2l, 6)
      const SUMl = add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16])
      const SUMh = add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16])
      SHA512_W_H[i] = SUMh | 0
      SHA512_W_L[i] = SUMl | 0
    }
    let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this
    for (let i = 0; i < 80; i++) {
      const sigma1h = rotrSH(Eh, El, 14) ^ rotrSH(Eh, El, 18) ^ rotrBH(Eh, El, 41)
      const sigma1l = rotrSL(Eh, El, 14) ^ rotrSL(Eh, El, 18) ^ rotrBL(Eh, El, 41)
      const CHIh = (Eh & Fh) ^ (~Eh & Gh)
      const CHIl = (El & Fl) ^ (~El & Gl)
      const T1ll = add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i])
      const T1h = add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i])
      const T1l = T1ll | 0
      const sigma0h = rotrSH(Ah, Al, 28) ^ rotrBH(Ah, Al, 34) ^ rotrBH(Ah, Al, 39)
      const sigma0l = rotrSL(Ah, Al, 28) ^ rotrBL(Ah, Al, 34) ^ rotrBL(Ah, Al, 39)
      const MAJh = (Ah & Bh) ^ (Ah & Ch) ^ (Bh & Ch)
      const MAJl = (Al & Bl) ^ (Al & Cl) ^ (Bl & Cl)
      Hh = Gh | 0
      Hl = Gl | 0
      Gh = Fh | 0
      Gl = Fl | 0
      Fh = Eh | 0
      Fl = El | 0
      ;({ h: Eh, l: El } = add(Dh | 0, Dl | 0, T1h | 0, T1l | 0))
      Dh = Ch | 0
      Dl = Cl | 0
      Ch = Bh | 0
      Cl = Bl | 0
      Bh = Ah | 0
      Bl = Al | 0
      const T2l = add3L(sigma0l, MAJl, T1l)
      Ah = add3H(T2l, sigma0h, MAJh, T1h)
      Al = T2l | 0
    }
    ;({ h: Ah, l: Al } = add(Ah, Al, this.Ah, this.Al))
    ;({ h: Bh, l: Bl } = add(Bh, Bl, this.Bh, this.Bl))
    ;({ h: Ch, l: Cl } = add(Ch, Cl, this.Ch, this.Cl))
    ;({ h: Dh, l: Dl } = add(Dh, Dl, this.Dh, this.Dl))
    ;({ h: Eh, l: El } = add(Eh, El, this.Eh, this.El))
    ;({ h: Fh, l: Fl } = add(Fh, Fl, this.Fh, this.Fl))
    ;({ h: Gh, l: Gl } = add(Gh, Gl, this.Gh, this.Gl))
    ;({ h: Hh, l: Hl } = add(Hh, Hl, this.Hh, this.Hl))
    this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl)
  }

  protected roundClean (): void {
    clean(SHA512_W_H, SHA512_W_L)
  }

  destroy (): void {
    clean(this.buffer)
    this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
  }
}
const sha512Fast = createHasher(() => new FastSHA512())

class HMAC<T extends Hash<T>> extends Hash<HMAC<T>> {
  oHash: T
  iHash: T
  blockLen: number
  outputLen: number
  private finished = false
  private destroyed = false
  constructor (hash: (msg: Input) => Uint8Array & { create: () => T, blockLen: number, outputLen: number }, _key: Input) {
    super()
    ahash(hash)
    const key = toBytes(_key)
    this.iHash = hash.create() as T
    if (typeof (this.iHash as any).update !== 'function') { throw new Error('Expected instance of class which extends utils.Hash') }
    this.blockLen = this.iHash.blockLen
    this.outputLen = this.iHash.outputLen
    const blockLen = this.blockLen
    const pad = new Uint8Array(blockLen)
    pad.set(key.length > blockLen ? hash.create().update(key).digest() : key)
    for (let i = 0; i < pad.length; i++) pad[i] ^= 0x36
    this.iHash.update(pad)
    this.oHash = hash.create() as T
    for (let i = 0; i < pad.length; i++) pad[i] ^= 0x36 ^ 0x5c
    this.oHash.update(pad)
    clean(pad)
  }

  update (buf: Input): this {
    aexists(this)
    this.iHash.update(buf)
    return this
  }

  digestInto (out: Uint8Array): void {
    aexists(this)
    abytes(out, this.outputLen)
    this.finished = true
    this.iHash.digestInto(out)
    this.oHash.update(out)
    this.oHash.digestInto(out)
    this.destroy()
  }

  digest (): Uint8Array {
    const out = new Uint8Array(this.oHash.outputLen)
    this.digestInto(out)
    return out
  }

  _cloneInto (to?: HMAC<T>): HMAC<T> {
    to ||= Object.create(Object.getPrototypeOf(this), {})
    const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this
    to = to as this
    to.finished = finished
    to.destroyed = destroyed
    to.blockLen = blockLen
    to.outputLen = outputLen
    to.oHash = oHash._cloneInto(to.oHash ?? undefined)
    to.iHash = iHash._cloneInto(to.iHash ?? undefined)
    return to
  }

  clone (): HMAC<T> {
    return this._cloneInto()
  }

  destroy (): void {
    this.destroyed = true
    this.oHash.destroy()
    this.iHash.destroy()
  }
}

function pbkdf2Core (hash: (msg: Input) => Uint8Array & { create: () => FastSHA512, blockLen: number, outputLen: number }, password: KDFInput, salt: KDFInput, opts: { c: number, dkLen?: number }): Uint8Array {
  ahash(hash)
  const { c, dkLen } = Object.assign({ dkLen: 32 }, opts)
  anumber(c)
  anumber(dkLen)
  if (c < 1) throw new Error('iterations (c) should be >= 1')
  const pwd = kdfInputToBytes(password)
  const slt = kdfInputToBytes(salt)
  const DK = new Uint8Array(dkLen)
  const PRF = hmac.create(hash, pwd)
  const PRFSalt = PRF._cloneInto().update(slt)
  let prfW: any
  const arr = new Uint8Array(4)
  const view = createView(arr)
  const u = new Uint8Array(PRF.outputLen)
  for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += PRF.outputLen) {
    const Ti = DK.subarray(pos, pos + PRF.outputLen)
    view.setInt32(0, ti, false)
    ;(prfW = PRFSalt._cloneInto(prfW)).update(arr).digestInto(u)
    Ti.set(u.subarray(0, Ti.length))
    for (let ui = 1; ui < c; ui++) {
      PRF._cloneInto(prfW).update(u).digestInto(u)
      for (let i = 0; i < Ti.length; i++) Ti[i] ^= u[i]
    }
  }
  PRF.destroy()
  PRFSalt.destroy()
  if (prfW != null) prfW.destroy()
  clean(u)
  return DK
}

const hmac = (hash: any, key: Input, message: Input): Uint8Array =>
  new HMAC<any>(hash, key).update(message).digest()
hmac.create = (hash: any, key: Input) => new HMAC<any>(hash, key)

function pbkdf2Fast (password: Uint8Array, salt: Uint8Array, iterations: number, keylen: number): Uint8Array {
  return pbkdf2Core(sha512Fast, password, salt, { c: iterations, dkLen: keylen })
}
// END fast-pbkdf2 helpers

/**
 * Limited SHA-512-only PBKDF2 function for use in deprecated BIP39 code.
 * @function pbkdf2
 * @param password - The PBKDF2 password
 * @param salt - The PBKDF2 salt
 * @param iterations - The number of of iterations to run
 * @param keylen - The length of the key
 * @param digest - The digest (must be sha512 for this implementation)
 *
 * @returns The computed key
 */
export function pbkdf2 (
  password: number[],
  salt: number[],
  iterations: number,
  keylen: number,
  digest = 'sha512'
): number[] {
  if (digest !== 'sha512') {
    throw new Error('Only sha512 is supported in this PBKDF2 implementation')
  }
  // Attempt to use the native Node.js implementation if available as it is
  // considerably faster than the pure TypeScript fallback below. If the crypto
  // module isn't present (for example in a browser build) we'll silently fall
  // back to the original implementation.
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const nodeCrypto = require('crypto')
    if (typeof nodeCrypto.pbkdf2Sync === 'function') {
      const p = Buffer.from(password)
      const s = Buffer.from(salt)
      return [...nodeCrypto.pbkdf2Sync(p, s, iterations, keylen, digest)]
    }
  } catch {
    // ignore
  }
  const p = Uint8Array.from(password)
  const s = Uint8Array.from(salt)
  const out = pbkdf2Fast(p, s, iterations, keylen)
  return Array.from(out)
}

/**
 * Unconditionally swaps the byte order of a 32-bit unsigned integer.
 *
 * This function performs a strict 32-bit byte swap regardless of host
 * endianness. It is equivalent to the behavior commonly referred to as
 * `bswap32` in low-level libraries.
 *
 * This function is introduced as part of TOB-20 to provide a clearly-named
 * alternative to `htonl()`, which was previously implemented as an
 * unconditional byte swap and did not match the semantics of the traditional
 * C `htonl()` function.
 *
 * @param w - A 32-bit unsigned integer.
 * @returns The value with its byte order reversed.
 *
 * @example
 * swapBytes32(0x11223344) // → 0x44332211
 */
export function swapBytes32 (w: number): number {
  const res =
    (w >>> 24) |
    ((w >>> 8) & 0xff00) |
    ((w << 8) & 0xff0000) |
    ((w & 0xff) << 24)
  return res >>> 0
}

// Detect the host machine's endianness at runtime.
//
// This is used by `realHtonl()` to determine whether the value must be
// byte-swapped or returned unchanged. JavaScript engines on common platforms
// are almost always little-endian, but this check is included for correctness.
const isLittleEndian = (() => {
  const b = new ArrayBuffer(4)
  const a = new Uint32Array(b)
  const c = new Uint8Array(b)
  a[0] = 0x01020304
  return c[0] === 0x04
})()

/**
 * Converts a 32-bit unsigned integer from host byte order to network byte order.
 *
 * Unlike the legacy `htonl()` implementation (which always swapped bytes),
 * this function behaves like the traditional C `htonl()`:
 *
 * - On **little-endian** machines → performs a byte swap.
 * - On **big-endian** machines → returns the value unchanged.
 *
 * This function is provided to resolve TOB-20, which identified that the
 * previous `htonl()` implementation had a misleading name and did not match
 * platform-dependent semantics.
 *
 * @param w - A 32-bit unsigned integer.
 * @returns The value converted to network byte order.
 *
 * @example
 * realHtonl(0x11223344) // → 0x44332211 on little-endian systems
 */
export function realHtonl (w: number): number {
  return isLittleEndian ? swapBytes32(w) : (w >>> 0)
}
