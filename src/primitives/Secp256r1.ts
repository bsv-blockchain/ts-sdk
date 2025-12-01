import Random from './Random.js'
import { sha256, sha256hmac } from './Hash.js'
import { toArray, toHex } from './utils.js'

export type P256Point = { x: bigint, y: bigint } | null

type ByteSource = string | Uint8Array | ArrayBufferView

const HEX_REGEX = /^[0-9a-fA-F]+$/

const P = BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff')
const N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551')
const A = P - 3n // a = -3 mod p
const B = BigInt('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b')
const GX = BigInt('0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296')
const GY = BigInt('0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')
const G: P256Point = { x: GX, y: GY }
const HALF_N = N >> 1n

const COMPRESSED_EVEN = '02'
const COMPRESSED_ODD = '03'
const UNCOMPRESSED = '04'

/**
 * Pure BigInt implementation of the NIST P-256 (secp256r1) curve with ECDSA sign/verify.
 *
 * This class is standalone (no dependency on the existing secp256k1 primitives) and exposes
 * key generation, point encoding/decoding, scalar multiplication, and SHA-256 based ECDSA.
 */
export default class Secp256r1 {
  readonly p = P
  readonly n = N
  readonly a = A
  readonly b = B
  readonly g = G

  private mod (x: bigint, m: bigint = this.p): bigint {
    const v = x % m
    return v >= 0n ? v : v + m
  }

  private modInv (x: bigint, m: bigint): bigint {
    if (x === 0n || m <= 0n) throw new Error('Invalid mod inverse input')
    let [a, b] = [this.mod(x, m), m]
    let [u, v] = [1n, 0n]
    while (b !== 0n) {
      const q = a / b
      ;[a, b] = [b, a - q * b]
      ;[u, v] = [v, u - q * v]
    }
    if (a !== 1n) throw new Error('Inverse does not exist')
    return this.mod(u, m)
  }

  private modPow (base: bigint, exponent: bigint, modulus: bigint): bigint {
    if (modulus === 1n) return 0n
    let result = 1n
    let b = this.mod(base, modulus)
    let e = exponent
    while (e > 0n) {
      if ((e & 1n) === 1n) result = this.mod(result * b, modulus)
      e >>= 1n
      b = this.mod(b * b, modulus)
    }
    return result
  }

  private isInfinity (p: P256Point): p is null {
    return p === null
  }

  private assertOnCurve (p: P256Point): void {
    if (this.isInfinity(p)) return
    const { x, y } = p
    const left = this.mod(y * y)
    const right = this.mod(this.mod(x * x * x + this.a * x) + this.b)
    if (left !== right) {
      throw new Error('Point is not on secp256r1')
    }
  }

  pointFromAffine (x: bigint, y: bigint): P256Point {
    const point: P256Point = { x: this.mod(x), y: this.mod(y) }
    this.assertOnCurve(point)
    return point
  }

  /**
   * Decode a point from compressed or uncompressed hex.
   */
  pointFromHex (hex: string): P256Point {
    if (hex.startsWith(UNCOMPRESSED)) {
      const x = BigInt('0x' + hex.slice(2, 66))
      const y = BigInt('0x' + hex.slice(66))
      return this.pointFromAffine(x, y)
    }
    if (hex.startsWith(COMPRESSED_EVEN) || hex.startsWith(COMPRESSED_ODD)) {
      const x = BigInt('0x' + hex.slice(2))
      const ySq = this.mod(this.mod(x * x * x + this.a * x) + this.b)
      const y = this.modPow(ySq, (this.p + 1n) >> 2n, this.p)
      const isOdd = (y & 1n) === 1n
      const shouldBeOdd = hex.startsWith(COMPRESSED_ODD)
      const yFinal = (isOdd === shouldBeOdd) ? y : this.p - y
      return this.pointFromAffine(x, yFinal)
    }
    throw new Error('Invalid point encoding')
  }

  /**
   * Encode a point to compressed or uncompressed hex. Infinity is encoded as `00`.
   */
  pointToHex (p: P256Point, compressed = false): string {
    if (this.isInfinity(p)) return '00'
    const xHex = this.to32BytesHex(p.x)
    const yHex = this.to32BytesHex(p.y)
    if (!compressed) return UNCOMPRESSED + xHex + yHex
    const prefix = (p.y & 1n) === 0n ? COMPRESSED_EVEN : COMPRESSED_ODD
    return prefix + xHex
  }

  /**
   * Add two affine points (handles infinity).
   */
  private addPoints (p1: P256Point, p2: P256Point): P256Point {
    if (this.isInfinity(p1)) return p2
    if (this.isInfinity(p2)) return p1

    const { x: x1, y: y1 } = p1
    const { x: x2, y: y2 } = p2

    if (x1 === x2) {
      if (y1 === y2) {
        return this.doublePoint(p1)
      }
      return null
    }

    const m = this.mod((y2 - y1) * this.modInv(x2 - x1, this.p))
    const x3 = this.mod(m * m - x1 - x2)
    const y3 = this.mod(m * (x1 - x3) - y1)
    return { x: x3, y: y3 }
  }

  private doublePoint (p: P256Point): P256Point {
    if (this.isInfinity(p)) return p
    if (p.y === 0n) return null
    const m = this.mod((3n * p.x * p.x + this.a) * this.modInv(2n * p.y, this.p))
    const x3 = this.mod(m * m - 2n * p.x)
    const y3 = this.mod(m * (p.x - x3) - p.y)
    return { x: x3, y: y3 }
  }

  /**
   * Add two points (handles infinity).
   */
  add (p1: P256Point, p2: P256Point): P256Point {
    return this.addPoints(p1, p2)
  }

  /**
   * Scalar multiply an arbitrary point using double-and-add.
   */
  multiply (point: P256Point, scalar: bigint): P256Point {
    if (scalar === 0n || this.isInfinity(point)) return null
    let k = this.mod(scalar, this.n)
    let result: P256Point = null
    let addend: P256Point = point
    while (k > 0n) {
      if ((k & 1n) === 1n) {
        result = this.addPoints(result, addend)
      }
      addend = this.doublePoint(addend)
      k >>= 1n
    }
    return result
  }

  /**
   * Scalar multiply the base point.
   */
  multiplyBase (scalar: bigint): P256Point {
    return this.multiply(this.g, scalar)
  }

  /**
   * Check if a point lies on the curve (including infinity).
   */
  isOnCurve (p: P256Point): boolean {
    try {
      this.assertOnCurve(p)
      return true
    } catch (err) {
      return false
    }
  }

  /**
   * Generate a new random private key as 32-byte hex.
   */
  generatePrivateKeyHex (): string {
    return this.to32BytesHex(this.randomScalar())
  }

  private randomScalar (): bigint {
    while (true) {
      const bytes = Random(32)
      const k = BigInt('0x' + toHex(bytes))
      if (k > 0n && k < this.n) return k
    }
  }

  private normalizePrivateKey (d: bigint): bigint {
    const key = this.mod(d, this.n)
    if (key === 0n) throw new Error('Invalid private key')
    return key
  }

  private toScalar (input: string | bigint): bigint {
    if (typeof input === 'bigint') return this.normalizePrivateKey(input)
    const hex = input.startsWith('0x') ? input.slice(2) : input
    if (!HEX_REGEX.test(hex) || hex.length === 0 || hex.length > 64) {
      throw new Error('Private key must be a hex string <= 32 bytes')
    }
    const value = BigInt('0x' + hex.padStart(64, '0'))
    return this.normalizePrivateKey(value)
  }

  publicKeyFromPrivate (privateKey: string | bigint): P256Point {
    const d = this.toScalar(privateKey)
    return this.multiplyBase(d)
  }

  /**
   * Create an ECDSA signature over a message. Uses SHA-256 unless `prehashed` is true.
   * Returns low-s normalized signature hex parts.
   */
  sign (message: ByteSource, privateKey: string | bigint, opts: { prehashed?: boolean, nonce?: bigint } = {}): { r: string, s: string } {
    const { prehashed = false, nonce } = opts
    const d = this.toScalar(privateKey)
    const digest = this.normalizeMessage(message, prehashed)
    const z = this.bytesToScalar(digest)
    let k = nonce ?? this.deterministicNonce(d, digest)

    while (true) {
      const p = this.multiplyBase(k)
      if (this.isInfinity(p)) {
        k = nonce ?? this.deterministicNonce(d, digest)
        continue
      }
      const r = this.mod(p.x, this.n)
      if (r === 0n) {
        k = nonce ?? this.deterministicNonce(d, digest)
        continue
      }
      const kinv = this.modInv(k, this.n)
      let s = this.mod(kinv * (z + r * d), this.n)
      if (s === 0n) {
        k = nonce ?? this.deterministicNonce(d, digest)
        continue
      }
      if (s > HALF_N) s = this.n - s // enforce low-s
      return { r: this.to32BytesHex(r), s: this.to32BytesHex(s) }
    }
  }

  /**
   * Verify an ECDSA signature against a message and public key.
   */
  verify (message: ByteSource, signature: { r: string | bigint, s: string | bigint }, publicKey: P256Point | string, opts: { prehashed?: boolean } = {}): boolean {
    const { prehashed = false } = opts
    let q: P256Point
    try {
      q = typeof publicKey === 'string' ? this.pointFromHex(publicKey) : publicKey
    } catch {
      return false
    }
    if ((q == null) || !this.isOnCurve(q)) return false

    const r = typeof signature.r === 'bigint' ? signature.r : BigInt('0x' + signature.r)
    const s = typeof signature.s === 'bigint' ? signature.s : BigInt('0x' + signature.s)
    if (r <= 0n || r >= this.n || s <= 0n || s >= this.n) return false

    const z = this.bytesToScalar(this.normalizeMessage(message, prehashed))
    const w = this.modInv(s, this.n)
    const u1 = this.mod(z * w, this.n)
    const u2 = this.mod(r * w, this.n)
    const p = this.addPoints(this.multiplyBase(u1), this.multiply(q, u2))
    if (this.isInfinity(p)) return false
    const v = this.mod(p.x, this.n)
    return v === r
  }

  private normalizeMessage (message: ByteSource, prehashed: boolean): Uint8Array {
    const bytes = this.toBytes(message)
    if (prehashed) return bytes
    return new Uint8Array(sha256(bytes))
  }

  private bytesToScalar (bytes: Uint8Array): bigint {
    const hex = toHex(Array.from(bytes))
    return BigInt('0x' + hex) % this.n
  }

  private deterministicNonce (priv: bigint, msgDigest: Uint8Array): bigint {
    const keyBytes = toArray(this.to32BytesHex(priv), 'hex')
    let counter = 0
    while (counter < 1024) { // safety bound
      const data = counter === 0
        ? Array.from(msgDigest)
        : Array.from(msgDigest).concat([counter & 0xff])
      const hmac = sha256hmac(keyBytes, data)
      const k = BigInt('0x' + toHex(hmac)) % this.n
      if (k > 0n) return k
      counter++
    }
    throw new Error('Failed to derive deterministic nonce')
  }

  private toBytes (data: ByteSource): Uint8Array {
    if (typeof data === 'string') {
      const isHex = HEX_REGEX.test(data) && data.length % 2 === 0
      return Uint8Array.from(toArray(data, isHex ? 'hex' : 'utf8'))
    }
    if (data instanceof Uint8Array) return data
    if (ArrayBuffer.isView(data)) {
      return new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
    }
    throw new Error('Unsupported message format')
  }

  private to32BytesHex (num: bigint): string {
    return num.toString(16).padStart(64, '0')
  }
}
