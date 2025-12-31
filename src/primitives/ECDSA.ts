import BigNumber from './BigNumber.js'
import Signature from './Signature.js'
import Curve from './Curve.js'
import Point, { scalarMultiplyWNAF, biModInv, BI_ZERO, biModMul, GX_BIGINT, GY_BIGINT, jpAdd, N_BIGINT, modInvN, modMulN, modN } from './Point.js'
import DRBG from './DRBG.js'

/**
 * Truncates a BigNumber message to the length of the curve order n, in the context of the Elliptic Curve Digital Signature Algorithm (ECDSA).
 * This method is used as part of ECDSA signing and verification.
 *
 * The method calculates `delta`, which is a difference obtained by subtracting the bit length of the curve order `n` from the byte length of the message in bits.
 * If `delta` is greater than zero, logical shifts msg to the right by `delta`, retaining the sign.
 *
 * Another condition is tested, but only if `truncOnly` is false. This condition compares the value of msg to curve order `n`.
 * If msg is greater or equal to `n`, it is decreased by `n` and returned.
 *
 * @method truncateToN
 * @param msg - The BigNumber message to be truncated.
 * @param truncOnly - An optional boolean parameter that if set to true, the method will only perform truncation of the BigNumber without doing the additional subtraction from the curve order.
 * @returns Returns the truncated BigNumber value, potentially subtracted by the curve order n.
 *
 * @example
 * let msg = new BigNumber('1234567890abcdef', 16);
 * let truncatedMsg = truncateToN(msg);
 *
 * This behavior follows the message truncation rules defined in FIPS 186-4.
 */
function truncateToN (
  msg: BigNumber,
  truncOnly?: boolean,
  curve = new Curve()
): BigNumber {
  const delta = msg.byteLength() * 8 - curve.n.bitLength()
  if (delta > 0) {
    msg.iushrn(delta)
  }
  if (truncOnly !== true && msg.cmp(curve.n) >= 0) {
    return msg.sub(curve.n)
  } else {
    return msg
  }
}

function bnToBigInt (bn: BigNumber): bigint {
  const bytes = bn.toArray('be')
  let x = 0n
  for (let i = 0; i < bytes.length; i++) {
    x = (x << 8n) | BigInt(bytes[i])
  }
  return x
}

const curve = new Curve()
const bytes = curve.n.byteLength()
const ns1 = curve.n.subn(1)
const halfN = N_BIGINT >> 1n

/**
 * Generates a digital signature for a given message.
 *
 * @function sign
 * @param msg - The BigNumber message for which the signature has to be computed.
 * @param key - Private key in BigNumber.
 * @param forceLowS - Optional boolean flag if True forces "s" to be the lower of two possible values.
 * @param customK - Optional specification for k value, which can be a function or BigNumber.
 * @returns Returns the elliptic curve digital signature of the message.
 *
 * @example
 * const msg = new BigNumber('2664878')
 * const key = new BigNumber('123456')
 * const signature = sign(msg, key)
 */
/**
 * SECURITY NOTE:
 *
 * This function implements ECDSA signing and expects `msg` to be the output of
 * a cryptographic hash function (e.g. SHA-256), not an arbitrary-length message.
 *
 * Per FIPS 186-4 / SEC 1, the message representative used by ECDSA must not
 * exceed the bit length of the curve order `n`. Inputs larger than `n` must be
 * hashed before signing.
 *
 * As a short-term mitigation for TOB-22, this implementation explicitly rejects
 * messages whose bit length exceeds that of the curve order.
 *
 * Long-term, callers SHOULD always hash messages before invoking `sign()`.
 */
export const sign = (
  msg: BigNumber,
  key: BigNumber,
  forceLowS: boolean = false,
  customK?: BigNumber | ((iter: number) => BigNumber)
): Signature => {
  const nBitLength = curve.n.bitLength()
  if (msg.bitLength() > nBitLength) {
    throw new Error(
      `ECDSA message is too large: expected <= ${nBitLength} bits. Callers must hash messages before signing.`
    )
  }

  msg = truncateToN(msg)
  const msgBig = bnToBigInt(msg)
  const keyBig = bnToBigInt(key)

  const bkey = key.toArray('be', bytes)
  const nonce = msg.toArray('be', bytes)
  const drbg = new DRBG(bkey, nonce)

  for (let iter = 0; ; iter++) {
    let kBN =
      typeof customK === 'function'
        ? customK(iter)
        : BigNumber.isBN(customK)
          ? customK
          : new BigNumber(drbg.generate(bytes), 16)

    if (kBN == null) {
      throw new Error('k is undefined')
    }

    kBN = truncateToN(kBN, true)

    if (kBN.cmpn(1) < 0 || kBN.cmp(ns1) > 0) {
      if (BigNumber.isBN(customK)) {
        throw new Error('Invalid fixed custom K value (must be >1 and <N-1)')
      }
      continue
    }

    const R = curve.g.mulCT(kBN)

    if (R.isInfinity()) {
      if (BigNumber.isBN(customK)) {
        throw new Error('Invalid fixed custom K value (k·G at infinity)')
      }
      continue
    }

    const xAff = BigInt('0x' + R.getX().toString(16))
    const rBig = modN(xAff)

    if (rBig === 0n) {
      if (BigNumber.isBN(customK)) {
        throw new Error('Invalid fixed custom K value (r == 0)')
      }
      continue
    }

    const kBig = BigInt('0x' + kBN.toString(16))
    const kInv = modInvN(kBig)
    const rTimesKey = modMulN(rBig, keyBig)
    const sum = modN(msgBig + rTimesKey)
    let sBig = modMulN(kInv, sum)

    if (sBig === 0n) {
      if (BigNumber.isBN(customK)) {
        throw new Error('Invalid fixed custom K value (s == 0)')
      }
      continue
    }

    if (forceLowS && sBig > halfN) {
      sBig = N_BIGINT - sBig
    }

    const r = new BigNumber(rBig.toString(16), 16)
    const s = new BigNumber(sBig.toString(16), 16)
    return new Signature(r, s)
  }
}

/**
 * Verifies a digital signature of a given message.
 *
 * Message and key used during the signature generation process, and the previously computed signature
 * are used to validate the authenticity of the digital signature.
 *
 * @function verify
 * @param msg - The BigNumber message for which the signature has to be verified.
 * @param sig - Signature object consisting of parameters 'r' and 's'.
 * @param key - Public key in Point.
 * @returns Returns true if the signature is valid and false otherwise.
 *
 * @example
 * const msg = new BigNumber('2664878', 16)
 * const key = new Point(new BigNumber(10), new BigNumber(20)
 * const signature = sign(msg, new BigNumber('123456'))
 * const isVerified = verify(msg, sig, key)
 */
/**
 * SECURITY NOTE:
 *
 * This verification routine assumes that `msg` is a hashed message
 * representative produced using the same hash function used during signing.
 *
 * As part of TOB-22 short-term hardening, messages exceeding the curve order
 * bit length are rejected to prevent misuse with non-hashed inputs.
 */
export const verify = (msg: BigNumber, sig: Signature, key: Point): boolean => {
  const nBitLength = curve.n.bitLength()
  if (msg.bitLength() > nBitLength) {
    // could be throw or return false; returning false is typical for verify
    return false
  }

  // Convert inputs to BigInt
  const hash = bnToBigInt(msg)
  if ((key.x == null) || (key.y == null)) {
    throw new Error('Invalid public key: missing coordinates.')
  }

  const publicKey = {
    x: bnToBigInt(key.x),
    y: bnToBigInt(key.y)
  }
  const signature = {
    r: bnToBigInt(sig.r),
    s: bnToBigInt(sig.s)
  }

  const { r, s } = signature
  const z = hash

  // Check r and s are in [1, n - 1]
  if (r <= BI_ZERO || r >= N_BIGINT || s <= BI_ZERO || s >= N_BIGINT) {
    return false
  }

  // ── compute u₁ = z·s⁻¹ mod n  and  u₂ = r·s⁻¹ mod n ───────────────────────
  const w = modInvN(s) // s⁻¹ mod n
  if (w === 0n) return false // should never happen
  const u1 = modMulN(z, w)
  const u2 = modMulN(r, w)

  // ── R = u₁·G + u₂·Q  (Jacobian, window‑NAF) ──────────────────────────────
  const RG = scalarMultiplyWNAF(u1, { x: GX_BIGINT, y: GY_BIGINT })
  const RQ = scalarMultiplyWNAF(u2, publicKey)
  const R = jpAdd(RG, RQ)
  if (R.Z === 0n) return false // point at infinity

  // ── affine x‑coordinate of R  (mod p) ─────────────────────────────────────
  const zInv = biModInv(R.Z) // (Z⁻¹ mod p)
  const zInv2 = biModMul(zInv, zInv) // Z⁻²
  const xAff = biModMul(R.X, zInv2) // X / Z²  mod p

  // ── v = xAff mod n  and final check ───────────────────────────────────────
  const v = modN(xAff)
  return v === r
}
