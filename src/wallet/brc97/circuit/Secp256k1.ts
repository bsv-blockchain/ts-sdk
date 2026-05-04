import { SecpPoint } from './Types.js'

export const SECP256K1_P =
  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
export const SECP256K1_N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
export const SECP256K1_G: SecpPoint = {
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
}

interface JacobianPoint {
  x: bigint
  y: bigint
  z: bigint
  infinity?: boolean
}

export enum SecpAddBranch {
  LeftInfinity = 0,
  RightInfinity = 1,
  Double = 2,
  Opposite = 3,
  Add = 4
}

export function modP (value: bigint): bigint {
  let result = value % SECP256K1_P
  if (result < 0n) result += SECP256K1_P
  return result
}

export function modInvP (value: bigint): bigint {
  value = modP(value)
  if (value === 0n) throw new Error('Cannot invert zero modulo p')
  let low = value
  let high = SECP256K1_P
  let lm = 1n
  let hm = 0n
  while (low > 1n) {
    const ratio = high / low
    ;[lm, hm] = [hm - lm * ratio, lm]
    ;[low, high] = [high - low * ratio, low]
  }
  return modP(lm)
}

export function secpFieldAdd (left: bigint, right: bigint): bigint {
  return modP(left + right)
}

export function secpFieldSub (left: bigint, right: bigint): bigint {
  return modP(left - right)
}

export function secpFieldMul (left: bigint, right: bigint): bigint {
  return modP(left * right)
}

export function secpFieldSquare (value: bigint): bigint {
  return secpFieldMul(value, value)
}

export function validateScalar (scalar: bigint): void {
  if (scalar <= 0n || scalar >= SECP256K1_N) {
    throw new Error('Scalar must satisfy 0 < scalar < secp256k1.n')
  }
}

export function isOnCurve (point: SecpPoint): boolean {
  if (point.infinity === true) return false
  if (point.x < 0n || point.x >= SECP256K1_P) return false
  if (point.y < 0n || point.y >= SECP256K1_P) return false
  return secpFieldSquare(point.y) === secpFieldAdd(
    secpFieldMul(secpFieldSquare(point.x), point.x),
    7n
  )
}

export function decompressPublicKey (bytes: number[] | Uint8Array): SecpPoint {
  if (bytes.length !== 33) throw new Error('Compressed public key must be 33 bytes')
  const prefix = bytes[0]
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new Error('Invalid compressed public key prefix')
  }
  const x = bytesToBigintBE(bytes.slice(1))
  if (x >= SECP256K1_P) throw new Error('Public key x-coordinate out of field')
  const y2 = secpFieldAdd(secpFieldMul(secpFieldSquare(x), x), 7n)
  let y = modPow(y2, (SECP256K1_P + 1n) >> 2n, SECP256K1_P)
  if (secpFieldSquare(y) !== y2) throw new Error('Invalid compressed public key')
  if ((y & 1n) !== BigInt(prefix & 1)) y = SECP256K1_P - y
  const point: SecpPoint = { x, y }
  if (!isOnCurve(point)) throw new Error('Invalid public key point')
  return point
}

export function compressPoint (point: SecpPoint): number[] {
  if (!isOnCurve(point)) throw new Error('Cannot compress invalid point')
  return [
    (point.y & 1n) === 0n ? 0x02 : 0x03,
    ...bigintToBytesBE(point.x, 32)
  ]
}

export function pointAddWithBranch (
  left: SecpPoint,
  right: SecpPoint
): { point: SecpPoint, branch: SecpAddBranch } {
  if (left.infinity === true) {
    if (right.infinity === true) return { point: infinityPoint(), branch: SecpAddBranch.LeftInfinity }
    if (!isOnCurve(right)) throw new Error('Cannot add invalid secp256k1 points')
    return { point: right, branch: SecpAddBranch.LeftInfinity }
  }
  if (right.infinity === true) {
    if (!isOnCurve(left)) throw new Error('Cannot add invalid secp256k1 points')
    return { point: left, branch: SecpAddBranch.RightInfinity }
  }
  if (!isOnCurve(left) || !isOnCurve(right)) {
    throw new Error('Cannot add invalid secp256k1 points')
  }
  if (left.x === right.x && left.y !== right.y) {
    return { point: infinityPoint(), branch: SecpAddBranch.Opposite }
  }
  if (left.x === right.x && left.y === right.y) {
    return { point: pointDouble(left), branch: SecpAddBranch.Double }
  }
  const slope = secpFieldMul(
    secpFieldSub(right.y, left.y),
    modInvP(secpFieldSub(right.x, left.x))
  )
  const x = secpFieldSub(secpFieldSub(secpFieldSquare(slope), left.x), right.x)
  const y = secpFieldSub(secpFieldMul(slope, secpFieldSub(left.x, x)), left.y)
  return { point: { x, y }, branch: SecpAddBranch.Add }
}

export function pointAdd (left: SecpPoint, right: SecpPoint): SecpPoint {
  return pointAddWithBranch(left, right).point
}

export function pointDouble (point: SecpPoint): SecpPoint {
  if (point.infinity === true) return point
  if (!isOnCurve(point)) throw new Error('Cannot double invalid secp256k1 point')
  if (point.y === 0n) return infinityPoint()
  const slope = secpFieldMul(
    secpFieldMul(3n, secpFieldSquare(point.x)),
    modInvP(secpFieldMul(2n, point.y))
  )
  const x = secpFieldSub(secpFieldSquare(slope), secpFieldMul(2n, point.x))
  const y = secpFieldSub(secpFieldMul(slope, secpFieldSub(point.x, x)), point.y)
  return { x, y }
}

export function scalarMultiply (
  scalar: bigint,
  point: SecpPoint = SECP256K1_G
): SecpPoint {
  validateScalar(scalar)
  if (!isOnCurve(point)) throw new Error('Cannot multiply invalid secp256k1 point')
  let acc = infinityJacobian()
  for (let bit = 255; bit >= 0; bit--) {
    acc = jacobianDouble(acc)
    if (((scalar >> BigInt(bit)) & 1n) === 1n) {
      acc = jacobianMixedAdd(acc, point)
    }
  }
  return jacobianToAffine(acc)
}

export function publicKeyToPoint (publicKey: { toDER: () => number[] | Uint8Array }): SecpPoint {
  return decompressPublicKey(publicKey.toDER())
}

function infinityPoint (): SecpPoint {
  return { x: 0n, y: 0n, infinity: true }
}

function infinityJacobian (): JacobianPoint {
  return { x: 0n, y: 0n, z: 0n, infinity: true }
}

function affineToJacobian (point: SecpPoint): JacobianPoint {
  if (point.infinity === true) return infinityJacobian()
  return { x: point.x, y: point.y, z: 1n }
}

function jacobianToAffine (point: JacobianPoint): SecpPoint {
  if (point.infinity === true || point.z === 0n) {
    throw new Error('Scalar multiplication produced infinity')
  }
  const zInv = modInvP(point.z)
  const zInv2 = secpFieldSquare(zInv)
  const zInv3 = secpFieldMul(zInv2, zInv)
  const out = {
    x: secpFieldMul(point.x, zInv2),
    y: secpFieldMul(point.y, zInv3)
  }
  if (!isOnCurve(out)) throw new Error('Scalar multiplication produced invalid point')
  return out
}

function jacobianMixedAdd (
  left: JacobianPoint,
  right: SecpPoint
): JacobianPoint {
  if (right.infinity === true) return left
  if (left.infinity === true || left.z === 0n) return affineToJacobian(right)
  const z1z1 = secpFieldSquare(left.z)
  const u2 = secpFieldMul(right.x, z1z1)
  const s2 = secpFieldMul(right.y, secpFieldMul(left.z, z1z1))
  const h = secpFieldSub(u2, left.x)
  const r = secpFieldMul(2n, secpFieldSub(s2, left.y))
  if (h === 0n) {
    if (r === 0n) return jacobianDouble(left)
    return infinityJacobian()
  }
  const hh = secpFieldSquare(h)
  const i = secpFieldMul(4n, hh)
  const j = secpFieldMul(h, i)
  const v = secpFieldMul(left.x, i)
  const x = secpFieldSub(secpFieldSub(secpFieldSquare(r), j), secpFieldMul(2n, v))
  const y = secpFieldSub(
    secpFieldMul(r, secpFieldSub(v, x)),
    secpFieldMul(2n, secpFieldMul(left.y, j))
  )
  const z = secpFieldSub(
    secpFieldSub(secpFieldSquare(secpFieldAdd(left.z, h)), z1z1),
    hh
  )
  return { x, y, z }
}

function jacobianDouble (point: JacobianPoint): JacobianPoint {
  if (point.infinity === true || point.z === 0n || point.y === 0n) {
    return infinityJacobian()
  }
  const yy = secpFieldSquare(point.y)
  const yyyy = secpFieldSquare(yy)
  const s = secpFieldMul(4n, secpFieldMul(point.x, yy))
  const m = secpFieldMul(3n, secpFieldSquare(point.x))
  const x = secpFieldSub(secpFieldSquare(m), secpFieldMul(2n, s))
  const y = secpFieldSub(
    secpFieldMul(m, secpFieldSub(s, x)),
    secpFieldMul(8n, yyyy)
  )
  const z = secpFieldMul(2n, secpFieldMul(point.y, point.z))
  return { x, y, z }
}

function modPow (base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n
  let current = base % modulus
  let exp = exponent
  while (exp > 0n) {
    if ((exp & 1n) === 1n) result = (result * current) % modulus
    current = (current * current) % modulus
    exp >>= 1n
  }
  return result
}

function bytesToBigintBE (bytes: ArrayLike<number>): bigint {
  let value = 0n
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i]
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error('Invalid byte')
    }
    value = (value << 8n) | BigInt(byte)
  }
  return value
}

function bigintToBytesBE (value: bigint, length: number): number[] {
  const bytes = new Array<number>(length)
  let v = value
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn)
    v >>= 8n
  }
  if (v !== 0n) throw new Error('Integer does not fit in requested bytes')
  return bytes
}
