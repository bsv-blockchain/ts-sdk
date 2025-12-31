import * as ECDSA from '../../primitives/ECDSA'
import BigNumber from '../../primitives/BigNumber'
import Curve from '../../primitives/Curve'
import Signature from '../../primitives/Signature'
import Point from '../../primitives/Point'

const msg = new BigNumber('deadbeef', 16)
const key = new BigNumber(
  '1e5edd45de6d22deebef4596b80444ffcc29143839c1dce18db470e25b4be7b5',
  16
)
const curve = new Curve()
const pub = curve.g.mul(key)
const wrongPub = curve.g.mul(new BigNumber(33))

describe('ECDSA', () => {
  it('should sign and verify', () => {
    const signature = ECDSA.sign(msg, key)
    expect(ECDSA.verify(msg, signature, pub)).toBeTruthy()
  })

  it('should encode and decode with DER', () => {
    const signature = ECDSA.sign(msg, key)
    const encoded = signature.toDER()
    expect(encoded.length).toBe(71)
    const decoded = Signature.fromDER(encoded)
    expect(decoded.r.toString(16)).toEqual(signature.r.toString(16))
    expect(decoded.s.toString(16)).toEqual(signature.s.toString(16))
  })

  it('should encode and decode with hex DER', () => {
    const signature = ECDSA.sign(msg, key)
    const encoded = signature.toDER('hex')
    expect(encoded.length).toBe(142)
    const decoded = Signature.fromDER(encoded, 'hex')
    expect(decoded.r.toString(16)).toEqual(signature.r.toString(16))
    expect(decoded.s.toString(16)).toEqual(signature.s.toString(16))
  })

  it('should have `signature.s <= keys.ec.nh`', () => {
    // key.sign(msg, options)
    const sign = ECDSA.sign(msg, key, true)
    expect(sign.s.cmp(curve.n.ushrn(1)) <= 0).toBeTruthy()
  })

  it('should support `options.k`', () => {
    const sign = ECDSA.sign(msg, key, undefined, new BigNumber(1358))
    expect(ECDSA.verify(msg, sign, pub)).toBeTruthy()
  })

  it('should not verify an incorrectly signed message', () => {
    const wrongMessage = new BigNumber(
      'BA5AABBE1AA9B6EC1E2ADB2DF99699344345678901234567890ABCDEFABCDEF02',
      16
    )
    const signature = ECDSA.sign(msg, key)
    const result = ECDSA.verify(wrongMessage, signature, pub)
    expect(result).toBe(false)
  })

  it('should not verify signature with wrong public key', () => {
    const signature = ECDSA.sign(msg, key)
    expect(ECDSA.verify(msg, signature, wrongPub)).toBeFalsy()
  })

  it('should accept custom k = 1 and k = n-1', () => {
    const n = curve.n
    const one = new BigNumber(1)

    // k = 1 → valid
    const k1 = one
    const sig1 = ECDSA.sign(msg, key, undefined, k1)
    expect(ECDSA.verify(msg, sig1, pub)).toBeTruthy()

    // k = n-1 → valid
    const km1 = n.subn(1)
    const sig2 = ECDSA.sign(msg, key, undefined, km1)
    expect(ECDSA.verify(msg, sig2, pub)).toBeTruthy()
  })

  it('should reject custom k < 1 or k > n-1', () => {
    const n = curve.n

    // k = 0 → invalid
    expect(() =>
      ECDSA.sign(msg, key, undefined, new BigNumber(0))
    ).toThrow()

    // k = n → invalid
    expect(() =>
      ECDSA.sign(msg, key, undefined, n)
    ).toThrow()
  })

  it('k·G + (−k·G) results in point at infinity (TOB-25)', () => {
    const k = new BigNumber('123456789abcdef', 16)

    const P = curve.g.mul(k)
    const negP = P.neg()
    const sum = P.add(negP)

    expect(sum.isInfinity()).toBe(true)
  })

  it('scalar multiplication by zero returns point at infinity (TOB-25)', () => {
    const zero = new BigNumber(0)
    const result = curve.g.mul(zero)

    expect(result.isInfinity()).toBe(true)
  })

  it('ECDSA verify rejects point-at-infinity public key (TOB-25)', () => {
    const signature = ECDSA.sign(msg, key)
    const infinityPub = new Point(null, null)

    expect(() =>
      ECDSA.verify(msg, signature, infinityPub)
    ).toThrow()
  })

  it('sign/verify works with large private key (mulCT stress)', () => {
    const bigKey = new BigNumber(
      'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f',
      16
    )

    const sig = ECDSA.sign(msg, bigKey)
    const pub = curve.g.mul(bigKey)

    expect(ECDSA.verify(msg, sig, pub)).toBe(true)
  })

  it('should reject signing messages larger than curve order bit length (TOB-22)', () => {
    // Create a message definitely larger than secp256k1 order size
    const tooLargeMsg = new BigNumber(1).iushln(curve.n.bitLength() + 1)

    expect(() =>
      ECDSA.sign(tooLargeMsg, key)
    ).toThrow(/message is too large/i)
  })

  it('verify should return false for messages larger than curve order bit length (TOB-22)', () => {
    const signature = ECDSA.sign(msg, key)
    const tooLargeMsg = new BigNumber(1).iushln(curve.n.bitLength() + 1)

    expect(ECDSA.verify(tooLargeMsg, signature, pub)).toBe(false)
  })
})
