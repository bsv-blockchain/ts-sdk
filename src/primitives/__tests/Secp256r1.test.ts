import crypto from 'crypto'
import Secp256r1 from '../Secp256r1.js'
import { sha256 } from '../Hash.js'

const curve = new Secp256r1()

const TWO_G =
  '047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1'
const THREE_G =
  '045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032'

const toBase64Url = (hex: string): string => Buffer.from(hex, 'hex').toString('base64url')

describe('Secp256r1', () => {
  test('base point multiplication matches known coordinates and handles infinity', () => {
    const twoG = curve.multiplyBase(2n)
    const threeG = curve.multiplyBase(3n)
    expect(curve.pointToHex(twoG)).toBe(TWO_G)
    expect(curve.pointToHex(threeG)).toBe(THREE_G)
    expect(curve.multiplyBase(curve.n)).toBeNull()
    expect(curve.multiply(null, 5n)).toBeNull()
  })

  test('public key generation stays on-curve, supports compression, and rejects bad encodings', () => {
    const priv = curve.generatePrivateKeyHex()
    const pub = curve.publicKeyFromPrivate(priv)
    expect(curve.isOnCurve(pub)).toBe(true)
    const compressed = curve.pointToHex(pub, true)
    const roundTrip = curve.pointFromHex(compressed)
    expect(roundTrip).toEqual(pub)
    expect(() => curve.pointFromHex('05abcdef')).toThrow()
    expect(() => curve.pointFromHex('')).toThrow()
  })

  test('adding inverse points yields infinity', () => {
    const p = curve.multiplyBase(9n)
    const neg = { x: p!.x, y: curve.p - p!.y }
    expect(curve.add(p, neg)).toBeNull()
    expect(curve.add(null, p)).toEqual(p)
  })

  test('ECDSA sign and verify round-trip, low-s enforced, rejects malformed inputs', () => {
    const priv = '1'.repeat(64)
    const pub = curve.publicKeyFromPrivate(priv)
    const message = Buffer.from('p256 check')
    const signature = curve.sign(message, priv)
    const sVal = BigInt('0x' + signature.s)
    expect(sVal <= curve.n / 2n).toBe(true)
    expect(curve.verify(message, signature, pub)).toBe(true)
    expect(curve.verify(Buffer.from('different'), signature, pub)).toBe(false)
    const tampered = { r: signature.r, s: signature.s.slice(0, 62) + '00' }
    expect(curve.verify(message, tampered, pub)).toBe(false)
    const zeroR = { r: '0'.repeat(64), s: signature.s }
    expect(curve.verify(message, zeroR, pub)).toBe(false)
    const zeroS = { r: signature.r, s: '0'.repeat(64) }
    expect(curve.verify(message, zeroS, pub)).toBe(false)
    expect(curve.verify(message, signature, '02deadbeef')).toBe(false)
  })

  test('deterministic nonce is stable across calls and message changes', () => {
    const priv = '2'.repeat(64)
    const pub = curve.publicKeyFromPrivate(priv)
    const message = Buffer.from('deterministic nonce')
    const sig1 = curve.sign(message, priv)
    const sig2 = curve.sign(message, priv)
    expect(sig1).toEqual(sig2)
    const sig3 = curve.sign(Buffer.from('deterministic nonce v2'), priv)
    expect(sig3).not.toEqual(sig1)
    expect(curve.verify(message, sig1, pub)).toBe(true)
  })

  test('prehashed signing path matches explicit hashing input', () => {
    const priv = '4'.repeat(64)
    const pub = curve.publicKeyFromPrivate(priv)
    const message = Buffer.from('prehashed path')
    const digest = new Uint8Array(sha256(message))
    const sig1 = curve.sign(message, priv)
    const sig2 = curve.sign(digest, priv, { prehashed: true })
    expect(sig1).toEqual(sig2)
    expect(curve.verify(digest, sig2, pub, { prehashed: true })).toBe(true)
  })

  test('signatures interoperate with Node crypto (ieee-p1363 encoding)', () => {
    const priv = '3'.repeat(64)
    const pub = curve.publicKeyFromPrivate(priv)
    const message = Buffer.from('interop check')
    const signature = curve.sign(message, priv)
    const sigBuf = Buffer.concat([Buffer.from(signature.r, 'hex'), Buffer.from(signature.s, 'hex')])

    const pubHex = curve.pointToHex(pub)
    const jwk = {
      kty: 'EC',
      crv: 'P-256',
      x: toBase64Url(pubHex.slice(2, 66)),
      y: toBase64Url(pubHex.slice(66))
    }

    const ok = crypto.verify('sha256', message, { key: jwk, format: 'jwk', dsaEncoding: 'ieee-p1363' }, sigBuf)
    expect(ok).toBe(true)
  })
})
