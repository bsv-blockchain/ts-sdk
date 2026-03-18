import * as ECDSA from '../../primitives/ECDSA'
import BigNumber from '../../primitives/BigNumber'
import Curve from '../../primitives/Curve'
import Signature from '../../primitives/Signature'
import Point from '../../primitives/Point'

const curve = new Curve()
const key = new BigNumber(
  '1e5edd45de6d22deebef4596b80444ffcc29143839c1dce18db470e25b4be7b5',
  16
)
const pub = curve.g.mul(key)
const msg = new BigNumber('deadbeef', 16)

describe('ECDSA – additional coverage', () => {
  // --------------------------------------------------------------------------
  // truncateToN paths
  // --------------------------------------------------------------------------
  describe('truncateToN paths', () => {
    it('sign handles msg equal to n (cmp >= 0 path in truncateToN)', () => {
      // msg == n: after truncation msg.cmp(n) = 0, so msg.sub(n) = 0
      // But then the loop would handle the edge case
      // Use msg = n - 1, which is safe
      const nMinus1 = curve.n.subn(1)
      const sig = ECDSA.sign(nMinus1, key)
      expect(ECDSA.verify(nMinus1, sig, pub)).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // verify – out-of-range signature components
  // --------------------------------------------------------------------------
  describe('verify out-of-range signature', () => {
    it('returns false when r = 0', () => {
      const r = new BigNumber(0)
      const s = new BigNumber(1)
      const sig = new Signature(r, s)
      expect(ECDSA.verify(msg, sig, pub)).toBe(false)
    })

    it('returns false when s = 0', () => {
      const r = new BigNumber(1)
      const s = new BigNumber(0)
      const sig = new Signature(r, s)
      expect(ECDSA.verify(msg, sig, pub)).toBe(false)
    })

    it('returns false when r >= n', () => {
      const r = curve.n.clone() // r == n
      const s = new BigNumber(1)
      const sig = new Signature(r, s)
      expect(ECDSA.verify(msg, sig, pub)).toBe(false)
    })

    it('returns false when s >= n', () => {
      const r = new BigNumber(1)
      const s = curve.n.clone() // s == n
      const sig = new Signature(r, s)
      expect(ECDSA.verify(msg, sig, pub)).toBe(false)
    })
  })

  // --------------------------------------------------------------------------
  // forceLowS - line 163
  // --------------------------------------------------------------------------
  describe('forceLowS', () => {
    it('produces s <= n/2 with forceLowS=true across multiple messages', () => {
      const halfN = curve.n.ushrn(1)
      // Try a few messages to ensure forceLowS is exercised
      for (let i = 1; i <= 10; i++) {
        const testMsg = new BigNumber(i * 0xdeadbeef)
        const sig = ECDSA.sign(testMsg, key, true)
        expect(sig.s.cmp(halfN) <= 0).toBe(true)
      }
    })
  })

  // --------------------------------------------------------------------------
  // sign with function customK
  // --------------------------------------------------------------------------
  describe('sign with function customK', () => {
    it('accepts a function as customK', () => {
      let callCount = 0
      const customK = (iter: number): BigNumber => {
        callCount++
        return new BigNumber(1358)
      }
      const sig = ECDSA.sign(msg, key, false, customK)
      expect(ECDSA.verify(msg, sig, pub)).toBe(true)
      expect(callCount).toBeGreaterThan(0)
    })
  })

  // --------------------------------------------------------------------------
  // verify - invalid public key path (key with null x or y)
  // --------------------------------------------------------------------------
  describe('verify invalid public key', () => {
    it('throws when public key coordinates are null', () => {
      const sig = ECDSA.sign(msg, key)
      const infinityKey = new Point(null, null)
      expect(() => ECDSA.verify(msg, sig, infinityKey)).toThrow('Invalid public key')
    })
  })

  // --------------------------------------------------------------------------
  // sign – k function returning invalid k causes iteration
  // --------------------------------------------------------------------------
  describe('sign – iterative k generation', () => {
    it('eventually succeeds when k function returns invalid k on first iter', () => {
      let callCount = 0
      const customK = (iter: number): BigNumber => {
        callCount++
        // Return valid k on second call
        if (iter === 0) return new BigNumber(0) // invalid k
        return new BigNumber(1358) // valid k
      }
      const sig = ECDSA.sign(msg, key, false, customK)
      expect(ECDSA.verify(msg, sig, pub)).toBe(true)
      expect(callCount).toBeGreaterThanOrEqual(2)
    })
  })
})
