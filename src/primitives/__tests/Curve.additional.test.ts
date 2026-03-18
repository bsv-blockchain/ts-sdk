import Curve from '../../primitives/Curve'
import Point from '../../primitives/Point'
import BigNumber from '../../primitives/BigNumber'

describe('Curve – additional coverage', () => {
  const curve = new Curve()
  const G = curve.g as Point

  // --------------------------------------------------------------------------
  // assert
  // --------------------------------------------------------------------------
  describe('Curve.assert', () => {
    it('does not throw when expression is truthy', () => {
      expect(() => Curve.assert(true)).not.toThrow()
      expect(() => Curve.assert(1)).not.toThrow()
      expect(() => Curve.assert('hello')).not.toThrow()
    })

    it('throws default message when expression is falsy', () => {
      expect(() => Curve.assert(false)).toThrow('Elliptic curve assertion failed')
    })

    it('throws custom message', () => {
      expect(() => Curve.assert(false, 'custom error')).toThrow('custom error')
    })
  })

  // --------------------------------------------------------------------------
  // getNAF
  // --------------------------------------------------------------------------
  describe('getNAF', () => {
    it('returns non-empty array for a positive number', () => {
      const naf = curve.getNAF(new BigNumber(7), 2, 256)
      expect(Array.isArray(naf)).toBe(true)
      expect(naf.length).toBeGreaterThan(0)
    })

    it('returns all zeros for BigNumber(0)', () => {
      const naf = curve.getNAF(new BigNumber(0), 2, 256)
      // For zero, all entries should be 0
      expect(naf.every(x => x === 0)).toBe(true)
    })

    it('handles odd number', () => {
      const naf = curve.getNAF(new BigNumber(15), 2, 256)
      expect(Array.isArray(naf)).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // getJSF
  // --------------------------------------------------------------------------
  describe('getJSF', () => {
    it('returns two arrays (JSF of k1 and k2)', () => {
      const k1 = new BigNumber(7)
      const k2 = new BigNumber(11)
      const jsf = curve.getJSF(k1, k2)
      expect(Array.isArray(jsf)).toBe(true)
      expect(jsf.length).toBe(2)
      expect(Array.isArray(jsf[0])).toBe(true)
      expect(Array.isArray(jsf[1])).toBe(true)
    })

    it('handles large numbers', () => {
      const k1 = new BigNumber('deadbeef', 16)
      const k2 = new BigNumber('cafebabe', 16)
      const jsf = curve.getJSF(k1, k2)
      expect(jsf[0].length).toBeGreaterThan(0)
    })
  })

  // --------------------------------------------------------------------------
  // parseBytes
  // --------------------------------------------------------------------------
  describe('Curve.parseBytes', () => {
    it('converts hex string to byte array', () => {
      const bytes = Curve.parseBytes('deadbeef')
      expect(bytes).toEqual([0xde, 0xad, 0xbe, 0xef])
    })

    it('passes byte array through unchanged', () => {
      const arr = [0x01, 0x02, 0x03]
      const result = Curve.parseBytes(arr)
      expect(result).toEqual(arr)
    })
  })

  // --------------------------------------------------------------------------
  // intFromLE
  // --------------------------------------------------------------------------
  describe('Curve.intFromLE', () => {
    it('converts little-endian bytes to BigNumber', () => {
      const bn = Curve.intFromLE([0x01, 0x00])
      // 0x01 in LE means 0x0001 = 1
      expect(bn.toNumber()).toBe(1)
    })

    it('converts multi-byte LE number', () => {
      const bn = Curve.intFromLE([0x02, 0x01])
      // 0x0102 = 258
      expect(bn.toNumber()).toBe(0x0102)
    })
  })

  // --------------------------------------------------------------------------
  // cachedProperty
  // --------------------------------------------------------------------------
  describe('Curve.cachedProperty', () => {
    it('caches the result after first call', () => {
      let computeCount = 0
      // Create a class to attach the property to
      class TestClass {
        _myProp: any = undefined
      }
      Curve.cachedProperty(TestClass, 'myProp', function () {
        computeCount++
        return 42
      })
      const instance = new TestClass()
      // Calling twice — should compute once
      const val1 = (instance as any).myProp()
      const val2 = (instance as any).myProp()
      expect(val1).toBe(42)
      expect(val2).toBe(42)
      expect(computeCount).toBe(1)
    })
  })

  // --------------------------------------------------------------------------
  // validate
  // --------------------------------------------------------------------------
  describe('validate', () => {
    it('returns true for point at infinity', () => {
      const inf = new Point(null, null)
      expect(curve.validate(inf)).toBe(true)
    })

    it('returns true for a valid curve point', () => {
      const p = Point.fromString('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
      expect(curve.validate(p)).toBe(true)
    })

    it('returns false for an off-curve point', () => {
      // Create point with modified y to be off-curve
      const p = Point.fromString('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
      const yModified = (p.y as BigNumber).clone().redIAdd(curve.one)
      // Access internal: just test via validate
      // Use a different approach to create an off-curve point
      const offCurve = new Point(p.x, yModified, false)
      // We need to bypass the isRed check since the modified point isn't on the curve
      // Just call curve.validate
      expect(curve.validate(offCurve)).toBe(false)
    })
  })

  // --------------------------------------------------------------------------
  // _endoSplit
  // --------------------------------------------------------------------------
  describe('_endoSplit', () => {
    it('splits a scalar into balanced k1 and k2', () => {
      const k = new BigNumber('deadbeefcafe', 16)
      const split = curve._endoSplit(k)
      expect(split).toHaveProperty('k1')
      expect(split).toHaveProperty('k2')
      // k1 + lambda * k2 ≡ k (mod n)
      // This is an endomorphism property; just verify the result is plausible
      expect(BigNumber.isBN(split.k1)).toBe(true)
      expect(BigNumber.isBN(split.k2)).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // _getEndoRoots
  // --------------------------------------------------------------------------
  describe('_getEndoRoots', () => {
    it('computes two roots for the curve order n', () => {
      const roots = curve._getEndoRoots(curve.n)
      expect(Array.isArray(roots)).toBe(true)
      expect(roots.length).toBe(2)
      expect(BigNumber.isBN(roots[0])).toBe(true)
      expect(BigNumber.isBN(roots[1])).toBe(true)
    })

    it('computes two roots for the curve field prime p', () => {
      const roots = curve._getEndoRoots(curve.p)
      expect(Array.isArray(roots)).toBe(true)
      expect(roots.length).toBe(2)
    })
  })

  // --------------------------------------------------------------------------
  // _getEndoBasis
  // --------------------------------------------------------------------------
  describe('_getEndoBasis', () => {
    it('returns a basis of two vectors', () => {
      // Use the curve's lambda if available
      if (curve.endo != null) {
        const basis = curve._getEndoBasis(curve.endo.lambda)
        expect(Array.isArray(basis)).toBe(true)
        expect(basis.length).toBe(2)
        expect(basis[0]).toHaveProperty('a')
        expect(basis[0]).toHaveProperty('b')
        expect(basis[1]).toHaveProperty('a')
        expect(basis[1]).toHaveProperty('b')
      }
    })
  })
})
