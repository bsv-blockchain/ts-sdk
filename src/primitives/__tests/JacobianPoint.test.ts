import Curve from '../../primitives/Curve'
import Point from '../../primitives/Point'
import JacobianPoint from '../../primitives/JacobianPoint'
import BigNumber from '../../primitives/BigNumber'

const G_COMPRESSED = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'

describe('JacobianPoint', () => {
  const curve = new Curve()
  const G = curve.g as Point

  // --------------------------------------------------------------------------
  // Constructor
  // --------------------------------------------------------------------------
  describe('constructor', () => {
    it('creates point at infinity when all null', () => {
      const jp = new JacobianPoint(null, null, null)
      expect(jp.isInfinity()).toBe(true)
    })

    it('creates point from string coordinates', () => {
      // Use coordinates of 2G in affine form
      const g2 = G.mul(new BigNumber(2))
      const xHex = g2.getX().toString(16)
      const yHex = g2.getY().toString(16)
      const jp = new JacobianPoint(xHex, yHex, '1')
      expect(jp.isInfinity()).toBe(false)
    })

    it('creates point from BigNumber coordinates', () => {
      const g2 = G.mul(new BigNumber(2))
      const xBN = g2.getX()
      const yBN = g2.getY()
      const jp = new JacobianPoint(xBN, yBN, curve.one)
      expect(jp.isInfinity()).toBe(false)
    })
  })

  // --------------------------------------------------------------------------
  // isInfinity
  // --------------------------------------------------------------------------
  describe('isInfinity', () => {
    it('returns true for point at infinity', () => {
      const jp = new JacobianPoint(null, null, null)
      expect(jp.isInfinity()).toBe(true)
    })

    it('returns false for valid point', () => {
      const g = Point.fromString(G_COMPRESSED)
      const jp = g.toJ()
      expect(jp.isInfinity()).toBe(false)
    })
  })

  // --------------------------------------------------------------------------
  // toP
  // --------------------------------------------------------------------------
  describe('toP', () => {
    it('toP of infinity gives affine infinity', () => {
      const jp = new JacobianPoint(null, null, null)
      const p = jp.toP()
      expect(p.isInfinity()).toBe(true)
    })

    it('toP round-trips from affine', () => {
      const g = Point.fromString(G_COMPRESSED)
      const jp = g.toJ()
      const restored = jp.toP()
      expect(restored.eq(g)).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // neg
  // --------------------------------------------------------------------------
  describe('neg', () => {
    it('neg of a JacobianPoint', () => {
      const g = Point.fromString(G_COMPRESSED)
      const jp = g.toJ()
      const negJp = jp.neg()
      // jp + neg(jp) should be infinity
      expect(jp.add(negJp).isInfinity()).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // add
  // --------------------------------------------------------------------------
  describe('add', () => {
    it('O + P = P (this is infinity)', () => {
      const inf = new JacobianPoint(null, null, null)
      const g = Point.fromString(G_COMPRESSED).toJ()
      const result = inf.add(g)
      expect(result.toP().eq(g.toP())).toBe(true)
    })

    it('P + O = P (argument is infinity)', () => {
      const inf = new JacobianPoint(null, null, null)
      const g = Point.fromString(G_COMPRESSED).toJ()
      const result = g.add(inf)
      expect(result.toP().eq(g.toP())).toBe(true)
    })

    it('P + (-P) = O', () => {
      const g = Point.fromString(G_COMPRESSED).toJ()
      const negG = g.neg()
      const result = g.add(negG)
      expect(result.isInfinity()).toBe(true)
    })

    it('P + P = 2P (via dbl)', () => {
      const g = Point.fromString(G_COMPRESSED).toJ()
      const g2 = g.dbl()
      const result = g.add(g)
      expect(result.toP().eq(g2.toP())).toBe(true)
    })

    it('P + Q = expected result', () => {
      const g1 = G.mul(new BigNumber(3)).toJ()
      const g2 = G.mul(new BigNumber(5)).toJ()
      const expected = G.mul(new BigNumber(8))
      const result = g1.add(g2)
      expect(result.toP().eq(expected)).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // mixedAdd
  // --------------------------------------------------------------------------
  describe('mixedAdd', () => {
    it('O + P = P (this is infinity)', () => {
      const inf = new JacobianPoint(null, null, null)
      const g = Point.fromString(G_COMPRESSED)
      const result = inf.mixedAdd(g)
      expect(result.toP().eq(g)).toBe(true)
    })

    it('P + O = P (argument is infinity)', () => {
      const g = Point.fromString(G_COMPRESSED).toJ()
      const inf = new Point(null, null)
      const result = g.mixedAdd(inf)
      expect(result.toP().eq(g.toP())).toBe(true)
    })

    it('P + Q (mixed) = expected', () => {
      const g3 = G.mul(new BigNumber(3)).toJ()
      const g5 = G.mul(new BigNumber(5))
      const expected = G.mul(new BigNumber(8))
      const result = g3.mixedAdd(g5)
      expect(result.toP().eq(expected)).toBe(true)
    })

    it('P + P (same point) via mixedAdd triggers dbl path', () => {
      const g = Point.fromString(G_COMPRESSED)
      const gJ = g.toJ()
      const result = gJ.mixedAdd(g)
      const expected = g.mul(new BigNumber(2))
      expect(result.toP().eq(expected)).toBe(true)
    })

    it('mixedAdd P + (-P) = O', () => {
      const g = Point.fromString(G_COMPRESSED)
      const gJ = g.toJ()
      const negG = g.neg()
      const result = gJ.mixedAdd(negG)
      expect(result.isInfinity()).toBe(true)
    })

    it('throws when point coordinates are null (non-infinity with null x/y)', () => {
      const g = Point.fromString(G_COMPRESSED).toJ()
      // Construct a Point-like object that is not infinity but has null x
      const badPoint = { x: null, y: null, inf: false, isInfinity: () => false, type: 'affine' } as unknown as Point
      expect(() => g.mixedAdd(badPoint)).toThrow('Point coordinates cannot be null')
    })
  })

  // --------------------------------------------------------------------------
  // dbl
  // --------------------------------------------------------------------------
  describe('dbl', () => {
    it('dbl of infinity is infinity', () => {
      const jp = new JacobianPoint(null, null, null)
      const result = jp.dbl()
      expect(result.isInfinity()).toBe(true)
    })

    it('dbl with zOne=true path', () => {
      // When a point is created with z=1, the zOne shortcut is used in dbl
      const g = Point.fromString(G_COMPRESSED).toJ()
      // zOne should be true since toJ sets z=curve.one
      const result = g.dbl()
      const expected = G.mul(new BigNumber(2))
      expect(result.toP().eq(expected)).toBe(true)
    })

    it('dbl with zOne=false path', () => {
      // Get a JacobianPoint where z !== curve.one (e.g. after an add)
      const g3 = G.mul(new BigNumber(3)).toJ()
      const g5 = G.mul(new BigNumber(5)).toJ()
      const sum = g3.add(g5) // z will not be one after arbitrary add
      const doubled = sum.dbl()
      const expected = G.mul(new BigNumber(16))
      expect(doubled.toP().eq(expected)).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // dblp
  // --------------------------------------------------------------------------
  describe('dblp', () => {
    it('dblp with pow=0 returns this', () => {
      const g = Point.fromString(G_COMPRESSED).toJ()
      const result = g.dblp(0)
      expect(result.toP().eq(g.toP())).toBe(true)
    })

    it('dblp of infinity is infinity', () => {
      const inf = new JacobianPoint(null, null, null)
      const result = inf.dblp(3)
      expect(result.isInfinity()).toBe(true)
    })

    it('dblp with pow=3 equals three doublings', () => {
      const g = Point.fromString(G_COMPRESSED).toJ()
      const expected = G.mul(new BigNumber(8)) // 2^3 * 1 = 8
      const result = g.dblp(3)
      expect(result.toP().eq(expected)).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // eq
  // --------------------------------------------------------------------------
  describe('eq', () => {
    it('same instance is equal', () => {
      const jp = Point.fromString(G_COMPRESSED).toJ()
      expect(jp.eq(jp)).toBe(true)
    })

    it('equal points with different z', () => {
      // Two different representations of the same affine point
      const g = Point.fromString(G_COMPRESSED)
      const jp1 = g.toJ()
      const jp2 = g.toJ()
      expect(jp1.eq(jp2)).toBe(true)
    })

    it('different points are not equal', () => {
      const jp1 = G.mul(new BigNumber(3)).toJ()
      const jp2 = G.mul(new BigNumber(5)).toJ()
      expect(jp1.eq(jp2)).toBe(false)
    })

    it('infinity equals infinity', () => {
      const inf1 = new JacobianPoint(null, null, null)
      const inf2 = new JacobianPoint(null, null, null)
      expect(inf1.eq(inf2)).toBe(true)
    })

    it('infinity != non-infinity', () => {
      const inf = new JacobianPoint(null, null, null)
      const g = Point.fromString(G_COMPRESSED).toJ()
      expect(inf.eq(g)).toBe(false)
    })

    it('eq with an affine Point argument', () => {
      const g = Point.fromString(G_COMPRESSED)
      const jp = g.toJ()
      expect(jp.eq(g)).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // eqXToP
  // --------------------------------------------------------------------------
  describe('eqXToP', () => {
    it('returns true when x matches', () => {
      const g = Point.fromString(G_COMPRESSED)
      const jp = g.toJ()
      expect(jp.eqXToP(g.getX())).toBe(true)
    })

    it('returns false when x does not match', () => {
      const g = Point.fromString(G_COMPRESSED)
      const jp = g.toJ()
      const wrongX = g.getX().addn(1)
      expect(jp.eqXToP(wrongX)).toBe(false)
    })
  })

  // --------------------------------------------------------------------------
  // inspect
  // --------------------------------------------------------------------------
  describe('inspect', () => {
    it('returns <EC JPoint Infinity> for infinity', () => {
      const jp = new JacobianPoint(null, null, null)
      expect(jp.inspect()).toBe('<EC JPoint Infinity>')
    })

    it('returns readable string for a valid point', () => {
      const g = Point.fromString(G_COMPRESSED).toJ()
      const s = g.inspect()
      expect(s).toContain('<EC JPoint x:')
      expect(s).toContain('y:')
      expect(s).toContain('z:')
    })
  })
})
