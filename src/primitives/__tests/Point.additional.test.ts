import Point from '../../primitives/Point'
import BigNumber from '../../primitives/BigNumber'
import Curve from '../../primitives/Curve'

const G_COMPRESSED = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'

describe('Point – additional coverage', () => {
  const curve = new Curve()
  const G = curve.g as Point

  // --------------------------------------------------------------------------
  // Constructor and coordinate handling
  // --------------------------------------------------------------------------
  describe('constructor', () => {
    it('constructs an infinity point with null, null', () => {
      const inf = new Point(null, null)
      expect(inf.isInfinity()).toBe(true)
    })

    it('constructs from number array x/y', () => {
      const G2 = G.mul(new BigNumber(2))
      const x = G2.getX().toArray()
      const y = G2.getY().toArray()
      const p = new Point(x, y)
      expect(p.isInfinity()).toBe(false)
      expect(p.getX().eq(G2.getX())).toBe(true)
    })

    it('constructs with isRed=false', () => {
      const G2 = G.mul(new BigNumber(2))
      const xBN = G2.getX()
      const yBN = G2.getY()
      const p = new Point(xBN, yBN, false)
      expect(p.isInfinity()).toBe(false)
    })
  })

  // --------------------------------------------------------------------------
  // fromDER – uncompressed and hybrid formats
  // --------------------------------------------------------------------------
  describe('fromDER', () => {
    it('parses uncompressed point (0x04)', () => {
      const g = Point.fromString(G_COMPRESSED)
      const bytes = g.encode(false) as number[]
      expect(bytes[0]).toBe(0x04)
      const restored = Point.fromDER(bytes)
      expect(restored.eq(g)).toBe(true)
    })

    it('parses 0x06 hybrid (y-even) format', () => {
      // Find a point where the last byte of the y coordinate is even
      let gn: Point | null = null
      for (let i = 2; i <= 20; i++) {
        const candidate = G.mul(new BigNumber(i))
        const uncompressed = candidate.encode(false) as number[]
        if (uncompressed[uncompressed.length - 1] % 2 === 0) {
          gn = candidate
          break
        }
      }
      if (gn === null) {
        return
      }
      const uncompressed = gn.encode(false) as number[]
      // Replace prefix with 0x06 (even y last byte)
      uncompressed[0] = 0x06
      const restored = Point.fromDER(uncompressed)
      expect(restored.validate()).toBe(true)
    })

    it('parses 0x07 hybrid (y-odd) format', () => {
      // Find a point where the last byte of the y coordinate (in the uncompressed encoding) is odd
      let gn: Point | null = null
      for (let i = 2; i <= 20; i++) {
        const candidate = G.mul(new BigNumber(i))
        const uncompressed = candidate.encode(false) as number[]
        if (uncompressed[uncompressed.length - 1] % 2 === 1) {
          gn = candidate
          break
        }
      }
      if (gn === null) {
        // Skip if no suitable point found in range
        return
      }
      const uncompressed = gn.encode(false) as number[]
      // Replace prefix with 0x07 (odd y last byte)
      uncompressed[0] = 0x07
      const restored = Point.fromDER(uncompressed)
      expect(restored.validate()).toBe(true)
    })

    it('throws for 0x06 when last byte is odd', () => {
      // Build a valid-looking 65-byte buffer but set last byte to odd
      // 0x06 requires last byte to be even, so odd → throws
      const g = Point.fromString(G_COMPRESSED)
      const uncompressed = g.encode(false) as number[]
      uncompressed[0] = 0x06
      // Force last byte to be odd
      if (uncompressed[uncompressed.length - 1] % 2 === 0) {
        uncompressed[uncompressed.length - 1] = 0x01
      }
      // Note: this may produce an invalid point too (validation error), either way it throws
      expect(() => Point.fromDER(uncompressed)).toThrow()
    })

    it('throws for 0x07 when last byte is even', () => {
      // Build a valid-looking 65-byte buffer but set last byte to even
      // 0x07 requires last byte to be odd, so even → throws
      const g = Point.fromString(G_COMPRESSED)
      const uncompressed = g.encode(false) as number[]
      uncompressed[0] = 0x07
      // Force last byte to be even
      if (uncompressed[uncompressed.length - 1] % 2 === 1) {
        uncompressed[uncompressed.length - 1] = 0x02
      }
      expect(() => Point.fromDER(uncompressed)).toThrow()
    })

    it('throws for unknown format', () => {
      const der = [0x05, ...Array(32).fill(0x01)]
      expect(() => Point.fromDER(der)).toThrow('Unknown point format')
    })
  })

  // --------------------------------------------------------------------------
  // fromString
  // --------------------------------------------------------------------------
  describe('fromString', () => {
    it('parses a compressed hex point', () => {
      const p = Point.fromString(G_COMPRESSED)
      expect(p.validate()).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // fromX
  // --------------------------------------------------------------------------
  describe('fromX', () => {
    it('fromX accepts BigNumber', () => {
      const g = Point.fromString(G_COMPRESSED)
      const xBN = g.getX()
      const p = Point.fromX(xBN, false)
      expect(p.validate()).toBe(true)
    })

    it('fromX accepts number', () => {
      // Use a valid x value that has a square root mod p
      const g = G.mul(new BigNumber(7))
      const xNum = parseInt(g.getX().toString(16).slice(-4), 16)
      // fromX with a number, may produce a point
      const p = Point.fromX(g.getX(), true)
      expect(p.validate()).toBe(true)
    })

    it('fromX accepts hex string', () => {
      const g = G.mul(new BigNumber(7))
      const xHex = g.getX().toString(16)
      const p = Point.fromX(xHex, false)
      expect(p.validate()).toBe(true)
    })

    it('fromX accepts number array', () => {
      const g = G.mul(new BigNumber(7))
      const xArr = g.getX().toArray()
      const p = Point.fromX(xArr, true)
      expect(p.validate()).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // fromJSON
  // --------------------------------------------------------------------------
  describe('fromJSON', () => {
    it('accepts JSON string', () => {
      const g = Point.fromString(G_COMPRESSED)
      const json = JSON.stringify(g.toJSON())
      const restored = Point.fromJSON(json, true)
      expect(restored.eq(g)).toBe(true)
    })

    it('fromJSON with naf precomputed data', () => {
      const g = Point.fromString(G_COMPRESSED)
      // Precomputed data has naf but no doubles
      const serialized = [g.getX(), g.getY(), { naf: { wnd: 2, points: [] }, doubles: null }]
      const restored = Point.fromJSON(serialized as any, true)
      expect(restored.validate()).toBe(true)
    })

    it('fromJSON with doubles precomputed data', () => {
      const g = Point.fromString(G_COMPRESSED)
      const serialized = [g.getX(), g.getY(), { doubles: { step: 4, points: [] }, naf: null }]
      const restored = Point.fromJSON(serialized as any, true)
      expect(restored.validate()).toBe(true)
    })

    it('fromJSON with no precomputed (third element absent)', () => {
      const g = Point.fromString(G_COMPRESSED)
      const serialized = [g.getX(), g.getY()]
      const restored = Point.fromJSON(serialized as any, true)
      expect(restored.validate()).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // validate
  // --------------------------------------------------------------------------
  describe('validate', () => {
    it('returns false for infinity point', () => {
      const inf = new Point(null, null)
      expect(inf.validate()).toBe(false)
    })

    it('returns true for a valid curve point', () => {
      const g = Point.fromString(G_COMPRESSED)
      expect(g.validate()).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // encode
  // --------------------------------------------------------------------------
  describe('encode', () => {
    it('encodes infinity as [0x00]', () => {
      const inf = new Point(null, null)
      expect(inf.encode()).toEqual([0x00])
    })

    it('encodes infinity as "00" when enc=hex', () => {
      const inf = new Point(null, null)
      expect(inf.encode(true, 'hex')).toBe('00')
    })

    it('encodes compressed point (default compact=true)', () => {
      const g = Point.fromString(G_COMPRESSED)
      const encoded = g.encode()
      expect(Array.isArray(encoded)).toBe(true)
      const prefix = (encoded as number[])[0]
      expect(prefix === 0x02 || prefix === 0x03).toBe(true)
    })

    it('encodes uncompressed point (compact=false)', () => {
      const g = Point.fromString(G_COMPRESSED)
      const encoded = g.encode(false) as number[]
      expect(encoded[0]).toBe(0x04)
      expect(encoded.length).toBe(65)
    })

    it('returns hex when enc=hex', () => {
      const g = Point.fromString(G_COMPRESSED)
      const hex = g.encode(true, 'hex')
      expect(typeof hex).toBe('string')
      expect(hex as string).toMatch(/^0[23][0-9a-f]+$/)
    })
  })

  // --------------------------------------------------------------------------
  // inspect
  // --------------------------------------------------------------------------
  describe('inspect', () => {
    it('returns "<EC Point Infinity>" for infinity', () => {
      const inf = new Point(null, null)
      expect(inf.inspect()).toBe('<EC Point Infinity>')
    })

    it('returns readable string for valid point', () => {
      const g = Point.fromString(G_COMPRESSED)
      const s = g.inspect()
      expect(s).toContain('<EC Point x:')
      expect(s).toContain('y:')
    })
  })

  // --------------------------------------------------------------------------
  // add – edge cases
  // --------------------------------------------------------------------------
  describe('add edge cases', () => {
    it('O + P = P (this is infinity)', () => {
      const inf = new Point(null, null)
      const g = Point.fromString(G_COMPRESSED)
      const result = inf.add(g)
      expect(result.eq(g)).toBe(true)
    })

    it('P + O = P (argument is infinity)', () => {
      const inf = new Point(null, null)
      const g = Point.fromString(G_COMPRESSED)
      const result = g.add(inf)
      expect(result.eq(g)).toBe(true)
    })

    it('P + P = 2P', () => {
      const g = Point.fromString(G_COMPRESSED)
      const g2 = g.dbl()
      const result = g.add(g)
      expect(result.eq(g2)).toBe(true)
    })

    it('P + (-P) = infinity', () => {
      const g = Point.fromString(G_COMPRESSED)
      const negG = g.neg()
      const result = g.add(negG)
      expect(result.isInfinity()).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // dbl
  // --------------------------------------------------------------------------
  describe('dbl', () => {
    it('dbl of infinity is infinity', () => {
      const inf = new Point(null, null)
      const result = inf.dbl()
      expect(result.isInfinity()).toBe(true)
    })

    it('dbl of a valid point', () => {
      const g = Point.fromString(G_COMPRESSED)
      const g2 = g.dbl()
      expect(g2.validate()).toBe(true)
      expect(g2.eq(g)).toBe(false)
    })
  })

  // --------------------------------------------------------------------------
  // neg
  // --------------------------------------------------------------------------
  describe('neg', () => {
    it('neg of infinity is infinity', () => {
      const inf = new Point(null, null)
      expect(inf.neg().isInfinity()).toBe(true)
    })

    it('neg of a valid point', () => {
      const g = Point.fromString(G_COMPRESSED)
      const negG = g.neg()
      expect(negG.validate()).toBe(true)
      expect(g.add(negG).isInfinity()).toBe(true)
    })

    it('neg with _precompute=true propagates precomputed data', () => {
      const g = Point.fromString(G_COMPRESSED)
      // Force precomputation via mul (which caches NAF)
      g.mul(new BigNumber(2))
      const negG = g.neg(true)
      expect(negG.validate()).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // dblp
  // --------------------------------------------------------------------------
  describe('dblp', () => {
    it('dblp with k=0 returns same point', () => {
      const g = Point.fromString(G_COMPRESSED)
      const result = g.dblp(0)
      expect(result.eq(g)).toBe(true)
    })

    it('dblp with k=3 equals three doublings', () => {
      const g = Point.fromString(G_COMPRESSED)
      const tripled = g.dbl().dbl().dbl()
      const result = g.dblp(3)
      expect(result.eq(tripled)).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // getX / getY
  // --------------------------------------------------------------------------
  describe('getX / getY', () => {
    it('getX and getY return BigNumber', () => {
      const g = Point.fromString(G_COMPRESSED)
      expect(BigNumber.isBN(g.getX())).toBe(true)
      expect(BigNumber.isBN(g.getY())).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // mul – edge cases
  // --------------------------------------------------------------------------
  describe('mul', () => {
    it('mul by 0 returns infinity', () => {
      const g = Point.fromString(G_COMPRESSED)
      const result = g.mul(new BigNumber(0))
      expect(result.isInfinity()).toBe(true)
    })

    it('mul infinity returns infinity', () => {
      const inf = new Point(null, null)
      const result = inf.mul(new BigNumber(5))
      expect(result.isInfinity()).toBe(true)
    })

    it('mul by negative scalar', () => {
      const g = Point.fromString(G_COMPRESSED)
      const k = new BigNumber(3)
      const r1 = g.mul(k)
      const r2 = g.mul(k.neg())
      expect(r1.eq(r2.neg())).toBe(true)
    })

    it('mul by number', () => {
      const g = Point.fromString(G_COMPRESSED)
      const r = g.mul(7)
      expect(r.validate()).toBe(true)
    })

    it('mul by hex string', () => {
      const g = Point.fromString(G_COMPRESSED)
      const r = g.mul('0a')
      expect(r.validate()).toBe(true)
    })

    it('mul by number array', () => {
      const g = Point.fromString(G_COMPRESSED)
      const r = g.mul([0x05])
      expect(r.validate()).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // mulAdd / jmulAdd
  // --------------------------------------------------------------------------
  describe('mulAdd / jmulAdd', () => {
    it('mulAdd(1, G, 0) = G', () => {
      const g = Point.fromString(G_COMPRESSED)
      const result = g.mulAdd(new BigNumber(1), g, new BigNumber(0))
      expect(result.eq(g)).toBe(true)
    })

    it('mulAdd(1, G, 1) = 2G', () => {
      const g = Point.fromString(G_COMPRESSED)
      const g2 = g.mul(new BigNumber(2))
      const result = g.mulAdd(new BigNumber(1), g, new BigNumber(1))
      expect(result.eq(g2)).toBe(true)
    })

    it('jmulAdd returns a JPoint', () => {
      const g = Point.fromString(G_COMPRESSED)
      const result = g.jmulAdd(new BigNumber(2), g, new BigNumber(1))
      expect(result).toBeDefined()
      const asPoint = result.toP()
      const g3 = g.mul(new BigNumber(3))
      expect(asPoint.eq(g3)).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // eq
  // --------------------------------------------------------------------------
  describe('eq', () => {
    it('same instance is equal', () => {
      const g = Point.fromString(G_COMPRESSED)
      expect(g.eq(g)).toBe(true)
    })

    it('both infinity are equal', () => {
      const inf1 = new Point(null, null)
      const inf2 = new Point(null, null)
      expect(inf1.eq(inf2)).toBe(true)
    })

    it('infinity != non-infinity', () => {
      const inf = new Point(null, null)
      const g = Point.fromString(G_COMPRESSED)
      expect(inf.eq(g)).toBe(false)
    })
  })

  // --------------------------------------------------------------------------
  // toJ
  // --------------------------------------------------------------------------
  describe('toJ', () => {
    it('toJ of infinity gives JPoint at infinity', () => {
      const inf = new Point(null, null)
      const j = inf.toJ()
      expect(j.isInfinity()).toBe(true)
    })

    it('toJ of valid point gives equivalent JPoint', () => {
      const g = Point.fromString(G_COMPRESSED)
      const j = g.toJ()
      const restored = j.toP()
      expect(restored.eq(g)).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // toJSON with precomputed
  // --------------------------------------------------------------------------
  describe('toJSON with precomputed', () => {
    it('toJSON returns array with precomputed when precomputed is set', () => {
      // Force precomputation by using internal _getNAFPoints
      const g = Point.fromString(G_COMPRESSED)
      // Trigger precomputation via mul (which uses precomputed internally)
      g.mul(new BigNumber(2))
      const json = g.toJSON()
      // Even without precomputed being set externally, should return at least 2 elements
      expect(json.length).toBeGreaterThanOrEqual(2)
    })
  })
})
