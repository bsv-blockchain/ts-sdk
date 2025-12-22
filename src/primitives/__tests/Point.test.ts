import Point from '../../primitives/Point'
import BigNumber from '../../primitives/BigNumber'

describe('Point.fromJSON / fromDER / fromX curve validation (TOB-24)', () => {
  it('rejects clearly off-curve coordinates', () => {
    expect(() =>
      Point.fromJSON([123, 456], true)
    ).toThrow(/Invalid point/)
  })

  it('rejects nested off-curve precomputed points', () => {
    const bad = [
      123,
      456,
      {
        doubles: {
          step: 2,
          points: [
            [1, 2],
            [3, 4]
          ]
        }
      }
    ]
    expect(() => Point.fromJSON(bad, true)).toThrow(/Invalid point/)
  })

  it('accepts valid generator point from toJSON → fromJSON roundtrip', () => {
    // Compressed secp256k1 G:
    const G_COMPRESSED =
      '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'

    const g = Point.fromString(G_COMPRESSED)
    const serialized = g.toJSON()
    const restored = Point.fromJSON(serialized as any, true)

    expect(restored.eq(g)).toBe(true)
  })

  it('rejects invalid compressed points in fromDER', () => {
    // 0x02 is a valid compressed prefix, but x = 0 gives y^2 = 7,
    // which has no square root mod p on secp256k1 → invalid point.
    const der = [0x02, ...Array(32).fill(0x00)]
    expect(() => Point.fromDER(der)).toThrow(/Invalid point/)
    })

  it('fromX rejects values with no square root mod p', () => {
    // x = 0 ⇒ y^2 = 7, which has no square root mod p on secp256k1.
    // This guarantees that fromX must reject it.
    const badX = '0000000000000000000000000000000000000000000000000000000000000000'
    expect(() => Point.fromX(badX, true)).toThrow(/Invalid point/)
    })
})

describe('Point.mulCT (constant-time scalar multiplication)', () => {
  const G = Point.fromString(
    '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
  )

  it('returns point at infinity for scalar = 0', () => {
    const r = G.mulCT(0)
    expect(r.isInfinity()).toBe(true)
  })

  it('matches regular mul for small scalar', () => {
    const k = 5
    const r1 = G.mul(k)
    const r2 = G.mulCT(k)

    expect(r2.eq(r1)).toBe(true)
  })

  it('matches regular mul for large scalar', () => {
    const k =
      'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'

    const r1 = G.mul(k)
    const r2 = G.mulCT(k)

    expect(r2.eq(r1)).toBe(true)
  })

  it('works with non-generator base point', () => {
    const base = G.mul(3)
    const k = 11

    const r1 = base.mul(k)
    const r2 = base.mulCT(k)

    expect(r2.eq(r1)).toBe(true)
  })

  it('handles alternating bit patterns (ctSwap exercised)', () => {
    // 101010... pattern forces both swap paths
    const k = BigInt(
      '0b101010101010101010101010101010101010101010101010101010101010101'
    )

    const r1 = G.mul(k.toString(10))
    const r2 = G.mulCT(k.toString(10))

    expect(r2.eq(r1)).toBe(true)
  })

  it('handles negative scalars correctly', () => {
    const k = new BigNumber('123456', 16)
    const r1 = G.mul(k.neg())
    const r2 = G.mulCT(k.neg())
    expect(r2.eq(r1)).toBe(true)
  })
})

