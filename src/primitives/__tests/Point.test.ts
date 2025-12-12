import Point from '../../primitives/Point'

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
