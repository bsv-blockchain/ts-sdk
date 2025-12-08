/* eslint-env jest */
import Curve from '../../primitives/Curve'
import Point from '../../primitives/Point'
import JPoint from '../../primitives/JacobianPoint'
import BigNumber from '../../primitives/BigNumber'

describe('Curve', () => {
  it('should work with secp256k1', () => {
    const curve = new Curve()

    const p = new Point(
      '79be667e f9dcbbac 55a06295 ce870b07 029bfcdb 2dce28d9 59f2815b 16f81798',
      '483ada77 26a3c465 5da4fbfc 0e1108a8 fd17b448 a6855419 9c47d08f fb10d4b8'
    )

    expect(p.validate()).toBe(true)
    expect(p.dbl().validate()).toBe(true)
    expect(p.toJ().dbl().toP().validate()).toBe(true)
    expect(
      p.mul(new BigNumber('79be667e f9dcbbac 55a06295 ce870b07', 16)).validate()
    ).toBe(true)

    // Endomorphism test
    if (curve.endo === null || curve.endo === undefined) {
      throw new Error('curve.endo is undefined')
    }
    expect(curve.endo).toBeDefined()
    expect(curve.endo.beta.fromRed().toString(16)).toEqual(
      '7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee'
    )
    expect(curve.endo.lambda.toString(16)).toEqual(
      '5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72'
    )

    const k = new BigNumber('1234567890123456789012345678901234', 16)
    const split = curve._endoSplit(k)
    const testK = split.k1.add(split.k2.mul(curve.endo.lambda)).umod(curve.n)

    expect(testK.toString(16)).toEqual(k.toString(16))
  })

  it('should compute this problematic secp256k1 multiplication', () => {
    const curve = new Curve()
    const g1 = curve.g // precomputed g
    expect(g1.precomputed).toBeDefined()
    const g2 = new Point(g1.getX(), g1.getY()) // not precomputed g
    expect(g2.precomputed).toBeNull()

    const a = new BigNumber(
      '6d1229a6b24c2e775c062870ad26bc261051e0198c67203167273c7c62538846',
      16
    )
    const p1 = g1.mul(a)
    const p2 = g2.mul(a)

    expect(p1.eq(p2)).toBe(true)
  })

  it('should not use fixed NAF when k is too large', () => {
    const curve = new Curve()
    const g1 = curve.g // precomputed g
    expect(g1.precomputed).toBeDefined()
    const g2 = new Point(g1.getX(), g1.getY()) // not precomputed g
    expect(g2.precomputed).toBeNull()

    const a = new BigNumber(
      '6d1229a6b24c2e775c062870ad26bc26' +
        '1051e0198c67203167273c7c6253884612345678',
      16
    )
    const p1 = g1.mul(a)
    const p2 = g2.mul(a)

    expect(p1.eq(p2)).toBe(true)
  })

  it('should not fail on secp256k1 regression', () => {
    const curve = new Curve()
    const k1 = new BigNumber(
      '32efeba414cd0c830aed727749e816a01c471831536fd2fce28c56b54f5a3bb1',
      16
    )
    const k2 = new BigNumber(
      '5f2e49b5d64e53f9811545434706cde4de528af97bfd49fde1f6cf792ee37a8c',
      16
    )

    let p1 = curve.g.mul(k1)
    let p2 = curve.g.mul(k2)

    // 2 + 2 + 1 = 2 + 1 + 2
    const two = p2.dbl()
    const five = two.dbl().add(p2)
    const three = two.add(p2)
    const maybeFive = three.add(two)

    expect(maybeFive.eq(five)).toBe(true)

    p1 = p1.mul(k2)
    p2 = p2.mul(k1)

    expect(p1.validate()).toBe(true)
    expect(p2.validate()).toBe(true)
    expect(p1.eq(p2)).toBe(true)
  })

  test('should correctly double the affine point on secp256k1', () => {
    const bad = new JPoint(
      new BigNumber('026a2073b1ef6fab47ace18e60e728a05180a82755bbcec9a0abc08ad9f7a3d4', 16),
      new BigNumber('9cd8cb48c3281596139f147c1364a3ede88d3f310fdb0eb98c924e599ca1b3c9', 16),
      new BigNumber('d78587ad45e4102f48b54b5d85598296e069ce6085002e169c6bad78ddc6d9bd', 16)
    )

    const good = new JPoint(
      new BigNumber('e7789226739ac2eb3c7ccb2a9a910066beeed86cdb4e0f8a7fee8eeb29dc7016', 16),
      new BigNumber('4b76b191fd6d47d07828ea965e275b76d0e3e0196cd5056d38384fbb819f9fcb', 16),
      new BigNumber('cbf8d99056618ba132d6145b904eee1ce566e0feedb9595139c45f84e90cfa7d', 16)
    )

    // They are the same points
    expect(bad.add(good.neg()).isInfinity()).toBe(true)

    // But doubling borks them out
    expect(bad.dbl().add(good.dbl().neg()).isInfinity()).toBe(true)
  })

  test('should correctly handle scalar multiplication of zero', () => {
    const curve = new Curve()
    const p1 = curve.g.mul('0')
    const p2 = p1.mul('2')
    expect(p1.eq(p2)).toBe(true)
  })
})

describe('Point codec', () => {
  interface PointDefinition {
    coordinates: {
      x: string
      y: string
    }
    compactEncoded: string
    encoded: string
    hybrid: string
  }

  const makeShortTest = (definition: PointDefinition): () => void => {
    return () => {
      const co = definition.coordinates
      const p = new Point(co.x, co.y)

      // Encodes as expected
      expect(p.encode(false, 'hex')).toBe(definition.encoded)
      expect(p.encode(true, 'hex')).toBe(definition.compactEncoded)

      // Decodes as expected
      expect(Point.fromString(definition.encoded).eq(p)).toBe(true)
      expect(Point.fromString(definition.compactEncoded).eq(p)).toBe(true)
      expect(Point.fromString(definition.hybrid).eq(p)).toBe(true)
    }
  }

  const shortPointEvenY = {
    coordinates: {
      x: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      y: '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
    },
    compactEncoded:
      '02' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    encoded:
      '04' +
      '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' +
      '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
    hybrid:
      '06' +
      '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' +
      '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
  }

  const shortPointOddY = {
    coordinates: {
      x: 'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556',
      y: 'ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297'
    },
    compactEncoded:
      '03' + 'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556',
    encoded:
      '04' +
      'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556' +
      'ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297',
    hybrid:
      '07' +
      'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556' +
      'ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297'
  }

  it('should throw when trying to decode random bytes', () => {
    expect(() => {
      Point.fromString(
        '05' +
          '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
      )
    }).toThrow()
  })

  it(
    'should be able to encode/decode a short curve point with even Y',
    makeShortTest(shortPointEvenY)
  )

  it(
    'should be able to encode/decode a short curve point with odd Y',
    makeShortTest(shortPointOddY)
  )
})

describe('JacobianPoint – Infinity handling and equality (TOB-18)', () => {
  function J(x: any, y: any, z: any) {
    return new JPoint(x, y, z)
  }

  it('Multiple infinity representations are canonicalized and equal', () => {
    const inf1 = J(null, null, null)
    const inf2 = J('0', '0', '0')
    const inf3 = J(new BigNumber(0), new BigNumber(0), new BigNumber(0))

    expect(inf1.isInfinity()).toBe(true)
    expect(inf2.isInfinity()).toBe(true)
    expect(inf3.isInfinity()).toBe(true)

    expect(inf1.eq(inf2)).toBe(true)
    expect(inf2.eq(inf3)).toBe(true)
    expect(inf1.eq(inf3)).toBe(true)
  })

  it('Infinity must not equal a finite point', () => {
    const inf = J(null, null, null)

    const good = J(
      new BigNumber('e7789226', 16),
      new BigNumber('4b76b191', 16),
      new BigNumber('cbf8d990', 16)
    )

    expect(inf.eq(good)).toBe(false)
    expect(good.eq(inf)).toBe(false)
  })

  it('Infinity equals infinity (canonicalized)', () => {
    const inf1 = J(null, null, null)
    const inf2 = J('0', '0', '0')

    expect(inf1.eq(inf2)).toBe(true)
    expect(inf2.eq(inf1)).toBe(true)
  })

  it('Infinity is detected when z is zero in RED form', () => {
    const redZero = new BigNumber(0).toRed(new Curve().red)
    const p = J('1', '2', redZero)

    expect(p.isInfinity()).toBe(true)

    const clean = J(null, null, null)
    expect(p.eq(clean)).toBe(true)
    expect(clean.eq(p)).toBe(true)
  })

  it('eq() must handle mixed canonical and non-canonical infinity cases', () => {
    const canonical = J(null, null, null)
    const messy = J('1', '1', new BigNumber(0))

    expect(messy.isInfinity()).toBe(true)
    expect(canonical.eq(messy)).toBe(true)
    expect(messy.eq(canonical)).toBe(true)
  })
})


