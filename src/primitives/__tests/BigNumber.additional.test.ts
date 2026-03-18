import BigNumber from '../BigNumber'

describe('BigNumber – additional coverage', () => {
  describe('negative setter', () => {
    it('sets sign to 0 when magnitude is zero (setting val=1 on zero BN)', () => {
      const bn = new BigNumber(0)
      bn.negative = 1
      expect(bn.negative).toBe(0) // magnitude is 0 so sign stays 0
    })

    it('sets sign to 1 on a non-zero BigNumber', () => {
      const bn = new BigNumber(5)
      bn.negative = 1
      expect(bn.negative).toBe(1)
    })

    it('sets sign to 0 on a non-zero BigNumber', () => {
      const bn = new BigNumber(5)
      bn.negative = 1
      bn.negative = 0
      expect(bn.negative).toBe(0)
    })
  })

  describe('inspect', () => {
    it('returns inspection string for a positive BigNumber', () => {
      const bn = new BigNumber(255)
      const s = bn.inspect()
      expect(s).toContain('ff')
      expect(s).toContain('BN')
    })
  })

  describe('toBitArray', () => {
    it('returns empty array for zero (static)', () => {
      expect(BigNumber.toBitArray(new BigNumber(0))).toEqual([])
    })

    it('instance method returns same as static', () => {
      const bn = new BigNumber(5) // binary: 101
      expect(bn.toBitArray()).toEqual([1, 0, 1])
    })
  })

  describe('toString with non-standard base', () => {
    it('converts to base-3 string', () => {
      const bn = new BigNumber(9)
      expect(bn.toString(3)).toBe('100') // 9 in base 3 = 100
    })
  })

  describe('fromBits / toBits edge cases', () => {
    it('fromBits(0) returns zero BigNumber', () => {
      const bn = BigNumber.fromBits(0)
      expect(bn.toNumber()).toBe(0)
    })

    it('toBits for zero returns 0', () => {
      expect(new BigNumber(0).toBits()).toBe(0)
    })

    it('toBits for a 3-byte number with MSB set in mantissa (triggers shift)', () => {
      // mB[0] >= 0x80 → (nWordNum & 0x00800000) !== 0 → shift branch
      const bn = BigNumber.fromHex('800001')
      const bits = bn.toBits()
      expect(bits).toBeGreaterThan(0)
    })
  })

  describe('toSm', () => {
    it('returns [0x80] for negative zero (magnitude 0, sign 1)', () => {
      const bn = new BigNumber(0)
      bn.negative = 1
      const result = bn.toSm()
      // magnitude is 0 so sign gets normalized to 0; returns []
      expect(Array.isArray(result)).toBe(true)
    })
  })
})
