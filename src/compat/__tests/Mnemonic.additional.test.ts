import Mnemonic from '../Mnemonic'

const VALID_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

describe('Mnemonic – additional coverage', () => {
  describe('fromRandom – default and edge-case bits', () => {
    it('uses 128 bits when bits is undefined', () => {
      const m = new Mnemonic().fromRandom(undefined)
      expect(m.mnemonic.split(' ')).toHaveLength(12) // 128-bit → 12 words
    })

    it('uses 128 bits when bits is 0', () => {
      const m = new Mnemonic().fromRandom(0)
      expect(m.mnemonic.split(' ')).toHaveLength(12)
    })

    it('uses 128 bits when bits is NaN', () => {
      const m = new Mnemonic().fromRandom(NaN)
      expect(m.mnemonic.split(' ')).toHaveLength(12)
    })

    it('throws when bits is a multiple of 32 but less than 128', () => {
      // 96 is a multiple of 32 but < 128
      expect(() => new Mnemonic().fromRandom(96)).toThrow('bits must be at least 128')
    })
  })

  describe('toBinary – empty mnemonic and seed', () => {
    it('encodes empty mnemonic as varint 0', () => {
      const m = new Mnemonic('', [])
      const buf = m.toBinary()
      // Both mnemonic and seed are empty → first byte (varint) is 0
      expect(buf[0]).toBe(0)
      expect(buf[1]).toBe(0)
    })
  })

  describe('fromBinary – empty fields', () => {
    it('round-trips an instance with empty mnemonic and seed', () => {
      const original = new Mnemonic('', [])
      const buf = original.toBinary()
      const restored = new Mnemonic().fromBinary(buf)
      expect(restored.mnemonic).toBe('')
      expect(restored.seed).toHaveLength(0)
    })
  })

  describe('mnemonic2Seed', () => {
    it('throws when passphrase is not a string', () => {
      const m = Mnemonic.fromString(VALID_MNEMONIC)
      expect(() => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        m.mnemonic2Seed(42 as any)
      }).toThrow('passphrase must be a string or undefined')
    })
  })

  describe('toString', () => {
    it('returns the mnemonic string', () => {
      const m = Mnemonic.fromString(VALID_MNEMONIC)
      expect(m.toString()).toBe(VALID_MNEMONIC)
    })
  })
})
