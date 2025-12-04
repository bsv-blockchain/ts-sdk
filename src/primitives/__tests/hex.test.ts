/* eslint-env jest */

import { assertValidHex, normalizeHex } from '../../primitives/hex'

describe('hex utils', () => {
  describe('assertValidHex', () => {
    it('should not throw on valid hex strings', () => {
      expect(() => assertValidHex('')).not.toThrow()          // empty is allowed
      expect(() => assertValidHex('00')).not.toThrow()
      expect(() => assertValidHex('abcdef')).not.toThrow()
      expect(() => assertValidHex('ABCDEF')).not.toThrow()
      expect(() => assertValidHex('1234567890')).not.toThrow()
    })

    it('should throw on non-hex characters', () => {
      expect(() => assertValidHex('zz')).toThrow('Invalid hex string')
      expect(() => assertValidHex('0x1234')).toThrow('Invalid hex string')
      expect(() => assertValidHex('12 34')).toThrow('Invalid hex string')
      expect(() => assertValidHex('g1')).toThrow('Invalid hex string')
    })

    // ❌ old behavior: empty string was considered invalid
    // it('should throw on empty string', () => {
    //   expect(() => assertValidHex('')).toThrow('Invalid hex string')
    // })

    it('should throw on undefined or null', () => {
      expect(() => assertValidHex(undefined as any)).toThrow('Invalid hex string')
      expect(() => assertValidHex(null as any)).toThrow('Invalid hex string')
    })
  })

  describe('normalizeHex', () => {
    it('should return lowercase hex', () => {
      expect(normalizeHex('ABCD')).toBe('abcd')
    })

    it('should prepend 0 to odd-length hex strings', () => {
      expect(normalizeHex('abc')).toBe('0abc')
      expect(normalizeHex('f')).toBe('0f')
    })

    it('should leave even-length hex strings untouched (except lowercase)', () => {
      expect(normalizeHex('AABB')).toBe('aabb')
      expect(normalizeHex('001122')).toBe('001122')
    })

    it('should return empty string unchanged', () => {
      expect(normalizeHex('')).toBe('')
    })

    it('should throw on invalid hex', () => {
      expect(() => normalizeHex('xyz')).toThrow('Invalid hex string')
      expect(() => normalizeHex('12 34')).toThrow('Invalid hex string')
    })
  })
})
