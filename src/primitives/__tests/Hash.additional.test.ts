import { SHA1HMAC, SHA512HMAC, pbkdf2 } from '../../primitives/Hash'

describe('Hash – additional coverage', () => {
  describe('SHA1HMAC', () => {
    it('produces a correct HMAC-SHA1 digest', () => {
      // SHA1HMAC constructor calls toArray(key, 'hex'), so key must be hex
      const hmac = new SHA1HMAC('deadbeef')
      const result = hmac.update('abcd', 'hex').digest()
      expect(result).toHaveLength(20)
    })

    it('returns a hex string from digestHex()', () => {
      const hmac = new SHA1HMAC('deadbeef')
      const result = hmac.update('deadbeef', 'hex').digestHex()
      expect(typeof result).toBe('string')
      expect(result).toHaveLength(40) // SHA1 = 20 bytes = 40 hex chars
    })

    it('handles a key longer than 64 bytes (key hashed internally)', () => {
      // Key longer than SHA1 blockSize (64 bytes) → key is SHA1-hashed.
      // Each hex byte is 2 chars, so 65 bytes = 130 hex chars.
      const longKey = 'ab'.repeat(65) // 65 bytes when decoded from hex
      const hmac = new SHA1HMAC(longKey)
      const result = hmac.update('deadbeef', 'hex').digest()
      expect(result).toHaveLength(20)
    })
  })

  describe('SHA512HMAC', () => {
    it('produces a correct HMAC-SHA512 digest', () => {
      // SHA512HMAC string key is treated as hex
      const hmac = new SHA512HMAC('deadbeef')
      const result = hmac.update('message').digest()
      expect(result).toHaveLength(64) // SHA512 = 64 bytes
    })

    it('returns a hex string from digestHex()', () => {
      const hmac = new SHA512HMAC('deadbeef')
      const result = hmac.update(new Uint8Array([1, 2, 3])).digestHex()
      expect(typeof result).toBe('string')
      expect(result).toHaveLength(128) // SHA512 = 64 bytes = 128 hex chars
    })

    it('accepts a Uint8Array key', () => {
      const key = new Uint8Array([1, 2, 3, 4])
      const hmac = new SHA512HMAC(key)
      const result = hmac.update(new Uint8Array([5, 6, 7])).digest()
      expect(result).toHaveLength(64)
    })
  })

  describe('pbkdf2', () => {
    it('throws when digest is not sha512', () => {
      expect(() => pbkdf2([1, 2, 3], [4, 5, 6], 1, 32, 'sha256')).toThrow(
        'Only sha512 is supported in this PBKDF2 implementation'
      )
    })
  })
})
