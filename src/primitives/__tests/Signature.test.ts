import Signature from '../../primitives/Signature'
import BigNumber from '../../primitives/BigNumber'
import PrivateKey from '../../primitives/PrivateKey'
import PublicKey from '../../primitives/PublicKey'
import * as ECDSA from '../../primitives/ECDSA'
import Curve from '../../primitives/Curve'

const key = new BigNumber(
  '1e5edd45de6d22deebef4596b80444ffcc29143839c1dce18db470e25b4be7b5',
  16
)
const curve = new Curve()
const msg = new BigNumber('deadbeef', 16)

describe('Signature', () => {
  // --------------------------------------------------------------------------
  // fromDER – error paths
  // --------------------------------------------------------------------------
  describe('fromDER error paths', () => {
    it('throws when DER does not start with 0x30', () => {
      // Replace leading 0x30 with 0x31
      const sig = ECDSA.sign(msg, key)
      const der = sig.toDER() as number[]
      der[0] = 0x31
      expect(() => Signature.fromDER(der)).toThrow('Signature DER must start with 0x30')
    })

    it('throws when outer length byte has high bit set (multi-byte length)', () => {
      // Set the length byte to 0x81 (high bit set) to trigger 'Invalid DER entity length'
      const der = [0x30, 0x81, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]
      expect(() => Signature.fromDER(der)).toThrow('Invalid DER entity length')
    })

    it('throws when outer length does not match data length', () => {
      const sig = ECDSA.sign(msg, key)
      const der = sig.toDER() as number[]
      // Corrupt the length byte to be too small
      der[1] = 1
      expect(() => Signature.fromDER(der)).toThrow('Signature DER invalid')
    })

    it('throws when second marker is not 0x02 (r marker)', () => {
      const sig = ECDSA.sign(msg, key)
      const der = sig.toDER() as number[]
      // Byte at index 2 should be 0x02
      der[2] = 0x03
      expect(() => Signature.fromDER(der)).toThrow('Signature DER invalid')
    })

    it('throws when s marker is not 0x02', () => {
      const sig = ECDSA.sign(msg, key)
      const der = sig.toDER() as number[]
      const rlen = der[3]
      // s marker is at position 4 + rlen
      der[4 + rlen] = 0x03
      expect(() => Signature.fromDER(der)).toThrow('Signature DER invalid')
    })

    it('throws when r starts with 0x00 but next byte is not high-bit', () => {
      // Construct a DER where r has leading 0x00 but r[1] high bit is 0 (invalid padding)
      // r = [0x00, 0x01], s = [0x01]
      const rBytes = [0x00, 0x01]
      const sBytes = [0x01]
      const der = [
        0x30,
        2 + rBytes.length + 2 + sBytes.length,
        0x02, rBytes.length, ...rBytes,
        0x02, sBytes.length, ...sBytes
      ]
      expect(() => Signature.fromDER(der)).toThrow('Invalid R-value in signature DER')
    })

    it('throws when s starts with 0x00 but next byte is not high-bit', () => {
      // r = [0x01], s = [0x00, 0x01]
      const rBytes = [0x01]
      const sBytes = [0x00, 0x01]
      const der = [
        0x30,
        2 + rBytes.length + 2 + sBytes.length,
        0x02, rBytes.length, ...rBytes,
        0x02, sBytes.length, ...sBytes
      ]
      expect(() => Signature.fromDER(der)).toThrow('Invalid S-value in signature DER')
    })

    it('throws on s-length mismatch', () => {
      const sig = ECDSA.sign(msg, key)
      const der = sig.toDER() as number[]
      // Corrupt the s-length byte to be too large
      const rlen = der[3]
      der[4 + rlen + 1] = 0x7f
      expect(() => Signature.fromDER(der)).toThrow()
    })

    it('parses from hex string', () => {
      const sig = ECDSA.sign(msg, key)
      const hexDER = sig.toDER('hex') as string
      const recovered = Signature.fromDER(hexDER, 'hex')
      expect(recovered.r.eq(sig.r)).toBe(true)
      expect(recovered.s.eq(sig.s)).toBe(true)
    })

    it('parses from base64 string', () => {
      const sig = ECDSA.sign(msg, key)
      const b64DER = sig.toDER('base64') as string
      const recovered = Signature.fromDER(b64DER, 'base64')
      expect(recovered.r.eq(sig.r)).toBe(true)
      expect(recovered.s.eq(sig.s)).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // fromCompact
  // --------------------------------------------------------------------------
  describe('fromCompact', () => {
    it('throws when data is not 65 bytes', () => {
      expect(() => Signature.fromCompact(new Array(64).fill(0))).toThrow('Invalid Compact Signature')
      expect(() => Signature.fromCompact(new Array(66).fill(0))).toThrow('Invalid Compact Signature')
    })

    it('throws when compact byte < 27', () => {
      const data = new Array(65).fill(0)
      data[0] = 26
      expect(() => Signature.fromCompact(data)).toThrow('Invalid Compact Byte')
    })

    it('throws when compact byte >= 35', () => {
      const data = new Array(65).fill(0)
      data[0] = 35
      expect(() => Signature.fromCompact(data)).toThrow('Invalid Compact Byte')
    })

    it('parses a valid compact signature', () => {
      const sig = ECDSA.sign(msg, key)
      const compact = sig.toCompact(0, true) as number[]
      const recovered = Signature.fromCompact(compact)
      expect(recovered.r.eq(sig.r)).toBe(true)
      expect(recovered.s.eq(sig.s)).toBe(true)
    })

    it('parses from hex compact string', () => {
      const sig = ECDSA.sign(msg, key)
      const hexCompact = sig.toCompact(0, true, 'hex') as string
      const recovered = Signature.fromCompact(hexCompact, 'hex')
      expect(recovered.r.eq(sig.r)).toBe(true)
    })

    it('parses from base64 compact string', () => {
      const sig = ECDSA.sign(msg, key)
      const b64Compact = sig.toCompact(0, true, 'base64') as string
      const recovered = Signature.fromCompact(b64Compact, 'base64')
      expect(recovered.r.eq(sig.r)).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // verify
  // --------------------------------------------------------------------------
  describe('verify', () => {
    it('verifies a valid signature against a string message', () => {
      const privKey = PrivateKey.fromRandom()
      const pubKey = PublicKey.fromPrivateKey(privKey)
      const sig = privKey.sign('hello world')
      expect(sig.verify('hello world', pubKey)).toBe(true)
    })

    it('returns false for a wrong signature', () => {
      const privKey = PrivateKey.fromRandom()
      const pubKey = PublicKey.fromPrivateKey(privKey)
      const otherKey = PrivateKey.fromRandom()
      const wrongSig = otherKey.sign('hello world')
      expect(wrongSig.verify('hello world', pubKey)).toBe(false)
    })

    it('verifies with hex encoding', () => {
      const privKey = PrivateKey.fromRandom()
      const pubKey = PublicKey.fromPrivateKey(privKey)
      const sig = privKey.sign('deadbeef', 'hex')
      expect(sig.verify('deadbeef', pubKey, 'hex')).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // toString / toDER
  // --------------------------------------------------------------------------
  describe('toString / toDER', () => {
    it('toString() with no args returns number array (same as toDER)', () => {
      const sig = ECDSA.sign(msg, key)
      const fromToString = sig.toString()
      const fromToDER = sig.toDER()
      expect(fromToString).toEqual(fromToDER)
    })

    it('toString(\"hex\") returns same as toDER(\"hex\")', () => {
      const sig = ECDSA.sign(msg, key)
      expect(sig.toString('hex')).toBe(sig.toDER('hex'))
    })

    it('toDER returns number[] by default', () => {
      const sig = ECDSA.sign(msg, key)
      expect(Array.isArray(sig.toDER())).toBe(true)
    })

    it('toDER(\"hex\") returns hex string', () => {
      const sig = ECDSA.sign(msg, key)
      const hex = sig.toDER('hex')
      expect(typeof hex).toBe('string')
      expect(hex as string).toMatch(/^[0-9a-f]+$/)
    })

    it('toDER(\"base64\") returns base64 string', () => {
      const sig = ECDSA.sign(msg, key)
      const b64 = sig.toDER('base64')
      expect(typeof b64).toBe('string')
      // base64 uses A-Z, a-z, 0-9, +, /, =
      expect(b64 as string).toMatch(/^[A-Za-z0-9+/=]+$/)
    })

    it('round-trips through toDER → fromDER', () => {
      const sig = ECDSA.sign(msg, key)
      const der = sig.toDER() as number[]
      const recovered = Signature.fromDER(der)
      expect(recovered.r.eq(sig.r)).toBe(true)
      expect(recovered.s.eq(sig.s)).toBe(true)
    })
  })

  // --------------------------------------------------------------------------
  // toCompact
  // --------------------------------------------------------------------------
  describe('toCompact', () => {
    it('throws when recovery < 0', () => {
      const sig = ECDSA.sign(msg, key)
      expect(() => sig.toCompact(-1, true)).toThrow('Invalid recovery param')
    })

    it('throws when recovery > 3', () => {
      const sig = ECDSA.sign(msg, key)
      expect(() => sig.toCompact(4, true)).toThrow('Invalid recovery param')
    })

    it('throws when compressed is not a boolean', () => {
      const sig = ECDSA.sign(msg, key)
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      expect(() => sig.toCompact(0, 'yes' as any)).toThrow('Invalid compressed param')
    })

    it('returns number[] by default', () => {
      const sig = ECDSA.sign(msg, key)
      const compact = sig.toCompact(0, true)
      expect(Array.isArray(compact)).toBe(true)
      expect((compact as number[]).length).toBe(65)
    })

    it('returns hex string when enc=\"hex\"', () => {
      const sig = ECDSA.sign(msg, key)
      const hex = sig.toCompact(0, true, 'hex')
      expect(typeof hex).toBe('string')
      expect((hex as string).length).toBe(130)
    })

    it('returns base64 string when enc=\"base64\"', () => {
      const sig = ECDSA.sign(msg, key)
      const b64 = sig.toCompact(0, true, 'base64')
      expect(typeof b64).toBe('string')
    })

    it('compact byte = 27 + recovery for uncompressed (recovery=0)', () => {
      const sig = ECDSA.sign(msg, key)
      const compact = sig.toCompact(0, false) as number[]
      expect(compact[0]).toBe(27)
    })

    it('compact byte = 31 + recovery for compressed (recovery=0)', () => {
      const sig = ECDSA.sign(msg, key)
      const compact = sig.toCompact(0, true) as number[]
      expect(compact[0]).toBe(31)
    })
  })

  // --------------------------------------------------------------------------
  // RecoverPublicKey
  // --------------------------------------------------------------------------
  describe('RecoverPublicKey', () => {
    it('recovers the public key from a signature', () => {
      const privKey = PrivateKey.fromRandom()
      const pubKey = PublicKey.fromPrivateKey(privKey)
      const msgHash = new BigNumber('deadbeef', 16)
      const sig = ECDSA.sign(msgHash, privKey)

      let recovered: PublicKey | null = null
      for (let r = 0; r <= 3; r++) {
        try {
          const candidate = sig.RecoverPublicKey(r, msgHash)
          if (candidate.toString() === pubKey.toString()) {
            recovered = candidate
            break
          }
        } catch {
          // try next
        }
      }
      expect(recovered).not.toBeNull()
    })
  })

  // --------------------------------------------------------------------------
  // CalculateRecoveryFactor
  // --------------------------------------------------------------------------
  describe('CalculateRecoveryFactor', () => {
    it('returns a valid recovery factor for a known key/msg pair', () => {
      const privKey = PrivateKey.fromRandom()
      const pubKey = PublicKey.fromPrivateKey(privKey)
      const msgHash = new BigNumber('cafebabe', 16)
      const sig = ECDSA.sign(msgHash, privKey)

      const factor = sig.CalculateRecoveryFactor(pubKey, msgHash)
      expect(factor).toBeGreaterThanOrEqual(0)
      expect(factor).toBeLessThanOrEqual(3)
    })

    it('throws when no valid recovery factor can be found', () => {
      const privKey = PrivateKey.fromRandom()
      const wrongKey = PublicKey.fromPrivateKey(PrivateKey.fromRandom())
      const msgHash = new BigNumber('cafebabe', 16)
      const sig = ECDSA.sign(msgHash, privKey)

      expect(() => sig.CalculateRecoveryFactor(wrongKey, msgHash)).toThrow(
        'Unable to find valid recovery factor'
      )
    })
  })
})
