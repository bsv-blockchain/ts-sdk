import PublicKey from '../../primitives/PublicKey'
import PrivateKey from '../../primitives/PrivateKey'
import BigNumber from '../../primitives/BigNumber'
import Signature from '../../primitives/Signature'
import { sha256 } from '../../primitives/Hash'

/**
 * Additional tests for PublicKey.ts
 *
 * The existing PublicKey.test.ts covers:
 *   - fromPrivateKey
 *   - fromString / fromDER round-trip
 *   - constructor DER-string guard
 *   - deriveSharedSecret (valid and invalid)
 *   - verify (valid signature)
 *   - toDER returning number[] and hex string
 *   - deriveChild (BRC-42 vectors)
 *
 * The methods/branches below are NOT yet exercised:
 *   - toDER with enc='hex' explicitly
 *   - toHash returning number[] and hex string
 *   - toAddress with all prefix variants ('mainnet', 'main', 'testnet', 'test', array, invalid)
 *   - fromMsgHashAndCompactSignature (happy-path and all error paths)
 *   - constructor with a Point instance (x instanceof Point branch)
 *   - constructor with explicit isRed = false (skips the DER-string guard)
 *   - verify with 'hex' encoding
 *   - deriveChild with cache functions (both retrieve-hit and retrieve-miss paths)
 */

// ---------------------------------------------------------------------------
// Fixed deterministic key pair used throughout these tests
// ---------------------------------------------------------------------------
const PRIV_HEX = 'f97c89aaacf0cd2e47ddbacc97dae1f88bec49106ac37716c451dcdd008a581b'
const privateKey = PrivateKey.fromString(PRIV_HEX, 'hex')
const publicKey = PublicKey.fromPrivateKey(privateKey)

describe('PublicKey – additional coverage', () => {
  // -------------------------------------------------------------------------
  // toDER
  // -------------------------------------------------------------------------
  describe('toDER', () => {
    it('returns a 66-char hex string when enc is "hex"', () => {
      const hex = publicKey.toDER('hex')
      expect(typeof hex).toBe('string')
      expect((hex as string).length).toBe(66)
      // Compressed keys start with 02 or 03
      expect((hex as string)).toMatch(/^0[23][0-9a-f]{64}$/)
    })

    it('returns a 33-byte number array when enc is undefined', () => {
      const bytes = publicKey.toDER()
      expect(Array.isArray(bytes)).toBe(true)
      expect((bytes as number[]).length).toBe(33)
    })

    it('toDER hex and toDER array encode the same key', () => {
      const hex = publicKey.toDER('hex') as string
      const arr = publicKey.toDER() as number[]
      const arrFromHex = Buffer.from(hex, 'hex')
      expect(Array.from(arrFromHex)).toEqual(arr)
    })
  })

  // -------------------------------------------------------------------------
  // fromDER (number array → PublicKey)
  // -------------------------------------------------------------------------
  describe('fromDER', () => {
    it('creates a PublicKey from a DER byte array', () => {
      const derBytes = publicKey.toDER() as number[]
      const recovered = PublicKey.fromDER(derBytes)
      expect(recovered).toBeInstanceOf(PublicKey)
      expect(recovered.toString()).toBe(publicKey.toString())
    })

    it('round-trips through toDER → fromDER correctly', () => {
      const original = PublicKey.fromPrivateKey(PrivateKey.fromRandom())
      const bytes = original.toDER() as number[]
      const restored = PublicKey.fromDER(bytes)
      expect(restored.toString()).toBe(original.toString())
    })
  })

  // -------------------------------------------------------------------------
  // toHash
  // -------------------------------------------------------------------------
  describe('toHash', () => {
    it('returns a non-empty number array by default', () => {
      const hash = publicKey.toHash()
      expect(Array.isArray(hash)).toBe(true)
      expect((hash as number[]).length).toBeGreaterThan(0)
    })

    it('returns a hex string when enc is "hex"', () => {
      const hex = publicKey.toHash('hex')
      expect(typeof hex).toBe('string')
      // hash160 = 20 bytes = 40 hex chars
      expect((hex as string).length).toBe(40)
      expect((hex as string)).toMatch(/^[0-9a-f]{40}$/)
    })

    it('toHash() and toHash("hex") represent the same bytes', () => {
      const arr = publicKey.toHash() as number[]
      const hex = publicKey.toHash('hex') as string
      expect(Buffer.from(arr).toString('hex')).toBe(hex)
    })

    it('different keys produce different hashes', () => {
      const other = PublicKey.fromPrivateKey(PrivateKey.fromRandom())
      expect(publicKey.toHash('hex')).not.toBe(other.toHash('hex'))
    })
  })

  // -------------------------------------------------------------------------
  // toAddress
  // -------------------------------------------------------------------------
  describe('toAddress', () => {
    it('returns a string when called with no arguments (mainnet default)', () => {
      const addr = publicKey.toAddress()
      expect(typeof addr).toBe('string')
      expect(addr.length).toBeGreaterThan(0)
    })

    it('accepts "mainnet" prefix string', () => {
      const addr = publicKey.toAddress('mainnet')
      expect(addr).toBe(publicKey.toAddress([0x00]))
    })

    it('accepts "main" prefix string (alias for mainnet)', () => {
      const addr = publicKey.toAddress('main')
      expect(addr).toBe(publicKey.toAddress([0x00]))
    })

    it('accepts "testnet" prefix string', () => {
      const addr = publicKey.toAddress('testnet')
      expect(addr).toBe(publicKey.toAddress([0x6f]))
    })

    it('accepts "test" prefix string (alias for testnet)', () => {
      const addr = publicKey.toAddress('test')
      expect(addr).toBe(publicKey.toAddress([0x6f]))
    })

    it('accepts an explicit byte-array prefix', () => {
      // P2PKH mainnet prefix
      const addr = publicKey.toAddress([0x00])
      expect(typeof addr).toBe('string')
    })

    it('mainnet and testnet addresses differ for the same key', () => {
      expect(publicKey.toAddress('mainnet')).not.toBe(publicKey.toAddress('testnet'))
    })

    it('throws on an unrecognised string prefix', () => {
      expect(() => publicKey.toAddress('regtest')).toThrow('Invalid prefix regtest')
    })
  })

  // -------------------------------------------------------------------------
  // Constructor – Point overload
  // -------------------------------------------------------------------------
  describe('constructor with Point argument', () => {
    it('builds a PublicKey from an existing Point (uses x/y of point)', () => {
      // The point from the existing key IS a Point; passing it should succeed
      // without going through the string-length guard.
      const copy = new PublicKey(publicKey)
      expect(copy).toBeInstanceOf(PublicKey)
      expect(copy.toString()).toBe(publicKey.toString())
    })
  })

  // -------------------------------------------------------------------------
  // Constructor – isRed = false (skips the DER string guard)
  // -------------------------------------------------------------------------
  describe('constructor with isRed = false', () => {
    it('does not throw for a 66-char string when isRed is false', () => {
      // With isRed=false the guard is bypassed (y is still null, but isRed is
      // false, so the condition is not met).
      // We test that the guard is only active when isRed is true.
      const derHex = publicKey.toString() // 66 hex chars
      expect(() => new PublicKey(derHex, null, false)).not.toThrow()
    })
  })

  // -------------------------------------------------------------------------
  // verify – hex-encoded message
  // -------------------------------------------------------------------------
  describe('verify with hex encoding', () => {
    it('verifies a signature against a hex-encoded message', () => {
      const msgHex = 'deadbeef'
      const sig = privateKey.sign(msgHex, 'hex')
      expect(publicKey.verify(msgHex, sig, 'hex')).toBe(true)
    })

    it('returns false for a wrong signature with hex encoding', () => {
      const msgHex = 'deadbeef'
      const otherKey = PrivateKey.fromRandom()
      const wrongSig = otherKey.sign(msgHex, 'hex')
      expect(publicKey.verify(msgHex, wrongSig, 'hex')).toBe(false)
    })
  })

  // -------------------------------------------------------------------------
  // fromMsgHashAndCompactSignature
  // -------------------------------------------------------------------------
  describe('fromMsgHashAndCompactSignature', () => {
    /**
     * Build a compact signature manually from a Signature object using the
     * compact-signature convention used by the BSV SDK:
     *   byte 0  = 27 + recovery_param          (uncompressed variants use 27-30)
     *             or 31 + recovery_param        (compressed variants use 31-34)
     *   bytes 1-32  = r (big-endian, 32 bytes)
     *   bytes 33-64 = s (big-endian, 32 bytes)
     */
    function makeCompactBytes (sig: Signature, recoveryParam: number, compressed: boolean): number[] {
      const compactByte = (compressed ? 31 : 27) + recoveryParam
      const rBytes = sig.r.toArray('be', 32)
      const sBytes = sig.s.toArray('be', 32)
      return [compactByte, ...rBytes, ...sBytes]
    }

    it('recovers the correct public key from a compact signature', () => {
      // privateKey.sign(msg, 'hex') internally does: msgHash = SHA256(msg as hex bytes)
      // so we must use that same SHA256 hash as the msgHash for recovery
      const msgHex = 'deadbeef'
      const sig = privateKey.sign(msgHex, 'hex')
      const msgHash = new BigNumber(sha256(msgHex, 'hex'), 16)
      // Try all valid recovery params until we get one that produces our key
      let recovered: PublicKey | null = null
      for (let r = 0; r <= 3; r++) {
        try {
          const compact = makeCompactBytes(sig, r, true)
          const candidate = PublicKey.fromMsgHashAndCompactSignature(msgHash, compact)
          if (candidate.toString() === publicKey.toString()) {
            recovered = candidate
            break
          }
        } catch {
          // This recovery param didn't work, try next
        }
      }
      expect(recovered).not.toBeNull()
      expect(recovered!.toString()).toBe(publicKey.toString())
    })

    it('throws for a signature array that is not 65 bytes', () => {
      const msgHash = new BigNumber(1)
      expect(() =>
        PublicKey.fromMsgHashAndCompactSignature(msgHash, new Array(64).fill(0))
      ).toThrow('Invalid Compact Signature')
    })

    it('throws for a signature array that is 66 bytes', () => {
      const msgHash = new BigNumber(1)
      expect(() =>
        PublicKey.fromMsgHashAndCompactSignature(msgHash, new Array(66).fill(0))
      ).toThrow('Invalid Compact Signature')
    })

    it('throws for a compact byte below the valid range (< 27)', () => {
      const msgHash = new BigNumber(1)
      const compact = new Array(65).fill(0)
      compact[0] = 26 // just below 27
      expect(() =>
        PublicKey.fromMsgHashAndCompactSignature(msgHash, compact)
      ).toThrow('Invalid Compact Byte')
    })

    it('throws for a compact byte at or above 35', () => {
      const msgHash = new BigNumber(1)
      const compact = new Array(65).fill(0)
      compact[0] = 35 // >= 35
      expect(() =>
        PublicKey.fromMsgHashAndCompactSignature(msgHash, compact)
      ).toThrow('Invalid Compact Byte')
    })

    it('handles hex-encoded compact signature string', () => {
      const msgHex = 'cafebabe'
      const sig = privateKey.sign(msgHex, 'hex')
      const msgHash = new BigNumber(sha256(msgHex, 'hex'), 16)

      for (let r = 0; r <= 3; r++) {
        try {
          const compactBytes = makeCompactBytes(sig, r, true)
          const hexStr = Buffer.from(compactBytes).toString('hex')
          const candidate = PublicKey.fromMsgHashAndCompactSignature(msgHash, hexStr, 'hex')
          if (candidate.toString() === publicKey.toString()) {
            expect(candidate).toBeInstanceOf(PublicKey)
            return // test passed
          }
        } catch {
          // continue trying recovery params
        }
      }
      // If we reach here all recovery params failed to match – that's a test data issue
      throw new Error('Could not find a valid recovery param for the test key pair')
    })

    it('handles uncompressed compact byte (27-30 range)', () => {
      const msgHex = 'aabbccdd'
      const sig = privateKey.sign(msgHex, 'hex')
      const msgHash = new BigNumber(sha256(msgHex, 'hex'), 16)

      // Try uncompressed recovery params (byte 27-30, i.e. r=0..3 without the +4)
      let passed = false
      for (let r = 0; r <= 3; r++) {
        try {
          const compact = makeCompactBytes(sig, r, false) // uncompressed variant (byte 27-30)
          const candidate = PublicKey.fromMsgHashAndCompactSignature(msgHash, compact)
          if (candidate.toString() === publicKey.toString()) {
            passed = true
            break
          }
        } catch {
          // next
        }
      }
      // At least one recovery param should work
      expect(passed).toBe(true)
    })
  })

  // -------------------------------------------------------------------------
  // deriveChild – cache callbacks
  // -------------------------------------------------------------------------
  describe('deriveChild cache callbacks', () => {
    const invoiceNumber = 'test-invoice-001'

    it('calls cacheSharedSecret when retrieveCachedSharedSecret returns undefined', () => {
      const cacheSharedSecret = jest.fn()
      const retrieveCachedSharedSecret = jest.fn().mockReturnValue(undefined)

      const derived = publicKey.deriveChild(
        privateKey,
        invoiceNumber,
        cacheSharedSecret,
        retrieveCachedSharedSecret
      )

      expect(derived).toBeInstanceOf(PublicKey)
      expect(retrieveCachedSharedSecret).toHaveBeenCalledTimes(1)
      expect(cacheSharedSecret).toHaveBeenCalledTimes(1)
    })

    it('uses cached shared secret when retrieveCachedSharedSecret returns a Point', () => {
      // First derive without cache to capture the real shared secret
      const realSharedSecret = publicKey.deriveSharedSecret(privateKey)

      const cacheSharedSecret = jest.fn()
      const retrieveCachedSharedSecret = jest.fn().mockReturnValue(realSharedSecret)

      const derivedWithCache = publicKey.deriveChild(
        privateKey,
        invoiceNumber,
        cacheSharedSecret,
        retrieveCachedSharedSecret
      )
      const derivedWithout = publicKey.deriveChild(privateKey, invoiceNumber)

      // Both derivations must produce the same child key
      expect(derivedWithCache.toString()).toBe(derivedWithout.toString())
      expect(retrieveCachedSharedSecret).toHaveBeenCalledTimes(1)
      // cacheSharedSecret should NOT be called when a cached value is found
      expect(cacheSharedSecret).not.toHaveBeenCalled()
    })

    it('does not call cacheSharedSecret when it is not provided (cache miss path)', () => {
      // retrieveCachedSharedSecret returns undefined but no cacheSharedSecret provided
      const retrieveCachedSharedSecret = jest.fn().mockReturnValue(undefined)

      expect(() =>
        publicKey.deriveChild(privateKey, invoiceNumber, undefined, retrieveCachedSharedSecret)
      ).not.toThrow()

      expect(retrieveCachedSharedSecret).toHaveBeenCalledTimes(1)
    })

    it('derives without any cache callbacks (direct path)', () => {
      const derived = publicKey.deriveChild(privateKey, invoiceNumber)
      expect(derived).toBeInstanceOf(PublicKey)
    })
  })
})
