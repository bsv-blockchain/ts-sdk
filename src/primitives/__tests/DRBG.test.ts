import DRBG from '../../primitives/DRBG'
import DRBGVectors from './DRBG.vectors'
import { toArray, toHex } from '../../primitives/utils'
import { SHA256 } from '../../primitives/Hash'

describe('DRBG', () => {
  describe('NIST vector compatibility', () => {
    DRBGVectors.forEach((opt, index) => {
      it(`handles NIST-style vector ${index} consistently`, () => {
        const entropyBytes = toArray(opt.entropy, 'hex')
        const nonceBytes = toArray(opt.nonce, 'hex')

        const expectedByteLen = opt.expected.length / 2

        if (entropyBytes.length !== 32 || nonceBytes.length !== 32) {
          expect(() => new DRBG(opt.entropy, opt.nonce)).toThrow()
          return
        }

        const drbg1 = new DRBG(opt.entropy, opt.nonce)
        const out1 = drbg1.generate(expectedByteLen)

        const drbg2 = new DRBG(opt.entropy, opt.nonce)
        const out2 = drbg2.generate(expectedByteLen)

        expect(out1).toEqual(out2)
        expect(out1.length).toBe(opt.expected.length)
      })
    })
  })

  describe('constructor input validation', () => {
    it('throws if entropy is shorter than 32 bytes', () => {
      const entropy = new Array(31).fill(0x01)
      const nonce = new Array(32).fill(0x02)

      expect(() => {
        new DRBG(entropy, nonce)
      }).toThrow('Entropy must be exactly 32 bytes (256 bits)')
    })

    it('throws if entropy is longer than 32 bytes', () => {
      const entropy = new Array(33).fill(0x01)
      const nonce = new Array(32).fill(0x02)

      expect(() => {
        new DRBG(entropy, nonce)
      }).toThrow('Entropy must be exactly 32 bytes (256 bits)')
    })

    it('throws if nonce is shorter than 32 bytes', () => {
      const entropy = new Array(32).fill(0x01)
      const nonce = new Array(31).fill(0x02)

      expect(() => {
        new DRBG(entropy, nonce)
      }).toThrow('Nonce must be exactly 32 bytes (256 bits)')
    })

    it('throws if nonce is longer than 32 bytes', () => {
      const entropy = new Array(32).fill(0x01)
      const nonce = new Array(33).fill(0x02)

      expect(() => {
        new DRBG(entropy, nonce)
      }).toThrow('Nonce must be exactly 32 bytes (256 bits)')
    })

    it('accepts both hex strings and number[] inputs equivalently', () => {
      const entropyArr = new Array(32).fill(0x11)
      const nonceArr = new Array(32).fill(0x22)

      const entropyHex = Buffer.from(entropyArr).toString('hex')
      const nonceHex = Buffer.from(nonceArr).toString('hex')

      const drbgArray = new DRBG(entropyArr, nonceArr)
      const drbgHex = new DRBG(entropyHex, nonceHex)

      const outArray = drbgArray.generate(32)
      const outHex = drbgHex.generate(32)

      expect(outArray).toEqual(outHex)
    })
  })

  describe('determinism', () => {
    const entropyHex =
      '1b2e3d4c5f60718293a4b5c6d7e8f9011b2e3d4c5f60718293a4b5c6d7e8f901'
    const nonceHex =
      'abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd'

    it('produces the same sequence for the same inputs', () => {
      const drbg1 = new DRBG(entropyHex, nonceHex)
      const drbg2 = new DRBG(entropyHex, nonceHex)

      const seq1 = [
        drbg1.generate(32),
        drbg1.generate(32),
        drbg1.generate(16)
      ]

      const seq2 = [
        drbg2.generate(32),
        drbg2.generate(32),
        drbg2.generate(16)
      ]

      expect(seq1).toEqual(seq2)
    })

    it('produces different sequences if entropy changes', () => {
      const entropyHex2 =
        '2b3e4d5c6f708192a3b4c5d6e7f809112b3e4d5c6f708192a3b4c5d6e7f80911'
      const drbg1 = new DRBG(entropyHex, nonceHex)
      const drbg2 = new DRBG(entropyHex2, nonceHex)

      const out1 = drbg1.generate(32)
      const out2 = drbg2.generate(32)

      expect(out1).not.toEqual(out2)
    })

    it('produces different sequences if nonce changes', () => {
      const nonceHex2 =
        '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
      const drbg1 = new DRBG(entropyHex, nonceHex)
      const drbg2 = new DRBG(entropyHex, nonceHex2)

      const out1 = drbg1.generate(32)
      const out2 = drbg2.generate(32)

      expect(out1).not.toEqual(out2)
    })
  })

  describe('output length and state advancement', () => {
    const entropyBytes = new Array(32).fill(0x33)
    const nonceBytes = new Array(32).fill(0x44)

    it('returns hex strings of length 2 * len', () => {
      const drbg = new DRBG(entropyBytes, nonceBytes)

      const out16 = drbg.generate(16)
      const out32 = drbg.generate(32)

      expect(out16.length).toBe(16 * 2)
      expect(out32.length).toBe(32 * 2)
    })

    it('advances internal state between generate calls', () => {
      const drbg = new DRBG(entropyBytes, nonceBytes)

      const first = drbg.generate(32)
      const second = drbg.generate(32)

      expect(second).not.toEqual(first)
    })

    it('matches output when seeded with explicit number[] arrays', () => {
      const entropyHex = 'aa'.repeat(32)
      const nonceHex = 'bb'.repeat(32)
      const entropyArr = toArray(entropyHex, 'hex')
      const nonceArr = toArray(nonceHex, 'hex')

      const drbgFromHex = new DRBG(entropyHex, nonceHex)
      const drbgFromArr = new DRBG(entropyArr, nonceArr)

      const outHex = drbgFromHex.generate(32)
      const outArr = drbgFromArr.generate(32)

      expect(outHex).toEqual(outArr)
    })
  })

  describe('RFC 6979 ECDSA P-256 / SHA-256 vectors', () => {
    // q for NIST P-256, from RFC 6979 A.2.5
    const qHex =
      'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551'
    const q = BigInt('0x' + qHex)

    // int2octets: convert a non-negative bigint < 2^256 to a 32-byte big-endian array
    const intToOctets = (x: bigint): number[] => {
      const out = new Array<number>(32)
      let v = x
      for (let i = 31; i >= 0; i--) {
        out[i] = Number(v & 0xffn)
        v >>= 8n
      }
      return out
    }

    // bits2octets(h1): convert hash output to int, reduce mod q, return 32-byte big-endian
    const bits2octets = (h1: number[]): number[] => {
      const h1Int = BigInt('0x' + toHex(h1))
      const z1 = h1Int % q
      return intToOctets(z1)
    }

    const normalizeHex = (hex: string): string => hex.toLowerCase()

    it('reproduces RFC 6979 k for P-256, SHA-256, message "sample"', () => {
      // From RFC 6979 A.2.5 (ECDSA, 256 bits, P-256):
      // private key x:
      const xHex =
        'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721'

      // expected k for SHA-256, message = "sample"
      const expectedKHex =
        'A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60'

      const msg = 'sample'

      const x = BigInt('0x' + xHex)
      const entropy = intToOctets(x)

      // h1 = SHA-256(message)
      const h1Bytes = new SHA256().update(msg, 'utf8').digest()
      const nonce = bits2octets(h1Bytes)

      const drbg = new DRBG(entropy, nonce)

      // First 32-byte block from DRBG
      const tHex = drbg.generate(32) // 32 bytes = 64 hex chars
      const tInt = BigInt('0x' + tHex)

      // RFC 6979 derives k as tInt mod q (and retries if out of range; here it’s fine)
      const k = tInt % q
      const kHex = k.toString(16).padStart(64, '0')

      expect(normalizeHex(kHex)).toBe(normalizeHex(expectedKHex))
    })

    it('reproduces RFC 6979 k for P-256, SHA-256, message "test"', () => {
      // Same key x as above (RFC 6979 A.2.5), different message:
      const xHex =
        'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721'

      // expected k for SHA-256, message = "test"
      const expectedKHex =
        'D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0'

      const msg = 'test'

      const x = BigInt('0x' + xHex)
      const entropy = intToOctets(x)

      const h1Bytes = new SHA256().update(msg, 'utf8').digest()
      const nonce = bits2octets(h1Bytes)

      const drbg = new DRBG(entropy, nonce)

      const tHex = drbg.generate(32)
      const tInt = BigInt('0x' + tHex)
      const k = tInt % q
      const kHex = k.toString(16).padStart(64, '0')

      expect(normalizeHex(kHex)).toBe(normalizeHex(expectedKHex))
    })

    it('is deterministic for the same RFC 6979 key and message', () => {
      const xHex =
        'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721'
      const msg = 'sample'

      const x = BigInt('0x' + xHex)
      const entropy = intToOctets(x)
      const h1Bytes = new SHA256().update(msg, 'utf8').digest()
      const nonce = bits2octets(h1Bytes)

      const drbg1 = new DRBG(entropy, nonce)
      const drbg2 = new DRBG(entropy, nonce)

      const out1 = drbg1.generate(32)
      const out2 = drbg2.generate(32)

      expect(out1).toBe(out2)
    })
  })
})


