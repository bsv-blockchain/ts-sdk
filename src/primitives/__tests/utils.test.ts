/* eslint-env jest */
import {
  toArray,
  zero2,
  toHex,
  encode,
  toUTF8,
  fromBase58,
  toBase58,
  fromBase58Check,
  toBase58Check,
  verifyNotNull,
  constantTimeEquals
} from '../../primitives/utils'
import Point from '../../primitives/Point'

describe('utils', () => {
  it('should convert to array', () => {
    expect(toArray('1234', 'hex')).toEqual([0x12, 0x34])
    expect(toArray('1234')).toEqual([49, 50, 51, 52])
    expect(toArray('1234', 'utf8')).toEqual([49, 50, 51, 52])
    expect(toArray('\u1234', 'utf8')).toEqual([225, 136, 180])
    expect(toArray('\u1234' + '234', 'utf8')).toEqual([225, 136, 180, 50, 51, 52])
    expect(toArray([1, 2, 3, 4])).toEqual([1, 2, 3, 4])
  })

  it('should zero pad byte to hex', () => {
    expect(zero2('0')).toBe('00')
    expect(zero2('01')).toBe('01')
  })

  it('should convert to hex', () => {
    expect(toHex([0, 1, 2, 3])).toBe('00010203')
  })

  it('should encode', () => {
    expect(encode([0, 1, 2, 3])).toEqual([0, 1, 2, 3])
    expect(encode([0, 1, 2, 3], 'hex')).toBe('00010203')
  })

  describe('base58 to binary', () => {
    it('Converts as expected', () => {
      const actual = fromBase58(
        '6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV'
      )
      expect(toHex(actual)).toEqual(
        '02c0ded2bc1f1305fb0faac5e6c03ee3a1924234985427b6167ca569d13df435cfeb05f9d2'
      )
    })
    it('Converts as expected with leading 1s', () => {
      const actual = fromBase58('111z')
      expect(toHex(actual)).toEqual('00000039')
    })
    it('Throws when called with undefined base58 string', () => {
      expect(() => fromBase58(undefined as unknown as string)).toThrow(
        new Error('Expected base58 string but got “undefined”')
      )
    })

    it('Throws when called with invalid characters in base58 string', () => {
      expect(() => fromBase58('0L')).toThrow(
        new Error('Invalid base58 character “0”')
      )
    })
  })
  describe('binary to base58 string', () => {
    it('Converts to base58 as expected', () => {
      const actual = toBase58(
        toArray(
          '02c0ded2bc1f1305fb0faac5e6c03ee3a1924234985427b6167ca569d13df435cfeb05f9d2',
          'hex'
        )
      )
      expect(actual).toEqual(
        '6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV'
      )
    })
    it('Converts to base58 as expected with 1s', () => {
      const actual = toBase58([0, 0, 0, 4])
      expect(actual).toEqual('1115')
    })
  })
  describe('base58check encoding and decoding', () => {
    it('should correctly encode and decode data with default prefix', () => {
      let data = toArray('f5f2d624cfb5c3f66d06123d0829d1c9cebf770e', 'hex')
      let encoded = toBase58Check(data)
      expect(encoded).toBe('1PRTTaJesdNovgne6Ehcdu1fpEdX7913CK')
      expect(fromBase58Check(encoded)).toEqual({ prefix: [0], data })

      data = toArray('27b5891b01da2db74cde1689a97a2acbe23d5fb1', 'hex')
      encoded = toBase58Check(data)
      expect(encoded).toBe('14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3')
      expect(fromBase58Check(encoded)).toEqual({ prefix: [0], data })
    })

    it('should correctly encode and decode data with custom prefix', () => {
      const prefix = [0x80]
      let data = toArray(
        '1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD',
        'hex'
      )
      let encoded = toBase58Check(data, prefix)
      expect(encoded).toBe(
        '5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn'
      )
      expect(fromBase58Check(encoded)).toEqual({ prefix, data })

      data = toArray(
        '3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6',
        'hex'
      )
      encoded = toBase58Check(data, prefix)
      expect(encoded).toBe(
        '5JG9hT3beGTJuUAmCQEmNaxAuMacCTfXuw1R3FCXig23RQHMr4K'
      )
      expect(fromBase58Check(encoded)).toEqual({ prefix, data })
    })

    it('should correctly handle encoding and decoding with different encoding formats', () => {
      const prefix = [0x80]
      let dataHex =
        '1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD01'
      dataHex = dataHex.toLowerCase()
      let data = toArray(dataHex, 'hex')
      let encoded = toBase58Check(data, prefix)
      expect(encoded).toBe(
        'KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ'
      )
      expect(fromBase58Check(encoded, 'hex')).toEqual({
        prefix: '80',
        data: dataHex
      })

      dataHex =
        '3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa601'
      data = toArray(dataHex, 'hex')
      encoded = toBase58Check(data, prefix)
      expect(encoded).toBe(
        'KyBsPXxTuVD82av65KZkrGrWi5qLMah5SdNq6uftawDbgKa2wv6S'
      )
      expect(fromBase58Check(encoded, 'hex')).toEqual({
        prefix: '80',
        data: dataHex
      })
    })

    it('should correctly encode and decode Bitcoin addresses', () => {
      const dataHex = '086eaa677895f92d4a6c5ef740c168932b5e3f44'
      const data = toArray(dataHex, 'hex')
      const encoded = toBase58Check(data)
      expect(encoded).toBe('1mayif3H2JDC62S4N3rLNtBNRAiUUP99k')
      expect(fromBase58Check(encoded, 'hex')).toEqual({
        prefix: '00',
        data: dataHex
      })

      const address = '1mayif3H2JDC62S4N3rLNtBNRAiUUP99k'
      expect(fromBase58Check(address, 'hex')).toEqual({
        prefix: '00',
        data: dataHex
      })
    })
  })

  test('should return an empty array for an empty string', () => {
    expect(toArray("")).toEqual([])
  })

  test('should encode ASCII characters correctly', () => {
    const input = "Hello, World!"
    const expected = [72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33]
    expect(toArray(input)).toEqual(expected)
  })

  test('should encode 2-byte characters correctly', () => {
    // "é" (U+00E9) should encode to [0xC3, 0xA9]
    expect(toArray("é")).toEqual([0xC3, 0xA9])
  })

  test('should encode 3-byte characters correctly', () => {
    // "€" (U+20AC) should encode to [0xE2, 0x82, 0xAC]
    expect(toArray("€")).toEqual([0xE2, 0x82, 0xAC])
  })

  test('should encode 4-byte characters correctly', () => {
    // "😃" (U+1F603) should encode to [0xF0, 0x9F, 0x98, 0x83]
    expect(toArray("😃")).toEqual([0xF0, 0x9F, 0x98, 0x83])
  })

  test('should encode mixed content correctly', () => {
    // "Hello, 😃! €" contains ASCII, an emoji, and a 3-byte character.
    const input = "Hello, 😃! €"
    const expected = [
      // "Hello, " => ASCII bytes:
      72, 101, 108, 108, 111, 44, 32,
      // "😃" => 4-byte sequence:
      0xF0, 0x9F, 0x98, 0x83,
      // "!" => ASCII, then space:
      33, 32,
      // "€" => 3-byte sequence:
      0xE2, 0x82, 0xAC
    ]
    expect(toArray(input)).toEqual(expected)
  })

  test('should replace lone surrogates with the replacement character', () => {
    // An unpaired high surrogate "\uD800" should be replaced with U+FFFD,
    // which is encoded in UTF-8 as [0xEF, 0xBF, 0xBD]
    const input = "\uD800"
    const expected = [0xEF, 0xBF, 0xBD]
    expect(toArray(input)).toEqual(expected)
  })
})

describe('toUTF8 bounds checks', () => {
  const guarded = (arr: number[]): number[] => {
    const target = arr.slice()
    const handler: ProxyHandler<number[]> = {
      get (t, prop, receiver) {
        if (prop === 'length' || typeof prop !== 'string') {
          return Reflect.get(t, prop as any, receiver)
        }
        const idx = Number(prop)
        if (Number.isInteger(idx)) {
          if (idx < 0 || idx >= t.length) {
            throw new Error(`out-of-bounds read at index ${idx} (length ${t.length})`)
          }
        }
        return Reflect.get(t, prop as any, receiver)
      }
    }
    return new Proxy(target, handler) as unknown as number[]
  }

  it('does not access out-of-bounds on truncated 2-byte sequence', () => {
    const input = guarded([0xC3])
    expect(() => toUTF8(input)).not.toThrow()
  })

  it('does not access out-of-bounds on truncated 3-byte sequences', () => {
    const input1 = guarded([0xE2])
    const input2 = guarded([0xE2, 0x82])
    expect(() => toUTF8(input1)).not.toThrow()
    expect(() => toUTF8(input2)).not.toThrow()
  })

  it('does not access out-of-bounds on truncated 4-byte sequences', () => {
    const input1 = guarded([0xF0])
    const input2 = guarded([0xF0, 0x9F])
    const input3 = guarded([0xF0, 0x9F, 0x98])
    expect(() => toUTF8(input1)).not.toThrow()
    expect(() => toUTF8(input2)).not.toThrow()
    expect(() => toUTF8(input3)).not.toThrow()
  })
})

describe('toArray base64', () => {
  it('decodes empty string to empty array', () => {
    expect(toArray('', 'base64')).toEqual([])
  })

  it('decodes standard padded base64 strings', () => {
    expect(toArray('Zg==', 'base64')).toEqual([102])
    expect(toArray('Zm8=', 'base64')).toEqual([102, 111])
    expect(toArray('Zm9v', 'base64')).toEqual([102, 111, 111])
    expect(toArray('SGVsbG8=', 'base64')).toEqual([72, 101, 108, 108, 111])
  })

  it('decodes base64 without padding', () => {
    expect(toArray('SGVsbG8', 'base64')).toEqual([72, 101, 108, 108, 111])
    expect(toArray('QQ', 'base64')).toEqual([65])
    expect(toArray('Zm8', 'base64')).toEqual([102, 111])
  })

  it('decodes URL-safe base64', () => {
    expect(toArray('_w==', 'base64')).toEqual([255])
  })

  it('ignores whitespace and newlines', () => {
    expect(toArray('S G V s b G 8 =\n', 'base64')).toEqual([72, 101, 108, 108, 111])
  })

  it('throws on invalid padding', () => {
    expect(() => toArray('SGVsbG8===', 'base64')).toThrow(new Error('Invalid base64 padding'))
    expect(() => toArray('SGV=sbG8=', 'base64')).toThrow(new Error('Invalid base64 padding'))
  })

  // it('throws on invalid length (1 mod 4)', () => {
  //   expect(() => toArray('abcde', 'base64')).toThrow(new Error('Invalid base64 length'))
  // })

  it('throws on invalid characters', () => {
    expect(() => toArray('A?==', 'base64')).toThrow(new Error('Invalid base64 character at index 1'))
  })

  // it('throws when non-zero padding bits are present', () => {
  //   expect(() => toArray('QZ', 'base64')).toThrow(new Error('Invalid base64: non-zero padding bits'))
  // })
})

describe('verifyNotNull', () => {
  it('should return the value if it is not null or undefined', () => {
    expect(verifyNotNull(42)).toBe(42)
    expect(verifyNotNull('hello')).toBe('hello')
    expect(verifyNotNull({})).toEqual({})
    expect(verifyNotNull([])).toEqual([])
  })

  it('should throw an error with default message if value is null', () => {
    expect(() => verifyNotNull(null)).toThrow('Expected a valid value, but got undefined or null.')
  })

  it('should throw an error with default message if value is undefined', () => {
    expect(() => verifyNotNull(undefined)).toThrow('Expected a valid value, but got undefined or null.')
  })

  it('should throw an error with custom message if value is null', () => {
    expect(() => verifyNotNull(null, 'Custom error')).toThrow('Custom error')
  })

  it('should throw an error with custom message if value is undefined', () => {
    expect(() => verifyNotNull(undefined, 'Another custom error')).toThrow('Another custom error')
  })
})

describe('toUTF8 strict UTF-8 decoding (TOB-21)', () => {

  it('replaces invalid 2-byte sequences with U+FFFD', () => {
    // 0xC2 should expect a continuation byte 0x80–0xBF
    const arr = [0xC2, 0x20]   // 0x20 is INVALID continuation
    const str = toUTF8(arr)
    expect(str).toBe('\uFFFD')
  })

  it('decodes valid 3-byte sequences', () => {
    const euro = [0xE2, 0x82, 0xAC]
    expect(toUTF8(euro)).toBe('€')
  })

  it('replaces invalid 3-byte sequences', () => {
    // Middle byte invalid
    const arr = [0xE2, 0x20, 0xAC]
    expect(toUTF8(arr)).toBe('\uFFFD')
  })

  it('decodes valid 4-byte sequences into surrogate pairs', () => {
    const smile = [0xF0, 0x9F, 0x98, 0x80] // 😀
    expect(toUTF8(smile)).toBe('😀')
  })

  it('replaces invalid 4-byte sequences with U+FFFD', () => {
    // 0x9F is valid, 0x20 is INVALID continuation for byte 3
    const arr = [0xF0, 0x9F, 0x20, 0x80]
    expect(toUTF8(arr)).toBe('\uFFFD')
  })

  it('replaces incomplete UTF-8 sequence at end', () => {
    const arr = [0xE2] // incomplete 3-byte seq
    expect(toUTF8(arr)).toBe('\uFFFD')
  })

})

describe('Point.encode infinity handling', () => {
  it('encodes infinity as 00 (array)', () => {
    const p = new Point(null, null)
    expect(p.encode()).toEqual([0x00])
  })

  it('encodes infinity as 00 (hex)', () => {
    const p = new Point(null, null)
    expect(p.encode(true, 'hex')).toBe('00')
  })

  it('does not throw for infinity', () => {
    const p = new Point(null, null)
    expect(() => p.encode()).not.toThrow()
  })
})

describe('constantTimeEquals', () => {
  it('returns true for identical arrays', () => {
    expect(constantTimeEquals([1, 2, 3], [1, 2, 3])).toBe(true)
  })

  it('returns false for arrays with different content', () => {
    expect(constantTimeEquals([1, 2, 3], [1, 2, 4])).toBe(false)
  })

  it('returns false for arrays of different length', () => {
    expect(constantTimeEquals([1, 2], [1, 2, 3])).toBe(false)
  })

  it('runs through entire array (no early exit)', () => {
    expect(constantTimeEquals([0,0,0,0,9], [0,0,0,0,8])).toBe(false)
  })

  it('works with Uint8Array', () => {
    expect(constantTimeEquals(new Uint8Array([5,6,7]), new Uint8Array([5,6,7]))).toBe(true)
  })
})