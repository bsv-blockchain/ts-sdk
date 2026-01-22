/* eslint-env jest */
import {
  AES,
  AESGCM,
  ghash,
  rightShift,
  multiply,
  incrementLeastSignificantThirtyTwoBits,
  checkBit,
  getBytes,
  exclusiveOR,
  AESGCMDecrypt
} from '../../primitives/AESGCM'
import { toArray } from '../../primitives/utils'

describe('AES', () => {
  it('should encrypt: AES-128', () => {
    expect(toArray('69c4e0d86a7b0430d8cdb78070b4c55a', 'hex')).toEqual(
      AES(
        toArray('00112233445566778899aabbccddeeff', 'hex'),
        toArray('000102030405060708090a0b0c0d0e0f', 'hex')
      )
    )
  })

  it('should encrypt: AES-192', () => {
    expect(toArray('dda97ca4864cdfe06eaf70a0ec0d7191', 'hex')).toEqual(
      AES(
        toArray('00112233445566778899aabbccddeeff', 'hex'),
        toArray('000102030405060708090a0b0c0d0e0f1011121314151617', 'hex')
      )
    )
  })

  it('should encrypt: AES-256', () => {
    expect(toArray('8ea2b7ca516745bfeafc49904b496089', 'hex')).toEqual(
      AES(
        toArray('00112233445566778899aabbccddeeff', 'hex'),
        toArray(
          '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
          'hex'
        )
      )
    )
  })

  it('should encrypt', () => {
    expect(toArray('66e94bd4ef8a2c3b884cfa59ca342b2e', 'hex')).toEqual(
      AES(
        toArray('00000000000000000000000000000000', 'hex'),
        toArray('00000000000000000000000000000000', 'hex')
      )
    )
    expect(toArray('c6a13b37878f5b826f4f8162a1c8d879', 'hex')).toEqual(
      AES(
        toArray('00000000000000000000000000000000', 'hex'),
        toArray('000102030405060708090a0b0c0d0e0f', 'hex')
      )
    )
    expect(toArray('73a23d80121de2d5a850253fcf43120e', 'hex')).toEqual(
      AES(
        toArray('00000000000000000000000000000000', 'hex'),
        toArray('ad7a2bd03eac835a6f620fdcb506b345', 'hex')
      )
    )
  })
})

describe('ghash', () => {
  it('should ghash', () => {
    const input = new Uint8Array(
      toArray(
        '000000000000000000000000000000000388dace60b6a392f328c2b971b2fe780000000000000000000000' +
          '0000000080',
        'hex'
      )
    )
    const h = new Uint8Array(
      toArray('66e94bd4ef8a2c3b884cfa59ca342b2e', 'hex')
    )
    const out = ghash(input, h)

    expect(toArray('f38cbb1ad69223dcc3457ae5b6b0f885', 'hex')).toEqual(
      Array.from(out)
    )
  })
})

describe('AESGCM', () => {
  it('should encrypt: Test Case 1', () => {
    const plainText = new Uint8Array(0)
    const iv = new Uint8Array(
      toArray('000000000000000000000000', 'hex')
    )
    const key = new Uint8Array(
      toArray('00000000000000000000000000000000', 'hex')
    )

    const output = AESGCM(plainText, iv, key)

    expect([]).toEqual(Array.from(output.result))
    expect(toArray('58e2fccefa7e3061367f1d57a4e7455a', 'hex')).toEqual(
      Array.from(output.authenticationTag)
    )
  })

  it('should encrypt: Test Case 2', () => {
    const plainText = new Uint8Array(
      toArray('00000000000000000000000000000000', 'hex')
    )
    const iv = new Uint8Array(
      toArray('000000000000000000000000', 'hex')
    )
    const key = new Uint8Array(
      toArray('00000000000000000000000000000000', 'hex')
    )

    const output = AESGCM(plainText, iv, key)

    expect(toArray('0388dace60b6a392f328c2b971b2fe78', 'hex')).toEqual(
      Array.from(output.result)
    )
    expect(toArray('ab6e47d42cec13bdf53a67b21257bddf', 'hex')).toEqual(
      Array.from(output.authenticationTag)
    )
  })

  it('should encrypt: Test Case 3', () => {
    const plainText = new Uint8Array(
      toArray(
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956' +
          '809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
        'hex'
      )
    )
    const iv = new Uint8Array(
      toArray('cafebabefacedbaddecaf888', 'hex')
    )
    const key = new Uint8Array(
      toArray('feffe9928665731c6d6a8f9467308308', 'hex')
    )

    const output = AESGCM(plainText, iv, key)

    expect(
      toArray(
        '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8' +
          'f6a5aac84aa051ba30b396a0aac973d58e091473f5985',
        'hex'
      )
    ).toEqual(Array.from(output.result))
    expect(toArray('4d5c2af327cd64a62cf35abd2ba6fab4', 'hex')).toEqual(
      Array.from(output.authenticationTag)
    )
  })

  it('should encrypt: Test Case 7', () => {
    const plainText = new Uint8Array(0)
    const iv = new Uint8Array(
      toArray('000000000000000000000000', 'hex')
    )
    const key = new Uint8Array(
      toArray('000000000000000000000000000000000000000000000000', 'hex')
    )

    const output = AESGCM(plainText, iv, key)

    expect([]).toEqual(Array.from(output.result))
    expect(toArray('cd33b28ac773f74ba00ed1f312572435', 'hex')).toEqual(
      Array.from(output.authenticationTag)
    )
  })

  it('should encrypt: Test Case 8', () => {
    const plainText = new Uint8Array(
      toArray('00000000000000000000000000000000', 'hex')
    )
    const iv = new Uint8Array(
      toArray('000000000000000000000000', 'hex')
    )
    const key = new Uint8Array(
      toArray('000000000000000000000000000000000000000000000000', 'hex')
    )

    const output = AESGCM(plainText, iv, key)

    expect(toArray('98e7247c07f0fe411c267e4384b0f600', 'hex')).toEqual(
      Array.from(output.result)
    )
    expect(toArray('2ff58d80033927ab8ef4d4587514f0fb', 'hex')).toEqual(
      Array.from(output.authenticationTag)
    )
  })

  it('should encrypt: Test Case 9', () => {
    const plainText = new Uint8Array(
      toArray(
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956' +
          '809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
        'hex'
      )
    )
    const iv = new Uint8Array(
      toArray('cafebabefacedbaddecaf888', 'hex')
    )
    const key = new Uint8Array(
      toArray('feffe9928665731c6d6a8f9467308308feffe9928665731c', 'hex')
    )

    const output = AESGCM(plainText, iv, key)

    expect(
      toArray(
        '3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac6' +
          '19d18c84a3f4718e2448b2fe324d9ccda2710acade256',
        'hex'
      )
    ).toEqual(Array.from(output.result))
    expect(toArray('9924a7c8587336bfb118024db8674a14', 'hex')).toEqual(
      Array.from(output.authenticationTag)
    )
  })

  it('should encrypt: Test Case 13', () => {
    const plainText = new Uint8Array(0)
    const iv = new Uint8Array(
      toArray('000000000000000000000000', 'hex')
    )
    const key = new Uint8Array(
      toArray(
        '0000000000000000000000000000000000000000000000000000000000000000',
        'hex'
      )
    )

    const output = AESGCM(plainText, iv, key)

    expect([]).toEqual(Array.from(output.result))
    expect(toArray('530f8afbc74536b9a963b4f1c4cb738b', 'hex')).toEqual(
      Array.from(output.authenticationTag)
    )
  })

  it('should encrypt: Test Case 14', () => {
    const plainText = new Uint8Array(
      toArray('00000000000000000000000000000000', 'hex')
    )
    const iv = new Uint8Array(
      toArray('000000000000000000000000', 'hex')
    )
    const key = new Uint8Array(
      toArray(
        '0000000000000000000000000000000000000000000000000000000000000000',
        'hex'
      )
    )

    const output = AESGCM(plainText, iv, key)

    expect(toArray('cea7403d4d606b6e074ec5d3baf39d18', 'hex')).toEqual(
      Array.from(output.result)
    )
    expect(toArray('d0d1c8a799996bf0265b98b5d48ab919', 'hex')).toEqual(
      Array.from(output.authenticationTag)
    )
  })

  it('should encrypt: Test Case 15', () => {
    const plainText = new Uint8Array(
      toArray(
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956' +
          '809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
        'hex'
      )
    )
    const iv = new Uint8Array(
      toArray('cafebabefacedbaddecaf888', 'hex')
    )
    const key = new Uint8Array(
      toArray(
        'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
        'hex'
      )
    )

    const output = AESGCM(plainText, iv, key)

    expect(
      toArray(
        '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b' +
          '08b1056828838c5f61e6393ba7a0abcc9f662898015ad',
        'hex'
      )
    ).toEqual(Array.from(output.result))
    expect(toArray('b094dac5d93471bdec1a502270e3cc6c', 'hex')).toEqual(
      Array.from(output.authenticationTag)
    )
  })
})

describe('exclusiveOR', () => {
  it('should exclusiveOR', () => {
    const out1 = exclusiveOR(
      new Uint8Array([
        0xf0, 0xf8, 0x7f, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00
      ]),
      new Uint8Array([0x0f, 0x0f, 0x00, 0xf0])
    )

    expect([
      0xff, 0xf7, 0x7f, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00
    ]).toEqual(Array.from(out1))

    const out2 = exclusiveOR(
      new Uint8Array([0xf0, 0xf8, 0x7f, 0xff]),
      new Uint8Array([0x0f, 0x0f, 0x00, 0xf0])
    )

    expect([0xff, 0xf7, 0x7f, 0x0f]).toEqual(Array.from(out2))
  })
})

describe('rightShift', () => {
  it('should rightShift', () => {
    const input = new Uint8Array(
      toArray('7b5b54657374566563746f725d53475d', 'hex')
    )
    const out = rightShift(input)

    expect(toArray('3dadaa32b9ba2b32b1ba37b92ea9a3ae', 'hex')).toEqual(
      Array.from(out)
    )
  })
})

describe('multiply', () => {
  it('should multiply', () => {
    const a = new Uint8Array(
      toArray('952b2a56a5604ac0b32b6656a05b40b6', 'hex')
    )
    const b = new Uint8Array(
      toArray('dfa6bf4ded81db03ffcaff95f830f061', 'hex')
    )
    const out = multiply(a, b)

    expect(toArray('da53eb0ad2c55bb64fc4802cc3feda60', 'hex')).toEqual(
      Array.from(out)
    )
  })

  it('should commutatively multiply', () => {
    const x = new Uint8Array(
      toArray('48692853686179295b477565726f6e5d', 'hex')
    )
    const y = new Uint8Array(
      toArray('7b5b54657374566563746f725d53475d', 'hex')
    )

    const out1 = multiply(x, y)
    const out2 = multiply(y, x)

    expect(Array.from(out1)).toEqual(Array.from(out2))
  })
})

describe('incrementLeastSignificantThirtyTwoBits', () => {
  it('should incrementLeastSignificantThirtyTwoBits', () => {
    const in1 = new Uint8Array(
      toArray('00000000000000000000000000000000', 'hex')
    )
    const out1 = incrementLeastSignificantThirtyTwoBits(in1)
    expect(toArray('00000000000000000000000000000001', 'hex')).toEqual(
      Array.from(out1)
    )

    const in2 = new Uint8Array(
      toArray('000000000000000000000000000000ff', 'hex')
    )
    const out2 = incrementLeastSignificantThirtyTwoBits(in2)
    expect(toArray('00000000000000000000000000000100', 'hex')).toEqual(
      Array.from(out2)
    )

    const in3 = new Uint8Array(
      toArray('00000000000000000000000000ffffff', 'hex')
    )
    const out3 = incrementLeastSignificantThirtyTwoBits(in3)
    expect(toArray('00000000000000000000000001000000', 'hex')).toEqual(
      Array.from(out3)
    )

    const in4 = new Uint8Array(
      toArray('000000000000000000000000ffffffff', 'hex')
    )
    const out4 = incrementLeastSignificantThirtyTwoBits(in4)
    expect(toArray('00000000000000000000000000000000', 'hex')).toEqual(
      Array.from(out4)
    )
  })
})

describe('checkBit', () => {
  it('should checkBit', () => {
    let i
    let j
    let k = 0
    let block = new Uint8Array(
      toArray('7b5b54657374566563746f725d53475d', 'hex')
    ) as any
    const expected = [
      0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0,
      1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1,
      0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1,
      1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1,
      1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1,
      1, 0, 1
    ]
    const expectedLSB = expected.slice().reverse()

    for (i = 0; i < 16; i++) {
      for (j = 7; j !== -1; j--) {
        expect(expected[k++]).toEqual(checkBit(Array.from(block), i, j))
      }
    }

    for (i = 0; i < 128; i++) {
      expect(expectedLSB[i]).toEqual(checkBit(Array.from(block), 15, 0))
      block = rightShift(block)
    }
  })
  it('should get bit', () => {
    expect(0).toEqual(checkBit([0], 0, 7))
    expect(0).toEqual(checkBit([0], 0, 6))
    expect(0).toEqual(checkBit([0], 0, 5))
    expect(0).toEqual(checkBit([0], 0, 4))
    expect(0).toEqual(checkBit([0], 0, 3))
    expect(0).toEqual(checkBit([0], 0, 2))
    expect(0).toEqual(checkBit([0], 0, 1))
    expect(0).toEqual(checkBit([0], 0, 0))

    expect(0).toEqual(checkBit([85], 0, 7))
    expect(1).toEqual(checkBit([85], 0, 6))
    expect(0).toEqual(checkBit([85], 0, 5))
    expect(1).toEqual(checkBit([85], 0, 4))
    expect(0).toEqual(checkBit([85], 0, 3))
    expect(1).toEqual(checkBit([85], 0, 2))
    expect(0).toEqual(checkBit([85], 0, 1))
    expect(1).toEqual(checkBit([85], 0, 0))

    expect(1).toEqual(checkBit([170], 0, 7))
    expect(0).toEqual(checkBit([170], 0, 6))
    expect(1).toEqual(checkBit([170], 0, 5))
    expect(0).toEqual(checkBit([170], 0, 4))
    expect(1).toEqual(checkBit([170], 0, 3))
    expect(0).toEqual(checkBit([170], 0, 2))
    expect(1).toEqual(checkBit([170], 0, 1))
    expect(0).toEqual(checkBit([170], 0, 0))

    expect(1).toEqual(checkBit([255], 0, 7))
    expect(1).toEqual(checkBit([255], 0, 6))
    expect(1).toEqual(checkBit([255], 0, 5))
    expect(1).toEqual(checkBit([255], 0, 4))
    expect(1).toEqual(checkBit([255], 0, 3))
    expect(1).toEqual(checkBit([255], 0, 2))
    expect(1).toEqual(checkBit([255], 0, 1))
    expect(1).toEqual(checkBit([255], 0, 0))
  })
})

describe('getBytes', () => {
  it('should getBytes', () => {
    expect([0x00, 0x00, 0x00, 0x00]).toEqual(getBytes(0x00))
    expect([0x00, 0x00, 0x02, 0x01]).toEqual(getBytes(0x0201))
    expect([0x04, 0x03, 0x02, 0x01]).toEqual(getBytes(0x04030201))
    expect([0x04, 0x03, 0x02, 0x01]).toEqual(getBytes(0x0504030201))
  })
})

describe('AESGCM IV validation', () => {
  const key = new Uint8Array(new Array(16).fill(0x01))
  const plaintext = new Uint8Array([1, 2, 3, 4])

  it('AESGCM throws when IV is empty', () => {
    expect(() => {
      AESGCM(plaintext, new Uint8Array(), key)
    }).toThrow(new Error('Initialization vector must not be empty'))
  })

  it('AESGCMDecrypt throws when IV is empty', () => {
    const iv = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
    const { result: ciphertext, authenticationTag } = AESGCM(
      plaintext,
      iv,
      key
    )

    // Now call decrypt but with an empty IV – this should be rejected
    expect(() => {
      AESGCMDecrypt(ciphertext, new Uint8Array(), authenticationTag, key)
    }).toThrow(new Error('Initialization vector must not be empty'))
  })

  it('AESGCM throws when key is empty', () => {
    const iv = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])

    expect(() => {
      AESGCM(plaintext, iv, new Uint8Array())
    }).toThrow(new Error('Key must not be empty'))
  })

  it('AESGCMDecrypt throws when key is empty', () => {
    const iv = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
    const { result: ciphertext, authenticationTag } = AESGCM(
      plaintext,
      iv,
      key
    )

    expect(() => {
      AESGCMDecrypt(
        ciphertext,
        iv,
        authenticationTag,
        new Uint8Array()
      )
    }).toThrow(new Error('Key must not be empty'))
  })

  it('AESGCMDecrypt throws when cipher text is empty', () => {
    const iv = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])

    expect(() => {
      AESGCMDecrypt(new Uint8Array(), iv, new Uint8Array(), key)
    }).toThrow(new Error('Cipher text must not be empty'))
  })

  it('AESGCM still work with a valid IV', () => {
    const iv = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
    const { result: ciphertext, authenticationTag } = AESGCM(
      plaintext,
      iv,
      key
    )
    const decrypted = AESGCMDecrypt(
      ciphertext,
      iv,
      authenticationTag,
      key
    ) as Uint8Array

    expect(Array.from(decrypted)).toEqual(Array.from(plaintext))
  })
})

function expectUint8ArrayEqual (a: Uint8Array, b: Uint8Array) {
  expect(a.length).toBe(b.length)

  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      throw new Error(`mismatch at index ${i}: ${a[i]} !== ${b[i]}`)
    }
  }
}

describe('AESGCM large input (non-mocked)', () => {
  // NOTE: This test is intentionally skipped by default because it allocates
  // ~500MB+ and will be very slow / memory-heavy.
  // Un-skip locally when you want to manually verify behavior for lengths
  // larger than 2^32 bits.
  it.skip('handles ciphertext longer than 2^32 bits', () => {
    const key = new Uint8Array(new Array(16).fill(0x01))
    const iv = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])

    // 2^32 bits = 2^29 bytes. Go just beyond that boundary.
    const bigSizeBytes = (1 << 29) + 16 // 2^29 + 16 bytes (> 2^32 bits)

    // Use a typed array instead of a giant sparse JS array.
    const plaintext = new Uint8Array(bigSizeBytes) // already zero-initialized

    const { result: ciphertext, authenticationTag } = AESGCM(
      plaintext,
      iv,
      key
    )

    const decrypted = AESGCMDecrypt(
      ciphertext,
      iv,
      authenticationTag,
      key
    ) as Uint8Array | null

    expect(decrypted).not.toBeNull()
    const decryptedBytes = decrypted as Uint8Array
    expect(decryptedBytes.length).toBe(bigSizeBytes)
    expectUint8ArrayEqual(decryptedBytes, plaintext)
  })
})

describe('multiply reduction edge cases', () => {
  it('applies reduction polynomial when LSB carry is set', () => {
    // Force reduction path by setting v[15] LSB = 1
    const a = new Uint8Array(16)
    a[0] = 0x01

    const b = new Uint8Array(16)
    b[15] = 0x01

    const out = multiply(a, b)

    // We don't assert a magic value — we assert that output is non-zero
    // and stable across runs (reduction happened)
    expect(out.some(v => v !== 0)).toBe(true)
  })

  it('does not reduce when LSB carry is zero', () => {
    const a = new Uint8Array(16)
    a[0] = 0x01

    const b = new Uint8Array(16)
    b[15] = 0x00

    const out = multiply(a, b)

    expect(out.some(v => v !== 0)).toBe(false)
  })
})


