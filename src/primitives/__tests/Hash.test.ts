/* eslint-env jest */
import * as hash from '../../primitives/Hash'
import * as crypto from 'crypto'
import PBKDF2Vectors from './PBKDF2.vectors'
import { toArray, toHex } from '../../primitives/utils'

describe('Hash', function () {
  function test (Hash, cases): void {
    for (let i = 0; i < cases.length; i++) {
      const msg = cases[i][0]
      const res = cases[i][1]
      const enc = cases[i][2]

      let dgst = new Hash().update(msg, enc).digestHex()
      expect(dgst).toEqual(res)

      // Split message
      dgst = new Hash()
        .update(msg.slice(0, 2), enc)
        .update(msg.slice(2), enc)
        .digestHex()
      expect(dgst).toEqual(res)
    }
  }

  it('should support sha256', function () {
    test(hash.SHA256, [
      [
        'abc',
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
      ],
      [
        'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
        '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'
      ],
      [
        'deadbeef',
        '5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953',
        'hex'
      ]
    ])
  })

  it('should support ripemd160', function () {
    test(hash.RIPEMD160, [
      ['', '9c1185a5c5e9fc54612808977ee8f548b2258d31'],
      ['abc', '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'],
      ['message digest', '5d0689ef49d2fae572b881b123a85ffa21595f36'],
      [
        'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
        '12a053384a9c0c88e405a06c27dcf49ada62eb2b'
      ],
      [
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
        'b0e20b6e3116640286ed3a87a5713079b21f5189'
      ]
    ])
  })

  it('should support sha1', function () {
    test(hash.SHA1, [
      ['', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'],
      ['abc', 'a9993e364706816aba3e25717850c26c9cd0d89d'],
      [
        'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
        '84983e441c3bd26ebaae4aa1f95129e5e54670f1'
      ],
      ['deadbeef', 'd78f8bb992a56a597f6c7a1fb918bb78271367eb', 'hex']
    ])
  })

  it('should support sha512', function () {
    test(hash.SHA512, [
      [
        'abc',
        'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
          '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'
      ],
      [
        'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn' +
          'hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
        '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018' +
          '501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909'
      ]
    ])
  })

  it('handles utf8 in strings just like crypto', function () {
    test(
      hash.SHA256,
      [
        'hello', // one byte per character
        'привет', // two bytes per character
        '您好', // three bytes per character
        '👋', // four bytes per character
        'hello привет 您好 👋!!!' // mixed character lengths
      ].map((str) => [
        str,
        crypto.createHash('sha256').update(str).digest('hex')
      ])
    )
  })

  describe('PBKDF2 vectors', () => {
    for (let i = 0; i < PBKDF2Vectors.length; i++) {
      const v = PBKDF2Vectors[i]
      let key, salt
      if (v.keyUint8Array != null) {
        key = v.keyUint8Array
      }
      if (v.key != null && v.key !== '') {
        key = toArray(v.key, 'utf8')
      }
      if (v.keyHex != null && v.keyHex !== '') {
        key = toArray(v.keyHex, 'hex')
      }
      if (v.saltUint8Array != null) {
        salt = v.saltUint8Array
      }
      if (v.salt != null && v.salt !== '') {
        salt = toArray(v.salt, 'utf8')
      }
      if (v.saltHex != null && v.saltHex !== '') {
        salt = toArray(v.saltHex, 'hex')
      }
      it(`Passes PBKDF2 vector ${i}`, () => {
        const output = hash.pbkdf2(key, salt, v.iterations, v.dkLen)
        expect(toHex(output)).toEqual(v.results.sha512)
      })
    }
  })

  describe('HKDF (RFC 5869 Test Vectors)', () => {
    // Test Case 1: Basic test case with SHA-256
    it('Test Case 1: Basic test', () => {
      const ikm = toArray('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex')
      const salt = toArray('000102030405060708090a0b0c', 'hex')
      const info = toArray('f0f1f2f3f4f5f6f7f8f9', 'hex')
      const length = 42

      const okm = hash.hkdf(ikm, length, salt, info)
      
      expect(toHex(okm)).toEqual(
        '3cb25f25faacd57a90434f64d0362f2a' +
        '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' +
        '34007208d5b887185865'
      )
    })

    // Test Case 2: Test with longer inputs/outputs
    it('Test Case 2: Longer inputs/outputs', () => {
      const ikm = toArray(
        '000102030405060708090a0b0c0d0e0f' +
        '101112131415161718191a1b1c1d1e1f' +
        '202122232425262728292a2b2c2d2e2f' +
        '303132333435363738393a3b3c3d3e3f' +
        '404142434445464748494a4b4c4d4e4f',
        'hex'
      )
      const salt = toArray(
        '606162636465666768696a6b6c6d6e6f' +
        '707172737475767778797a7b7c7d7e7f' +
        '808182838485868788898a8b8c8d8e8f' +
        '909192939495969798999a9b9c9d9e9f' +
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
        'hex'
      )
      const info = toArray(
        'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' +
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
        'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf' +
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
        'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
        'hex'
      )
      const length = 82

      const okm = hash.hkdf(ikm, length, salt, info)
      
      expect(toHex(okm)).toEqual(
        'b11e398dc80327a1c8e7f78c596a4934' +
        '4f012eda2d4efad8a050cc4c19afa97c' +
        '59045a99cac7827271cb41c65e590e09' +
        'da3275600c2f09b8367793a9aca3db71' +
        'cc30c58179ec3e87c14c01d5c1f3434f' +
        '1d87'
      )
    })

    // Test Case 3: Test with empty salt and info
    it('Test Case 3: Empty salt and info', () => {
      const ikm = toArray('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex')
      const salt = undefined
      const info = undefined
      const length = 42

      const okm = hash.hkdf(ikm, length, salt, info)
      
      expect(toHex(okm)).toEqual(
        '8da4e775a563c18f715f802a063c5a31' +
        'b8a11f5c5ee1879ec3454e5f3c738d2d' +
        '9d201395faa4b61a96c8'
      )
    })

    // Test Case 4: Verify KDF can produce 32-byte keys
    it('Test Case 4: 32-byte output', () => {
      const ikm = toArray('0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c', 'hex')
      const length = 32

      const okm = hash.hkdf(ikm, length)
      
      expect(okm.length).toEqual(32)
    })

    // Test Case 5: Error handling - length too large
    it('Test Case 5: Should throw error for length too large', () => {
      const ikm = toArray('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex')
      const length = 255 * 32 + 1 // Exceeds maximum

      expect(() => hash.hkdf(ikm, length)).toThrow(
        /Requested length.*is too large/
      )
    })
  })
})
