import SymmetricKey from '../SymmetricKey'
import PrivateKey from '../PrivateKey'

describe('Cross-SDK Compatibility Tests', () => {
  describe('31-byte key cross-decryption', () => {
    it('can decrypt Go SDK ciphertext with TypeScript SDK', () => {
      // Use the same 31-byte key as Go SDK
      const privKey = PrivateKey.fromWif('L4B2postXdaP7TiUrUBYs53Fqzheu7WhSoQVPuY8qBdoBeEwbmZx')
      const pubKey = privKey.toPublicKey()

      expect(pubKey.x).toBeTruthy()
      const keyBytes = pubKey.x!.toArray()

      // Verify this is a 31-byte key
      expect(keyBytes.length).toBe(31)

      const symKey = new SymmetricKey(keyBytes)
      const expectedPlaintext = 'cross-sdk test message'

      // Test cases: Go-generated ciphertext that TypeScript should be able to decrypt
      const testCases = [
        {
          name: 'Go 31-byte ciphertext 1',
          ciphertextHex: '7604d5bdb0eb843051d21873c871c9b1507c3de7ba222e1b407c163c2c166277df95de73be9534a2caf9d4b72157f78e5e2e69d97bc25b18ff4cfbd61a1306c02c0b8b2d165e'
        },
        {
          name: 'Go 31-byte ciphertext 2',
          ciphertextHex: 'ab74fa03d7b2d308f007e21fbae056cfde6e3e5fbea7032880e0482b0b5fbe8583d5221b985a8cdfdff1f70c2bb28c9a3149a34dde3b56f54ecd4728d2dd70c1212642b18bc4'
        },
        {
          name: 'Go 31-byte ciphertext 3',
          ciphertextHex: '6c64ae72a1371084347983568d25515ca75599f747236be6971267fa4b48e518855ce4f8380cc479bb75835641f2173b7932b93be5cd40f54cd84aaff053dbc94c3748e427af'
        }
      ]

      testCases.forEach(({ name, ciphertextHex }) => {
        // Convert hex to byte array
        const ciphertext: number[] = []
        for (let i = 0; i < ciphertextHex.length; i += 2) {
          ciphertext.push(parseInt(ciphertextHex.slice(i, i + 2), 16))
        }

        // Decrypt using TypeScript SDK
        const decrypted = symKey.decrypt(ciphertext, 'utf8')

        expect(decrypted).toBe(expectedPlaintext)
      })
    })
  })

  describe('32-byte key cross-decryption', () => {
    it('can decrypt Go SDK ciphertext with TypeScript SDK', () => {
      // Use the same 32-byte key as Go SDK
      const privKey = PrivateKey.fromWif('KyLGEhYicSoGchHKmVC2fUx2MRrHzWqvwBFLLT4DZB93Nv5DxVR9')
      const pubKey = privKey.toPublicKey()

      expect(pubKey.x).toBeTruthy()
      const keyBytes = pubKey.x!.toArray()

      // Verify this is a 32-byte key
      expect(keyBytes.length).toBe(32)

      const symKey = new SymmetricKey(keyBytes)
      const expectedPlaintext = 'cross-sdk test message'

      // Test cases: Go-generated ciphertext that TypeScript should be able to decrypt
      const testCases = [
        {
          name: 'Go 32-byte ciphertext 1',
          ciphertextHex: 'd7744c85ad3dafcb9fc5752ab0d04c40f87084e8a466f6b6013ebe0fc5170daab8184aaef66ab2c2733f01c0dc3de322ba3ddeea976499548bc6ec166581181f919c69aa2de5'
        },
        {
          name: 'Go 32-byte ciphertext 2',
          ciphertextHex: 'bed1fc660bb7219d05a0115bc3c8dfb063fceb07c6571e0a21af1a052988dfd8911f625ae747ae6dad4cadb872dbd1d1bdc4b78bf7817e90bc5df718d77b247805eb06773d13'
        },
        {
          name: 'Go 32-byte ciphertext 3',
          ciphertextHex: '7411f0e9ff2b6ebbb804614fcf11db548a92baeea9cd769e8ee11bd7853a2d055799df476655b7d30f11be17f9513a16b72b6c73f85edd4b6e7548fae68fb47252ff72ace4cf'
        }
      ]

      testCases.forEach(({ name, ciphertextHex }) => {
        // Convert hex to byte array
        const ciphertext: number[] = []
        for (let i = 0; i < ciphertextHex.length; i += 2) {
          ciphertext.push(parseInt(ciphertextHex.slice(i, i + 2), 16))
        }

        // Decrypt using TypeScript SDK
        const decrypted = symKey.decrypt(ciphertext, 'utf8')
        expect(decrypted).toBe(expectedPlaintext)
      })
    })
  })

  describe('Bidirectional cross-decryption', () => {
    it('verifies both SDKs can decrypt each others ciphertext', () => {
      const testCases = [
        {
          name: '31-byte key bidirectional',
          wif: 'L4B2postXdaP7TiUrUBYs53Fqzheu7WhSoQVPuY8qBdoBeEwbmZx',
          expectedKeyLength: 31,
          goCiphertext: '7604d5bdb0eb843051d21873c871c9b1507c3de7ba222e1b407c163c2c166277df95de73be9534a2caf9d4b72157f78e5e2e69d97bc25b18ff4cfbd61a1306c02c0b8b2d165e',
          tsCiphertext: 'c374d70a4623036f1dd7b971dbeeea375630dc1da40e7068f4c4aa03487d3b19de3afb26a29173deccfbb1ece4fee6c92406b25948e6fe9cb53383057cb826d0a20269e290bd'
        },
        {
          name: '32-byte key bidirectional',
          wif: 'KyLGEhYicSoGchHKmVC2fUx2MRrHzWqvwBFLLT4DZB93Nv5DxVR9',
          expectedKeyLength: 32,
          goCiphertext: 'd7744c85ad3dafcb9fc5752ab0d04c40f87084e8a466f6b6013ebe0fc5170daab8184aaef66ab2c2733f01c0dc3de322ba3ddeea976499548bc6ec166581181f919c69aa2de5',
          tsCiphertext: '2059fc32910bef280d89c4c7edbbc587b31be22339e609fdcc23319bf458840a91ad1b2da87aea13a5dc5cb3469b41c52001070b8003863843978acbdf57755b24491581a059'
        }
      ]

      testCases.forEach(({ name, wif, expectedKeyLength, goCiphertext, tsCiphertext }) => {
        // Create symmetric key
        const privKey = PrivateKey.fromWif(wif)
        const pubKey = privKey.toPublicKey()

        expect(pubKey.x).toBeTruthy()
        const keyBytes = pubKey.x!.toArray()
        expect(keyBytes.length).toBe(expectedKeyLength)

        const symKey = new SymmetricKey(keyBytes)
        const expectedPlaintext = 'cross-sdk test message'

        // Test TypeScript decrypting Go ciphertext
        const goCiphertextBytes: number[] = []
        for (let i = 0; i < goCiphertext.length; i += 2) {
          goCiphertextBytes.push(parseInt(goCiphertext.substr(i, 2), 16))
        }

        const goDecrypted = symKey.decrypt(goCiphertextBytes, 'utf8')
        expect(goDecrypted).toBe(expectedPlaintext)

        // Test TypeScript decrypting TypeScript ciphertext (sanity check)
        const tsCiphertextBytes: number[] = []
        for (let i = 0; i < tsCiphertext.length; i += 2) {
          tsCiphertextBytes.push(parseInt(tsCiphertext.substr(i, 2), 16))
        }

        const tsDecrypted = symKey.decrypt(tsCiphertextBytes, 'utf8')
        expect(tsDecrypted).toBe(expectedPlaintext)

        expect(goDecrypted).toBe(expectedPlaintext)
        expect(tsDecrypted).toBe(expectedPlaintext)
      })
    })
  })
})
