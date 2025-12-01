import SymmetricKey from '../../primitives/SymmetricKey'
import PrivateKey from '../../primitives/PrivateKey'
import vectors from './SymmetricKey.vectors'

const KEYS: SymmetricKey[] = [
  new SymmetricKey(
    '5a90d59d829197983a54d887fdea2dc4c38098f00ba3110f2645633b6ea11458',
    16
  ),
  new SymmetricKey(
    'bac6ac492f54d7c997fadc1be593a4ace26ecdf37d30b3ad12f34077fb2629e4',
    16
  ),
  new SymmetricKey(
    '53dcdc6ea6a6910af35a48708f49228e0e6661ea885435080cbabc58e6a14f10',
    16
  )
]

const PLAINTEXT_1 = 'hello there'
const CIPHERTEXT_1 =
  '8c8d25348dfd5240be833215a123173c64919779ab8845a700a4520311504c168ade2d4b728cc53a254f0aba857caaf6af97453ac2ff61487d0d52'

describe('SymmetricKey', () => {
  it('Produces output that can be decrypted', () => {
    const originalValue = 'a thing to encrypt'
    const encryptedValue = KEYS[2].encrypt(originalValue)
    const decryptedValue = KEYS[2].decrypt(encryptedValue, 'utf8')
    expect(originalValue).toEqual(decryptedValue)
  })
  it('Encrypts values as an array', () => {
    const originalValue = [42, 99, 33, 0, 1]
    const encryptedValue = KEYS[2].encrypt(originalValue)
    const decryptedValue = KEYS[2].decrypt(encryptedValue)
    expect(originalValue).toEqual(decryptedValue)
  })
  it('Decrypts a correctly-encrypted value', () => {
    const result = KEYS[0].decrypt(CIPHERTEXT_1, 'hex') as string
    expect(Buffer.from(result, 'hex').toString('utf8')).toEqual(PLAINTEXT_1)
  })
  it('Throws a useful error when decryption fails', () => {
    expect(() => {
      KEYS[2].decrypt(CIPHERTEXT_1, 'hex')
    }).toThrow(new Error('Decryption failed!'))
  })
  it('decrypts values encrypted with the encrypt function', () => {
    const originalValue = 'secret value'
    const encryptedValue = KEYS[1].encrypt(originalValue)
    const decryptedValue = KEYS[1].decrypt(encryptedValue, 'utf8')
    expect(originalValue).toEqual(decryptedValue)
  })
  vectors.forEach((vector, index) => {
    it(`Should pass test vector #${index + 1}`, () => {
      const key = new SymmetricKey([...Buffer.from(vector.key, 'base64')])
      const result = key.decrypt(
        [...Buffer.from(vector.ciphertext, 'base64')],
        'hex'
      )
      expect(result).toEqual(Buffer.from(vector.plaintext).toString('hex'))
    })
  })

  describe('31-byte and 32-byte key encryption', () => {
    it('encrypts and decrypts with 31-byte key', () => {
      // Use a private key that generates a 31-byte X coordinate
      const privKey = PrivateKey.fromWif('L4B2postXdaP7TiUrUBYs53Fqzheu7WhSoQVPuY8qBdoBeEwbmZx')
      const pubKey = privKey.toPublicKey()

      expect(pubKey.x).toBeTruthy()
      const keyArray = pubKey.x!.toArray()

      // Verify this is indeed a 31-byte key
      expect(keyArray.length).toBe(31)

      const symKey = new SymmetricKey(keyArray)
      const plaintext = 'test message'

      // Test encryption and decryption
      const ciphertext = symKey.encrypt(plaintext)
      const decrypted = symKey.decrypt(ciphertext, 'utf8')

      expect(decrypted).toBe(plaintext)
    })

    it('encrypts and decrypts with 32-byte key', () => {
      // Use a private key that generates a 32-byte X coordinate
      const privKey = PrivateKey.fromWif('KyLGEhYicSoGchHKmVC2fUx2MRrHzWqvwBFLLT4DZB93Nv5DxVR9')
      const pubKey = privKey.toPublicKey()

      expect(pubKey.x).toBeTruthy()
      const keyArray = pubKey.x!.toArray()

      // Verify this is indeed a 32-byte key
      expect(keyArray.length).toBe(32)

      const symKey = new SymmetricKey(keyArray)
      const plaintext = 'test message'

      // Test encryption and decryption
      const ciphertext = symKey.encrypt(plaintext)
      const decrypted = symKey.decrypt(ciphertext, 'utf8')

      expect(decrypted).toBe(plaintext)
    })
    
    it('throws "Ciphertext too short" for inputs shorter than IV + tag', () => {
      const shortCipherArray = new Array(47).fill(0)
      expect(() => {
        KEYS[0].decrypt(shortCipherArray)
      }).toThrow(new Error('Ciphertext too short'))
    })

    it('throws "Ciphertext too short" for hex-encoded inputs shorter than IV + tag', () => {
      const shortBuffer = Buffer.alloc(47, 0)
      const shortHex = shortBuffer.toString('hex')

      expect(() => {
        KEYS[0].decrypt(shortHex, 'hex')
      }).toThrow(new Error('Ciphertext too short'))
    })

    it('still throws "Decryption failed!" for structurally valid but wrong ciphertext', () => {
      expect(() => {
        KEYS[2].decrypt(CIPHERTEXT_1, 'hex')
      }).toThrow(new Error('Decryption failed!'))
    })
  })
})
