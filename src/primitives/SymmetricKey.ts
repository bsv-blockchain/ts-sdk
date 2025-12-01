import BigNumber from './BigNumber.js'
import { AESGCM, AESGCMDecrypt } from './AESGCM.js'
import Random from './Random.js'
import { toArray, encode } from './utils.js'

/**
 * `SymmetricKey` is a class that extends the `BigNumber` class and implements symmetric encryption and decryption methods.
 * Symmetric-Key encryption is a form of encryption where the same key is used to encrypt and decrypt the message.
 * It leverages the Advanced Encryption Standard Galois/Counter Mode (AES-GCM) for encryption and decryption of messages.
 *
 * @class SymmetricKey
 * @extends {BigNumber}
 */
export default class SymmetricKey extends BigNumber {
  /**
   * Generates a symmetric key randomly.
   *
   * @method fromRandom
   * @static
   * @returns The newly generated Symmetric Key.
   *
   * @example
   * const symmetricKey = SymmetricKey.fromRandom();
   */
  static fromRandom (): SymmetricKey {
    return new SymmetricKey(Random(32))
  }

  /**
   * Encrypts a given message using AES-GCM encryption.
   * The generated Initialization Vector (IV) is attached to the encrypted message for decryption purposes.
   * The OpenSSL format of |IV|encryptedContent|authTag| is used.
   *
   * @method encrypt
   * @param msg - The message to be encrypted. It can be a string or an array of numbers.
   * @param enc - optional. The encoding of the message. If hex, the string is assumed to be hex, UTF-8 otherwise.
   * @returns Returns the encrypted message as a string or an array of numbers, depending on `enc` argument.
   *
   * @example
   * const key = new SymmetricKey(1234);
   * const encryptedMessage = key.encrypt('plainText', 'utf8');
   */
  encrypt (msg: number[] | string, enc?: 'hex'): string | number[] {
    const iv = Random(32)
    msg = toArray(msg, enc)
    const keyBytes = this.toArray('be', 32)
    const { result, authenticationTag } = AESGCM(msg, [], iv, keyBytes)
    const totalLength = iv.length + result.length + authenticationTag.length
    const combined = new Array(totalLength)
    let offset = 0
    for (const chunk of [iv, result, authenticationTag]) {
      for (let i = 0; i < chunk.length; i++) {
        combined[offset++] = chunk[i]
      }
    }
    return encode(combined, enc)
  }

  /**
   * Decrypts a given AES-GCM encrypted message using the same key that was used for encryption.
   * The method extracts the IV and the authentication tag from the encrypted message, then attempts to decrypt it.
   * If the decryption fails (e.g., due to message tampering), an error is thrown.
   *
   * @method decrypt
   * @param msg - The encrypted message to be decrypted. It can be a string or an array of numbers.
   * @param enc - optional. The encoding of the message (if no encoding is provided, uses utf8 for strings, unless specified as hex).
   * @returns Returns the decrypted message as a string or an array of numbers, depending on `enc` argument. If absent, an array of numbers is returned.
   *
   * @example
   * const key = new SymmetricKey(1234);
   * const decryptedMessage = key.decrypt(encryptedMessage, 'utf8');
   *
   * @throws {Error} Will throw an error if the decryption fails, likely due to message tampering or incorrect decryption key.
   */
  decrypt (msg: number[] | string, enc?: 'hex' | 'utf8'): string | number[] {
    msg = toArray(msg, enc)

    const ivLength = 32
    const tagLength = 16

    if (msg.length < ivLength + tagLength) {
      throw new Error('Ciphertext too short')
    }

    const iv = msg.slice(0, ivLength)
    const tagStart = msg.length - tagLength
    const ciphertext = msg.slice(ivLength, tagStart)
    const messageTag = msg.slice(tagStart)

    if (tagStart < ivLength) {
      throw new Error('Malformed ciphertext')
    }

    const result = AESGCMDecrypt(
      ciphertext,
      [],
      iv,
      messageTag,
      this.toArray('be', 32)
    )
    if (result === null) {
      throw new Error('Decryption failed!')
    }
    return encode(result, enc)
  }
}
