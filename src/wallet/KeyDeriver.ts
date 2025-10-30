import {
  PrivateKey,
  PublicKey,
  SymmetricKey,
  Hash,
  Utils,
  Point
} from '../primitives/index.js'
import { WalletProtocol, PubKeyHex } from './Wallet.interfaces.js'

export type Counterparty = PublicKey | PubKeyHex | 'self' | 'anyone'

export interface KeyDeriverApi {
  /**
   * The root key from which all other keys are derived.
   */
  rootKey: PrivateKey

  /**
   * The identity of this key deriver which is normally the public key associated with the `rootKey`
   */
  identityKey: string

  /**
   * Derives a public key based on protocol ID, key ID, and counterparty.
   * @param {WalletProtocol} protocolID - The protocol ID including a security level and protocol name.
   * @param {string} keyID - The key identifier.
   * @param {Counterparty} counterparty - The counterparty's public key or a predefined value ('self' or 'anyone').
   * @param {boolean} [forSelf=false] - Optional. false if undefined. Whether deriving for self.
   * @returns {PublicKey} - The derived public key.
   */
  derivePublicKey: (
    protocolID: WalletProtocol,
    keyID: string,
    counterparty: Counterparty,
    forSelf?: boolean
  ) => PublicKey

  /**
   * Derives a private key based on protocol ID, key ID, and counterparty.
   * @param {WalletProtocol} protocolID - The protocol ID including a security level and protocol name.
   * @param {string} keyID - The key identifier.
   * @param {Counterparty} counterparty - The counterparty's public key or a predefined value ('self' or 'anyone').
   * @returns {PrivateKey} - The derived private key.
   */
  derivePrivateKey: (
    protocolID: WalletProtocol,
    keyID: string,
    counterparty: Counterparty
  ) => PrivateKey

  /**
   * Derives a symmetric key based on protocol ID, key ID, and counterparty.
   * Note: Symmetric keys should not be derivable by everyone due to security risks.
   * @param {WalletProtocol} protocolID - The protocol ID including a security level and protocol name.
   * @param {string} keyID - The key identifier.
   * @param {Counterparty} counterparty - The counterparty's public key or a predefined value ('self' or 'anyone').
   * @returns {SymmetricKey} - The derived symmetric key.
   */
  deriveSymmetricKey: (
    protocolID: WalletProtocol,
    keyID: string,
    counterparty: Counterparty
  ) => SymmetricKey

  /**
   * Reveals the shared secret between the root key and the counterparty.
   * Note: This should not be used for 'self'.
   * @param {Counterparty} counterparty - The counterparty's public key or a predefined value ('self' or 'anyone').
   * @returns {number[]} - The shared secret as a number array.
   * @throws {Error} - Throws an error if attempting to reveal a shared secret for 'self'.
   */
  revealCounterpartySecret: (counterparty: Counterparty) => number[]

  /**
   * Reveals the specific key association for a given protocol ID, key ID, and counterparty.
   * @param {Counterparty} counterparty - The counterparty's public key or a predefined value ('self' or 'anyone').
   * @param {WalletProtocol} protocolID - The protocol ID including a security level and protocol name.
   * @param {string} keyID - The key identifier.
   * @returns {number[]} - The specific key association as a number array.
   */
  revealSpecificSecret: (
    counterparty: Counterparty,
    protocolID: WalletProtocol,
    keyID: string
  ) => number[]
}

/**
 * Class responsible for deriving various types of keys using a root private key.
 * It supports deriving public and private keys, symmetric keys, and revealing key linkages.
 */
export class KeyDeriver implements KeyDeriverApi {
  rootKey: PrivateKey
  identityKey: string
  private readonly anyone: PublicKey

  /**
   * Initializes the KeyDeriver instance with a root private key.
   * @param {PrivateKey | 'anyone'} rootKey - The root private key or the string 'anyone'.
   */
  constructor (
    rootKey: PrivateKey | 'anyone',
    private readonly cacheSharedSecret?: ((priv: PrivateKey, pub: Point, point: Point) => void),
    private readonly retrieveCachedSharedSecret?: ((priv: PrivateKey, pub: Point) => (Point | undefined))
  ) {
    this.anyone = new PrivateKey(1).toPublicKey()
    if (rootKey === 'anyone') {
      this.rootKey = new PrivateKey(1)
    } else {
      this.rootKey = rootKey
    }
    this.identityKey = this.rootKey.toPublicKey().toString()
  }

  /**
   * Derives a public key based on protocol ID, key ID, and counterparty.
   * @param {WalletProtocol} protocolID - The protocol ID including a security level and protocol name.
   * @param {string} keyID - The key identifier.
   * @param {Counterparty} counterparty - The counterparty's public key or a predefined value ('self' or 'anyone').
   * @param {boolean} [forSelf=false] - Whether deriving for self.
   * @returns {PublicKey} - The derived public key.
   */
  derivePublicKey (
    protocolID: WalletProtocol,
    keyID: string,
    counterparty: Counterparty,
    forSelf: boolean = false
  ): PublicKey {
    counterparty = this.normalizeCounterparty(counterparty)
    if (forSelf) {
      return this.rootKey
        .deriveChild(
          counterparty,
          this.computeInvoiceNumber(protocolID, keyID),
          this.cacheSharedSecret,
          this.retrieveCachedSharedSecret
        )
        .toPublicKey()
    } else {
      return counterparty.deriveChild(
        this.rootKey,
        this.computeInvoiceNumber(protocolID, keyID),
        this.cacheSharedSecret,
        this.retrieveCachedSharedSecret
      )
    }
  }

  /**
   * Derives a private key based on protocol ID, key ID, and counterparty.
   * @param {WalletProtocol} protocolID - The protocol ID including a security level and protocol name.
   * @param {string} keyID - The key identifier.
   * @param {Counterparty} counterparty - The counterparty's public key or a predefined value ('self' or 'anyone').
   * @returns {PrivateKey} - The derived private key.
   */
  derivePrivateKey (
    protocolID: WalletProtocol,
    keyID: string,
    counterparty: Counterparty
  ): PrivateKey {
    counterparty = this.normalizeCounterparty(counterparty)
    return this.rootKey.deriveChild(
      counterparty,
      this.computeInvoiceNumber(protocolID, keyID),
      this.cacheSharedSecret,
      this.retrieveCachedSharedSecret
    )
  }

  /**
   * Derives a symmetric key based on protocol ID, key ID, and counterparty.
   * Note: Symmetric keys should not be derivable by everyone due to security risks.
   * 
   * This method uses HKDF (HMAC-based Key Derivation Function) as recommended by
   * NIST SP 800-56C to derive a symmetric key from the ECDH shared secret. This is
   * more secure than using the x-coordinate directly as it removes structure from
   * the elliptic curve point.
   * 
   * @param {WalletProtocol} protocolID - The protocol ID including a security level and protocol name.
   * @param {string} keyID - The key identifier.
   * @param {Counterparty} counterparty - The counterparty's public key or a predefined value ('self' or 'anyone').
   * @returns {SymmetricKey} - The derived symmetric key.
   */
  deriveSymmetricKey (
    protocolID: WalletProtocol,
    keyID: string,
    counterparty: Counterparty
  ): SymmetricKey {
    // If counterparty is 'anyone', we use 1*G as the public key.
    // This is a publicly derivable key and should only be used in scenarios where public disclosure is intended.
    if (counterparty === 'anyone') {
      counterparty = this.anyone
    } else {
      counterparty = this.normalizeCounterparty(counterparty)
    }
    const derivedPublicKey = this.derivePublicKey(
      protocolID,
      keyID,
      counterparty
    )
    const derivedPrivateKey = this.derivePrivateKey(
      protocolID,
      keyID,
      counterparty
    )
    
    // Get the shared secret point from ECDH
    const sharedSecret = derivedPrivateKey.deriveSharedSecret(derivedPublicKey)
    if (sharedSecret == null || sharedSecret.x == null) {
      throw new Error('Failed to derive shared secret')
    }
    
    // Use the x-coordinate as input keying material (IKM) for HKDF
    const ikm = sharedSecret.x.toArray()
    
    // Use protocol and key information as context for HKDF
    const invoiceNumber = this.computeInvoiceNumber(protocolID, keyID)
    const info = Utils.toArray(invoiceNumber, 'utf8')
    
    // Derive a 32-byte symmetric key using HKDF-SHA256
    // No salt is used (defaults to zeros) as the shared secret is already pseudorandom
    const derivedKey = Hash.hkdf(ikm, 32, undefined, info)
    
    return new SymmetricKey(derivedKey)
  }

  /**
   * Reveals the shared secret between the root key and the counterparty.
   * Note: This should not be used for 'self'.
   * @param {Counterparty} counterparty - The counterparty's public key or a predefined value ('self' or 'anyone').
   * @returns {number[]} - The shared secret as a number array.
   * @throws {Error} - Throws an error if attempting to reveal a shared secret for 'self'.
   */
  revealCounterpartySecret (counterparty: Counterparty): number[] {
    if (counterparty === 'self') {
      throw new Error(
        'Counterparty secrets cannot be revealed for counterparty=self.'
      )
    }
    counterparty = this.normalizeCounterparty(counterparty)

    // Double-check to ensure not revealing the secret for 'self'
    const self = this.rootKey.toPublicKey()
    const keyDerivedBySelf = this.rootKey.deriveChild(self, 'test').toHex()
    const keyDerivedByCounterparty = this.rootKey
      .deriveChild(counterparty, 'test')
      .toHex()

    if (keyDerivedBySelf === keyDerivedByCounterparty) {
      throw new Error(
        'Counterparty secrets cannot be revealed for counterparty=self.'
      )
    }

    return this.rootKey
      .deriveSharedSecret(counterparty)
      .encode(true) as number[]
  }

  /**
   * Reveals the specific key association for a given protocol ID, key ID, and counterparty.
   * @param {Counterparty} counterparty - The counterparty's public key or a predefined value ('self' or 'anyone').
   * @param {WalletProtocol} protocolID - The protocol ID including a security level and protocol name.
   * @param {string} keyID - The key identifier.
   * @returns {number[]} - The specific key association as a number array.
   */
  revealSpecificSecret (
    counterparty: Counterparty,
    protocolID: WalletProtocol,
    keyID: string
  ): number[] {
    counterparty = this.normalizeCounterparty(counterparty)
    const sharedSecret = this.rootKey.deriveSharedSecret(counterparty)
    const invoiceNumberBin = Utils.toArray(
      this.computeInvoiceNumber(protocolID, keyID),
      'utf8'
    )
    return Hash.sha256hmac(sharedSecret.encode(true), invoiceNumberBin)
  }

  /**
   * Normalizes the counterparty to a public key.
   * @param {Counterparty} counterparty - The counterparty's public key or a predefined value ('self' or 'anyone').
   * @returns {PublicKey} - The normalized counterparty public key.
   * @throws {Error} - Throws an error if the counterparty is invalid.
   */
  private normalizeCounterparty (counterparty: Counterparty): PublicKey {
    if (counterparty === null || counterparty === undefined) {
      throw new Error('counterparty must be self, anyone or a public key!')
    } else if (counterparty === 'self') {
      return this.rootKey.toPublicKey()
    } else if (counterparty === 'anyone') {
      return new PrivateKey(1).toPublicKey()
    } else if (typeof counterparty === 'string') {
      return PublicKey.fromString(counterparty)
    } else {
      return counterparty
    }
  }

  /**
   * Computes the invoice number based on the protocol ID and key ID.
   * @param {WalletProtocol} protocolID - The protocol ID including a security level and protocol name.
   * @param {string} keyID - The key identifier.
   * @returns {string} - The computed invoice number.
   * @throws {Error} - Throws an error if protocol ID or key ID are invalid.
   */
  private computeInvoiceNumber (
    protocolID: WalletProtocol,
    keyID: string
  ): string {
    const securityLevel = protocolID[0]
    if (
      !Number.isInteger(securityLevel) ||
      securityLevel < 0 ||
      securityLevel > 2
    ) {
      throw new Error('Protocol security level must be 0, 1, or 2')
    }
    const protocolName = protocolID[1].toLowerCase().trim()
    if (keyID.length > 800) {
      throw new Error('Key IDs must be 800 characters or less')
    }
    if (keyID.length < 1) {
      throw new Error('Key IDs must be 1 character or more')
    }
    if (protocolName.length > 400) {
      // Specific linkage revelation is the only protocol ID that can contain another protocol ID.
      // Therefore, we allow it to be long enough to encapsulate the target protocol
      if (protocolName.startsWith('specific linkage revelation ')) {
        // The format is: 'specific linkage revelation x YYYYY'
        // Where: x is the security level and YYYYY is the target protocol
        // Thus, the max acceptable length is 30 + 400 = 430 bytes
        if (protocolName.length > 430) {
          throw new Error(
            'Specific linkage revelation protocol names must be 430 characters or less'
          )
        }
      } else {
        throw new Error('Protocol names must be 400 characters or less')
      }
    }
    if (protocolName.length < 5) {
      throw new Error('Protocol names must be 5 characters or more')
    }
    if (protocolName.includes('  ')) {
      throw new Error(
        'Protocol names cannot contain multiple consecutive spaces ("  ")'
      )
    }
    if (!/^[a-z0-9 ]+$/g.test(protocolName)) {
      throw new Error(
        'Protocol names can only contain letters, numbers and spaces'
      )
    }
    if (protocolName.endsWith(' protocol')) {
      throw new Error('No need to end your protocol name with " protocol"')
    }
    return `${securityLevel}-${protocolName}-${keyID}`
  }
}

export default KeyDeriver
