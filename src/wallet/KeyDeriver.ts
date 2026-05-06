import {
  PrivateKey,
  PublicKey,
  SymmetricKey,
  Hash,
  Utils,
  Point
} from '../primitives/index.js'
import { WalletProtocol, PubKeyHex } from './Wallet.interfaces.js'
import { computeInvoiceNumber } from './keyLinkage.js'

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
    return new SymmetricKey(
      derivedPrivateKey.deriveSharedSecret(derivedPublicKey)?.x?.toArray() ?? []
    )
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

  private computeInvoiceNumber (
    protocolID: WalletProtocol,
    keyID: string
  ): string {
    return computeInvoiceNumber(protocolID, keyID)
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
}

export default KeyDeriver
