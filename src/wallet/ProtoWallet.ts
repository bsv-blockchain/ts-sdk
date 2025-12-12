import { KeyDeriver, KeyDeriverApi } from './KeyDeriver.js'
import CachedKeyDeriver from './CachedKeyDeriver.js'
import {
  Hash,
  ECDSA,
  BigNumber,
  Signature,
  Schnorr,
  PublicKey,
  Point,
  PrivateKey
} from '../primitives/index.js'
import {
  CreateHmacArgs,
  CreateHmacResult,
  CreateSignatureArgs,
  CreateSignatureResult,
  GetPublicKeyArgs,
  PubKeyHex,
  RevealCounterpartyKeyLinkageArgs,
  RevealCounterpartyKeyLinkageResult,
  RevealSpecificKeyLinkageArgs,
  RevealSpecificKeyLinkageResult,
  VerifyHmacArgs,
  VerifyHmacResult,
  VerifySignatureArgs,
  VerifySignatureResult,
  WalletDecryptArgs,
  WalletDecryptResult,
  WalletEncryptArgs,
  WalletEncryptResult
} from './Wallet.interfaces.js'
import { constantTimeEquals, toArray } from '../primitives/utils.js'

/**
 * A ProtoWallet is precursor to a full wallet, capable of performing all foundational cryptographic operations.
 * It can derive keys, create signatures, facilitate encryption and HMAC operations, and reveal key linkages.
 *
 * However, ProtoWallet does not create transactions, manage outputs, interact with the blockchain,
 * enable the management of identity certificates, or store any data. It is also not concerned with privileged keys.
 */
export class ProtoWallet {
  keyDeriver?: KeyDeriverApi

  constructor (rootKeyOrKeyDeriver?: PrivateKey | 'anyone' | KeyDeriverApi) {
    if (typeof (rootKeyOrKeyDeriver as KeyDeriver).identityKey !== 'string') {
      rootKeyOrKeyDeriver = new CachedKeyDeriver(
        rootKeyOrKeyDeriver as PrivateKey | 'anyone'
      )
    }
    this.keyDeriver = rootKeyOrKeyDeriver as KeyDeriverApi
  }

  async getPublicKey (
    args: GetPublicKeyArgs
  ): Promise<{ publicKey: PubKeyHex }> {
    if (args.identityKey) {
      if (this.keyDeriver == null) {
        throw new Error('keyDeriver is undefined')
      }
      return { publicKey: this.keyDeriver.rootKey.toPublicKey().toString() }
    } else {
      if (args.protocolID == null || args.keyID == null || args.keyID === '') {
        throw new Error(
          'protocolID and keyID are required if identityKey is false or undefined.'
        )
      }
      const keyDeriver =
        this.keyDeriver ??
        (() => {
          throw new Error('keyDeriver is undefined')
        })()
      return {
        publicKey: keyDeriver
          .derivePublicKey(
            args.protocolID,
            args.keyID,
            args.counterparty ?? 'self',
            args.forSelf
          )
          .toString()
      }
    }
  }

  async revealCounterpartyKeyLinkage (
    args: RevealCounterpartyKeyLinkageArgs
  ): Promise<RevealCounterpartyKeyLinkageResult> {
    const { publicKey: identityKey } = await this.getPublicKey({
      identityKey: true
    })
    if (this.keyDeriver == null) {
      throw new Error('keyDeriver is undefined')
    }
    const linkage = this.keyDeriver.revealCounterpartySecret(args.counterparty)
    const linkageProof = new Schnorr().generateProof(
      this.keyDeriver.rootKey,
      this.keyDeriver.rootKey.toPublicKey(),
      PublicKey.fromString(args.counterparty),
      Point.fromDER(linkage)
    )
    const linkageProofBin = [
      ...linkageProof.R.encode(true),
      ...linkageProof.SPrime.encode(true),
      ...linkageProof.z.toArray()
    ] as number[]
    const revelationTime = new Date().toISOString()
    const { ciphertext: encryptedLinkage } = await this.encrypt({
      plaintext: linkage,
      protocolID: [2, 'counterparty linkage revelation'],
      keyID: revelationTime,
      counterparty: args.verifier
    })
    const { ciphertext: encryptedLinkageProof } = await this.encrypt({
      plaintext: linkageProofBin,
      protocolID: [2, 'counterparty linkage revelation'],
      keyID: revelationTime,
      counterparty: args.verifier
    })
    return {
      prover: identityKey,
      verifier: args.verifier,
      counterparty: args.counterparty,
      revelationTime,
      encryptedLinkage,
      encryptedLinkageProof
    }
  }

  async revealSpecificKeyLinkage (
    args: RevealSpecificKeyLinkageArgs
  ): Promise<RevealSpecificKeyLinkageResult> {
    const { publicKey: identityKey } = await this.getPublicKey({
      identityKey: true
    })
    if (this.keyDeriver == null) {
      throw new Error('keyDeriver is undefined')
    }
    const linkage = this.keyDeriver.revealSpecificSecret(
      args.counterparty,
      args.protocolID,
      args.keyID
    )
    const { ciphertext: encryptedLinkage } = await this.encrypt({
      plaintext: linkage,
      protocolID: [
        2,
        `specific linkage revelation ${args.protocolID[0]} ${args.protocolID[1]}`
      ],
      keyID: args.keyID,
      counterparty: args.verifier
    })
    const { ciphertext: encryptedLinkageProof } = await this.encrypt({
      plaintext: [0], // Proof type 0, no proof provided
      protocolID: [
        2,
        `specific linkage revelation ${args.protocolID[0]} ${args.protocolID[1]}`
      ],
      keyID: args.keyID,
      counterparty: args.verifier
    })
    return {
      prover: identityKey,
      verifier: args.verifier,
      counterparty: args.counterparty,
      protocolID: args.protocolID,
      keyID: args.keyID,
      encryptedLinkage,
      encryptedLinkageProof,
      proofType: 0
    }
  }

  async encrypt (
    args: WalletEncryptArgs
  ): Promise<WalletEncryptResult> {
    if (this.keyDeriver == null) {
      throw new Error('keyDeriver is undefined')
    }
    const key = this.keyDeriver.deriveSymmetricKey(
      args.protocolID,
      args.keyID,
      args.counterparty ?? 'self'
    )
    return { ciphertext: key.encrypt(args.plaintext) as number[] }
  }

  async decrypt (
    args: WalletDecryptArgs, originator?: string): Promise<WalletDecryptResult> {
    if (this.keyDeriver == null) {
      throw new Error('keyDeriver is undefined')
    }
    const key = this.keyDeriver.deriveSymmetricKey(
      args.protocolID,
      args.keyID,
      args.counterparty ?? 'self'
    )
    return { plaintext: key.decrypt(args.ciphertext) as number[] }
  }

  async createHmac (
    args: CreateHmacArgs
  ): Promise<CreateHmacResult> {
    if (this.keyDeriver == null) {
      throw new Error('keyDeriver is undefined')
    }
    const key = this.keyDeriver.deriveSymmetricKey(
      args.protocolID,
      args.keyID,
      args.counterparty ?? 'self'
    )
    return { hmac: Hash.sha256hmac(key.toArray(), args.data) }
  }

  async verifyHmac (
    args: VerifyHmacArgs
  ): Promise<VerifyHmacResult> {
    if (this.keyDeriver == null) {
      throw new Error('keyDeriver is undefined')
    }
    const key = this.keyDeriver.deriveSymmetricKey(
      args.protocolID,
      args.keyID,
      args.counterparty ?? 'self'
    )
    const computed = Hash.sha256hmac(key.toArray(), args.data)
    const provided = args.hmac

    const valid = constantTimeEquals(
      toArray(computed),
      toArray(provided)
    )
    if (!valid) {
      const e = new Error('HMAC is not valid') as Error & { code: string }
      e.code = 'ERR_INVALID_HMAC'
      throw e
    }
    return { valid }
  }

  async createSignature (
    args: CreateSignatureArgs
  ): Promise<CreateSignatureResult> {
    if ((args.hashToDirectlySign == null) && (args.data == null)) {
      throw new Error('args.data or args.hashToDirectlySign must be valid')
    }

    const hash: number[] =
      args.hashToDirectlySign ?? Hash.sha256(args.data ?? [])
    const keyDeriver =
      this.keyDeriver ??
      (() => {
        throw new Error('keyDeriver is undefined')
      })()

    const key = keyDeriver.derivePrivateKey(
      args.protocolID,
      args.keyID,
      args.counterparty ?? 'anyone'
    )

    return {
      signature: ECDSA.sign(new BigNumber(hash), key, true).toDER() as number[]
    }
  }

  async verifySignature (
    args: VerifySignatureArgs
  ): Promise<VerifySignatureResult> {
    if ((args.hashToDirectlyVerify == null) && (args.data == null)) {
      throw new Error('args.data or args.hashToDirectlyVerify must be valid')
    }

    const hash: number[] =
      args.hashToDirectlyVerify ?? Hash.sha256(args.data ?? [])
    const keyDeriver =
      this.keyDeriver ??
      (() => {
        throw new Error('keyDeriver is undefined')
      })()

    const key = keyDeriver.derivePublicKey(
      args.protocolID,
      args.keyID,
      args.counterparty ?? 'self',
      args.forSelf
    )

    const valid = ECDSA.verify(
      new BigNumber(hash),
      Signature.fromDER(args.signature),
      key
    )

    if (!valid) {
      const e = new Error('Signature is not valid') as Error & { code: string }
      e.code = 'ERR_INVALID_SIGNATURE'
      throw e
    }

    return { valid }
  }
}

export default ProtoWallet
