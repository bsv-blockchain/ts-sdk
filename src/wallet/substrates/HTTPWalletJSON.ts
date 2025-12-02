import {
  WalletInterface,
  CreateActionArgs,
  OriginatorDomainNameStringUnder250Bytes,
  CreateActionResult,
  BooleanDefaultTrue,
  AcquireCertificateArgs,
  AcquireCertificateResult,
  Base64String,
  BasketStringUnder300Bytes,
  BooleanDefaultFalse,
  Byte,
  CertificateFieldNameUnder50Bytes,
  DescriptionString5to50Bytes,
  DiscoverCertificatesResult,
  HexString,
  InternalizeActionArgs,
  ISOTimestampString,
  KeyIDStringUnder800Bytes,
  ListActionsArgs,
  ListActionsResult,
  ListCertificatesResult,
  ListOutputsArgs,
  ListOutputsResult,
  OutpointString,
  PositiveInteger,
  PositiveIntegerDefault10Max10000,
  PositiveIntegerOrZero,
  ProtocolString5To400Bytes,
  ProveCertificateArgs,
  ProveCertificateResult,
  PubKeyHex,
  SecurityLevel,
  SignActionArgs,
  SignActionResult,
  VersionString7To30Bytes
} from '../Wallet.interfaces.js'
import { WERR_REVIEW_ACTIONS } from '../WERR_REVIEW_ACTIONS.js'
import { WERR_INVALID_PARAMETER } from '../WERR_INVALID_PARAMETER.js'
import { toOriginHeader } from './utils/toOriginHeader.js'
import WERR_INSUFFICIENT_FUNDS from '../WERR_INSUFFICIENT_FUNDS.js'

export default class HTTPWalletJSON implements WalletInterface {
  baseUrl: string
  httpClient: typeof fetch
  originator: OriginatorDomainNameStringUnder250Bytes | undefined
  api: (call: string, args: object) => Promise<unknown> // Fixed `any` types

  constructor (
    originator: OriginatorDomainNameStringUnder250Bytes | undefined,
    baseUrl: string = 'http://localhost:3321',
    httpClient = fetch
  ) {
    this.baseUrl = baseUrl
    this.originator = originator
    this.httpClient = httpClient

    // Detect if we're in a browser environment
    const isBrowser = typeof window !== 'undefined' && typeof document !== 'undefined' && window?.origin !== 'file://'

    this.api = async (call: string, args: object) => {
      // In browser environments, let the browser handle Origin header automatically
      // In Node.js environments, we need to set it manually if originator is provided
      const origin = !isBrowser && this.originator
        ? toOriginHeader(this.originator, 'http')
        : undefined

      if (!isBrowser && origin === undefined) {
        console.error('Originator is required in Node.js environments')
      }

      const res = await (
        await httpClient(`${this.baseUrl}/${call}`, {
          method: 'POST',
          headers: {
            Accept: 'application/json',
            'Content-Type': 'application/json',
            ...(origin ? { Origin: origin } : {}),
            ...(origin ? { Originator: origin } : {})
          },
          body: JSON.stringify(args)
        })
      )

      const data = await res.json()

      // Check the HTTP status on the original response
      if (!res.ok) {
        if (res.status === 400 && data.isError) {
          let err: any
          switch (data.code) {
            case 5:
              err = new WERR_REVIEW_ACTIONS(data.reviewActionResults, data.sendWithResults, data.txid, data.tx, data.noSendChange); break
            case 6:
              err = new WERR_INVALID_PARAMETER(data.parameter); err.message = data.message; break
            case 7:
              err = new WERR_INSUFFICIENT_FUNDS(data.totalSatoshisNeeded, data.moreSatoshisNeeded); break
            default: break
          }
          if (err) throw err
        }
        const err = {
          call,
          args,
          message: data.message ?? `HTTP Client error ${res.status}`
        }
        throw new Error(JSON.stringify(err))
      }
      return data
    }
  }

  async createAction (args: CreateActionArgs): Promise<CreateActionResult> {
    return await this.api('createAction', args) as CreateActionResult
  }

  async signAction (args: SignActionArgs): Promise<SignActionResult> {
    return await this.api('signAction', args) as SignActionResult
  }

  async abortAction (args: {
    reference: Base64String
  }): Promise<{ aborted: true }> {
    return await this.api('abortAction', args) as { aborted: true }
  }

  async listActions (args: ListActionsArgs): Promise<ListActionsResult> {
    return await this.api('listActions', args) as ListActionsResult
  }

  async internalizeAction (
    args: InternalizeActionArgs
  ): Promise<{ accepted: true }> {
    return await this.api('internalizeAction', args) as { accepted: true }
  }

  async listOutputs (args: ListOutputsArgs): Promise<ListOutputsResult> {
    return await this.api('listOutputs', args) as ListOutputsResult
  }

  async relinquishOutput (args: {
    basket: BasketStringUnder300Bytes
    output: OutpointString
  }): Promise<{ relinquished: true }> {
    return await this.api('relinquishOutput', args) as { relinquished: true }
  }

  async getPublicKey (args: {
    seekPermission?: BooleanDefaultTrue
    identityKey?: true
    protocolID?: [SecurityLevel, ProtocolString5To400Bytes]
    keyID?: KeyIDStringUnder800Bytes
    privileged?: BooleanDefaultFalse
    privilegedReason?: DescriptionString5to50Bytes
    counterparty?: PubKeyHex | 'self' | 'anyone'
    forSelf?: BooleanDefaultFalse
  }): Promise<{ publicKey: PubKeyHex }> {
    return await this.api('getPublicKey', args) as { publicKey: PubKeyHex }
  }

  async revealCounterpartyKeyLinkage (args: {
    counterparty: PubKeyHex
    verifier: PubKeyHex
    privilegedReason?: DescriptionString5to50Bytes
    privileged?: BooleanDefaultFalse
  }): Promise<{
      prover: PubKeyHex
      verifier: PubKeyHex
      counterparty: PubKeyHex
      revelationTime: ISOTimestampString
      encryptedLinkage: Byte[]
      encryptedLinkageProof: number[]
    }> {
    return await this.api('revealCounterpartyKeyLinkage', args) as {
      prover: PubKeyHex
      verifier: PubKeyHex
      counterparty: PubKeyHex
      revelationTime: ISOTimestampString
      encryptedLinkage: Byte[]
      encryptedLinkageProof: number[]
    }
  }

  async revealSpecificKeyLinkage (args: {
    counterparty: PubKeyHex
    verifier: PubKeyHex
    protocolID: [SecurityLevel, ProtocolString5To400Bytes]
    keyID: KeyIDStringUnder800Bytes
    privilegedReason?: DescriptionString5to50Bytes
    privileged?: BooleanDefaultFalse
  }): Promise<{
      prover: PubKeyHex
      verifier: PubKeyHex
      counterparty: PubKeyHex
      protocolID: [SecurityLevel, ProtocolString5To400Bytes]
      keyID: KeyIDStringUnder800Bytes
      encryptedLinkage: Byte[]
      encryptedLinkageProof: Byte[]
      proofType: Byte
    }> {
    return await this.api('revealSpecificKeyLinkage', args) as {
      prover: PubKeyHex
      verifier: PubKeyHex
      counterparty: PubKeyHex
      protocolID: [SecurityLevel, ProtocolString5To400Bytes]
      keyID: KeyIDStringUnder800Bytes
      encryptedLinkage: Byte[]
      encryptedLinkageProof: Byte[]
      proofType: Byte
    }
  }

  async encrypt (args: {
    seekPermission?: BooleanDefaultTrue
    plaintext: Byte[]
    protocolID: [SecurityLevel, ProtocolString5To400Bytes]
    keyID: KeyIDStringUnder800Bytes
    privilegedReason?: DescriptionString5to50Bytes
    counterparty?: PubKeyHex | 'self' | 'anyone'
    privileged?: BooleanDefaultFalse
  }): Promise<{ ciphertext: Byte[] }> {
    return await this.api('encrypt', args) as { ciphertext: Byte[] }
  }

  async decrypt (args: {
    seekPermission?: BooleanDefaultTrue
    ciphertext: Byte[]
    protocolID: [SecurityLevel, ProtocolString5To400Bytes]
    keyID: KeyIDStringUnder800Bytes
    privilegedReason?: DescriptionString5to50Bytes
    counterparty?: PubKeyHex | 'self' | 'anyone'
    privileged?: BooleanDefaultFalse
  }): Promise<{ plaintext: Byte[] }> {
    return await this.api('decrypt', args) as { plaintext: Byte[] }
  }

  async createHmac (args: {
    seekPermission?: BooleanDefaultTrue
    data: Byte[]
    protocolID: [SecurityLevel, ProtocolString5To400Bytes]
    keyID: KeyIDStringUnder800Bytes
    privilegedReason?: DescriptionString5to50Bytes
    counterparty?: PubKeyHex | 'self' | 'anyone'
    privileged?: BooleanDefaultFalse
  }): Promise<{ hmac: Byte[] }> {
    return await this.api('createHmac', args) as { hmac: Byte[] }
  }

  async verifyHmac (args: {
    seekPermission?: BooleanDefaultTrue
    data: Byte[]
    hmac: Byte[]
    protocolID: [SecurityLevel, ProtocolString5To400Bytes]
    keyID: KeyIDStringUnder800Bytes
    privilegedReason?: DescriptionString5to50Bytes
    counterparty?: PubKeyHex | 'self' | 'anyone'
    privileged?: BooleanDefaultFalse
  }): Promise<{ valid: true }> {
    return await this.api('verifyHmac', args) as { valid: true }
  }

  async createSignature (args: {
    seekPermission?: BooleanDefaultTrue
    data?: Byte[]
    hashToDirectlySign?: Byte[]
    protocolID: [SecurityLevel, ProtocolString5To400Bytes]
    keyID: KeyIDStringUnder800Bytes
    privilegedReason?: DescriptionString5to50Bytes
    counterparty?: PubKeyHex | 'self' | 'anyone'
    privileged?: BooleanDefaultFalse
  }): Promise<{ signature: Byte[] }> {
    return await this.api('createSignature', args) as { signature: Byte[] }
  }

  async verifySignature (args: {
    seekPermission?: BooleanDefaultTrue
    data?: Byte[]
    hashToDirectlyVerify?: Byte[]
    signature: Byte[]
    protocolID: [SecurityLevel, ProtocolString5To400Bytes]
    keyID: KeyIDStringUnder800Bytes
    privilegedReason?: DescriptionString5to50Bytes
    counterparty?: PubKeyHex | 'self' | 'anyone'
    forSelf?: BooleanDefaultFalse
    privileged?: BooleanDefaultFalse
  }): Promise<{ valid: true }> {
    return await this.api('verifySignature', args) as { valid: true }
  }

  async acquireCertificate (
    args: AcquireCertificateArgs
  ): Promise<AcquireCertificateResult> {
    return await this.api('acquireCertificate', args) as AcquireCertificateResult
  }

  async listCertificates (args: {
    certifiers: PubKeyHex[]
    types: Base64String[]
    limit?: PositiveIntegerDefault10Max10000
    offset?: PositiveIntegerOrZero
    privileged?: BooleanDefaultFalse
    privilegedReason?: DescriptionString5to50Bytes
  }): Promise<ListCertificatesResult> {
    return await this.api('listCertificates', args) as ListCertificatesResult
  }

  async proveCertificate (
    args: ProveCertificateArgs
  ): Promise<ProveCertificateResult> {
    return await this.api('proveCertificate', args) as ProveCertificateResult
  }

  async relinquishCertificate (args: {
    type: Base64String
    serialNumber: Base64String
    certifier: PubKeyHex
  }): Promise<{ relinquished: true }> {
    return await this.api('relinquishCertificate', args) as { relinquished: true }
  }

  async discoverByIdentityKey (args: {
    seekPermission?: BooleanDefaultTrue
    identityKey: PubKeyHex
    limit?: PositiveIntegerDefault10Max10000
    offset?: PositiveIntegerOrZero
  }): Promise<DiscoverCertificatesResult> {
    return await this.api('discoverByIdentityKey', args) as DiscoverCertificatesResult
  }

  async discoverByAttributes (args: {
    seekPermission?: BooleanDefaultTrue
    attributes: Record<CertificateFieldNameUnder50Bytes, string>
    limit?: PositiveIntegerDefault10Max10000
    offset?: PositiveIntegerOrZero
  }): Promise<DiscoverCertificatesResult> {
    return await this.api('discoverByAttributes', args) as DiscoverCertificatesResult
  }

  async isAuthenticated (args: object): Promise<{ authenticated: true }> {
    return await this.api('isAuthenticated', args) as { authenticated: true }
  }

  async waitForAuthentication (args: object): Promise<{ authenticated: true }> {
    return await this.api('waitForAuthentication', args) as { authenticated: true }
  }

  async getHeight (args: object): Promise<{ height: PositiveInteger }> {
    return await this.api('getHeight', args) as { height: PositiveInteger }
  }

  async getHeaderForHeight (args: {
    height: PositiveInteger
  }): Promise<{ header: HexString }> {
    return await this.api('getHeaderForHeight', args) as { header: HexString }
  }

  async getNetwork (args: object): Promise<{ network: 'mainnet' | 'testnet' }> {
    return await this.api('getNetwork', args) as { network: 'mainnet' | 'testnet' }
  }

  async getVersion (args: object): Promise<{ version: VersionString7To30Bytes }> {
    return await this.api('getVersion', args) as { version: VersionString7To30Bytes }
  }
}
