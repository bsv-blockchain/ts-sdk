import {
  Base64String,
  BasketStringUnder300Bytes,
  BEEF,
  BooleanDefaultFalse,
  BooleanDefaultTrue,
  Byte,
  CertificateFieldNameUnder50Bytes,
  DescriptionString5to50Bytes,
  EntityIconURLStringMax500Bytes,
  EntityNameStringMax100Bytes,
  HexString,
  ISOTimestampString,
  KeyIDStringUnder800Bytes,
  LabelStringUnder300Bytes,
  OutpointString,
  OutputTagStringUnder300Bytes,
  PositiveInteger,
  PositiveIntegerDefault10Max10000,
  PositiveIntegerMax10,
  PositiveIntegerOrZero,
  ProtocolString5To400Bytes,
  PubKeyHex,
  SatoshiValue,
  SecurityLevel,
  TXIDHexString,
  VersionString7To30Bytes,
  WalletInterface
} from '../Wallet.interfaces.js'
import Random from '../../primitives/Random.js'
import * as Utils from '../../primitives/utils.js'
import { WalletError } from '../WalletError.js'
import { CallType } from './WalletWireCalls.js'

type ReactNativeWindow = Window & {
  ReactNativeWebView: {
    postMessage: (message: any) => void
  }
}

/**
 * Facilitates wallet operations over cross-document messaging.
 */
export default class ReactNativeWebView implements WalletInterface {
  private readonly domain: string


  constructor(domain: string = '*') {
    if (typeof window !== 'object') {
      throw new Error('The XDM substrate requires a global window object.')
    }
    if (!(window as unknown as ReactNativeWindow).hasOwnProperty("ReactNativeWebView")) {
      throw new Error(
        'The window object does not have a ReactNativeWebView property.'
      )
    }
    if (typeof (window as unknown as ReactNativeWindow).ReactNativeWebView.postMessage !== 'function') {
      throw new Error(
        'The window.ReactNativeWebView property does not seem to support postMessage calls.'
      )
    }
    this.domain = domain
  }

  async invoke(call: CallType, args: any): Promise<any> {
    return await new Promise((resolve, reject) => {
      const id = Utils.toBase64(Random(12))
      const listener = (e: MessageEvent): void => {
        const data = JSON.parse(e.data)
        if (
          data.type !== 'CWI' ||
          data.id !== id ||
          data.isInvocation === true
        ) {
          return
        }
        if (typeof window.removeEventListener === 'function') {
          window.removeEventListener('message', listener)
        }
        if (data.status === 'error') {
          const err = new WalletError(data.description, data.code)
          reject(err)
        } else {
          resolve(data.result)
        }
      }
      window.addEventListener('message', listener)
      ;(window as unknown as ReactNativeWindow).ReactNativeWebView.postMessage(
        JSON.stringify({
          type: 'CWI',
          isInvocation: true,
          id,
          call,
          args
        })
      )
    })
  }

  async createAction(args: {
    description: DescriptionString5to50Bytes
    inputs?: Array<{
      tx?: BEEF
      outpoint: OutpointString
      unlockingScript?: HexString
      unlockingScriptLength?: PositiveInteger
      inputDescription: DescriptionString5to50Bytes
      sequenceNumber?: PositiveIntegerOrZero
    }>
    outputs?: Array<{
      lockingScript: HexString
      satoshis: SatoshiValue
      outputDescription: DescriptionString5to50Bytes
      basket?: BasketStringUnder300Bytes
      customInstructions?: string
      tags?: OutputTagStringUnder300Bytes[]
    }>
    lockTime?: PositiveIntegerOrZero
    version?: PositiveIntegerOrZero
    labels?: LabelStringUnder300Bytes[]
    reference?: Base64String
    options?: {
      signAndProcess?: BooleanDefaultTrue
      acceptDelayedBroadcast?: BooleanDefaultTrue
      trustSelf?: 'known'
      knownTxids?: TXIDHexString[]
      returnTXIDOnly?: BooleanDefaultFalse
      noSend?: BooleanDefaultFalse
      noSendChange?: OutpointString[]
      sendWith?: TXIDHexString[]
    }
  }): Promise<{
    txid?: TXIDHexString
    tx?: BEEF
    noSendChange?: OutpointString[]
    sendWithResults?: Array<{
      txid: TXIDHexString
      status: 'unproven' | 'sending' | 'failed'
    }>
    signableTransaction?: { tx: BEEF, reference: Base64String }
  }> {
    return await this.invoke('createAction', args)
  }

  async signAction(args: {
    spends: Record<
      PositiveIntegerOrZero,
      { unlockingScript: HexString, sequenceNumber?: PositiveIntegerOrZero }
    >
    reference: Base64String
    options?: {
      acceptDelayedBroadcast?: BooleanDefaultTrue
      returnTXIDOnly?: BooleanDefaultFalse
      noSend?: BooleanDefaultFalse
      noSendChange?: OutpointString[]
      sendWith: TXIDHexString[]
    }
  }): Promise<{
    txid?: TXIDHexString
    tx?: BEEF
    noSendChange?: OutpointString[]
    sendWithResults?: Array<{
      txid: TXIDHexString
      status: 'unproven' | 'sending' | 'failed'
    }>
  }> {
    return await this.invoke('signAction', args)
  }

  async abortAction(args: {
    reference: Base64String
  }): Promise<{ aborted: true }> {
    return await this.invoke('abortAction', args)
  }

  async listActions(args: {
    labels: LabelStringUnder300Bytes[]
    labelQueryMode?: 'any' | 'all'
    includeLabels?: BooleanDefaultFalse
    includeInputs?: BooleanDefaultFalse
    includeInputSourceLockingScripts?: BooleanDefaultFalse
    includeInputUnlockingScripts?: BooleanDefaultFalse
    includeOutputs?: BooleanDefaultFalse
    includeOutputLockingScripts?: BooleanDefaultFalse
    limit?: PositiveIntegerDefault10Max10000
    offset?: PositiveIntegerOrZero
    reference?: Base64String
  }): Promise<{
    totalActions: PositiveIntegerOrZero
    actions: Array<{
      txid: TXIDHexString
      satoshis: SatoshiValue
      status:
      | 'completed'
      | 'unprocessed'
      | 'sending'
      | 'unproven'
      | 'unsigned'
      | 'nosend'
      | 'nonfinal'
      isOutgoing: boolean
      description: DescriptionString5to50Bytes
      labels?: LabelStringUnder300Bytes[]
      version: PositiveIntegerOrZero
      lockTime: PositiveIntegerOrZero
      inputs?: Array<{
        sourceOutpoint: OutpointString
        sourceSatoshis: SatoshiValue
        sourceLockingScript?: HexString
        unlockingScript?: HexString
        inputDescription: DescriptionString5to50Bytes
        sequenceNumber: PositiveIntegerOrZero
      }>
      outputs?: Array<{
        outputIndex: PositiveIntegerOrZero
        satoshis: SatoshiValue
        lockingScript?: HexString
        spendable: boolean
        outputDescription: DescriptionString5to50Bytes
        basket: BasketStringUnder300Bytes
        tags: OutputTagStringUnder300Bytes[]
        customInstructions?: string
      }>
    }>
  }> {
    return await this.invoke('listActions', args)
  }

  async internalizeAction(args: {
    tx: BEEF
    outputs: Array<{
      outputIndex: PositiveIntegerOrZero
      protocol: 'wallet payment' | 'basket insertion'
      paymentRemittance?: {
        derivationPrefix: Base64String
        derivationSuffix: Base64String
        senderIdentityKey: PubKeyHex
      }
      insertionRemittance?: {
        basket: BasketStringUnder300Bytes
        customInstructions?: string
        tags?: OutputTagStringUnder300Bytes[]
      }
    }>
    description: DescriptionString5to50Bytes
    labels?: LabelStringUnder300Bytes[]
    reference?: Base64String
  }): Promise<{ accepted: true }> {
    return await this.invoke('internalizeAction', args)
  }

  async listOutputs(args: {
    basket: BasketStringUnder300Bytes
    tags?: OutputTagStringUnder300Bytes[]
    tagQueryMode?: 'all' | 'any'
    include?: 'locking scripts' | 'entire transactions'
    includeCustomInstructions?: BooleanDefaultFalse
    includeTags?: BooleanDefaultFalse
    includeLabels?: BooleanDefaultFalse
    limit?: PositiveIntegerDefault10Max10000
    offset?: PositiveIntegerOrZero
  }): Promise<{
    totalOutputs: PositiveIntegerOrZero
    outputs: Array<{
      outpoint: OutpointString
      satoshis: SatoshiValue
      lockingScript?: HexString
      tx?: BEEF
      spendable: boolean
      customInstructions?: string
      tags?: OutputTagStringUnder300Bytes[]
      labels?: LabelStringUnder300Bytes[]
    }>
  }> {
    return await this.invoke('listOutputs', args)
  }

  async relinquishOutput(args: {
    basket: BasketStringUnder300Bytes
    output: OutpointString
  }): Promise<{ relinquished: true }> {
    return await this.invoke('relinquishOutput', args)
  }

  async getPublicKey(args: {
    identityKey?: true
    protocolID?: [SecurityLevel, ProtocolString5To400Bytes]
    keyID?: KeyIDStringUnder800Bytes
    privileged?: BooleanDefaultFalse
    privilegedReason?: DescriptionString5to50Bytes
    counterparty?: PubKeyHex | 'self' | 'anyone'
    forSelf?: BooleanDefaultFalse
  }): Promise<{ publicKey: PubKeyHex }> {
    return await this.invoke('getPublicKey', args)
  }

  async revealCounterpartyKeyLinkage(args: {
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
    encryptedLinkageProof: Byte[]
  }> {
    return await this.invoke('revealCounterpartyKeyLinkage', args)
  }

  async revealSpecificKeyLinkage(args: {
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
    return await this.invoke('revealSpecificKeyLinkage', args)
  }

  async encrypt(args: {
    plaintext: Byte[]
    protocolID: [SecurityLevel, ProtocolString5To400Bytes]
    keyID: KeyIDStringUnder800Bytes
    privilegedReason?: DescriptionString5to50Bytes
    counterparty?: PubKeyHex | 'self' | 'anyone'
    privileged?: BooleanDefaultFalse
  }): Promise<{ ciphertext: Byte[] }> {
    return await this.invoke('encrypt', args)
  }

  async decrypt(args: {
    ciphertext: Byte[]
    protocolID: [SecurityLevel, ProtocolString5To400Bytes]
    keyID: KeyIDStringUnder800Bytes
    privilegedReason?: DescriptionString5to50Bytes
    counterparty?: PubKeyHex | 'self' | 'anyone'
    privileged?: BooleanDefaultFalse
  }): Promise<{ plaintext: Byte[] }> {
    return await this.invoke('decrypt', args)
  }

  async createHmac(args: {
    data: Byte[]
    protocolID: [SecurityLevel, ProtocolString5To400Bytes]
    keyID: KeyIDStringUnder800Bytes
    privilegedReason?: DescriptionString5to50Bytes
    counterparty?: PubKeyHex | 'self' | 'anyone'
    privileged?: BooleanDefaultFalse
  }): Promise<{ hmac: Byte[] }> {
    return await this.invoke('createHmac', args)
  }

  async verifyHmac(args: {
    data: Byte[]
    hmac: Byte[]
    protocolID: [SecurityLevel, ProtocolString5To400Bytes]
    keyID: KeyIDStringUnder800Bytes
    privilegedReason?: DescriptionString5to50Bytes
    counterparty?: PubKeyHex | 'self' | 'anyone'
    privileged?: BooleanDefaultFalse
  }): Promise<{ valid: true }> {
    return await this.invoke('verifyHmac', args)
  }

  async createSignature(args: {
    data?: Byte[]
    hashToDirectlySign?: Byte[]
    protocolID: [SecurityLevel, ProtocolString5To400Bytes]
    keyID: KeyIDStringUnder800Bytes
    privilegedReason?: DescriptionString5to50Bytes
    counterparty?: PubKeyHex | 'self' | 'anyone'
    privileged?: BooleanDefaultFalse
  }): Promise<{ signature: Byte[] }> {
    return await this.invoke('createSignature', args)
  }

  async verifySignature(args: {
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
    return await this.invoke('verifySignature', args)
  }

  async acquireCertificate(args: {
    type: Base64String
    subject: PubKeyHex
    serialNumber: Base64String
    revocationOutpoint: OutpointString
    signature: HexString
    fields: Record<CertificateFieldNameUnder50Bytes, string>
    certifier: PubKeyHex
    keyringRevealer: PubKeyHex | 'certifier'
    keyringForSubject: Record<CertificateFieldNameUnder50Bytes, Base64String>
    acquisitionProtocol: 'direct' | 'issuance'
    certifierUrl?: string
  }): Promise<{
    type: Base64String
    subject: PubKeyHex
    serialNumber: Base64String
    certifier: PubKeyHex
    revocationOutpoint: OutpointString
    signature: HexString
    fields: Record<CertificateFieldNameUnder50Bytes, string>
  }> {
    return await this.invoke('acquireCertificate', args)
  }

  async listCertificates(args: {
    certifiers: PubKeyHex[]
    types: Base64String[]
    limit?: PositiveIntegerDefault10Max10000
    offset?: PositiveIntegerOrZero
    privileged?: BooleanDefaultFalse
    privilegedReason?: DescriptionString5to50Bytes
  }): Promise<{
    totalCertificates: PositiveIntegerOrZero
    certificates: Array<{
      type: Base64String
      subject: PubKeyHex
      serialNumber: Base64String
      certifier: PubKeyHex
      revocationOutpoint: OutpointString
      signature: HexString
      fields: Record<CertificateFieldNameUnder50Bytes, string>
    }>
  }> {
    return await this.invoke('listCertificates', args)
  }

  async proveCertificate(args: {
    certificate: {
      type: Base64String
      subject: PubKeyHex
      serialNumber: Base64String
      certifier: PubKeyHex
      revocationOutpoint: OutpointString
      signature: HexString
      fields: Record<CertificateFieldNameUnder50Bytes, string>
    }
    fieldsToReveal: CertificateFieldNameUnder50Bytes[]
    verifier: PubKeyHex
    privileged?: BooleanDefaultFalse
    privilegedReason?: DescriptionString5to50Bytes
  }): Promise<{
    keyringForVerifier: Record<CertificateFieldNameUnder50Bytes, Base64String>
  }> {
    return await this.invoke('proveCertificate', args)
  }

  async relinquishCertificate(args: {
    type: Base64String
    serialNumber: Base64String
    certifier: PubKeyHex
  }): Promise<{ relinquished: true }> {
    return await this.invoke('relinquishCertificate', args)
  }

  async discoverByIdentityKey(args: {
    identityKey: PubKeyHex
    limit?: PositiveIntegerDefault10Max10000
    offset?: PositiveIntegerOrZero
  }): Promise<{
    totalCertificates: PositiveIntegerOrZero
    certificates: Array<{
      type: Base64String
      subject: PubKeyHex
      serialNumber: Base64String
      certifier: PubKeyHex
      revocationOutpoint: OutpointString
      signature: HexString
      fields: Record<CertificateFieldNameUnder50Bytes, Base64String>
      certifierInfo: {
        name: EntityNameStringMax100Bytes
        iconUrl: EntityIconURLStringMax500Bytes
        description: DescriptionString5to50Bytes
        trust: PositiveIntegerMax10
      }
      publiclyRevealedKeyring: Record<
        CertificateFieldNameUnder50Bytes,
        Base64String
      >
      decryptedFields: Record<CertificateFieldNameUnder50Bytes, string>
    }>
  }> {
    return await this.invoke('discoverByIdentityKey', args)
  }

  async discoverByAttributes(args: {
    attributes: Record<CertificateFieldNameUnder50Bytes, string>
    limit?: PositiveIntegerDefault10Max10000
    offset?: PositiveIntegerOrZero
  }): Promise<{
    totalCertificates: PositiveIntegerOrZero
    certificates: Array<{
      type: Base64String
      subject: PubKeyHex
      serialNumber: Base64String
      certifier: PubKeyHex
      revocationOutpoint: OutpointString
      signature: HexString
      fields: Record<CertificateFieldNameUnder50Bytes, Base64String>
      certifierInfo: {
        name: EntityNameStringMax100Bytes
        iconUrl: EntityIconURLStringMax500Bytes
        description: DescriptionString5to50Bytes
        trust: PositiveIntegerMax10
      }
      publiclyRevealedKeyring: Record<
        CertificateFieldNameUnder50Bytes,
        Base64String
      >
      decryptedFields: Record<CertificateFieldNameUnder50Bytes, string>
    }>
  }> {
    return await this.invoke('discoverByAttributes', args)
  }

  async isAuthenticated(args: {}): Promise<{ authenticated: true }> {
    return await this.invoke('isAuthenticated', args)
  }

  async waitForAuthentication(args: {}): Promise<{ authenticated: true }> {
    return await this.invoke('waitForAuthentication', args)
  }

  async getHeight(args: {}): Promise<{ height: PositiveInteger }> {
    return await this.invoke('getHeight', args)
  }

  async getHeaderForHeight(args: {
    height: PositiveInteger
  }): Promise<{ header: HexString }> {
    return await this.invoke('getHeaderForHeight', args)
  }

  async getNetwork(args: {}): Promise<{ network: 'mainnet' | 'testnet' }> {
    return await this.invoke('getNetwork', args)
  }

  async getVersion(args: {}): Promise<{ version: VersionString7To30Bytes }> {
    return await this.invoke('getVersion', args)
  }
}
