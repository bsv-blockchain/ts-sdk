import {
  AcquireCertificateArgs,
  AcquireCertificateResult,
  Base64String,
  BasketStringUnder300Bytes,
  BooleanDefaultFalse,
  Byte,
  CertificateFieldNameUnder50Bytes,
  CreateActionArgs,
  CreateActionResult,
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
  OriginatorDomainNameStringUnder250Bytes,
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
  VersionString7To30Bytes,
  WalletInterface,
  AuthenticatedResult
} from './Wallet.interfaces.js'
import WindowCWISubstrate from './substrates/window.CWI.js'
import XDMSubstrate from './substrates/XDM.js'
import WalletWireTransceiver from './substrates/WalletWireTransceiver.js'
import HTTPWalletWire from './substrates/HTTPWalletWire.js'
import HTTPWalletJSON from './substrates/HTTPWalletJSON.js'
import ReactNativeWebView from './substrates/ReactNativeWebView.js'
import {
  validateAbortActionArgs,
  validateAcquireDirectCertificateArgs,
  validateAcquireIssuanceCertificateArgs,
  validateCreateActionArgs,
  validateDiscoverByAttributesArgs,
  validateDiscoverByIdentityKeyArgs,
  validateInternalizeActionArgs,
  validateListActionsArgs,
  validateListCertificatesArgs,
  validateListOutputsArgs,
  validateProveCertificateArgs,
  validateRelinquishCertificateArgs,
  validateRelinquishOutputArgs,
  validateSignActionArgs
} from './validationHelpers.js'
import { WERR_INVALID_PARAMETER } from './WERR_INVALID_PARAMETER.js'

const MAX_XDM_RESPONSE_WAIT = 200

/**
 * The SDK is how applications communicate with wallets over a communications substrate.
 */
export default class WalletClient implements WalletInterface {
  public substrate: 'auto' | WalletInterface
  originator?: OriginatorDomainNameStringUnder250Bytes
  constructor (
    substrate:
    | 'auto'
    | 'Cicada'
    | 'XDM'
    | 'window.CWI'
    | 'json-api'
    | 'react-native'
    | 'secure-json-api'
    | WalletInterface = 'auto',
    originator?: OriginatorDomainNameStringUnder250Bytes
  ) {
    if (substrate === 'Cicada') {
      substrate = new WalletWireTransceiver(new HTTPWalletWire(originator))
    }
    if (substrate === 'window.CWI') substrate = new WindowCWISubstrate()
    if (substrate === 'XDM') substrate = new XDMSubstrate()
    if (substrate === 'json-api') substrate = new HTTPWalletJSON(originator)
    if (substrate === 'react-native') substrate = new ReactNativeWebView(originator)
    if (substrate === 'secure-json-api') substrate = new HTTPWalletJSON(originator, 'https://localhost:2121')
    this.substrate = substrate
    this.originator = originator
  }

  async connectToSubstrate (): Promise<void> {
    if (typeof this.substrate === 'object') {
      return // substrate is already connected
    }

    const attemptSubstrate = async (factory: () => WalletInterface, timeout?: number): Promise<{ success: boolean, sub?: WalletInterface }> => {
      try {
        const sub = factory()
        let result
        if (typeof timeout === 'number') {
          result = await Promise.race([
            sub.getVersion({}),
            new Promise<never>((_resolve, reject) =>
              setTimeout(() => reject(new Error('Timed out.')), timeout)
            )
          ])
        } else {
          result = await sub.getVersion({})
        }
        if (typeof result !== 'object' || typeof result.version !== 'string') {
          return { success: false }
        }
        return { success: true, sub }
      } catch {
        return { success: false }
      }
    }

    // Try all substrates concurrently, select first available by priority order
    const fastAttempts = [
      attemptSubstrate(() => new WindowCWISubstrate()),
      attemptSubstrate(() => new WalletWireTransceiver(new HTTPWalletWire(this.originator))),
      attemptSubstrate(() => new HTTPWalletJSON(this.originator, 'https://localhost:2121')),
      attemptSubstrate(() => new HTTPWalletJSON(this.originator)),
      attemptSubstrate(() => new ReactNativeWebView(this.originator))
    ]

    const fastResults = await Promise.allSettled(fastAttempts)
    const fastSuccessful = fastResults
      .filter((r): r is PromiseFulfilledResult<{ success: boolean, sub?: WalletInterface }> => r.status === 'fulfilled' && r.value.success && r.value.sub !== undefined)
      .map(r => r.value.sub as WalletInterface)

    if (fastSuccessful.length > 0) {
      this.substrate = fastSuccessful[0]
      return
    }

    // Fall back to slower XDM substrate
    const xdmResult = await attemptSubstrate(() => new XDMSubstrate(), MAX_XDM_RESPONSE_WAIT)
    if (xdmResult.success && xdmResult.sub !== undefined) {
      this.substrate = xdmResult.sub
    } else {
      throw new Error(
        'No wallet available over any communication substrate. Install a BSV wallet today!'
      )
    }
  }

  async createAction (args: CreateActionArgs): Promise<CreateActionResult> {
    validateCreateActionArgs(args)
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).createAction(
      args,
      this.originator
    )
  }

  async signAction (args: SignActionArgs): Promise<SignActionResult> {
    validateSignActionArgs(args)
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).signAction(
      args,
      this.originator
    )
  }

  async abortAction (args: {
    reference: Base64String
  }): Promise<{ aborted: true }> {
    validateAbortActionArgs(args)
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).abortAction(
      args,
      this.originator
    )
  }

  async listActions (args: ListActionsArgs): Promise<ListActionsResult> {
    validateListActionsArgs(args)
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).listActions(
      args,
      this.originator
    )
  }

  async internalizeAction (
    args: InternalizeActionArgs
  ): Promise<{ accepted: true }> {
    validateInternalizeActionArgs(args)
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).internalizeAction(
      args,
      this.originator
    )
  }

  async listOutputs (args: ListOutputsArgs): Promise<ListOutputsResult> {
    validateListOutputsArgs(args)
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).listOutputs(
      args,
      this.originator
    )
  }

  async relinquishOutput (args: {
    basket: BasketStringUnder300Bytes
    output: OutpointString
  }): Promise<{ relinquished: true }> {
    validateRelinquishOutputArgs(args)
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).relinquishOutput(
      args,
      this.originator
    )
  }

  async getPublicKey (args: {
    identityKey?: true
    protocolID?: [SecurityLevel, ProtocolString5To400Bytes]
    keyID?: KeyIDStringUnder800Bytes
    privileged?: BooleanDefaultFalse
    privilegedReason?: DescriptionString5to50Bytes
    counterparty?: PubKeyHex | 'self' | 'anyone'
    forSelf?: BooleanDefaultFalse
  }): Promise<{ publicKey: PubKeyHex }> {
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).getPublicKey(
      args,
      this.originator
    )
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
      encryptedLinkageProof: Byte[]
    }> {
    await this.connectToSubstrate()
    return await (
      this.substrate as WalletInterface
    ).revealCounterpartyKeyLinkage(args, this.originator)
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
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).revealSpecificKeyLinkage(
      args,
      this.originator
    )
  }

  async encrypt (args: {
    plaintext: Byte[]
    protocolID: [SecurityLevel, ProtocolString5To400Bytes]
    keyID: KeyIDStringUnder800Bytes
    privilegedReason?: DescriptionString5to50Bytes
    counterparty?: PubKeyHex | 'self' | 'anyone'
    privileged?: BooleanDefaultFalse
  }): Promise<{ ciphertext: Byte[] }> {
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).encrypt(
      args,
      this.originator
    )
  }

  async decrypt (args: {
    ciphertext: Byte[]
    protocolID: [SecurityLevel, ProtocolString5To400Bytes]
    keyID: KeyIDStringUnder800Bytes
    privilegedReason?: DescriptionString5to50Bytes
    counterparty?: PubKeyHex | 'self' | 'anyone'
    privileged?: BooleanDefaultFalse
  }): Promise<{ plaintext: Byte[] }> {
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).decrypt(
      args,
      this.originator
    )
  }

  async createHmac (args: {
    data: Byte[]
    protocolID: [SecurityLevel, ProtocolString5To400Bytes]
    keyID: KeyIDStringUnder800Bytes
    privilegedReason?: DescriptionString5to50Bytes
    counterparty?: PubKeyHex | 'self' | 'anyone'
    privileged?: BooleanDefaultFalse
  }): Promise<{ hmac: Byte[] }> {
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).createHmac(
      args,
      this.originator
    )
  }

  async verifyHmac (args: {
    data: Byte[]
    hmac: Byte[]
    protocolID: [SecurityLevel, ProtocolString5To400Bytes]
    keyID: KeyIDStringUnder800Bytes
    privilegedReason?: DescriptionString5to50Bytes
    counterparty?: PubKeyHex | 'self' | 'anyone'
    privileged?: BooleanDefaultFalse
  }): Promise<{ valid: true }> {
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).verifyHmac(
      args,
      this.originator
    )
  }

  async createSignature (args: {
    data?: Byte[]
    hashToDirectlySign?: Byte[]
    protocolID: [SecurityLevel, ProtocolString5To400Bytes]
    keyID: KeyIDStringUnder800Bytes
    privilegedReason?: DescriptionString5to50Bytes
    counterparty?: PubKeyHex | 'self' | 'anyone'
    privileged?: BooleanDefaultFalse
  }): Promise<{ signature: Byte[] }> {
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).createSignature(
      args,
      this.originator
    )
  }

  async verifySignature (args: {
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
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).verifySignature(
      args,
      this.originator
    )
  }

  async acquireCertificate (
    args: AcquireCertificateArgs
  ): Promise<AcquireCertificateResult> {
    if (args.acquisitionProtocol === 'direct') { validateAcquireDirectCertificateArgs(args) } else if (args.acquisitionProtocol === 'issuance') { validateAcquireIssuanceCertificateArgs(args) } else { throw new WERR_INVALID_PARAMETER('acquisitionProtocol', `valid. ${String(args.acquisitionProtocol)} is unrecognized.`) }
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).acquireCertificate(
      args,
      this.originator
    )
  }

  async listCertificates (args: {
    certifiers: PubKeyHex[]
    types: Base64String[]
    limit?: PositiveIntegerDefault10Max10000
    offset?: PositiveIntegerOrZero
    privileged?: BooleanDefaultFalse
    privilegedReason?: DescriptionString5to50Bytes
  }): Promise<ListCertificatesResult> {
    validateListCertificatesArgs(args)
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).listCertificates(
      args,
      this.originator
    )
  }

  async proveCertificate (
    args: ProveCertificateArgs
  ): Promise<ProveCertificateResult> {
    validateProveCertificateArgs(args)
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).proveCertificate(
      args,
      this.originator
    )
  }

  async relinquishCertificate (args: {
    type: Base64String
    serialNumber: Base64String
    certifier: PubKeyHex
  }): Promise<{ relinquished: true }> {
    validateRelinquishCertificateArgs(args)
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).relinquishCertificate(
      args,
      this.originator
    )
  }

  async discoverByIdentityKey (args: {
    identityKey: PubKeyHex
    limit?: PositiveIntegerDefault10Max10000
    offset?: PositiveIntegerOrZero
  }): Promise<DiscoverCertificatesResult> {
    validateDiscoverByIdentityKeyArgs(args)
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).discoverByIdentityKey(
      args,
      this.originator
    )
  }

  async discoverByAttributes (args: {
    attributes: Record<CertificateFieldNameUnder50Bytes, string>
    limit?: PositiveIntegerDefault10Max10000
    offset?: PositiveIntegerOrZero
  }): Promise<DiscoverCertificatesResult> {
    validateDiscoverByAttributesArgs(args)
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).discoverByAttributes(
      args,
      this.originator
    )
  }

  async isAuthenticated (args: object = {}): Promise<AuthenticatedResult> {
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).isAuthenticated(
      args,
      this.originator
    )
  }

  async waitForAuthentication (args: object = {}): Promise<{ authenticated: true }> {
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).waitForAuthentication(
      args,
      this.originator
    )
  }

  async getHeight (args: object = {}): Promise<{ height: PositiveInteger }> {
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).getHeight(
      args,
      this.originator
    )
  }

  async getHeaderForHeight (args: {
    height: PositiveInteger
  }): Promise<{ header: HexString }> {
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).getHeaderForHeight(
      args,
      this.originator
    )
  }

  async getNetwork (args: object = {}): Promise<{ network: 'mainnet' | 'testnet' }> {
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).getNetwork(
      args,
      this.originator
    )
  }

  async getVersion (
    args: object = {}
  ): Promise<{ version: VersionString7To30Bytes }> {
    await this.connectToSubstrate()
    return await (this.substrate as WalletInterface).getVersion(
      args,
      this.originator
    )
  }
}
