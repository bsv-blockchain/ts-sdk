import {
  WalletInterface,
  CreateActionArgs,
  CreateActionResult,
  SignActionArgs,
  SignActionResult,
  AbortActionArgs,
  AbortActionResult,
  ListActionsArgs,
  ListActionsResult,
  InternalizeActionArgs,
  InternalizeActionResult,
  ListOutputsArgs,
  ListOutputsResult,
  RelinquishOutputArgs,
  RelinquishOutputResult,
  GetPublicKeyArgs,
  GetPublicKeyResult,
  RevealCounterpartyKeyLinkageArgs,
  RevealCounterpartyKeyLinkageResult,
  RevealSpecificKeyLinkageArgs,
  RevealSpecificKeyLinkageResult,
  WalletEncryptArgs,
  WalletEncryptResult,
  WalletDecryptArgs,
  WalletDecryptResult,
  CreateHmacArgs,
  CreateHmacResult,
  VerifyHmacArgs,
  VerifyHmacResult,
  CreateSignatureArgs,
  CreateSignatureResult,
  VerifySignatureArgs,
  VerifySignatureResult,
  AcquireCertificateArgs,
  AcquireCertificateResult,
  ListCertificatesArgs,
  ListCertificatesResult,
  ProveCertificateArgs,
  ProveCertificateResult,
  RelinquishCertificateArgs,
  RelinquishCertificateResult,
  DiscoverByIdentityKeyArgs,
  DiscoverCertificatesResult,
  DiscoverByAttributesArgs,
  AuthenticatedResult,
  GetHeightResult,
  GetHeaderArgs,
  GetHeaderResult,
  GetNetworkResult,
  GetVersionResult
} from '../Wallet.interfaces.js'
import { CallType } from './WalletWireCalls.js'

/**
 * Abstract base class for WalletInterface substrates that delegate all
 * wallet method calls through an `invoke` transport mechanism.
 *
 * Subclasses only need to implement the `invoke` method to provide
 * the specific transport (e.g. XDM postMessage, ReactNative bridge).
 */
export abstract class InvokableWalletBase implements WalletInterface {
  abstract invoke(call: CallType, args: any): Promise<any>

  async createAction(args: CreateActionArgs): Promise<CreateActionResult> {
    return await this.invoke('createAction', args)
  }

  async signAction(args: SignActionArgs): Promise<SignActionResult> {
    return await this.invoke('signAction', args)
  }

  async abortAction(args: AbortActionArgs): Promise<AbortActionResult> {
    return await this.invoke('abortAction', args)
  }

  async listActions(args: ListActionsArgs): Promise<ListActionsResult> {
    return await this.invoke('listActions', args)
  }

  async internalizeAction(args: InternalizeActionArgs): Promise<InternalizeActionResult> {
    return await this.invoke('internalizeAction', args)
  }

  async listOutputs(args: ListOutputsArgs): Promise<ListOutputsResult> {
    return await this.invoke('listOutputs', args)
  }

  async relinquishOutput(args: RelinquishOutputArgs): Promise<RelinquishOutputResult> {
    return await this.invoke('relinquishOutput', args)
  }

  async getPublicKey(args: GetPublicKeyArgs): Promise<GetPublicKeyResult> {
    return await this.invoke('getPublicKey', args)
  }

  async revealCounterpartyKeyLinkage(args: RevealCounterpartyKeyLinkageArgs): Promise<RevealCounterpartyKeyLinkageResult> {
    return await this.invoke('revealCounterpartyKeyLinkage', args)
  }

  async revealSpecificKeyLinkage(args: RevealSpecificKeyLinkageArgs): Promise<RevealSpecificKeyLinkageResult> {
    return await this.invoke('revealSpecificKeyLinkage', args)
  }

  async encrypt(args: WalletEncryptArgs): Promise<WalletEncryptResult> {
    return await this.invoke('encrypt', args)
  }

  async decrypt(args: WalletDecryptArgs): Promise<WalletDecryptResult> {
    return await this.invoke('decrypt', args)
  }

  async createHmac(args: CreateHmacArgs): Promise<CreateHmacResult> {
    return await this.invoke('createHmac', args)
  }

  async verifyHmac(args: VerifyHmacArgs): Promise<VerifyHmacResult> {
    return await this.invoke('verifyHmac', args)
  }

  async createSignature(args: CreateSignatureArgs): Promise<CreateSignatureResult> {
    return await this.invoke('createSignature', args)
  }

  async verifySignature(args: VerifySignatureArgs): Promise<VerifySignatureResult> {
    return await this.invoke('verifySignature', args)
  }

  async acquireCertificate(args: AcquireCertificateArgs): Promise<AcquireCertificateResult> {
    return await this.invoke('acquireCertificate', args)
  }

  async listCertificates(args: ListCertificatesArgs): Promise<ListCertificatesResult> {
    return await this.invoke('listCertificates', args)
  }

  async proveCertificate(args: ProveCertificateArgs): Promise<ProveCertificateResult> {
    return await this.invoke('proveCertificate', args)
  }

  async relinquishCertificate(args: RelinquishCertificateArgs): Promise<RelinquishCertificateResult> {
    return await this.invoke('relinquishCertificate', args)
  }

  async discoverByIdentityKey(args: DiscoverByIdentityKeyArgs): Promise<DiscoverCertificatesResult> {
    return await this.invoke('discoverByIdentityKey', args)
  }

  async discoverByAttributes(args: DiscoverByAttributesArgs): Promise<DiscoverCertificatesResult> {
    return await this.invoke('discoverByAttributes', args)
  }

  async isAuthenticated(args: {}): Promise<AuthenticatedResult> {
    return await this.invoke('isAuthenticated', args)
  }

  async waitForAuthentication(args: {}): Promise<AuthenticatedResult> {
    return await this.invoke('waitForAuthentication', args)
  }

  async getHeight(args: {}): Promise<GetHeightResult> {
    return await this.invoke('getHeight', args)
  }

  async getHeaderForHeight(args: GetHeaderArgs): Promise<GetHeaderResult> {
    return await this.invoke('getHeaderForHeight', args)
  }

  async getNetwork(args: {}): Promise<GetNetworkResult> {
    return await this.invoke('getNetwork', args)
  }

  async getVersion(args: {}): Promise<GetVersionResult> {
    return await this.invoke('getVersion', args)
  }
}
