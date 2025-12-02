// @ts-nocheck
import PrivateKey from '../../../primitives/PrivateKey.js'
import {
  ProtoWallet,
  WalletInterface,
  CreateActionResult,
  SignActionResult,
  AbortActionResult,
  ListActionsResult,
  InternalizeActionResult,
  ListOutputsResult,
  RelinquishOutputResult,
  AcquireCertificateResult,
  ListCertificatesResult,
  ProveCertificateResult,
  RelinquishCertificateResult,
  DiscoverCertificatesResult,
  GetHeightResult,
  GetHeaderResult,
  KeyDeriverApi,
  KeyDeriver,
  GetPublicKeyArgs,
  PubKeyHex,
  AuthenticatedResult,
  GetNetworkResult,
  GetVersionResult,
  CachedKeyDeriver
} from '../../../wallet/index.js'

// Test Mock wallet which extends ProtoWallet but still implements Wallet interface
// Unsupported methods throw
export class CompletedProtoWallet
  extends ProtoWallet
  implements WalletInterface {
  keyDeriver: KeyDeriver
  constructor (rootKeyOrKeyDeriver: PrivateKey | 'anyone' | KeyDeriverApi) {
    super(rootKeyOrKeyDeriver)

    if (rootKeyOrKeyDeriver instanceof KeyDeriver) {
      this.keyDeriver = rootKeyOrKeyDeriver
    } else if (
      typeof rootKeyOrKeyDeriver === 'string' ||
      rootKeyOrKeyDeriver instanceof PrivateKey
    ) {
      this.keyDeriver = new CachedKeyDeriver(rootKeyOrKeyDeriver)
    } else {
      throw new Error('Invalid key deriver provided')
    }
  }

  async isAuthenticated (
  ): Promise<AuthenticatedResult> {
    throw new Error('not implemented')
  }

  async waitForAuthentication (

  ): Promise<AuthenticatedResult> {
    throw new Error('not implemented')
  }

  async getNetwork (

  ): Promise<GetNetworkResult> {
    throw new Error('not implemented')
  }

  async getVersion (

  ): Promise<GetVersionResult> {
    throw new Error('not implemented')
  }

  async getPublicKey (
    args: GetPublicKeyArgs
  ): Promise<{ publicKey: PubKeyHex }> {
    if (args.privileged === true) {
      throw new Error('no privilege support')
    }

    if (args.identityKey === true) {
      if (this.keyDeriver === null || this.keyDeriver === undefined) {
        throw new Error('keyDeriver is not initialized')
      }

      return { publicKey: this.keyDeriver.rootKey.toPublicKey().toString() }
    } else {
      if (args.protocolID == null || typeof args.keyID !== 'string' || args.keyID.trim() === '') {
        throw new Error(
          'protocolID and keyID are required if identityKey is false or undefined.'
        )
      }

      if (this.keyDeriver === null || this.keyDeriver === undefined) {
        throw new Error('keyDeriver is not initialized')
      }

      return {
        publicKey: this.keyDeriver
          .derivePublicKey(
            args.protocolID,
            args.keyID,
            typeof args.counterparty === 'string' && args.counterparty.trim() !== ''
              ? args.counterparty
              : 'self',
            Boolean(args.forSelf)
          )
          .toString()
      }
    }
  }

  async createAction (

  ): Promise<CreateActionResult> {
    throw new Error('not implemented')
  }

  async signAction (

  ): Promise<SignActionResult> {
    throw new Error('not implemented')
  }

  async abortAction (

  ): Promise<AbortActionResult> {
    throw new Error('not implemented')
  }

  async listActions (

  ): Promise<ListActionsResult> {
    throw new Error('not implemented')
  }

  async internalizeAction (

  ): Promise<InternalizeActionResult> {
    throw new Error('not implemented')
  }

  async listOutputs (

  ): Promise<ListOutputsResult> {
    throw new Error('not implemented')
  }

  async relinquishOutput (

  ): Promise<RelinquishOutputResult> {
    throw new Error('not implemented')
  }

  async acquireCertificate (

  ): Promise<AcquireCertificateResult> {
    throw new Error('not implemented')
  }

  async listCertificates (

  ): Promise<ListCertificatesResult> {
    throw new Error('not implemented')
  }

  async proveCertificate (

  ): Promise<ProveCertificateResult> {
    throw new Error('not implemented')
  }

  async relinquishCertificate (

  ): Promise<RelinquishCertificateResult> {
    throw new Error('not implemented')
  }

  async discoverByIdentityKey (

  ): Promise<DiscoverCertificatesResult> {
    throw new Error('not implemented')
  }

  async discoverByAttributes (

  ): Promise<DiscoverCertificatesResult> {
    throw new Error('not implemented')
  }

  async getHeight (

  ): Promise<GetHeightResult> {
    throw new Error('not implemented')
  }

  async getHeaderForHeight (

  ): Promise<GetHeaderResult> {
    throw new Error('not implemented')
  }
}
