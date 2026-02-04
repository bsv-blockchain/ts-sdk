import { Peer } from '../../auth/Peer.js'
import { AuthMessage, Transport } from '../../auth/types.js'
import { jest } from '@jest/globals'
import { WalletInterface } from '../../wallet/Wallet.interfaces.js'
import { Utils, PrivateKey } from '../../primitives/index.js'
import { VerifiableCertificate } from '../../auth/certificates/VerifiableCertificate.js'
import { MasterCertificate } from '../../auth/certificates/MasterCertificate.js'
import { getVerifiableCertificates } from '../../auth/utils/getVerifiableCertificates.js'
import { CompletedProtoWallet } from '../certificates/__tests/CompletedProtoWallet.js'
import { SimplifiedFetchTransport } from '../../auth/transports/SimplifiedFetchTransport.js'

const certifierPrivKey = new PrivateKey(21)
const alicePrivKey = new PrivateKey(22)
const bobPrivKey = new PrivateKey(23)
const DUMMY_REVOCATION_OUTPOINT_HEX = '00'.repeat(36)

jest.mock('../../auth/utils/getVerifiableCertificates')

class LocalTransport implements Transport {
  private peerTransport?: LocalTransport
  private onDataCallback?: (message: AuthMessage) => void

  connect(peerTransport: LocalTransport): void {
    this.peerTransport = peerTransport
    peerTransport.peerTransport = this
  }

  async send(message: AuthMessage): Promise<void> {
    if (
      this.peerTransport?.onDataCallback !== undefined &&
      this.peerTransport?.onDataCallback !== null
    ) {
      // Simulate message delivery by calling the onData callback of the peer
      this.peerTransport.onDataCallback(message)
    } else {
      throw new Error(
        'Peer transport is not connected or not listening for data.'
      )
    }
  }

  async onData(
    callback: (message: AuthMessage) => void
  ): Promise<void> {
    this.onDataCallback = callback
  }
}

function waitForNextGeneralMessage (
  peer: Peer,
  handler?: (senderPublicKey: string, payload: number[]) => void
): Promise<void> {
  return new Promise(resolve => {
    const listenerId = peer.listenForGeneralMessages((senderPublicKey, payload) => {
      peer.stopListeningForGeneralMessages(listenerId)
      if (handler !== undefined) handler(senderPublicKey, payload)
      resolve()
    })
  })
}

describe('Peer class mutual authentication and certificate exchange', () => {
  let walletA: WalletInterface, walletB: WalletInterface
  let transportA: LocalTransport, transportB: LocalTransport
  let alice: Peer, bob: Peer
  let certificatesReceivedByAlice: VerifiableCertificate[] | undefined
  let certificatesReceivedByBob: VerifiableCertificate[] | undefined

  const certificateType = Utils.toBase64(new Array(32).fill(1))
  // const certificateSerialNumber = Utils.toBase64(new Array(32).fill(2))
  const certifierPrivateKey = certifierPrivKey
  const certifierPublicKey = certifierPrivateKey.toPublicKey().toString()
  const certificatesToRequest = {
    certifiers: [certifierPublicKey],
    types: { [certificateType]: ['name', 'email'] }
  }

  const aliceFields = {
    name: 'Alice',
    email: 'alice@example.com',
    libraryCardNumber: 'A123456'
  }
  const bobFields = {
    name: 'Bob',
    email: 'bob@example.com',
    libraryCardNumber: 'B654321'
  }

  async function createMasterCertificate(
    subjectWallet: WalletInterface,
    fields: Record<string, string>
  ): Promise<MasterCertificate> {
    const subjectPubKey = (
      await subjectWallet.getPublicKey({ identityKey: true })
    ).publicKey
    const certifierWallet = new CompletedProtoWallet(certifierPrivateKey)

    // Issue a new MasterCertificate for the subject (e.g. Alice/Bob)
    const masterCertificate =
      await MasterCertificate.issueCertificateForSubject(
        certifierWallet,
        subjectPubKey,
        fields,
        certificateType,
        async () => DUMMY_REVOCATION_OUTPOINT_HEX
      )

    // For test consistency, you could override the auto-generated serialNumber:
    // masterCertificate.signature = undefined
    // masterCertificate.serialNumber = certificateSerialNumber
    // await masterCertificate.sign(certifierWallet)

    return masterCertificate
  }

  async function createVerifiableCertificate(
    masterCertificate: MasterCertificate,
    wallet: WalletInterface,
    verifierIdentityKey: string,
    fieldsToReveal: string[]
  ): Promise<VerifiableCertificate> {
    const certifierWallet = new CompletedProtoWallet(certifierPrivateKey)

    if (certifierWallet.keyDeriver === undefined) {
      throw new Error('KeyDeriver must be defined for test!')
    }

    const keyringForVerifier = await MasterCertificate.createKeyringForVerifier(
      wallet,
      certifierWallet.keyDeriver.identityKey,
      verifierIdentityKey,
      masterCertificate.fields,
      fieldsToReveal,
      masterCertificate.masterKeyring,
      masterCertificate.serialNumber
    )
    return new VerifiableCertificate(
      masterCertificate.type,
      masterCertificate.serialNumber,
      masterCertificate.subject,
      masterCertificate.certifier,
      masterCertificate.revocationOutpoint,
      masterCertificate.fields,
      keyringForVerifier,
      masterCertificate.signature
    )
  }

  function setupPeers(
    aliceRequests: boolean,
    bobRequests: boolean,
    options: {
      aliceCertsToRequest?: typeof certificatesToRequest
      bobCertsToRequest?: typeof certificatesToRequest
    } = {}
  ): any {
    const {
      aliceCertsToRequest = certificatesToRequest,
      bobCertsToRequest = certificatesToRequest
    } = options

    alice = new Peer(
      walletA,
      transportA,
      aliceRequests ? aliceCertsToRequest : undefined
    )
    bob = new Peer(
      walletB,
      transportB,
      bobRequests ? bobCertsToRequest : undefined
    )

    const aliceReceivedCertificates = new Promise<void>((resolve) => {
      alice.listenForCertificatesReceived((senderPublicKey, certificates) => {
        certificatesReceivedByAlice = certificates
        resolve()
      })
    })

    const bobReceivedCertificates = new Promise<void>((resolve) => {
      bob.listenForCertificatesReceived((senderPublicKey, certificates) => {
        certificatesReceivedByBob = certificates
        resolve()
      })
    })

    return { aliceReceivedCertificates, bobReceivedCertificates }
  }

  async function mockGetVerifiableCertificates(
    aliceCertificate: VerifiableCertificate | undefined,
    bobCertificate: VerifiableCertificate | undefined,
    alicePubKey: string,
    bobPubKey: string
  ): Promise<any> {
    ; (getVerifiableCertificates as jest.Mock).mockImplementation(
      async (wallet, _, verifierIdentityKey) => {
        if (wallet === walletA && verifierIdentityKey === bobPubKey) {
          return aliceCertificate !== null && aliceCertificate !== undefined
            ? await Promise.resolve([aliceCertificate])
            : await Promise.resolve([])
        } else if (wallet === walletB && verifierIdentityKey === alicePubKey) {
          return bobCertificate !== null && bobCertificate !== undefined
            ? await Promise.resolve([bobCertificate])
            : await Promise.resolve([])
        }
        return await Promise.resolve([])
      }
    )
  }

  beforeEach(async () => {
    transportA = new LocalTransport()
    transportB = new LocalTransport()
    transportA.connect(transportB)

    certificatesReceivedByAlice = []
    certificatesReceivedByBob = []

    walletA = new CompletedProtoWallet(alicePrivKey)
    walletB = new CompletedProtoWallet(bobPrivKey)
  })

  it('Neither Alice nor Bob request certificates, mutual authentication completes successfully', async () => {
    setupPeers(
      false,
      false
    )

    const bobReceivedGeneralMessage = new Promise<void>((resolve) => {
      bob.listenForGeneralMessages((senderPublicKey, payload) => {
        (async () => {
          await bob.toPeer(Utils.toArray('Hello Alice!'), senderPublicKey)
          resolve()
        })().catch(e => { })
      })
    })
    const aliceReceivedGeneralMessage = new Promise<void>((resolve) => {
      alice.listenForGeneralMessages((senderPublicKey, payload) => {
        resolve()
      })
    })

    await alice.toPeer(Utils.toArray('Hello Bob!'))
    await bobReceivedGeneralMessage
    await aliceReceivedGeneralMessage

    expect(certificatesReceivedByAlice).toEqual([])
    expect(certificatesReceivedByBob).toEqual([])
  }, 15000)

  it('Alice talks to Bob across two devices, Bob can respond across both sessions', async () => {
    const transportA1 = new LocalTransport()
    const transportA2 = new LocalTransport()
    const transportB = new LocalTransport()
    transportA1.connect(transportB)
    const aliceKey = alicePrivKey
    const walletA1 = new CompletedProtoWallet(aliceKey)
    const walletA2 = new CompletedProtoWallet(aliceKey)
    const walletB = new CompletedProtoWallet(alicePrivKey)
    const aliceFirstDevice = new Peer(
      walletA1,
      transportA1
    )
    const aliceOtherDevice = new Peer(
      walletA2,
      transportA2
    )
    const bob = new Peer(
      walletB,
      transportB
    )
    const alice1MessageHandler = jest.fn()
    const alice2MessageHandler = jest.fn()
    const bobMessageHandler = jest.fn()

    const bobReceivedGeneralMessage = new Promise<void>((resolve) => {
      bob.listenForGeneralMessages((senderPublicKey, payload) => {
        (async () => {
          await bob.toPeer(Utils.toArray('Hello Alice!'), senderPublicKey)
          resolve()
          bobMessageHandler(senderPublicKey, payload)
        })().catch(e => { })
      })
    })
    const aliceReceivedGeneralMessageOnFirstDevice = waitForNextGeneralMessage(
      aliceFirstDevice,
      alice1MessageHandler
    )
    const aliceReceivedGeneralMessageOnOtherDevice = waitForNextGeneralMessage(
      aliceOtherDevice,
      alice2MessageHandler
    )

    await aliceFirstDevice.toPeer(Utils.toArray('Hello Bob!'))
    await bobReceivedGeneralMessage
    await aliceReceivedGeneralMessageOnFirstDevice
    transportA2.connect(transportB)
    await aliceOtherDevice.toPeer(Utils.toArray('Hello Bob from my other device!'))
    await aliceReceivedGeneralMessageOnOtherDevice
    transportA1.connect(transportB)
    const waitForSecondMessage = waitForNextGeneralMessage(
      aliceFirstDevice,
      alice1MessageHandler
    )
    await aliceFirstDevice.toPeer(
      Utils.toArray('Back on my first device now, Bob! Can you still hear me?')
    )
    await waitForSecondMessage
    expect(alice1MessageHandler.mock.calls.length).toEqual(2)
  }, 30000)

  it('Bob requests certificates from Alice, Alice does not request any from Bob', async () => {
    const alicePubKey = (await walletA.getPublicKey({ identityKey: true }))
      .publicKey
    const bobPubKey = (await walletB.getPublicKey({ identityKey: true }))
      .publicKey

    const aliceMasterCertificate = await createMasterCertificate(
      walletA,
      aliceFields
    )
    const aliceVerifiableCertificate = await createVerifiableCertificate(
      aliceMasterCertificate,
      walletA,
      bobPubKey,
      certificatesToRequest.types[certificateType]
    )

    const { bobReceivedCertificates } = setupPeers(false, true)

    await mockGetVerifiableCertificates(
      aliceVerifiableCertificate,
      undefined,
      alicePubKey,
      bobPubKey
    )

    // Initiate handshake ONLY
    await alice.getAuthenticatedSession(bobPubKey)

    // Wait for Bob to receive Alice's certificates
    await bobReceivedCertificates

    expect(certificatesReceivedByAlice).toEqual([])
    expect(certificatesReceivedByBob).toEqual([aliceVerifiableCertificate])
  }, 15000)

  describe('propagateTransportError', () => {
    const createPeerInstance = (): Peer => {
      const transport: Transport = {
        send: jest.fn(async (_message: AuthMessage) => {}),
        onData: async () => {}
      }
      return new Peer({} as WalletInterface, transport)
    }

    it('adds peer identity details to existing errors', () => {
      const peer = createPeerInstance()
      const originalError = new Error('send failed')

      let thrown: Error | undefined
      try {
        (peer as any).propagateTransportError('peer-public-key', originalError)
      } catch (error) {
        thrown = error as Error
      }

      expect(thrown).toBe(originalError)
      expect((thrown as any).details).toEqual({ peerIdentityKey: 'peer-public-key' })
    })

    it('preserves existing details when appending peer identity', () => {
      const peer = createPeerInstance()
      const originalError = new Error('existing details')
      ;(originalError as any).details = { status: 503 }

      let thrown: Error | undefined
      try {
        (peer as any).propagateTransportError('peer-public-key', originalError)
      } catch (error) {
        thrown = error as Error
      }

      expect(thrown).toBe(originalError)
      expect((thrown as any).details).toEqual({
        status: 503,
        peerIdentityKey: 'peer-public-key'
      })
    })

    it('wraps non-error values with a helpful message', () => {
      const peer = createPeerInstance()
      expect(() => (peer as any).propagateTransportError(undefined, 'timeout')).toThrow(
        'Failed to send message to peer unknown: timeout'
      )
    })
  })

  it('Alice requests Bob to present his library card before lending him a book', async () => {
    const alicePubKey = (await walletA.getPublicKey({ identityKey: true })).publicKey
    const bobPubKey = (await walletB.getPublicKey({ identityKey: true })).publicKey

    const bobMasterCertificate = await createMasterCertificate(walletB, bobFields)
    const bobVerifiableCertificate = await createVerifiableCertificate(
      bobMasterCertificate,
      walletB,
      alicePubKey,
      ['libraryCardNumber']
    )

    const aliceCertificatesToRequest = {
      certifiers: [certifierPublicKey],
      types: { [certificateType]: ['libraryCardNumber'] }
    }

    const { aliceReceivedCertificates } = setupPeers(true, false, {
      aliceCertsToRequest: aliceCertificatesToRequest
    })

    await mockGetVerifiableCertificates(
      undefined,
      bobVerifiableCertificate,
      alicePubKey,
      bobPubKey
    )

    const aliceAcceptedLibraryCard = jest.fn()

    alice.listenForCertificatesReceived(async (_sender, certificates) => {
      for (const cert of certificates) {
        const decrypted = await cert.decryptFields(walletA)
        if (decrypted.libraryCardNumber !== undefined) {
          aliceAcceptedLibraryCard()
        }
      }
    })

    // 🔑 Correct trigger: certificate request, NOT general message
    await alice.requestCertificates(aliceCertificatesToRequest, bobPubKey)

    await aliceReceivedCertificates

    expect(aliceAcceptedLibraryCard).toHaveBeenCalled()
    expect(certificatesReceivedByAlice).toEqual([bobVerifiableCertificate])
    expect(certificatesReceivedByBob).toEqual([])
  }, 15000)

  it('Bob requests additional certificates from Alice after initial communication', async () => {
    const alicePubKey = (await walletA.getPublicKey({ identityKey: true }))
      .publicKey
    const bobPubKey = (await walletB.getPublicKey({ identityKey: true }))
      .publicKey

    const aliceMasterCertificate = await createMasterCertificate(walletA, {
      name: 'Alice'
    })

    const aliceVerifiableCertificate = await createVerifiableCertificate(
      aliceMasterCertificate,
      walletA,
      bobPubKey,
      ['name']
    )

    const { bobReceivedCertificates } = setupPeers(false, true)

    await mockGetVerifiableCertificates(
      aliceVerifiableCertificate,
      undefined,
      alicePubKey,
      bobPubKey
    )

    // ---- Initial communication = handshake + initial cert exchange
    await alice.getAuthenticatedSession(bobPubKey)
    await bobReceivedCertificates

    // ---- Bob requests additional certificates AFTER validation
    const bobReceivedAdditionalCertificates = new Promise<void>((resolve) => {
      bob.listenForCertificatesReceived(async (senderPublicKey, certificates) => {
        if (certificates.length > 0) {
          for (const cert of certificates) {
            await cert.decryptFields(walletB)
          }
          resolve()
        }
      })
    })

    await bob.requestCertificates(certificatesToRequest, alicePubKey)
    await bobReceivedAdditionalCertificates

    expect(certificatesReceivedByBob).toEqual([aliceVerifiableCertificate])
  }, 15000)

  it('Bob requests Alice to provide her membership status before granting access to premium content', async () => {
    const alicePubKey = (await walletA.getPublicKey({ identityKey: true }))
      .publicKey
    const bobPubKey = (await walletB.getPublicKey({ identityKey: true }))
      .publicKey

    const aliceMasterCertificate = await createMasterCertificate(walletA, {
      ...aliceFields,
      membershipStatus: 'Gold'
    })

    const aliceVerifiableCertificate = await createVerifiableCertificate(
      aliceMasterCertificate,
      walletA,
      bobPubKey,
      ['membershipStatus']
    )

    const bobCertificatesToRequest = {
      certifiers: [certifierPublicKey],
      types: { [certificateType]: ['membershipStatus'] }
    }

    const { bobReceivedCertificates } = setupPeers(false, true, {
      bobCertsToRequest: bobCertificatesToRequest
    })

    await mockGetVerifiableCertificates(
      aliceVerifiableCertificate,
      undefined,
      alicePubKey,
      bobPubKey
    )

    const bobAcceptedMembershipStatus = jest.fn()

    const waitForCerts = new Promise<void>((resolve) => {
      bob.listenForCertificatesReceived(async (_, certificates) => {
        for (const cert of certificates) {
          const decryptedFields = await cert.decryptFields(walletB)
          if (decryptedFields.membershipStatus === 'Gold') {
            bobAcceptedMembershipStatus()
            resolve()
          }
        }
      })
    })

    // ---- INITIAL COMMUNICATION = handshake + certificate exchange
    await alice.getAuthenticatedSession(bobPubKey)
    await bobReceivedCertificates
    await waitForCerts

    // ---- OPTIONAL: now Alice can request premium content
    await alice.toPeer(
      Utils.toArray('I would like to access the premium content.')
    )

    expect(bobAcceptedMembershipStatus).toHaveBeenCalled()
    expect(certificatesReceivedByBob).toEqual([aliceVerifiableCertificate])
    expect(certificatesReceivedByAlice).toEqual([])
  }, 15000)

  it("Both peers require each other's driver's license before carpooling", async () => {
    const alicePubKey = (await walletA.getPublicKey({ identityKey: true })).publicKey
    const bobPubKey = (await walletB.getPublicKey({ identityKey: true })).publicKey

    const aliceMasterCertificate = await createMasterCertificate(walletA, {
      ...aliceFields,
      driversLicenseNumber: 'DLA123456'
    })
    const aliceVerifiableCertificate = await createVerifiableCertificate(
      aliceMasterCertificate,
      walletA,
      bobPubKey,
      ['driversLicenseNumber']
    )

    const bobMasterCertificate = await createMasterCertificate(walletB, {
      ...bobFields,
      driversLicenseNumber: 'DLB654321'
    })
    const bobVerifiableCertificate = await createVerifiableCertificate(
      bobMasterCertificate,
      walletB,
      alicePubKey,
      ['driversLicenseNumber']
    )

    const certificatesToRequestDriversLicense = {
      certifiers: [certifierPublicKey],
      types: { [certificateType]: ['driversLicenseNumber'] }
    }

    const { aliceReceivedCertificates, bobReceivedCertificates } = setupPeers(
      true,
      true,
      {
        aliceCertsToRequest: certificatesToRequestDriversLicense,
        bobCertsToRequest: certificatesToRequestDriversLicense
      }
    )

    await mockGetVerifiableCertificates(
      aliceVerifiableCertificate,
      bobVerifiableCertificate,
      alicePubKey,
      bobPubKey
    )

    // 🔑 Step 1: Alice requests Bob's cert
    await alice.requestCertificates(certificatesToRequestDriversLicense, bobPubKey)
    await aliceReceivedCertificates

    // 🔑 Step 2: Bob requests Alice's cert
    await bob.requestCertificates(certificatesToRequestDriversLicense, alicePubKey)
    await bobReceivedCertificates

    expect(certificatesReceivedByAlice).toEqual([bobVerifiableCertificate])
    expect(certificatesReceivedByBob).toEqual([aliceVerifiableCertificate])

    // 🔓 Step 3: NOW general messages are allowed
    const bobReceivedMessage = new Promise<void>((resolve) => {
      bob.listenForGeneralMessages(() => resolve())
    })

    await alice.toPeer(Utils.toArray('Ready to carpool!'), bobPubKey)
    await bobReceivedMessage
  }, 20000)

  it('Peers accept partial certificates if at least one required field is present', async () => {
    const alicePubKey = (await walletA.getPublicKey({ identityKey: true })).publicKey
    const bobPubKey = (await walletB.getPublicKey({ identityKey: true })).publicKey

    // Alice has name+email, Bob has only email
    const aliceMasterCertificate = await createMasterCertificate(walletA, {
      name: 'Alice',
      email: 'alice@example.com'
    })
    const aliceVerifiableCertificate = await createVerifiableCertificate(
      aliceMasterCertificate,
      walletA,
      bobPubKey,
      ['name', 'email']
    )

    const bobMasterCertificate = await createMasterCertificate(walletB, {
      email: 'bob@example.com'
    })
    const bobVerifiableCertificate = await createVerifiableCertificate(
      bobMasterCertificate,
      walletB,
      alicePubKey,
      ['email']
    )

    const partialCertificatesToRequest = {
      certifiers: [certifierPublicKey],
      types: { [certificateType]: ['name', 'email'] }
    }

    const { aliceReceivedCertificates, bobReceivedCertificates } = setupPeers(
      true,
      true,
      {
        aliceCertsToRequest: partialCertificatesToRequest,
        bobCertsToRequest: partialCertificatesToRequest
      }
    )

    await mockGetVerifiableCertificates(
      aliceVerifiableCertificate,
      bobVerifiableCertificate,
      alicePubKey,
      bobPubKey
    )

    // --- Exchange certs explicitly (no general messages yet) ---
    await alice.requestCertificates(partialCertificatesToRequest, bobPubKey)
    await bob.requestCertificates(partialCertificatesToRequest, alicePubKey)

    await aliceReceivedCertificates
    await bobReceivedCertificates

    // --- Validate "partial" acceptance by decrypting on each side ---
    const aliceDecrypted = await certificatesReceivedByAlice![0].decryptFields(walletA)
    const bobDecrypted = await certificatesReceivedByBob![0].decryptFields(walletB)

    // Alice received Bob's cert which only has email, but request was name+email
    expect(aliceDecrypted.email).toBeDefined()
    // (Bob did not reveal name, so it may be undefined)
    expect(aliceDecrypted.name).toBeUndefined()

    // Bob received Alice's cert which has both name+email
    expect(bobDecrypted.email).toBeDefined()
    expect(bobDecrypted.name).toBeDefined()

    expect(certificatesReceivedByAlice).toEqual([bobVerifiableCertificate])
    expect(certificatesReceivedByBob).toEqual([aliceVerifiableCertificate])

    // --- Optional: now general messages should work (since validation happened) ---
    const bobReceivedGeneralMessage = new Promise<void>((resolve) => {
      bob.listenForGeneralMessages(() => resolve())
    })

    await alice.toPeer(Utils.toArray('Hello Bob!'), bobPubKey)
    await bobReceivedGeneralMessage
  }, 20000)

  describe('Transport Error Handling', () => {
    const privKey = PrivateKey.fromRandom()

    test('Should trigger "Failed to send message to peer" error with network failure', async () => {
      // Create a mock fetch that always fails
      const failingFetch = (jest.fn() as any).mockRejectedValue(new Error('Network connection failed'))
      
      // Create a transport that will fail
      const transport = new SimplifiedFetchTransport('http://localhost:9999', failingFetch)
      
      // Create a peer with the failing transport
      const wallet = new CompletedProtoWallet(privKey)
      const peer = new Peer(wallet, transport)
      
      // Register a dummy onData callback (required before sending)
      await transport.onData(async (message) => {
        // This won't be called due to network failure
      })

      // Try to send a message to peer - this should fail and trigger the error
      try {
        await peer.toPeer([1, 2, 3, 4], '03abc123def456')
        fail('Expected error to be thrown')
      } catch (error: any) {
        expect(error.message).toContain('Network error while sending authenticated request')
        expect(error.message).toContain('Network connection failed')
      }
    }, 15000)

    test('Should trigger error with connection timeout', async () => {
      // Create a fetch that times out
      const timeoutFetch = (jest.fn() as any).mockImplementation(() => {
        return new Promise((_, reject) => {
          setTimeout(() => {
            reject(new Error('Request timeout'))
          }, 100)
        })
      })
      
      const transport = new SimplifiedFetchTransport('http://localhost:9999', timeoutFetch)
      const wallet = new CompletedProtoWallet(privKey)
      const peer = new Peer(wallet, transport)
      
      await transport.onData(async (message) => {})

      try {
        await peer.toPeer([5, 6, 7, 8], '03def789abc123')
        fail('Expected error to be thrown')
      } catch (error: any) {
        expect(error.message).toContain('Network error while sending authenticated request')
        expect(error.message).toContain('Request timeout')
      }
    }, 15000)

    test('Should trigger error with DNS resolution failure', async () => {
      // Create a fetch that fails with DNS error
      const dnsFetch = (jest.fn() as any).mockRejectedValue({
        code: 'ENOTFOUND',
        errno: -3008,
        message: 'getaddrinfo ENOTFOUND nonexistent.domain'
      })
      
      const transport = new SimplifiedFetchTransport('http://nonexistent.domain:3000', dnsFetch)
      const wallet = new CompletedProtoWallet(privKey)
      const peer = new Peer(wallet, transport)
      
      await transport.onData(async (message) => {})

      try {
        await peer.toPeer([9, 10, 11, 12], '03xyz987fed654')
        fail('Expected error to be thrown')
      } catch (error: any) {
        expect(error.message).toContain('Network error while sending authenticated request')
        expect(error.message).toContain('[object Object]')
      }
    }, 15000)

    test('Should trigger error during certificate request send', async () => {
      // Create a failing fetch
      const failingFetch = (jest.fn() as any).mockRejectedValue(new Error('Connection reset by peer'))
      
      const transport = new SimplifiedFetchTransport('http://localhost:9999', failingFetch)
      const wallet = new CompletedProtoWallet(privKey)
      const peer = new Peer(wallet, transport)
      
      await transport.onData(async (message) => {})

      try {
        // Try to send a certificate request - this should also trigger the error
        await peer.requestCertificates({
          certifiers: ['03certifier123'],
          types: { 'type1': ['field1'] }
        }, '03abc123def456')
        fail('Expected error to be thrown')
      } catch (error: any) {
        expect(error.message).toContain('Network error while sending authenticated request')
        expect(error.message).toContain('Connection reset by peer')
      }
    }, 15000)

    test('Should trigger error during certificate response send', async () => {
      // Create a failing fetch
      const failingFetch = (jest.fn() as any).mockRejectedValue(new Error('Socket hang up'))
      
      const transport = new SimplifiedFetchTransport('http://localhost:9999', failingFetch)
      const wallet = new CompletedProtoWallet(privKey)
      const peer = new Peer(wallet, transport)
      
      await transport.onData(async (message) => {})

      try {
        // Try to send a certificate response - this should also trigger the error
        await peer.sendCertificateResponse('03verifier123', [])
        fail('Expected error to be thrown')
      } catch (error: any) {
        expect(error.message).toContain('Network error while sending authenticated request')
        expect(error.message).toContain('Socket hang up')
      }
    }, 15000)

    test('Should propagate network errors with proper details', async () => {
      // Create a fetch that throws a custom error
      const customError = new Error('Custom transport error')
      customError.stack = 'Custom stack trace'
      const failingFetch = (jest.fn() as any).mockRejectedValue(customError)
      
      const transport = new SimplifiedFetchTransport('http://localhost:9999', failingFetch)
      const wallet = new CompletedProtoWallet(privKey)
      const peer = new Peer(wallet, transport)
      
      await transport.onData(async (message) => {})

      try {
        await peer.toPeer([13, 14, 15, 16], '03peer123456')
        fail('Expected error to be thrown')
      } catch (error: any) {
        // Should create a network error wrapping the original error
        expect(error.message).toContain('Network error while sending authenticated request')
        expect(error.message).toContain('Custom transport error')
        expect(error.cause).toBeDefined()
        expect(error.cause.message).toBe('Custom transport error')
      }
    }, 15000)

    test('Should handle non-Error transport failures', async () => {
      // Create a fetch that throws a non-Error object
      const failingFetch = (jest.fn() as any).mockRejectedValue('String error message')
      
      const transport = new SimplifiedFetchTransport('http://localhost:9999', failingFetch)
      const wallet = new CompletedProtoWallet(privKey)
      const peer = new Peer(wallet, transport)
      
      await transport.onData(async (message) => {})

      try {
        await peer.toPeer([17, 18, 19, 20], '03peer789abc')
        fail('Expected error to be thrown')
      } catch (error: any) {
        // Should create network error for non-Error objects
        expect(error.message).toContain('Network error while sending authenticated request')
        expect(error.message).toContain('String error message')
      }
    }, 15000)

    test('Should handle undefined peer identity gracefully', async () => {
      // Create a failing fetch
      const failingFetch = (jest.fn() as any).mockRejectedValue('Network failure')
      
      const transport = new SimplifiedFetchTransport('http://localhost:9999', failingFetch)
      const wallet = new CompletedProtoWallet(privKey)
      const peer = new Peer(wallet, transport)
      
      await transport.onData(async (message) => {})

      try {
        // Try to send to an undefined peer (this might happen in some edge cases)
        await peer.toPeer([21, 22, 23, 24], undefined as any)
        fail('Expected error to be thrown')
      } catch (error: any) {
        expect(error.message).toContain('Network error while sending authenticated request')
        expect(error.message).toContain('Network failure')
      }
    }, 15000)
  })

  describe('Certificate gating for general messages', () => {
    it('rejects incoming general messages before certificate validation', async () => {
      const bobPubKey = (await walletB.getPublicKey({ identityKey: true })).publicKey

      setupPeers(false, true) // Bob requires certs

      // Prevent Alice from auto-sending certificate response
      // This keeps Bob in "certs required but not validated" state
      alice.listenForCertificatesRequested(() => {
        // Intentionally do nothing (no auto-response)
      })

      let received = false
      bob.listenForGeneralMessages(() => {
        received = true
      })

      // Send message — Bob will wait for certificates that never arrive
      try {
        await alice.toPeer(Utils.toArray('Hello Bob!'), bobPubKey)
      } catch {
        // swallow — error is expected but not part of assertion
      }

      // Allow transport handlers to run
      await new Promise(r => setTimeout(r, 50))

      // Message must NOT be delivered since certificates haven't been validated
      expect(received).toBe(false)
    })

    it('blocks outgoing messages until certificates are validated', async () => {
      setupPeers(true, false) // Alice requires certs from Bob

      // Prevent Bob from auto-supplying certificates during the handshake.
      // This keeps Alice in "certs required but not validated" state.
      bob.listenForCertificatesRequested(() => {
        // Intentionally do nothing (no auto-response)
      })

      await expect(
        alice.toPeer(Utils.toArray('Hello Bob!'))
      ).rejects.toThrow('certificate validation')
    })

    it('allows general messages after certificate validation completes', async () => {
      const alicePubKey = (await walletA.getPublicKey({ identityKey: true })).publicKey
      const bobPubKey = (await walletB.getPublicKey({ identityKey: true })).publicKey

      const bobMasterCert = await createMasterCertificate(walletB, { name: 'Bob' })
      const bobCert = await createVerifiableCertificate(
        bobMasterCert,
        walletB,
        alicePubKey,
        ['name']
      )

      // Alice requires certs from Bob
      const { aliceReceivedCertificates } = setupPeers(true, false)

      // Bob will provide his cert to Alice when asked
      await mockGetVerifiableCertificates(
        undefined,
        bobCert,
        alicePubKey,
        bobPubKey
      )

      // Trigger handshake + cert exchange WITHOUT sending a general message
      await alice.toPeer(Utils.toArray('handshake'), bobPubKey)

      // Wait until Alice has validated Bob’s certificate
      await aliceReceivedCertificates

      // Now general messages must be allowed
      const received = new Promise<void>((resolve) => {
        bob.listenForGeneralMessages(() => resolve())
      })

      await alice.toPeer(Utils.toArray('Hello Bob!'), bobPubKey)
      await received
    })
  })
})
