import { WalletCertificate, WalletInterface } from '../../wallet/index'
import { IdentityClient } from '../IdentityClient'
import { Certificate } from '../../auth/certificates/index.js'
import { KNOWN_IDENTITY_TYPES, defaultIdentity } from '../types/index.js'

// ----- Mocks for external dependencies -----
jest.mock('../../script', () => {
  return {
    PushDrop: jest.fn().mockImplementation(() => ({
      lock: jest.fn().mockResolvedValue({
        toHex: () => 'lockingScriptHex'
      }),
      unlock: jest.fn()
    }))
  }
})

// Store mock functions for LookupResolver so tests can configure them
const mockLookupResolverQuery = jest.fn()

jest.mock('../../overlay-tools/index.js', () => {
  return {
    TopicBroadcaster: jest.fn().mockImplementation(() => ({
      broadcast: jest.fn().mockResolvedValue('broadcastResult')
    })),
    LookupResolver: jest.fn().mockImplementation(() => ({
      query: mockLookupResolverQuery
    }))
  }
})

// Mock VerifiableCertificate for resolveViaLookup tests
const mockDecryptFields = jest.fn()
const mockVerify = jest.fn()

jest.mock('../../auth/certificates/VerifiableCertificate.js', () => {
  return {
    VerifiableCertificate: jest.fn().mockImplementation(() => ({
      decryptFields: mockDecryptFields,
      verify: mockVerify
    }))
  }
})

// Mock ProtoWallet for resolveViaLookup tests
jest.mock('../../wallet/ProtoWallet.js', () => {
  return {
    __esModule: true,
    default: jest.fn().mockImplementation(() => ({}))
  }
})

jest.mock('../../transaction/index.js', () => {
  return {
    Transaction: {
      fromAtomicBEEF: jest.fn().mockImplementation((tx) => ({
        toHexBEEF: () => 'transactionHex'
      })),
      fromBEEF: jest.fn().mockReturnValue({
        outputs: [{ lockingScript: { toHex: () => 'mockLockingScript' } }]
      })
    }
  }
})

jest.mock('../../script', () => {
  const mockPushDropInstance = {
    lock: jest.fn().mockResolvedValue({
      toHex: () => 'lockingScriptHex'
    }),
    unlock: jest.fn().mockReturnValue({
      sign: jest.fn().mockResolvedValue({
        toHex: () => 'unlockingScriptHex'
      })
    })
  }

  const mockPushDrop: any = jest.fn().mockImplementation(() => mockPushDropInstance)
  mockPushDrop.decode = jest.fn().mockReturnValue({
    fields: [new Uint8Array([1, 2, 3, 4])]
  })

  return {
    PushDrop: mockPushDrop,
    // Provide LockingScript.fromHex to satisfy ContactsManager.getContacts decode path
    LockingScript: {
      fromHex: jest.fn().mockImplementation((hex: string) => ({ toHex: () => hex }))
    }
  }
})

jest.mock('../../primitives/index.js', () => {
  return {
    Utils: {
      toBase64: jest.fn().mockReturnValue('mockKeyID'),
      toArray: jest.fn().mockReturnValue(new Uint8Array()),
      toUTF8: jest.fn().mockImplementation((data) => {
        return new TextDecoder().decode(data)
      }),
      toHex: jest.fn().mockReturnValue('0102030405060708')
    },
    Random: jest.fn().mockReturnValue(new Uint8Array(32)),
    PrivateKey: jest.fn().mockImplementation(() => ({
      toPublicKey: jest.fn().mockReturnValue({
        toString: jest.fn().mockReturnValue('mockPublicKeyString')
      })
    }))
  }
})

// ----- Begin Test Suite -----
describe('IdentityClient', () => {
  let walletMock: Partial<WalletInterface>
  let identityClient: IdentityClient

  beforeEach(() => {
    // Mock localStorage for Node.js environment
    const localStorageMock = {
      getItem: jest.fn(),
      setItem: jest.fn(),
      removeItem: jest.fn()
    }
    Object.defineProperty(global, 'localStorage', {
      value: localStorageMock,
      writable: true
    })

    // Create a fake wallet implementing the methods used by IdentityClient.
    walletMock = {
      proveCertificate: jest.fn().mockResolvedValue({ keyringForVerifier: 'fakeKeyring' }),
      createAction: jest.fn().mockResolvedValue({
        tx: [1, 2, 3],
        signableTransaction: { tx: [1, 2, 3], reference: 'ref' }
      }),
      listCertificates: jest.fn().mockResolvedValue({ certificates: [] }),
      acquireCertificate: jest.fn().mockResolvedValue({
        fields: { name: 'Alice' },
        verify: jest.fn().mockResolvedValue(true)
      }),
      signAction: jest.fn().mockResolvedValue({ tx: [4, 5, 6] }),
      getNetwork: jest.fn().mockResolvedValue({ network: 'testnet' }),
      discoverByIdentityKey: jest.fn(),
      discoverByAttributes: jest.fn(),
      // ContactsManager specific methods
      listOutputs: jest.fn().mockResolvedValue({ outputs: [], BEEF: [] }),
      createHmac: jest.fn().mockResolvedValue({ hmac: new Uint8Array([1, 2, 3, 4]) }),
      decrypt: jest.fn().mockResolvedValue({ plaintext: new Uint8Array() }),
      encrypt: jest.fn().mockResolvedValue({ ciphertext: new Uint8Array([5, 6, 7, 8]) })
    }

    identityClient = new IdentityClient(walletMock as WalletInterface)

    // Clear any previous calls/spies.
    jest.clearAllMocks()
  })

  describe('publiclyRevealAttributes', () => {
    it('should throw an error if certificate has no fields', async () => {
      const certificate = {
        fields: {},
        verify: jest.fn().mockResolvedValue(true)
      } as any as WalletCertificate
      const fieldsToReveal = ['name']
      await expect(
        identityClient.publiclyRevealAttributes(certificate, fieldsToReveal)
      ).rejects.toThrow('Certificate has no fields to reveal!')
    })

    it('should throw an error if fieldsToReveal is empty', async () => {
      const certificate = {
        fields: { name: 'Alice' },
        verify: jest.fn().mockResolvedValue(true)
      } as any as WalletCertificate
      const fieldsToReveal: string[] = []
      await expect(
        identityClient.publiclyRevealAttributes(certificate, fieldsToReveal)
      ).rejects.toThrow('You must reveal at least one field!')
    })

    it('should throw an error if certificate verification fails', async () => {
      const certificate = {
        fields: { name: 'Alice' },
        verify: jest.fn().mockRejectedValue(new Error('Verification error')),
        type: 'dummyType',
        serialNumber: 'dummySerial',
        subject: 'dummySubject',
        certifier: 'dummyCertifier',
        revocationOutpoint: 'dummyRevocation',
        signature: 'dummySignature'
      } as any as WalletCertificate
      const fieldsToReveal = ['name']
      await expect(
        identityClient.publiclyRevealAttributes(certificate, fieldsToReveal)
      ).rejects.toThrow('Certificate verification failed!')
    })

    it('should publicly reveal attributes successfully', async () => {
      // Prepare a dummy certificate with all required properties.
      const certificate = {
        fields: { name: 'Alice' },
        verify: jest.fn().mockResolvedValue(true), // this property is not used since the Certificate is re-instantiated
        type: 'xCert',
        serialNumber: '12345',
        subject: 'abcdef1234567890',
        certifier: 'CertifierX',
        revocationOutpoint: 'outpoint1',
        signature: 'signature1'
      } as any as WalletCertificate

      // Ensure that Certificate.verify (called on the re-instantiated Certificate)
      // resolves successfully.
      jest.spyOn(Certificate.prototype, 'verify').mockResolvedValue(false)

      const fieldsToReveal = ['name']
      const result = await identityClient.publiclyRevealAttributes(certificate, fieldsToReveal)
      expect(result).toEqual('broadcastResult')

      // Validate that proveCertificate was called with the proper arguments.
      expect(walletMock.proveCertificate).toHaveBeenCalledWith({
        certificate,
        fieldsToReveal,
        verifier: expect.any(String)
      }, undefined)

      // Validate that createAction was called.
      expect(walletMock.createAction).toHaveBeenCalled()
    })
  })

  describe('resolveByIdentityKey', () => {
    it('should return parsed identities from discovered certificates', async () => {
      const dummyCertificate = {
        type: KNOWN_IDENTITY_TYPES.xCert,
        subject: 'abcdef1234567890',
        decryptedFields: {
          userName: 'Alice',
          profilePhoto: 'alicePhotoUrl'
        },
        certifierInfo: {
          name: 'CertifierX',
          iconUrl: 'certifierIconUrl'
        }
      }
      // Mock discoverByIdentityKey to return a certificate list.
      walletMock.discoverByIdentityKey = jest.fn().mockResolvedValue({ certificates: [dummyCertificate] })

      const identities = await identityClient.resolveByIdentityKey({ identityKey: 'dummyKey' })
      expect(walletMock.discoverByIdentityKey).toHaveBeenCalledWith({ identityKey: 'dummyKey' }, undefined)
      expect(identities).toHaveLength(1)
      expect(identities[0]).toEqual({
        name: 'Alice',
        avatarURL: 'alicePhotoUrl',
        abbreviatedKey: 'abcdef1234...',
        identityKey: 'abcdef1234567890',
        badgeLabel: 'X account certified by CertifierX',
        badgeIconURL: 'certifierIconUrl',
        badgeClickURL: 'https://socialcert.net'
      })
    })

    it('should prioritize contacts over discovered identities for same identity key', async () => {
      const contact = {
        name: 'Alice Smith (Personal Contact)',
        identityKey: 'alice-identity-key',
        avatarURL: 'alice-avatar.png',
        abbreviatedKey: 'alice-i...',
        badgeIconURL: '',
        badgeLabel: '',
        badgeClickURL: ''
      }

      const discoveredCertificate = {
        type: KNOWN_IDENTITY_TYPES.xCert,
        subject: 'alice-identity-key',
        decryptedFields: {
          userName: 'Alice Public',
          profilePhoto: 'public-photo.png'
        },
        certifierInfo: {
          name: 'CertifierX',
          iconUrl: 'certifier-icon.png'
        }
      }

      // Mock ContactsManager to return contact for the specific identity key
      const mockContactsManager = identityClient['contactsManager']
      mockContactsManager.getContacts = jest.fn().mockResolvedValue([contact])
      walletMock.discoverByIdentityKey = jest.fn().mockResolvedValue({ certificates: [discoveredCertificate] })

      const identities = await identityClient.resolveByIdentityKey({ identityKey: 'alice-identity-key' })

      expect(identities).toHaveLength(1)
      expect(identities[0].name).toBe('Alice Smith (Personal Contact)') // Contact should be returned, not discovered identity
      // Wallet method should not be called when contact is found
      expect(walletMock.discoverByIdentityKey).not.toHaveBeenCalled()
    })

    it('should fallback to LookupResolver when no wallet is available', async () => {
      // Mock wallet methods to throw "No wallet available" error
      walletMock.discoverByIdentityKey = jest.fn().mockRejectedValue(
        new Error('No wallet available over any communication substrate. Install a BSV wallet today!')
      )

      // Mock ContactsManager to also throw (since it requires wallet)
      const mockContactsManager = identityClient['contactsManager']
      mockContactsManager.getContacts = jest.fn().mockRejectedValue(
        new Error('No wallet available')
      )

      // Setup mock certificate data that would come from lookup
      const certData = {
        type: KNOWN_IDENTITY_TYPES.xCert,
        serialNumber: 'serial123',
        subject: 'test-identity-key',
        certifier: '02cf6cdf466951d8dfc9e7c9367511d0007ed6fba35ed42d425cc412fd6cfd4a17',
        revocationOutpoint: 'outpoint',
        fields: { userName: 'encrypted', profilePhoto: 'encrypted' },
        keyring: { fieldKey: 'keyringValue' },
        signature: 'sig123'
      }

      // Mock LookupResolver to return output-list with certificate data
      mockLookupResolverQuery.mockResolvedValue({
        type: 'output-list',
        outputs: [{
          beef: new Uint8Array([1, 2, 3]),
          outputIndex: 0
        }]
      })

      // Mock PushDrop.decode to return certificate JSON
      const { PushDrop } = require('../../script')
      PushDrop.decode.mockReturnValue({
        fields: [new TextEncoder().encode(JSON.stringify(certData))]
      })

      // Mock VerifiableCertificate methods
      mockDecryptFields.mockResolvedValue({
        userName: 'TestUser',
        profilePhoto: 'test-photo-url'
      })
      mockVerify.mockResolvedValue(true)

      const identities = await identityClient.resolveByIdentityKey(
        { identityKey: 'test-identity-key' },
        false // Don't override with contacts
      )

      // Verify wallet was called and threw
      expect(walletMock.discoverByIdentityKey).toHaveBeenCalled()

      // Verify LookupResolver was queried
      expect(mockLookupResolverQuery).toHaveBeenCalledWith({
        service: 'ls_identity',
        query: {
          certifiers: ['02cf6cdf466951d8dfc9e7c9367511d0007ed6fba35ed42d425cc412fd6cfd4a17'],
          identityKey: 'test-identity-key'
        }
      })

      // Verify results were returned from fallback
      expect(identities).toHaveLength(1)
      expect(identities[0].name).toBe('TestUser')
      expect(identities[0].identityKey).toBe('test-identity-key')
    })

    it('should return empty array when LookupResolver returns no results', async () => {
      walletMock.discoverByIdentityKey = jest.fn().mockRejectedValue(
        new Error('No wallet available')
      )

      const mockContactsManager = identityClient['contactsManager']
      mockContactsManager.getContacts = jest.fn().mockRejectedValue(
        new Error('No wallet available')
      )

      // Mock LookupResolver to return empty results
      mockLookupResolverQuery.mockResolvedValue({
        type: 'output-list',
        outputs: []
      })

      const identities = await identityClient.resolveByIdentityKey(
        { identityKey: 'nonexistent-key' },
        false
      )

      expect(identities).toHaveLength(0)
    })

    it('should return empty array when LookupResolver returns non-output-list type', async () => {
      walletMock.discoverByIdentityKey = jest.fn().mockRejectedValue(
        new Error('No wallet available')
      )

      const mockContactsManager = identityClient['contactsManager']
      mockContactsManager.getContacts = jest.fn().mockRejectedValue(
        new Error('No wallet available')
      )

      // Mock LookupResolver to return different type
      mockLookupResolverQuery.mockResolvedValue({
        type: 'freeform',
        result: {}
      })

      const identities = await identityClient.resolveByIdentityKey(
        { identityKey: 'some-key' },
        false
      )

      expect(identities).toHaveLength(0)
    })

    it('should skip invalid certificates and continue processing', async () => {
      walletMock.discoverByIdentityKey = jest.fn().mockRejectedValue(
        new Error('No wallet available')
      )

      const mockContactsManager = identityClient['contactsManager']
      mockContactsManager.getContacts = jest.fn().mockRejectedValue(
        new Error('No wallet available')
      )

      // Mock LookupResolver to return multiple outputs
      mockLookupResolverQuery.mockResolvedValue({
        type: 'output-list',
        outputs: [
          { beef: new Uint8Array([1]), outputIndex: 0 },
          { beef: new Uint8Array([2]), outputIndex: 0 }
        ]
      })

      // First call throws (invalid cert), second succeeds
      const { PushDrop } = require('../../script')
      PushDrop.decode
        .mockImplementationOnce(() => { throw new Error('Invalid script') })
        .mockImplementationOnce(() => ({
          fields: [new TextEncoder().encode(JSON.stringify({
            type: KNOWN_IDENTITY_TYPES.xCert,
            serialNumber: 'serial',
            subject: 'valid-key',
            certifier: 'certifier',
            revocationOutpoint: 'outpoint',
            fields: {},
            keyring: {},
            signature: 'sig'
          }))]
        }))

      mockDecryptFields.mockResolvedValue({ userName: 'ValidUser' })
      mockVerify.mockResolvedValue(true)

      const identities = await identityClient.resolveByIdentityKey(
        { identityKey: 'some-key' },
        false
      )

      // Should have 1 identity (the valid one)
      expect(identities).toHaveLength(1)
      expect(identities[0].name).toBe('ValidUser')
    })

    it('should re-throw non-wallet errors', async () => {
      walletMock.discoverByIdentityKey = jest.fn().mockRejectedValue(
        new Error('Network timeout')
      )

      const mockContactsManager = identityClient['contactsManager']
      mockContactsManager.getContacts = jest.fn().mockRejectedValue(
        new Error('No wallet available')
      )

      await expect(
        identityClient.resolveByIdentityKey({ identityKey: 'test-key' }, false)
      ).rejects.toThrow('Network timeout')
    })
  })

  it('should throw if createAction returns no tx', async () => {
    const certificate = {
      fields: { name: 'Alice' },
      verify: jest.fn().mockResolvedValue(true),
      type: 'xCert',
      serialNumber: '12345',
      subject: 'abcdef1234567890',
      certifier: 'CertifierX',
      revocationOutpoint: 'outpoint1',
      signature: 'signature1'
    } as any as WalletCertificate

    jest.spyOn(Certificate.prototype, 'verify').mockResolvedValue(false)

    // Simulate createAction returning an object with tx = undefined
    walletMock.createAction = jest.fn().mockResolvedValue({
      tx: undefined,
      signableTransaction: { tx: undefined, reference: 'ref' }
    })

    const fieldsToReveal = ['name']

    await expect(
      identityClient.publiclyRevealAttributes(certificate, fieldsToReveal)
    ).rejects.toThrow('Public reveal failed: failed to create action!')
  })

  describe('resolveByAttributes', () => {
    beforeEach(() => {
      // Mock both getContacts and discoverByAttributes
      walletMock.discoverByAttributes = jest.fn().mockResolvedValue({ certificates: [] })
      identityClient.getContacts = jest.fn().mockResolvedValue([])
    })

    it('should return parsed identities from discovered certificates only', async () => {
      const dummyCertificate = {
        type: KNOWN_IDENTITY_TYPES.emailCert,
        subject: 'alice-identity-key',
        decryptedFields: {
          identityKey: 'alice-identity-key',
          email: 'alice@example.com'
        },
        certifierInfo: {
          name: 'Email Certifier',
          iconUrl: 'certifier-icon.png',
          publicKey: 'certifier-public-key',
          website: 'https://certifier.example.com'
        }
      }

      walletMock.discoverByAttributes = jest.fn().mockResolvedValue({ certificates: [dummyCertificate] })

      const identities = await identityClient.resolveByAttributes({ attributes: { email: 'alice@example.com' } })
      expect(identities).toHaveLength(1)
      expect(identities[0].name).toBe('alice@example.com')
    })

    it('should prioritize contacts over discovered identities for same identity key', async () => {
      const contact = {
        name: 'Alice Smith (Personal)',
        identityKey: 'alice-identity-key',
        avatarURL: 'alice-avatar.png',
        abbreviatedKey: 'alice-i...',
        badgeIconURL: '',
        badgeLabel: '',
        badgeClickURL: ''
      }

      const discoveredCertificate = {
        type: KNOWN_IDENTITY_TYPES.emailCert,
        subject: 'alice-identity-key',
        decryptedFields: {
          email: 'alice@example.com'
        },
        certifierInfo: {
          name: 'Email Certifier',
          iconUrl: 'certifier-icon.png',
          publicKey: 'certifier-public-key',
          website: 'https://certifier.example.com'
        }
      }

      // Mock the ContactsManager's getContacts method instead of the IdentityClient method
      const mockContactsManager = identityClient['contactsManager']
      mockContactsManager.getContacts = jest.fn().mockResolvedValue([contact])
      walletMock.discoverByAttributes = jest.fn().mockResolvedValue({ certificates: [discoveredCertificate] })

      const identities = await identityClient.resolveByAttributes({ attributes: { name: 'Alice' } })

      expect(identities).toHaveLength(1)
      expect(identities[0].name).toBe('Alice Smith (Personal)') // Contact should be returned, not discovered identity
    })

    it('should return empty array for empty search terms', async () => {
      const contacts = [
        {
          name: 'Alice Smith',
          identityKey: 'alice-key',
          avatarURL: '',
          abbreviatedKey: 'alice-i...',
          badgeIconURL: '',
          badgeLabel: '',
          badgeClickURL: ''
        }
      ]

      const mockContactsManager = identityClient['contactsManager']
      mockContactsManager.getContacts = jest.fn().mockResolvedValue(contacts)

      const identities = await identityClient.resolveByAttributes({ attributes: { name: '', email: '   ' } })

      expect(identities).toHaveLength(0)
    })

    it('should return only discovered identities when overrideWithContacts is false', async () => {
      const contacts = [
        {
          name: 'Alice Smith (Personal)',
          identityKey: 'alice-key',
          avatarURL: '', abbreviatedKey: 'alice-i...', badgeIconURL: '', badgeLabel: '', badgeClickURL: ''
        }
      ]

      const discoveredCertificate = {
        type: KNOWN_IDENTITY_TYPES.emailCert,
        subject: 'alice-key', // Same key as contact but should not be filtered out
        decryptedFields: {
          email: 'alice@example.com'
        },
        certifierInfo: {
          name: 'Email Certifier',
          iconUrl: 'certifier-icon.png',
          publicKey: 'certifier-public-key',
          website: 'https://certifier.example.com'
        }
      }

      const mockContactsManager = identityClient['contactsManager']
      mockContactsManager.getContacts = jest.fn().mockResolvedValue(contacts)
      walletMock.discoverByAttributes = jest.fn().mockResolvedValue({ certificates: [discoveredCertificate] })

      // With overrideWithContacts = false, should ignore contacts entirely
      const identities = await identityClient.resolveByAttributes(
        { attributes: { name: 'Alice' } },
        false
      )

      expect(identities).toHaveLength(1)
      expect(identities[0].name).toBe('alice@example.com') // Should be discovered identity, not contact
      expect(mockContactsManager.getContacts).not.toHaveBeenCalled() // Should not fetch contacts
    })

    it('should fallback to LookupResolver when no wallet is available for attribute search', async () => {
      walletMock.discoverByAttributes = jest.fn().mockRejectedValue(
        new Error('No wallet available')
      )

      // Setup mock certificate data
      const certData = {
        type: KNOWN_IDENTITY_TYPES.emailCert,
        serialNumber: 'serial123',
        subject: 'found-identity-key',
        certifier: '02cf6cdf466951d8dfc9e7c9367511d0007ed6fba35ed42d425cc412fd6cfd4a17',
        revocationOutpoint: 'outpoint',
        fields: { email: 'encrypted' },
        keyring: { fieldKey: 'keyringValue' },
        signature: 'sig123'
      }

      mockLookupResolverQuery.mockResolvedValue({
        type: 'output-list',
        outputs: [{
          beef: new Uint8Array([1, 2, 3]),
          outputIndex: 0
        }]
      })

      const { PushDrop } = require('../../script')
      PushDrop.decode.mockReturnValue({
        fields: [new TextEncoder().encode(JSON.stringify(certData))]
      })

      mockDecryptFields.mockResolvedValue({ email: 'found@example.com' })
      mockVerify.mockResolvedValue(true)

      const identities = await identityClient.resolveByAttributes(
        { attributes: { email: 'found@example.com' } },
        false
      )

      // Verify LookupResolver was queried with attributes
      expect(mockLookupResolverQuery).toHaveBeenCalledWith({
        service: 'ls_identity',
        query: {
          certifiers: ['02cf6cdf466951d8dfc9e7c9367511d0007ed6fba35ed42d425cc412fd6cfd4a17'],
          attributes: { any: 'found@example.com' }
        }
      })

      expect(identities).toHaveLength(1)
      expect(identities[0].name).toBe('found@example.com')
    })

    it('should use multi-attribute query when multiple attributes provided', async () => {
      walletMock.discoverByAttributes = jest.fn().mockRejectedValue(
        new Error('No wallet available')
      )

      mockLookupResolverQuery.mockResolvedValue({
        type: 'output-list',
        outputs: []
      })

      await identityClient.resolveByAttributes(
        { attributes: { firstName: 'John', lastName: 'Doe' } },
        false
      )

      // Verify query uses full attributes object when more than one
      expect(mockLookupResolverQuery).toHaveBeenCalledWith({
        service: 'ls_identity',
        query: {
          certifiers: ['02cf6cdf466951d8dfc9e7c9367511d0007ed6fba35ed42d425cc412fd6cfd4a17'],
          attributes: { firstName: 'John', lastName: 'Doe' }
        }
      })
    })
  })

  describe('parseIdentity', () => {
    it('should correctly parse an xCert identity', () => {
      const dummyCertificate = {
        type: KNOWN_IDENTITY_TYPES.xCert,
        subject: 'abcdef1234567890',
        decryptedFields: {
          userName: 'Alice',
          profilePhoto: 'alicePhotoUrl'
        },
        certifierInfo: {
          name: 'CertifierX',
          iconUrl: 'certifierIconUrl'
        }
      }
      const identity = IdentityClient.parseIdentity(dummyCertificate as unknown as any)
      expect(identity).toEqual({
        name: 'Alice',
        avatarURL: 'alicePhotoUrl',
        abbreviatedKey: 'abcdef1234...',
        identityKey: 'abcdef1234567890',
        badgeLabel: 'X account certified by CertifierX',
        badgeIconURL: 'certifierIconUrl',
        badgeClickURL: 'https://socialcert.net'
      })
    })

    it('should return default identity for unknown type', () => {
      const dummyCertificate = {
        type: 'unknownType',
        subject: '',
        decryptedFields: {
          profilePhoto: 'defaultPhoto'
        },
        certifierInfo: {}
      }
      const identity = IdentityClient.parseIdentity(dummyCertificate as any)
      expect(identity).toEqual({
        name: defaultIdentity.name,
        avatarURL: 'defaultPhoto',
        abbreviatedKey: '',
        identityKey: '',
        badgeLabel: defaultIdentity.badgeLabel,
        badgeIconURL: defaultIdentity.badgeIconURL,
        badgeClickURL: defaultIdentity.badgeClickURL
      })
    })
  })

  describe('ContactsManager Integration', () => {
    const mockContact = {
      name: 'Alice Smith',
      identityKey: 'abcdef1234567890abcdef1234567890',
      avatarURL: 'https://example.com/avatar.jpg',
      abbreviatedKey: 'abcdef1234...',
      badgeLabel: 'Verified User',
      badgeIconURL: 'https://example.com/badge.png',
      badgeClickURL: 'https://example.com/verify'
    }

    const mockContactWithMetadata = {
      ...mockContact,
      metadata: { notes: 'Met at conference' }
    }

    beforeEach(() => {
      // Reset wallet mocks for each test
      jest.clearAllMocks()
    })

    describe('saveContact', () => {
      it('should save a contact without metadata', async () => {
        // Mock empty contacts list (new contact)
        ; (walletMock.listOutputs as jest.Mock).mockResolvedValue({
          outputs: [],
          BEEF: []
        })

        await identityClient.saveContact(mockContact)

        // Verify HMAC was created for tagging
        expect(walletMock.createHmac).toHaveBeenCalledWith({
          protocolID: [2, 'contact'],
          keyID: mockContact.identityKey,
          counterparty: 'self',
          data: expect.any(Uint8Array)
        }, undefined)

        // Verify contact data was encrypted
        expect(walletMock.encrypt).toHaveBeenCalledWith({
          plaintext: expect.any(Uint8Array),
          protocolID: [2, 'contact'],
          keyID: expect.any(String),
          counterparty: 'self'
        }, undefined)

        // Verify new contact transaction was created
        expect(walletMock.createAction).toHaveBeenCalledWith(
          expect.objectContaining({
            description: 'Add Contact',
            outputs: expect.arrayContaining([
              expect.objectContaining({
                basket: 'contacts',
                outputDescription: `Contact: ${mockContact.name}`
              })
            ])
          }),
          undefined
        )

        // Verify contact is now available from cache
        const contacts = await identityClient.getContacts()
        expect(contacts).toContainEqual(expect.objectContaining({
          name: mockContact.name,
          identityKey: mockContact.identityKey
        }))
      })

      it('should save a contact with metadata', async () => {
        ; (walletMock.listOutputs as jest.Mock).mockResolvedValue({
          outputs: [],
          BEEF: []
        })

        await identityClient.saveContact(mockContact, { notes: 'Met at conference' })

        // Verify contact with metadata is available from cache
        const contacts = await identityClient.getContacts()
        expect(contacts).toContainEqual(expect.objectContaining({
          name: mockContact.name,
          identityKey: mockContact.identityKey,
          metadata: { notes: 'Met at conference' }
        }))
      })

      it('should update existing contact', async () => {
        // First save a contact to establish it exists
        ; (walletMock.listOutputs as jest.Mock).mockResolvedValueOnce({
          outputs: [],
          BEEF: []
        })
        await identityClient.saveContact(mockContact)

        // Now mock finding the existing contact for update
        const existingOutput = {
          outpoint: 'txid.0',
          customInstructions: JSON.stringify({ keyID: 'existingKeyID' })
        }

          ; (walletMock.listOutputs as jest.Mock).mockResolvedValueOnce({
            outputs: [existingOutput],
            BEEF: [1, 2, 3]
          })

          ; (walletMock.decrypt as jest.Mock).mockResolvedValue({
            plaintext: new TextEncoder().encode(JSON.stringify(mockContact))
          })

        const updatedContact = { ...mockContact, name: 'Alice Updated' }
        await identityClient.saveContact(updatedContact)

        // Should create update action since contact exists
        expect(walletMock.createAction).toHaveBeenLastCalledWith(
          expect.objectContaining({
            description: 'Update Contact',
            inputBEEF: [1, 2, 3],
            inputs: expect.arrayContaining([
              expect.objectContaining({
                outpoint: 'txid.0'
              })
            ])
          }),
          undefined
        )
      })
    })

    describe('getContacts', () => {
      it('should return cached contacts when available', async () => {
        // First save a contact to populate cache
        ; (walletMock.listOutputs as jest.Mock).mockResolvedValue({
          outputs: [],
          BEEF: []
        })
        await identityClient.saveContact(mockContact)

        // Clear mocks to verify cache is used
        jest.clearAllMocks()

        // Get contacts should use cache and not call wallet
        const result = await identityClient.getContacts()

        expect(result).toContainEqual(expect.objectContaining({
          name: mockContact.name,
          identityKey: mockContact.identityKey
        }))
        expect(walletMock.listOutputs).not.toHaveBeenCalled()
      })

      it('should load contacts from wallet basket when cache is empty', async () => {
        const mockOutput = {
          outpoint: 'txid.0',
          customInstructions: JSON.stringify({ keyID: 'mockKeyID' }),
          lockingScript: 'lockingScriptHex'
        }

          ; (walletMock.listOutputs as jest.Mock).mockResolvedValue({
            outputs: [mockOutput],
            BEEF: [1, 2, 3]
          })

          ; (walletMock.decrypt as jest.Mock).mockResolvedValue({
            plaintext: new TextEncoder().encode(JSON.stringify(mockContact))
          })

        const result = await identityClient.getContacts()

        expect(result).toEqual([mockContact])
        expect(walletMock.listOutputs).toHaveBeenCalledWith({
          basket: 'contacts',
          include: 'locking scripts',
          includeCustomInstructions: true,
          tags: [],
          limit: 1000
        }, undefined)

        // Verify subsequent call uses cache
        jest.clearAllMocks()
        const cachedResult = await identityClient.getContacts()
        expect(cachedResult).toEqual([mockContact])
        expect(walletMock.listOutputs).not.toHaveBeenCalled()
      })

      it('should force refresh when requested', async () => {
        // First populate cache
        ; (walletMock.listOutputs as jest.Mock).mockResolvedValue({
          outputs: [],
          BEEF: []
        })
        await identityClient.saveContact(mockContact)

          // Mock empty result for force refresh
          ; (walletMock.listOutputs as jest.Mock).mockResolvedValue({
            outputs: [],
            BEEF: []
          })

        const result = await identityClient.getContacts(undefined, true)

        expect(result).toEqual([])
        expect(walletMock.listOutputs).toHaveBeenCalled()
      })

      it('should filter by identity key when provided', async () => {
        // Save two different contacts
        ; (walletMock.listOutputs as jest.Mock).mockResolvedValue({
          outputs: [],
          BEEF: []
        })
        await identityClient.saveContact(mockContact)

        const otherContact = { ...mockContact, identityKey: 'different-key', name: 'Bob' }
        await identityClient.saveContact(otherContact)

        // Filter by specific identity key
        const result = await identityClient.getContacts(mockContact.identityKey)

        expect(result).toEqual([expect.objectContaining({
          name: mockContact.name,
          identityKey: mockContact.identityKey
        })])
        expect(result).toHaveLength(1)
      })

      it('should throw error on listOutputs failure', async () => {
        ; (walletMock.listOutputs as jest.Mock).mockRejectedValue(
          new Error('List outputs error')
        )

        await expect(
          identityClient.getContacts(undefined, true)
        ).rejects.toThrow('List outputs error')
      })
    })

    describe('removeContact', () => {
      it('should remove contact from cache and spend UTXO', async () => {
        // First save two contacts
        ; (walletMock.listOutputs as jest.Mock).mockResolvedValue({
          outputs: [],
          BEEF: []
        })
        await identityClient.saveContact(mockContact)

        const otherContact = { ...mockContact, identityKey: 'other-key', name: 'Bob' }
        await identityClient.saveContact(otherContact)

        // Mock finding the contact to remove
        const mockOutput = {
          outpoint: 'txid.0',
          customInstructions: JSON.stringify({ keyID: 'mockKeyID' })
        }

          ; (walletMock.listOutputs as jest.Mock).mockResolvedValue({
            outputs: [mockOutput],
            BEEF: [1, 2, 3]
          })

          ; (walletMock.decrypt as jest.Mock).mockResolvedValue({
            plaintext: new TextEncoder().encode(JSON.stringify(mockContact))
          })

        await identityClient.removeContact(mockContact.identityKey)

        // Verify delete action was created
        expect(walletMock.createAction).toHaveBeenLastCalledWith(
          expect.objectContaining({
            description: 'Delete Contact',
            inputBEEF: [1, 2, 3],
            inputs: expect.arrayContaining([
              expect.objectContaining({
                outpoint: 'txid.0'
              })
            ]),
            outputs: [] // No outputs for deletion
          }),
          undefined
        )

        // Verify contact is removed from cache
        const remainingContacts = await identityClient.getContacts()
        expect(remainingContacts).not.toContainEqual(
          expect.objectContaining({ identityKey: mockContact.identityKey })
        )
      })

      it('should handle contact not found gracefully', async () => {
        ; (walletMock.listOutputs as jest.Mock).mockResolvedValue({
          outputs: [],
          BEEF: []
        })

        // Should not throw when contact doesn't exist
        await expect(
          identityClient.removeContact('non-existent-key')
        ).resolves.toBeUndefined()

        // Should not call createAction since no contact found
        expect(walletMock.createAction).not.toHaveBeenCalled()
      })
    })
  })
})
