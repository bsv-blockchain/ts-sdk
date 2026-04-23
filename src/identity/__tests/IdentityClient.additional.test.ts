import { WalletCertificate, WalletInterface } from '../../wallet/index'
import { IdentityClient } from '../IdentityClient'
import { Certificate } from '../../auth/certificates/index.js'
import { KNOWN_IDENTITY_TYPES, defaultIdentity } from '../types/index.js'

// ----- Mocks for external dependencies -----
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
    LockingScript: {
      fromHex: jest.fn().mockImplementation((hex: string) => ({ toHex: () => hex }))
    }
  }
})

jest.mock('../../overlay-tools/index.js', () => {
  return {
    TopicBroadcaster: jest.fn().mockImplementation(() => ({
      broadcast: jest.fn().mockResolvedValue('broadcastResult')
    })),
    SHIPBroadcaster: jest.fn().mockImplementation(() => ({
      broadcast: jest.fn().mockResolvedValue('broadcastResult')
    })),
    LookupResolver: jest.fn().mockImplementation(() => ({
      query: jest.fn().mockResolvedValue({
        type: 'output-list',
        outputs: [
          {
            beef: [1, 2, 3]
          }
        ]
      })
    })),
    withDoubleSpendRetry: jest.fn().mockImplementation(async (fn: () => Promise<void>) => {
      await fn()
    })
  }
})

jest.mock('../../transaction/index.js', () => {
  return {
    Transaction: {
      fromAtomicBEEF: jest.fn().mockImplementation((_tx) => ({
        toHexBEEF: () => 'transactionHex'
      })),
      fromBEEF: jest.fn().mockReturnValue({
        id: jest.fn().mockReturnValue('mocktxid'),
        outputs: [
          {
            lockingScript: {
              toHex: () => 'mockLockingScript'
            }
          }
        ]
      })
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
describe('IdentityClient (additional coverage)', () => {
  let walletMock: Partial<WalletInterface>
  let identityClient: IdentityClient

  beforeEach(() => {
    const localStorageMock = {
      getItem: jest.fn(),
      setItem: jest.fn(),
      removeItem: jest.fn()
    }
    Object.defineProperty(global, 'localStorage', {
      value: localStorageMock,
      writable: true
    })

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
      discoverByIdentityKey: jest.fn().mockResolvedValue({ certificates: [] }),
      discoverByAttributes: jest.fn().mockResolvedValue({ certificates: [] }),
      listOutputs: jest.fn().mockResolvedValue({ outputs: [], BEEF: [] }),
      createHmac: jest.fn().mockResolvedValue({ hmac: new Uint8Array([1, 2, 3, 4]) }),
      decrypt: jest.fn().mockResolvedValue({ plaintext: new Uint8Array() }),
      encrypt: jest.fn().mockResolvedValue({ ciphertext: new Uint8Array([5, 6, 7, 8]) })
    }

    identityClient = new IdentityClient(walletMock as WalletInterface)
    jest.clearAllMocks()
  })

  // ─── parseIdentity: remaining known cert types ──────────────────────────────

  describe('parseIdentity — remaining known cert types', () => {
    it('parses discordCert correctly', () => {
      const cert = {
        type: KNOWN_IDENTITY_TYPES.discordCert,
        subject: 'discordSubject123',
        decryptedFields: { userName: 'DiscordUser', profilePhoto: 'discord-photo.png' },
        certifierInfo: { name: 'DiscordCertifier', iconUrl: 'discord-icon.png' }
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.name).toBe('DiscordUser')
      expect(result.avatarURL).toBe('discord-photo.png')
      expect(result.badgeLabel).toBe('Discord account certified by DiscordCertifier')
      expect(result.badgeIconURL).toBe('discord-icon.png')
      expect(result.badgeClickURL).toBe('https://socialcert.net')
      expect(result.identityKey).toBe('discordSubject123')
      expect(result.abbreviatedKey).toBe('discordSub...')
    })

    it('parses emailCert correctly', () => {
      const cert = {
        type: KNOWN_IDENTITY_TYPES.emailCert,
        subject: 'emailSubjectABC',
        decryptedFields: { email: 'user@example.com' },
        certifierInfo: { name: 'EmailCertifier', iconUrl: 'email-icon.png' }
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.name).toBe('user@example.com')
      // avatarURL is a hard-coded constant for email
      expect(result.avatarURL).toBe('XUTZxep7BBghAJbSBwTjNfmcsDdRFs5EaGEgkESGSgjJVYgMEizu')
      expect(result.badgeLabel).toBe('Email certified by EmailCertifier')
      expect(result.badgeIconURL).toBe('email-icon.png')
      expect(result.badgeClickURL).toBe('https://socialcert.net')
    })

    it('parses phoneCert correctly', () => {
      const cert = {
        type: KNOWN_IDENTITY_TYPES.phoneCert,
        subject: 'phoneSubjectXYZ',
        decryptedFields: { phoneNumber: '+15555551234' },
        certifierInfo: { name: 'PhoneCertifier', iconUrl: 'phone-icon.png' }
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.name).toBe('+15555551234')
      // avatarURL is a hard-coded constant for phone
      expect(result.avatarURL).toBe('XUTLxtX3ELNUwRhLwL7kWNGbdnFM8WG2eSLv84J7654oH8HaJWrU')
      expect(result.badgeLabel).toBe('Phone certified by PhoneCertifier')
      expect(result.badgeClickURL).toBe('https://socialcert.net')
    })

    it('parses identiCert correctly', () => {
      const cert = {
        type: KNOWN_IDENTITY_TYPES.identiCert,
        subject: 'identiSubjectFOO',
        decryptedFields: { firstName: 'Jane', lastName: 'Doe', profilePhoto: 'id-photo.png' },
        certifierInfo: { name: 'GovCertifier', iconUrl: 'gov-icon.png' }
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.name).toBe('Jane Doe')
      expect(result.avatarURL).toBe('id-photo.png')
      expect(result.badgeLabel).toBe('Government ID certified by GovCertifier')
      expect(result.badgeClickURL).toBe('https://identicert.me')
    })

    it('parses registrant correctly', () => {
      const cert = {
        type: KNOWN_IDENTITY_TYPES.registrant,
        subject: 'registrantSubject',
        decryptedFields: { name: 'ACME Corp', icon: 'acme-icon.png' },
        certifierInfo: { name: 'RegistryCertifier', iconUrl: 'registry-icon.png' }
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.name).toBe('ACME Corp')
      expect(result.avatarURL).toBe('acme-icon.png')
      expect(result.badgeLabel).toBe('Entity certified by RegistryCertifier')
      expect(result.badgeClickURL).toBe('https://bsv-blockchain.github.io/ts-sdk/reference/identity/')
    })

    it('parses coolCert with cool=true', () => {
      const cert = {
        type: KNOWN_IDENTITY_TYPES.coolCert,
        subject: 'coolSubject001',
        decryptedFields: { cool: 'true' },
        certifierInfo: {}
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.name).toBe('Cool Person!')
    })

    it('parses coolCert with cool != true', () => {
      const cert = {
        type: KNOWN_IDENTITY_TYPES.coolCert,
        subject: 'coolSubject002',
        decryptedFields: { cool: 'false' },
        certifierInfo: {}
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.name).toBe('Not cool!')
    })

    it('parses anyone identity type', () => {
      const cert = {
        type: KNOWN_IDENTITY_TYPES.anyone,
        subject: 'anyoneSubjectAAA',
        decryptedFields: {},
        certifierInfo: {}
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.name).toBe('Anyone')
      expect(result.avatarURL).toBe('XUT4bpQ6cpBaXi1oMzZsXfpkWGbtp2JTUYAoN7PzhStFJ6wLfoeR')
      expect(result.badgeLabel).toBe('Represents the ability for anyone to access this information.')
      expect(result.badgeClickURL).toBe('https://bsv-blockchain.github.io/ts-sdk/reference/identity/')
    })

    it('parses self identity type', () => {
      const cert = {
        type: KNOWN_IDENTITY_TYPES.self,
        subject: 'selfSubjectBBB',
        decryptedFields: {},
        certifierInfo: {}
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.name).toBe('You')
      expect(result.avatarURL).toBe('XUT9jHGk2qace148jeCX5rDsMftkSGYKmigLwU2PLLBc7Hm63VYR')
      expect(result.badgeLabel).toBe('Represents your ability to access this information.')
      expect(result.badgeClickURL).toBe('https://bsv-blockchain.github.io/ts-sdk/reference/identity/')
    })

    it('produces empty abbreviatedKey when subject is empty string', () => {
      const cert = {
        type: KNOWN_IDENTITY_TYPES.anyone,
        subject: '',
        decryptedFields: {},
        certifierInfo: {}
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.abbreviatedKey).toBe('')
    })

    it('abbreviatedKey is subject.substring(0,10)+"..." when subject is non-empty', () => {
      const cert = {
        type: KNOWN_IDENTITY_TYPES.anyone,
        subject: '0123456789ABCDEF',
        decryptedFields: {},
        certifierInfo: {}
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.abbreviatedKey).toBe('0123456789...')
    })
  })

  // ─── parseIdentity: generic/unknown type — tryToParseGenericIdentity paths ──

  describe('parseIdentity — generic/unknown type (tryToParseGenericIdentity)', () => {
    it('uses decryptedFields.name when present', () => {
      const cert = {
        type: 'custom-type',
        subject: 'sub1',
        decryptedFields: { name: 'Custom Name' },
        certifierInfo: { name: 'SomeCert', iconUrl: 'some-icon.png' }
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.name).toBe('Custom Name')
    })

    it('falls back to decryptedFields.userName when name is absent', () => {
      const cert = {
        type: 'custom-type',
        subject: 'sub1',
        decryptedFields: { userName: 'userNameValue' },
        certifierInfo: { name: 'SomeCert', iconUrl: 'icon.png' }
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.name).toBe('userNameValue')
    })

    it('falls back to firstName + lastName when both present', () => {
      const cert = {
        type: 'custom-type',
        subject: 'sub1',
        decryptedFields: { firstName: 'John', lastName: 'Smith' },
        certifierInfo: {}
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.name).toBe('John Smith')
    })

    it('uses only firstName when lastName is absent', () => {
      const cert = {
        type: 'custom-type',
        subject: 'sub1',
        decryptedFields: { firstName: 'OnlyFirst' },
        certifierInfo: {}
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.name).toBe('OnlyFirst')
    })

    it('uses only lastName when firstName is absent', () => {
      const cert = {
        type: 'custom-type',
        subject: 'sub1',
        decryptedFields: { lastName: 'OnlyLast' },
        certifierInfo: {}
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.name).toBe('OnlyLast')
    })

    it('falls back to email when no name/userName/firstName/lastName', () => {
      const cert = {
        type: 'custom-type',
        subject: 'sub1',
        decryptedFields: { email: 'generic@example.com' },
        certifierInfo: {}
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.name).toBe('generic@example.com')
    })

    it('uses defaultIdentity.name when no name fields exist', () => {
      const cert = {
        type: 'custom-type',
        subject: 'sub1',
        decryptedFields: {},
        certifierInfo: {}
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.name).toBe(defaultIdentity.name)
    })

    it('uses decryptedFields.profilePhoto for avatarURL', () => {
      const cert = {
        type: 'custom-type',
        subject: 'sub1',
        decryptedFields: { name: 'X', profilePhoto: 'profile.png' },
        certifierInfo: {}
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.avatarURL).toBe('profile.png')
    })

    it('falls back to decryptedFields.avatar for avatarURL', () => {
      const cert = {
        type: 'custom-type',
        subject: 'sub1',
        decryptedFields: { name: 'X', avatar: 'avatar.png' },
        certifierInfo: {}
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.avatarURL).toBe('avatar.png')
    })

    it('falls back to decryptedFields.icon for avatarURL', () => {
      const cert = {
        type: 'custom-type',
        subject: 'sub1',
        decryptedFields: { name: 'X', icon: 'icon.png' },
        certifierInfo: {}
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.avatarURL).toBe('icon.png')
    })

    it('falls back to decryptedFields.photo for avatarURL', () => {
      const cert = {
        type: 'custom-type',
        subject: 'sub1',
        decryptedFields: { name: 'X', photo: 'photo.png' },
        certifierInfo: {}
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.avatarURL).toBe('photo.png')
    })

    it('uses defaultIdentity.avatarURL when no avatar field is present', () => {
      const cert = {
        type: 'custom-type',
        subject: 'sub1',
        decryptedFields: { name: 'X' },
        certifierInfo: {}
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.avatarURL).toBe(defaultIdentity.avatarURL)
    })

    it('generates badgeLabel from certifierInfo.name', () => {
      const cert = {
        type: 'my-cert-type',
        subject: 'sub1',
        decryptedFields: {},
        certifierInfo: { name: 'MyCertifier', iconUrl: 'cert-icon.png' }
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.badgeLabel).toBe('my-cert-type certified by MyCertifier')
    })

    it('uses defaultIdentity.badgeLabel when certifierInfo.name is absent', () => {
      const cert = {
        type: 'my-cert-type',
        subject: 'sub1',
        decryptedFields: {},
        certifierInfo: {}
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.badgeLabel).toBe(defaultIdentity.badgeLabel)
    })

    it('uses certifierInfo.iconUrl for badgeIconURL when present', () => {
      const cert = {
        type: 'my-cert-type',
        subject: 'sub1',
        decryptedFields: {},
        certifierInfo: { name: 'Cert', iconUrl: 'specific-icon.png' }
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.badgeIconURL).toBe('specific-icon.png')
    })

    it('uses defaultIdentity.badgeIconURL when certifierInfo.iconUrl is absent', () => {
      const cert = {
        type: 'my-cert-type',
        subject: 'sub1',
        decryptedFields: {},
        certifierInfo: { name: 'Cert' }
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.badgeIconURL).toBe(defaultIdentity.badgeIconURL)
    })

    it('always uses defaultIdentity.badgeClickURL', () => {
      const cert = {
        type: 'my-cert-type',
        subject: 'sub1',
        decryptedFields: {},
        certifierInfo: {}
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.badgeClickURL).toBe(defaultIdentity.badgeClickURL)
    })

    it('handles null certifierInfo gracefully', () => {
      const cert = {
        type: 'my-cert-type',
        subject: 'sub1',
        decryptedFields: {},
        certifierInfo: null
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.badgeLabel).toBe(defaultIdentity.badgeLabel)
      expect(result.badgeIconURL).toBe(defaultIdentity.badgeIconURL)
    })

    it('treats empty-string field values as absent (hasValue returns false)', () => {
      const cert = {
        type: 'my-cert-type',
        subject: 'sub1',
        decryptedFields: {
          name: '',
          userName: '',
          firstName: '',
          lastName: '',
          email: ''
        },
        certifierInfo: {}
      }
      const result = IdentityClient.parseIdentity(cert as any)
      expect(result.name).toBe(defaultIdentity.name)
    })
  })

  // ─── resolveByIdentityKey: overrideWithContacts = false ────────────────────

  describe('resolveByIdentityKey with overrideWithContacts=false', () => {
    it('skips contacts and returns parsed certificates directly', async () => {
      const dummyCertificate = {
        type: KNOWN_IDENTITY_TYPES.xCert,
        subject: 'aliceKey123456789',
        decryptedFields: { userName: 'Alice', profilePhoto: 'photo.png' },
        certifierInfo: { name: 'CertX', iconUrl: 'icon.png' }
      }
      walletMock.discoverByIdentityKey = jest.fn().mockResolvedValue({ certificates: [dummyCertificate] })

      const mockContactsManager = identityClient['contactsManager']
      mockContactsManager.getContacts = jest.fn().mockResolvedValue([{ name: 'Alice Contact', identityKey: 'aliceKey123456789' }])

      const result = await identityClient.resolveByIdentityKey({ identityKey: 'aliceKey123456789' }, false)

      expect(result).toHaveLength(1)
      expect(result[0].name).toBe('Alice') // from cert, not contact
      expect(mockContactsManager.getContacts).not.toHaveBeenCalled()
    })

    it('returns empty array when no certificates found and contacts skipped', async () => {
      walletMock.discoverByIdentityKey = jest.fn().mockResolvedValue({ certificates: [] })

      const result = await identityClient.resolveByIdentityKey({ identityKey: 'unknown-key' }, false)
      expect(result).toEqual([])
    })

    it('handles undefined certificates result gracefully', async () => {
      walletMock.discoverByIdentityKey = jest.fn().mockResolvedValue({ certificates: undefined })

      const result = await identityClient.resolveByIdentityKey({ identityKey: 'some-key' }, false)
      expect(result).toEqual([])
    })
  })

  // ─── resolveByAttributes: additional branches ──────────────────────────────

  describe('resolveByAttributes additional branches', () => {
    it('handles null/undefined certificates result gracefully', async () => {
      walletMock.discoverByAttributes = jest.fn().mockResolvedValue(null)
      const result = await identityClient.resolveByAttributes({ attributes: { name: 'Alice' } }, false)
      expect(result).toEqual([])
    })

    it('maps contact for subject when contact exists in map', async () => {
      const contact = {
        name: 'Alice From Contact',
        identityKey: 'matched-key',
        avatarURL: 'contact-avatar.png',
        abbreviatedKey: 'matched-ke...',
        badgeIconURL: '',
        badgeLabel: '',
        badgeClickURL: ''
      }
      const discoveredCertificate = {
        type: KNOWN_IDENTITY_TYPES.emailCert,
        subject: 'matched-key',
        decryptedFields: { email: 'alice@example.com' },
        certifierInfo: { name: 'EmailCert', iconUrl: '' }
      }
      const mockContactsManager = identityClient['contactsManager']
      mockContactsManager.getContacts = jest.fn().mockResolvedValue([contact])
      walletMock.discoverByAttributes = jest.fn().mockResolvedValue({ certificates: [discoveredCertificate] })

      const result = await identityClient.resolveByAttributes({ attributes: { email: 'alice@example.com' } })
      expect(result[0].name).toBe('Alice From Contact')
    })

    it('falls through to parseIdentity when no matching contact for subject', async () => {
      const contact = {
        name: 'Bob From Contact',
        identityKey: 'bob-key',
        avatarURL: '',
        abbreviatedKey: '',
        badgeIconURL: '',
        badgeLabel: '',
        badgeClickURL: ''
      }
      const discoveredCertificate = {
        type: KNOWN_IDENTITY_TYPES.emailCert,
        subject: 'alice-different-key',
        decryptedFields: { email: 'alice@example.com' },
        certifierInfo: { name: 'EmailCert', iconUrl: '' }
      }
      const mockContactsManager = identityClient['contactsManager']
      mockContactsManager.getContacts = jest.fn().mockResolvedValue([contact])
      walletMock.discoverByAttributes = jest.fn().mockResolvedValue({ certificates: [discoveredCertificate] })

      const result = await identityClient.resolveByAttributes({ attributes: { email: 'alice@example.com' } })
      expect(result[0].name).toBe('alice@example.com')
    })
  })

  // ─── revokeCertificateRevelation ────────────────────────────────────────────

  describe('revokeCertificateRevelation', () => {
    const { LookupResolver, SHIPBroadcaster, withDoubleSpendRetry } = jest.requireMock('../../overlay-tools/index.js')

    beforeEach(() => {
      jest.clearAllMocks()
    })

    it('throws when lookup result type is not output-list', async () => {
      LookupResolver.mockImplementation(() => ({
        query: jest.fn().mockResolvedValue({ type: 'freeform', result: 'some data' })
      }))

      await expect(
        identityClient.revokeCertificateRevelation('serialXYZ')
      ).rejects.toThrow('Failed to get lookup result')
    })

    it('completes successfully with valid lookup output', async () => {
      LookupResolver.mockImplementation(() => ({
        query: jest.fn().mockResolvedValue({
          type: 'output-list',
          outputs: [{ beef: [1, 2, 3] }]
        })
      }))

      SHIPBroadcaster.mockImplementation(() => ({
        broadcast: jest.fn().mockResolvedValue('broadcasted')
      }))

      withDoubleSpendRetry.mockImplementation(async (fn: () => Promise<void>) => {
        await fn()
      })

      const { Transaction } = jest.requireMock('../../transaction/index.js')
      Transaction.fromBEEF.mockReturnValue({
        id: jest.fn().mockReturnValue('mocktxid'),
        outputs: [{ lockingScript: { toHex: () => 'scriptHex' } }]
      })

      walletMock.createAction = jest.fn().mockResolvedValue({
        signableTransaction: { tx: [1, 2, 3], reference: 'ref' },
        tx: undefined
      })
      walletMock.signAction = jest.fn().mockResolvedValue({ tx: [4, 5, 6] })

      await expect(
        identityClient.revokeCertificateRevelation('serialABC')
      ).resolves.toBeUndefined()
    })

    it('throws when signableTransaction is undefined', async () => {
      LookupResolver.mockImplementation(() => ({
        query: jest.fn().mockResolvedValue({
          type: 'output-list',
          outputs: [{ beef: [1, 2, 3] }]
        })
      }))

      SHIPBroadcaster.mockImplementation(() => ({
        broadcast: jest.fn()
      }))

      withDoubleSpendRetry.mockImplementation(async (fn: () => Promise<void>) => {
        await fn()
      })

      const { Transaction } = jest.requireMock('../../transaction/index.js')
      Transaction.fromBEEF.mockReturnValue({
        id: jest.fn().mockReturnValue('mocktxid'),
        outputs: [{ lockingScript: { toHex: () => 'scriptHex' } }]
      })

      walletMock.createAction = jest.fn().mockResolvedValue({
        signableTransaction: undefined,
        tx: undefined
      })

      await expect(
        identityClient.revokeCertificateRevelation('serialDEF')
      ).rejects.toThrow('Failed to create signable transaction')
    })

    it('throws when signed tx is undefined after signAction', async () => {
      LookupResolver.mockImplementation(() => ({
        query: jest.fn().mockResolvedValue({
          type: 'output-list',
          outputs: [{ beef: [1, 2, 3] }]
        })
      }))

      SHIPBroadcaster.mockImplementation(() => ({
        broadcast: jest.fn()
      }))

      withDoubleSpendRetry.mockImplementation(async (fn: () => Promise<void>) => {
        await fn()
      })

      const { Transaction } = jest.requireMock('../../transaction/index.js')
      Transaction.fromBEEF.mockReturnValue({
        id: jest.fn().mockReturnValue('mocktxid'),
        outputs: [{ lockingScript: { toHex: () => 'scriptHex' } }]
      })

      walletMock.createAction = jest.fn().mockResolvedValue({
        signableTransaction: { tx: [1, 2, 3], reference: 'ref' },
        tx: undefined
      })
      walletMock.signAction = jest.fn().mockResolvedValue({ tx: undefined })

      await expect(
        identityClient.revokeCertificateRevelation('serialGHI')
      ).rejects.toThrow('Failed to sign transaction')
    })
  })

  // ─── constructor defaults ───────────────────────────────────────────────────

  describe('constructor', () => {
    it('defaults to WalletClient when no wallet provided', () => {
      // Should not throw — WalletClient is instantiated internally
      expect(() => new IdentityClient()).not.toThrow()
    })

    it('accepts an originator parameter', () => {
      const client = new IdentityClient(walletMock as WalletInterface, undefined, 'example.com')
      expect(client).toBeInstanceOf(IdentityClient)
    })
  })

  // ─── getContacts / saveContact / removeContact delegation ──────────────────

  describe('contact delegation methods', () => {
    it('getContacts delegates to contactsManager', async () => {
      const mockContactsManager = identityClient['contactsManager']
      const expected = [{ name: 'Test', identityKey: 'key1', avatarURL: '', abbreviatedKey: '', badgeIconURL: '', badgeLabel: '', badgeClickURL: '' }]
      mockContactsManager.getContacts = jest.fn().mockResolvedValue(expected)

      const result = await identityClient.getContacts('key1', true, 50)
      expect(mockContactsManager.getContacts).toHaveBeenCalledWith('key1', true, 50)
      expect(result).toBe(expected)
    })

    it('saveContact delegates to contactsManager', async () => {
      const mockContactsManager = identityClient['contactsManager']
      mockContactsManager.saveContact = jest.fn().mockResolvedValue(undefined)

      const contact = { name: 'Alice', identityKey: 'key1', avatarURL: '', abbreviatedKey: '', badgeIconURL: '', badgeLabel: '', badgeClickURL: '' }
      const metadata = { note: 'test' }
      await identityClient.saveContact(contact, metadata)

      expect(mockContactsManager.saveContact).toHaveBeenCalledWith(contact, metadata)
    })

    it('removeContact delegates to contactsManager', async () => {
      const mockContactsManager = identityClient['contactsManager']
      mockContactsManager.removeContact = jest.fn().mockResolvedValue(undefined)

      await identityClient.removeContact('key-to-remove')
      expect(mockContactsManager.removeContact).toHaveBeenCalledWith('key-to-remove')
    })
  })
})
