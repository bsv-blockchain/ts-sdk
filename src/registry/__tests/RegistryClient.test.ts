import { RegistryClient } from '../RegistryClient'
import { WalletInterface } from '../../wallet/index.js'
import { TopicBroadcaster, LookupResolver } from '../../overlay-tools/index.js'
import { PushDrop } from '../../script/index.js'
import {
  DefinitionType,
  DefinitionData,
  BasketDefinitionData,
  ProtocolDefinitionData,
  CertificateDefinitionData,
  RegistryRecord,
  CertificateFieldDescriptor
} from '../types/index.js'

// -------------------- Mocks Setup -------------------- //

// 1) A top-level broadcast mock function
const mockBroadcast = jest.fn().mockResolvedValue('mockBroadcastSuccess')

jest.mock('../../overlay-tools/index.js', () => {
  return {
    TopicBroadcaster: jest.fn().mockImplementation(() => ({
      broadcast: mockBroadcast
    })),
    LookupResolver: jest.fn().mockImplementation(() => ({
      query: jest.fn() // We'll override in tests
    }))
  }
})

jest.mock('../../script/index.js', () => {
  const actualScriptModule = jest.requireActual('../../script/index.js')
  return {
    ...actualScriptModule,
    PushDrop: Object.assign(
      jest.fn().mockImplementation(() => ({
        lock: jest.fn().mockResolvedValue({ toHex: () => 'mockLockingScriptHex' }),
        unlock: jest.fn().mockReturnValue({
          sign: jest.fn().mockResolvedValue({
            toHex: () => 'mockUnlockingScriptHex'
          })
        })
      })),
      {
        decode: jest.fn() // We'll override in tests
      }
    ),
    LockingScript: {
      fromHex: jest.fn().mockImplementation((hex: string) => ({ hex }))
    }
  }
})

jest.mock('../../transaction/index.js', () => {
  return {
    Transaction: {
      fromAtomicBEEF: jest.fn().mockImplementation((_tx: number[]) => ({
        // minimal mock
        toHexBEEF: () => 'mockTxHexBEEF',
        outputs: [
          { lockingScript: 'mockLockingScriptObject0' },
          { lockingScript: 'mockLockingScriptObject1' },
          { lockingScript: 'mockLockingScriptObject2' }
        ]
      })),
      fromBEEF: jest.fn().mockImplementation((_tx: number[]) => ({
        outputs: [
          { lockingScript: 'decodedLockScript0' },
          { lockingScript: 'decodedLockScript1' },
          {
            lockingScript: {
              toHex: jest.fn().mockImplementation(() => 'decodedLockScript1AsHex')
            }
          }
        ]
      }))
    }
  }
})

jest.mock('../../primitives/index.js', () => {
  return {
    Utils: {
      toArray: jest.fn().mockImplementation((str: string) =>
        Array.from(str).map((c) => c.charCodeAt(0))
      ),
      toUTF8: jest.fn().mockImplementation((arr: number[] | string) => {
        if (Array.isArray(arr)) {
          return arr.map((n) => String.fromCharCode(n)).join('')
        }
        return arr
      })
    }
  }
})

let walletMock: Partial<WalletInterface>
const TEST_ORIGINATOR = 'test.originator.example'

/**
 * Build minimal valid DefinitionData for each type
 */
function buildDefinitionData(type: DefinitionType): DefinitionData {
  switch (type) {
    case 'basket': {
      const data: BasketDefinitionData = {
        definitionType: 'basket',
        basketID: 'someBasketId',
        name: 'Test Basket',
        iconURL: 'https://someiconurl.com',
        description: 'Basket Description',
        documentationURL: 'https://docs.basket.com'
      }
      return data
    }
    case 'protocol': {
      const data: ProtocolDefinitionData = {
        definitionType: 'protocol',
        protocolID: [1, 'someProtocolId'],
        name: 'Test Protocol',
        iconURL: 'https://someiconurl.com',
        description: 'Protocol Description',
        documentationURL: 'https://docs.protocol.com'
      }
      return data
    }
    case 'certificate': {
      const fields: Record<string, CertificateFieldDescriptor> = {
        myField: {
          friendlyName: 'Friendly Field Name',
          description: 'some field description',
          type: 'text',
          fieldIcon: 'https://someiconurl.com/icons/myField.png'
        }
      }
      const data: CertificateDefinitionData = {
        definitionType: 'certificate',
        type: 'someCertType',
        name: 'Test Certificate',
        iconURL: 'https://someiconurl.com',
        description: 'Certificate Description',
        documentationURL: 'https://docs.certificate.com',
        fields
      }
      return data
    }
    default:
      throw new Error(`Invalid test usage: unsupported DefinitionType "${type}"`)
  }
}

describe('RegistryClient', () => {
  let registryClient: RegistryClient

  beforeEach(() => {
    walletMock = {
      getPublicKey: jest.fn().mockResolvedValue({ publicKey: 'mockPublicKey' }),
      createAction: jest.fn().mockResolvedValue({
        tx: [1, 2, 3],
        signableTransaction: { tx: [1, 2, 3], reference: 'someRef' }
      }),
      signAction: jest.fn().mockResolvedValue({ tx: [4, 5, 6] }),
      listOutputs: jest.fn().mockResolvedValue({ outputs: [] }),
      getNetwork: jest.fn().mockResolvedValue({ network: 'main' })
    }

    registryClient = new RegistryClient(walletMock as WalletInterface, {}, TEST_ORIGINATOR)
    
    // Mock the resolver instance since it's now initialized in constructor
    ; (registryClient as any).resolver = {
      query: jest.fn().mockResolvedValue({ type: 'output-list', outputs: [] })
    }

    jest.clearAllMocks()
    mockBroadcast.mockClear()
  })

  // ------------------------------------------------------------------
  // registerDefinition
  // ------------------------------------------------------------------
  describe('registerDefinition', () => {
    it('should register a basket definition and broadcast with networkPreset=main', async () => {
      const data = buildDefinitionData('basket')
      const result = await registryClient.registerDefinition(data)
      expect(result).toBe('mockBroadcastSuccess')

      // We use partial matching so extra fields (like options) are allowed
      expect(walletMock.createAction).toHaveBeenCalledWith(
        expect.objectContaining({
          description: 'Register a new basket item',
          outputs: expect.arrayContaining([
            expect.objectContaining({
              satoshis: 1,
              outputDescription: 'New basket registration token',
              basket: 'basketmap',
              lockingScript: 'mockLockingScriptHex'
            })
          ])
        }),
        TEST_ORIGINATOR
      )
      expect(TopicBroadcaster).toHaveBeenCalledWith(['tm_basketmap'], expect.objectContaining({
        networkPreset: 'main'
      }))
      expect(mockBroadcast).toHaveBeenCalledTimes(1)
    })

    it('should register a protocol definition and broadcast with networkPreset=main', async () => {
      const data = buildDefinitionData('protocol')
      const result = await registryClient.registerDefinition(data)
      expect(result).toBe('mockBroadcastSuccess')

      expect(walletMock.createAction).toHaveBeenCalledWith(
        expect.objectContaining({
          description: 'Register a new protocol item',
          outputs: expect.arrayContaining([
            expect.objectContaining({
              satoshis: 1,
              outputDescription: 'New protocol registration token',
              basket: 'protomap',
              lockingScript: 'mockLockingScriptHex'
            })
          ])
        }),
        TEST_ORIGINATOR
      )

      expect(TopicBroadcaster).toHaveBeenCalledWith(['tm_protomap'], expect.objectContaining({
        networkPreset: 'main'
      }))
      expect(mockBroadcast).toHaveBeenCalledTimes(1)
    })

    it('should register a certificate definition and broadcast with networkPreset=main', async () => {
      const data = buildDefinitionData('certificate')
      const result = await registryClient.registerDefinition(data)
      expect(result).toBe('mockBroadcastSuccess')

      expect(walletMock.createAction).toHaveBeenCalledWith(
        expect.objectContaining({
          description: 'Register a new certificate item',
          outputs: expect.arrayContaining([
            expect.objectContaining({
              satoshis: 1,
              outputDescription: 'New certificate registration token',
              basket: 'certmap',
              lockingScript: 'mockLockingScriptHex'
            })
          ])
        }),
        TEST_ORIGINATOR
      )

      expect(TopicBroadcaster).toHaveBeenCalledWith(['tm_certmap'], expect.objectContaining({
        networkPreset: 'main'
      }))
      expect(mockBroadcast).toHaveBeenCalledTimes(1)
    })

    it('should throw if createAction returns undefined tx', async () => {
      (walletMock.createAction as jest.Mock).mockResolvedValueOnce({
        tx: undefined
      })
      const data = buildDefinitionData('basket')
      await expect(registryClient.registerDefinition(data)).rejects.toThrow(
        'Failed to create basket registration transaction!'
      )
    })

    it('should throw an error on invalid definition type', async () => {
      // We expect "Unsupported definition type" if that’s what your code throws
      const invalidData = { definitionType: 'invalidType' } as unknown as DefinitionData
      await expect(registryClient.registerDefinition(invalidData)).rejects.toThrow(
        'Unsupported definition type'
      )
    })
  })

  // ------------------------------------------------------------------
  // resolve
  // ------------------------------------------------------------------
  describe('resolve', () => {
    it('should return empty array if resolver does not return output-list', async () => {
      // Mock the instance resolver
      ; (registryClient as any).resolver.query = jest.fn().mockResolvedValue({ type: 'not-output-list' })

      const result = await registryClient.resolve('basket', { name: 'foo' })
      expect(result).toEqual([])
    })

    it('should parse outputs from resolver if type is output-list', async () => {
      // Mock the instance resolver
      ; (registryClient as any).resolver.query = jest.fn().mockResolvedValue({
        type: 'output-list',
        outputs: [{ beef: [9, 9, 9], outputIndex: 0 }]
      })

        // Basket has 7 fields: 5 data fields + operator + signature
        ; (PushDrop.decode as jest.Mock).mockReturnValue({
          fields: [
            [98], // 'b' - basketID
            [97], // 'a' - name
            [115], // 's' - iconURL
            [107], // 'k' - description
            [101], // 'e' - documentationURL
            [116], // 't' - operator
            [111]  // signature field
          ]
        })

        // The final field must match the current wallet pubkey => 'mockPublicKey'
        ; (walletMock.getPublicKey as jest.Mock).mockResolvedValueOnce({
          publicKey: 't'
        })

      const result = await registryClient.resolve('basket', { basketID: 'whatever' })
      expect(result).toHaveLength(1)
      expect(result[0]).toMatchObject({
        definitionType: 'basket',
        basketID: 'b',
        name: 'a',
        iconURL: 's',
        description: 'k',
        documentationURL: 'e',
        registryOperator: 't'
      })
    })

    it('should skip outputs that fail parseLockingScript', async () => {
      // Mock the instance resolver
      ; (registryClient as any).resolver.query = jest.fn().mockResolvedValue({
        type: 'output-list',
        outputs: [
          { beef: [1, 1, 1], outputIndex: 0 },
          { beef: [2, 2, 2], outputIndex: 1 }
        ]
      })

        // Return empty fields so parseLockingScript fails the length check
        ; (PushDrop.decode as jest.Mock)
          .mockReturnValueOnce({ fields: [] }) // fail
          .mockReturnValueOnce({ fields: [] }) // fail again

      const result = await registryClient.resolve('basket', { name: 'fooAgain' })
      expect(result).toEqual([])
    })
  })

  // ------------------------------------------------------------------
  // listOwnRegistryEntries
  // ------------------------------------------------------------------
  describe('listOwnRegistryEntries', () => {
    it('should parse and return registry records from wallet outputs', async () => {
      // The wallet returns 3 outputs; only one is spendable
      (walletMock.listOutputs as jest.Mock).mockResolvedValue({
        outputs: [
          {
            outpoint: 'abc123.0',
            satoshis: 1000,
            lockingScript: 'lsHexA',
            spendable: false
          },
          {
            outpoint: 'xyz999.1',
            satoshis: 500,
            lockingScript: 'lsHexB',
            spendable: false
          },
          {
            outpoint: 'skipMe.2',
            satoshis: 200,
            lockingScript: {
              toHex: jest.fn(() => 'lsHexC')
            },
            spendable: true
          }
        ],
        BEEF: [0, 1, 2, 3]
      });

      // Use a mockImplementation to inspect the lockingScript and return appropriate decoded fields.
      // Basket has 7 fields: 5 data fields + operator + signature
      (PushDrop.decode as jest.Mock).mockImplementation((scriptObj) => {
        return {
          fields: [
            [98],  // 'b' - basketID
            [97],  // 'a' - name
            [115], // 's' - iconURL
            [107], // 'k' - description
            [101], // 'e' - documentationURL
            [116], // 't' - operator
            [111]  // signature field
          ]
        }
      });

      const records = await registryClient.listOwnRegistryEntries('basket');
      expect(walletMock.listOutputs).toHaveBeenCalledWith({
        basket: 'basketmap',
        include: 'entire transactions'
      });
      // Only one spendable item should be returned if parsing succeeds.
      expect(records).toHaveLength(1);
      expect(records[0]).toMatchObject({
        definitionType: 'basket',
        txid: 'skipMe',
        outputIndex: 2,
        satoshis: 200,
        lockingScript: 'decodedLockScript1AsHex'
      });
    });

  })

  // ------------------------------------------------------------------
  // removeDefinition
  // ------------------------------------------------------------------
  describe('removeDefinition', () => {
    let validRecord: RegistryRecord

    beforeEach(() => {
      validRecord = {
        definitionType: 'basket',
        basketID: 'myBasket',
        name: 'whatever',
        iconURL: 'url',
        description: 'desc',
        documentationURL: 'docURL',
        txid: 'someTxId',
        outputIndex: 0,
        satoshis: 1000,
        lockingScript: 'someLockingScriptHex',
        registryOperator: 'mockPublicKey',
        beef: [0, 1, 2]
      }
    })

    it('should remove a record successfully (networkPreset=main)', async () => {
      const result = await registryClient.removeDefinition(validRecord)
      expect(result).toBe('mockBroadcastSuccess')

      expect(walletMock.createAction).toHaveBeenCalledWith(
        expect.objectContaining({
          description: 'Remove basket item: myBasket',
          inputs: [
            {
              outpoint: 'someTxId.0',
              unlockingScriptLength: 74,
              inputDescription: 'Removing basket token'
            }
          ]
        }),
        TEST_ORIGINATOR
      )

      expect(TopicBroadcaster).toHaveBeenCalledWith(['tm_basketmap'], expect.objectContaining({
        networkPreset: 'main'
      }))
      expect(mockBroadcast).toHaveBeenCalled()
    })

    it('should throw if createAction returns no signableTransaction', async () => {
      ; (walletMock.createAction as jest.Mock).mockResolvedValueOnce({
        tx: [1, 2, 3],
        signableTransaction: undefined
      })
      await expect(registryClient.removeDefinition(validRecord)).rejects.toThrow(
        'Failed to create signable transaction.'
      )
    })

    it('should throw if signAction returns no signedTx', async () => {
      ; (walletMock.signAction as jest.Mock).mockResolvedValueOnce({ tx: undefined })
      await expect(registryClient.removeDefinition(validRecord)).rejects.toThrow(
        'Failed to finalize the transaction signature.'
      )
    })

    it('should propagate broadcast errors', async () => {
      mockBroadcast.mockRejectedValueOnce(new Error('Broadcast failure!'))
      await expect(registryClient.removeDefinition(validRecord)).rejects.toThrow(
        'Broadcast failure!'
      )
    })

    it('should throw if registry record is missing required fields', async () => {
      const invalidRecord = { ...validRecord, txid: undefined }
      await expect(registryClient.removeDefinition(invalidRecord as any)).rejects.toThrow(
        'Invalid registry record. Missing txid, outputIndex, or lockingScript.'
      )
    })

    it('should throw if registry record has undefined outputIndex', async () => {
      const invalidRecord = { ...validRecord, outputIndex: undefined }
      await expect(registryClient.removeDefinition(invalidRecord as any)).rejects.toThrow(
        'Invalid registry record. Missing txid, outputIndex, or lockingScript.'
      )
    })

    it('should throw if registry record is missing lockingScript', async () => {
      const invalidRecord = { ...validRecord, lockingScript: undefined }
      await expect(registryClient.removeDefinition(invalidRecord as any)).rejects.toThrow(
        'Invalid registry record. Missing txid, outputIndex, or lockingScript.'
      )
    })

    it('should throw if registry record does not belong to current wallet', async () => {
      const otherUserRecord = { ...validRecord, registryOperator: 'differentPublicKey' }
      await expect(registryClient.removeDefinition(otherUserRecord)).rejects.toThrow(
        'This registry token does not belong to the current wallet.'
      )
    })

    it('should handle protocol definition removal with correct description', async () => {
      const protocolRecord: RegistryRecord = {
        definitionType: 'protocol',
        protocolID: [1, 'testProtocol'],
        name: 'Test Protocol',
        iconURL: 'url',
        description: 'desc',
        documentationURL: 'docURL',
        txid: 'protocolTxId',
        outputIndex: 1,
        satoshis: 1000,
        lockingScript: 'protocolLockingScript',
        registryOperator: 'mockPublicKey',
        beef: [0, 1, 2]
      }

      const result = await registryClient.removeDefinition(protocolRecord)
      expect(result).toBe('mockBroadcastSuccess')

      expect(walletMock.createAction).toHaveBeenCalledWith(
        expect.objectContaining({
          description: 'Remove protocol item: Test Protocol',
          inputs: [
            {
              outpoint: 'protocolTxId.1',
              unlockingScriptLength: 74,
              inputDescription: 'Removing protocol token'
            }
          ]
        }),
        TEST_ORIGINATOR
      )

      expect(TopicBroadcaster).toHaveBeenCalledWith(['tm_protomap'], expect.objectContaining({
        networkPreset: 'main'
      }))
    })

    it('should handle certificate definition removal with correct description', async () => {
      const certificateRecord: RegistryRecord = {
        definitionType: 'certificate',
        type: 'testCert',
        name: 'Test Certificate',
        iconURL: 'url',
        description: 'desc',
        documentationURL: 'docURL',
        fields: {},
        txid: 'certTxId',
        outputIndex: 2,
        satoshis: 1000,
        lockingScript: 'certLockingScript',
        registryOperator: 'mockPublicKey',
        beef: [0, 1, 2]
      }

      const result = await registryClient.removeDefinition(certificateRecord)
      expect(result).toBe('mockBroadcastSuccess')

      expect(walletMock.createAction).toHaveBeenCalledWith(
        expect.objectContaining({
          description: 'Remove certificate item: Test Certificate',
          inputs: [
            {
              outpoint: 'certTxId.2',
              unlockingScriptLength: 74,
              inputDescription: 'Removing certificate token'
            }
          ]
        }),
        TEST_ORIGINATOR
      )

      expect(TopicBroadcaster).toHaveBeenCalledWith(['tm_certmap'], expect.objectContaining({
        networkPreset: 'main'
      }))
    })

    it('should use certificate type as identifier when name is undefined', async () => {
      const certificateRecord: RegistryRecord = {
        definitionType: 'certificate',
        type: 'testCertType',
        name: undefined as any,
        iconURL: 'url',
        description: 'desc',
        documentationURL: 'docURL',
        fields: {},
        txid: 'certTxId',
        outputIndex: 2,
        satoshis: 1000,
        lockingScript: 'certLockingScript',
        registryOperator: 'mockPublicKey',
        beef: [0, 1, 2]
      }

      const result = await registryClient.removeDefinition(certificateRecord)
      expect(result).toBe('mockBroadcastSuccess')

      expect(walletMock.createAction).toHaveBeenCalledWith(
        expect.objectContaining({
          description: 'Remove certificate item: testCertType'
        }),
        TEST_ORIGINATOR
      )
    })

    it('should use acceptDelayedBroadcast setting from constructor', async () => {
      // Create a new client with acceptDelayedBroadcast: true
      const clientWithDelayedBroadcast = new RegistryClient(walletMock as WalletInterface, { acceptDelayedBroadcast: true }, TEST_ORIGINATOR)
      ; (clientWithDelayedBroadcast as any).resolver = {
        query: jest.fn().mockResolvedValue({ type: 'output-list', outputs: [] })
      }

      await clientWithDelayedBroadcast.removeDefinition(validRecord)

      expect(walletMock.createAction).toHaveBeenCalledWith(
        expect.objectContaining({
          options: expect.objectContaining({
            acceptDelayedBroadcast: true
          })
        }),
        TEST_ORIGINATOR
      )

      expect(walletMock.signAction).toHaveBeenCalledWith(
        expect.objectContaining({
          options: expect.objectContaining({
            acceptDelayedBroadcast: true
          })
        }),
        TEST_ORIGINATOR
      )
    })
  })
})
