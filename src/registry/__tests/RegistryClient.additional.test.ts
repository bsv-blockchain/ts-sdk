/**
 * RegistryClient additional tests.
 *
 * Focuses on branches not covered by the primary test file:
 *  - updateDefinition (all paths)
 *  - removeDefinition itemIdentifier for unknown definitionType
 *  - listOwnRegistryEntries: non-spendable skip, parse errors, empty BEEF
 *  - resolve: protocol and certificate parsing, JSON parse error in certificate fields
 *  - deserializeWalletProtocol: all validation error paths
 *  - getIdentityKey: caching behaviour
 *  - getNetwork: caching behaviour
 */

import { RegistryClient, deserializeWalletProtocol } from '../RegistryClient'
import { WalletInterface } from '../../wallet/index.js'
import { TopicBroadcaster, LookupResolver } from '../../overlay-tools/index.js'
import { PushDrop } from '../../script/index.js'
import {
  DefinitionType,
  DefinitionData,
  ProtocolDefinitionData,
  CertificateDefinitionData,
  RegistryRecord,
  CertificateFieldDescriptor
} from '../types/index.js'

// -------------------- Module-level mocks -------------------- //

const mockBroadcast = jest.fn().mockResolvedValue('broadcastSuccess')

jest.mock('../../overlay-tools/index.js', () => ({
  TopicBroadcaster: jest.fn().mockImplementation(() => ({
    broadcast: mockBroadcast
  })),
  LookupResolver: jest.fn().mockImplementation(() => ({
    query: jest.fn()
  }))
}))

jest.mock('../../script/index.js', () => {
  const actual = jest.requireActual('../../script/index.js')
  return {
    ...actual,
    PushDrop: Object.assign(
      jest.fn().mockImplementation(() => ({
        lock: jest.fn().mockResolvedValue({ toHex: () => 'mockLockHex' }),
        unlock: jest.fn().mockReturnValue({
          sign: jest.fn().mockResolvedValue({ toHex: () => 'mockUnlockHex' })
        })
      })),
      { decode: jest.fn() }
    ),
    LockingScript: {
      fromHex: jest.fn().mockImplementation((hex: string) => ({ hex }))
    }
  }
})

jest.mock('../../transaction/index.js', () => ({
  Transaction: {
    fromAtomicBEEF: jest.fn().mockImplementation(() => ({
      outputs: [
        { lockingScript: 'mockLS0' },
        { lockingScript: 'mockLS1' }
      ]
    })),
    fromBEEF: jest.fn().mockImplementation(() => ({
      outputs: [
        { lockingScript: { toHex: () => 'mockLSHex0' } },
        { lockingScript: { toHex: () => 'mockLSHex1' } },
        { lockingScript: { toHex: () => 'mockLSHex2' } }
      ]
    }))
  }
}))

jest.mock('../../primitives/index.js', () => ({
  Utils: {
    toArray: jest.fn().mockImplementation((str: string) =>
      Array.from(str).map((c) => c.charCodeAt(0))
    ),
    toUTF8: jest.fn().mockImplementation((arr: number[] | string) => {
      if (Array.isArray(arr)) return arr.map((n) => String.fromCharCode(n)).join('')
      return arr
    })
  }
}))

// -------------------- Test helpers -------------------- //

const TEST_ORIGINATOR = 'test.additional.origin'
const MOCK_PUB_KEY = 'mockPublicKey'

function buildWalletMock (): jest.Mocked<Partial<WalletInterface>> {
  return {
    getPublicKey: jest.fn().mockResolvedValue({ publicKey: MOCK_PUB_KEY }),
    createAction: jest.fn().mockResolvedValue({
      tx: [1, 2, 3],
      signableTransaction: { tx: [1, 2, 3], reference: 'ref123' }
    }),
    signAction: jest.fn().mockResolvedValue({ tx: [7, 8, 9] }),
    listOutputs: jest.fn().mockResolvedValue({ outputs: [], BEEF: [] }),
    getNetwork: jest.fn().mockResolvedValue({ network: 'testnet' })
  }
}

function buildClient (wallet: Partial<WalletInterface>): RegistryClient {
  const client = new RegistryClient(wallet as WalletInterface, {}, TEST_ORIGINATOR)
  ;(client as any).resolver = {
    query: jest.fn().mockResolvedValue({ type: 'output-list', outputs: [] })
  }
  return client
}

const baseRegistryRecord: RegistryRecord = {
  definitionType: 'basket',
  basketID: 'testBasket',
  name: 'Test Basket',
  iconURL: 'https://icon.com',
  description: 'A basket',
  documentationURL: 'https://docs.com',
  txid: 'txid123',
  outputIndex: 0,
  satoshis: 1,
  lockingScript: 'lockhex',
  registryOperator: MOCK_PUB_KEY,
  beef: [1, 2, 3]
}

// -------------------- deserializeWalletProtocol -------------------- //

describe('deserializeWalletProtocol', () => {
  it('parses a valid protocol string', () => {
    const result = deserializeWalletProtocol(JSON.stringify([1, 'my-protocol']))
    expect(result).toEqual([1, 'my-protocol'])
  })

  it('throws for non-array input', () => {
    expect(() => deserializeWalletProtocol('"not-array"')).toThrow(
      'Invalid wallet protocol format.'
    )
  })

  it('throws for array with wrong length', () => {
    expect(() => deserializeWalletProtocol(JSON.stringify([1]))).toThrow(
      'Invalid wallet protocol format.'
    )
  })

  it('throws for invalid security level', () => {
    expect(() => deserializeWalletProtocol(JSON.stringify([3, 'proto']))).toThrow(
      'Invalid security level.'
    )
  })

  it('accepts security level 0', () => {
    const result = deserializeWalletProtocol(JSON.stringify([0, 'proto']))
    expect(result[0]).toBe(0)
  })

  it('accepts security level 2', () => {
    const result = deserializeWalletProtocol(JSON.stringify([2, 'proto']))
    expect(result[0]).toBe(2)
  })

  it('throws for non-string protocol string', () => {
    expect(() => deserializeWalletProtocol(JSON.stringify([1, 42]))).toThrow(
      'Invalid protocolID'
    )
  })

  it('throws for completely invalid JSON', () => {
    expect(() => deserializeWalletProtocol('not-json')).toThrow()
  })
})

// -------------------- getIdentityKey caching -------------------- //

describe('RegistryClient.getIdentityKey – caching', () => {
  it('calls getPublicKey only once on repeated calls', async () => {
    const wallet = buildWalletMock()
    const client = buildClient(wallet)

    // Trigger two operations that each call getIdentityKey internally
    await client.registerDefinition({
      definitionType: 'basket',
      basketID: 'b1',
      name: 'Basket 1',
      iconURL: 'https://icon.com',
      description: 'desc',
      documentationURL: 'https://docs.com'
    })
    await client.registerDefinition({
      definitionType: 'basket',
      basketID: 'b2',
      name: 'Basket 2',
      iconURL: 'https://icon.com',
      description: 'desc',
      documentationURL: 'https://docs.com'
    })

    // getPublicKey should only have been called once (identity key was cached)
    expect(wallet.getPublicKey).toHaveBeenCalledTimes(1)
  })
})

// -------------------- getNetwork caching -------------------- //

describe('RegistryClient.getNetwork – caching', () => {
  it('calls wallet.getNetwork only once even across multiple operations', async () => {
    const wallet = buildWalletMock()
    const client = buildClient(wallet)

    await client.registerDefinition({
      definitionType: 'basket',
      basketID: 'b1',
      name: 'Basket 1',
      iconURL: 'https://icon.com',
      description: 'desc',
      documentationURL: 'https://docs.com'
    })
    await client.registerDefinition({
      definitionType: 'basket',
      basketID: 'b2',
      name: 'Basket 2',
      iconURL: 'https://icon.com',
      description: 'desc',
      documentationURL: 'https://docs.com'
    })

    expect(wallet.getNetwork).toHaveBeenCalledTimes(1)
  })
})

// -------------------- updateDefinition -------------------- //

describe('RegistryClient.updateDefinition', () => {
  let wallet: jest.Mocked<Partial<WalletInterface>>
  let client: RegistryClient

  beforeEach(() => {
    wallet = buildWalletMock()
    client = buildClient(wallet)
    jest.clearAllMocks()
    mockBroadcast.mockClear()
    mockBroadcast.mockResolvedValue('broadcastSuccess')
  })

  it('throws if txid is missing from the record', async () => {
    const record = { ...baseRegistryRecord, txid: undefined }
    const updated: DefinitionData = { ...baseRegistryRecord }
    await expect(client.updateDefinition(record as any, updated)).rejects.toThrow(
      'Invalid registry record. Missing txid, outputIndex, or lockingScript.'
    )
  })

  it('throws if outputIndex is missing from the record', async () => {
    const record = { ...baseRegistryRecord, outputIndex: undefined }
    const updated: DefinitionData = { ...baseRegistryRecord }
    await expect(client.updateDefinition(record as any, updated)).rejects.toThrow(
      'Invalid registry record. Missing txid, outputIndex, or lockingScript.'
    )
  })

  it('throws if lockingScript is missing from the record', async () => {
    const record = { ...baseRegistryRecord, lockingScript: undefined }
    const updated: DefinitionData = { ...baseRegistryRecord }
    await expect(client.updateDefinition(record as any, updated)).rejects.toThrow(
      'Invalid registry record. Missing txid, outputIndex, or lockingScript.'
    )
  })

  it('throws if definitionType does not match updatedData', async () => {
    const record = { ...baseRegistryRecord }
    const updated: DefinitionData = {
      definitionType: 'protocol',
      protocolID: [1, 'p'],
      name: 'P',
      iconURL: 'u',
      description: 'd',
      documentationURL: 'doc'
    }
    await expect(client.updateDefinition(record, updated)).rejects.toThrow(
      'Cannot change definition type from basket to protocol'
    )
  })

  it('throws if the registry record does not belong to the current wallet', async () => {
    const record = { ...baseRegistryRecord, registryOperator: 'differentKey' }
    const updated: DefinitionData = { ...baseRegistryRecord }
    await expect(client.updateDefinition(record, updated)).rejects.toThrow(
      'This registry token does not belong to the current wallet.'
    )
  })

  it('throws if createAction returns no signableTransaction', async () => {
    ;(wallet.createAction as jest.Mock).mockResolvedValueOnce({
      tx: [1, 2, 3],
      signableTransaction: undefined
    })
    const record = { ...baseRegistryRecord }
    const updated: DefinitionData = { ...baseRegistryRecord }
    await expect(client.updateDefinition(record, updated)).rejects.toThrow(
      'Failed to create signable transaction.'
    )
  })

  it('throws if signAction returns no tx', async () => {
    ;(wallet.signAction as jest.Mock).mockResolvedValueOnce({ tx: undefined })
    const record = { ...baseRegistryRecord }
    const updated: DefinitionData = { ...baseRegistryRecord }
    await expect(client.updateDefinition(record, updated)).rejects.toThrow(
      'Failed to finalize the transaction signature.'
    )
  })

  it('successfully updates a basket definition and broadcasts', async () => {
    const record = { ...baseRegistryRecord }
    const updated: DefinitionData = {
      definitionType: 'basket',
      basketID: 'updatedBasket',
      name: 'Updated Basket',
      iconURL: 'https://newicon.com',
      description: 'Updated description',
      documentationURL: 'https://newdocs.com'
    }

    const result = await client.updateDefinition(record, updated)

    expect(result).toBe('broadcastSuccess')
    expect(wallet.createAction).toHaveBeenCalledWith(
      expect.objectContaining({
        description: 'Update basket item: testBasket',
        inputs: [expect.objectContaining({ outpoint: 'txid123.0' })],
        outputs: [expect.objectContaining({ basket: 'basketmap' })]
      }),
      TEST_ORIGINATOR
    )
    expect(wallet.signAction).toHaveBeenCalledWith(
      expect.objectContaining({ reference: 'ref123' }),
      TEST_ORIGINATOR
    )
    expect(TopicBroadcaster).toHaveBeenCalledWith(
      ['tm_basketmap'],
      expect.objectContaining({ networkPreset: 'testnet' })
    )
  })

  it('successfully updates a protocol definition and uses protocol item identifier', async () => {
    const protocolRecord: RegistryRecord = {
      definitionType: 'protocol',
      protocolID: [1, 'oldProto'],
      name: 'Old Protocol',
      iconURL: 'https://icon.com',
      description: 'desc',
      documentationURL: 'https://docs.com',
      txid: 'protTxid',
      outputIndex: 0,
      satoshis: 1,
      lockingScript: 'lockhex',
      registryOperator: MOCK_PUB_KEY,
      beef: [1, 2, 3]
    }
    const updated: ProtocolDefinitionData = {
      definitionType: 'protocol',
      protocolID: [1, 'newProto'],
      name: 'New Protocol',
      iconURL: 'https://icon.com',
      description: 'Updated desc',
      documentationURL: 'https://newdocs.com'
    }

    const result = await client.updateDefinition(protocolRecord, updated)

    expect(result).toBe('broadcastSuccess')
    expect(wallet.createAction).toHaveBeenCalledWith(
      expect.objectContaining({
        description: 'Update protocol item: Old Protocol'
      }),
      TEST_ORIGINATOR
    )
    expect(TopicBroadcaster).toHaveBeenCalledWith(['tm_protomap'], expect.anything())
  })

  it('uses certificate type when name is undefined in the item identifier', async () => {
    const certRecord: RegistryRecord = {
      definitionType: 'certificate',
      type: 'certType123',
      name: undefined as any,
      iconURL: 'https://icon.com',
      description: 'desc',
      documentationURL: 'https://docs.com',
      fields: {},
      txid: 'certTxid',
      outputIndex: 0,
      satoshis: 1,
      lockingScript: 'lockhex',
      registryOperator: MOCK_PUB_KEY,
      beef: [1, 2, 3]
    }
    const updated: CertificateDefinitionData = {
      definitionType: 'certificate',
      type: 'certType123',
      name: 'New Cert Name',
      iconURL: 'https://icon.com',
      description: 'Updated',
      documentationURL: 'https://docs.com',
      fields: {}
    }

    const result = await client.updateDefinition(certRecord, updated)

    expect(result).toBe('broadcastSuccess')
    expect(wallet.createAction).toHaveBeenCalledWith(
      expect.objectContaining({
        description: 'Update certificate item: certType123'
      }),
      TEST_ORIGINATOR
    )
  })

  it('uses certificate name when defined for the item identifier', async () => {
    const certRecord: RegistryRecord = {
      definitionType: 'certificate',
      type: 'certType456',
      name: 'Named Cert',
      iconURL: 'https://icon.com',
      description: 'desc',
      documentationURL: 'https://docs.com',
      fields: {},
      txid: 'certTxid2',
      outputIndex: 0,
      satoshis: 1,
      lockingScript: 'lockhex',
      registryOperator: MOCK_PUB_KEY,
      beef: [1, 2, 3]
    }
    const updated: CertificateDefinitionData = {
      definitionType: 'certificate',
      type: 'certType456',
      name: 'Updated Cert',
      iconURL: 'https://icon.com',
      description: 'desc',
      documentationURL: 'https://docs.com',
      fields: {}
    }

    await client.updateDefinition(certRecord, updated)

    expect(wallet.createAction).toHaveBeenCalledWith(
      expect.objectContaining({
        description: 'Update certificate item: Named Cert'
      }),
      TEST_ORIGINATOR
    )
  })

  it('uses acceptDelayedBroadcast: true when configured', async () => {
    const delayedClient = new RegistryClient(
      wallet as WalletInterface,
      { acceptDelayedBroadcast: true },
      TEST_ORIGINATOR
    )
    ;(delayedClient as any).resolver = {
      query: jest.fn().mockResolvedValue({ type: 'output-list', outputs: [] })
    }

    const record = { ...baseRegistryRecord }
    const updated: DefinitionData = { ...baseRegistryRecord }
    await delayedClient.updateDefinition(record, updated)

    expect(wallet.createAction).toHaveBeenCalledWith(
      expect.objectContaining({
        options: expect.objectContaining({ acceptDelayedBroadcast: true })
      }),
      TEST_ORIGINATOR
    )
    expect(wallet.signAction).toHaveBeenCalledWith(
      expect.objectContaining({
        options: expect.objectContaining({ acceptDelayedBroadcast: true })
      }),
      TEST_ORIGINATOR
    )
  })

  it('propagates broadcast errors', async () => {
    mockBroadcast.mockRejectedValueOnce(new Error('Update broadcast failed!'))
    const record = { ...baseRegistryRecord }
    const updated: DefinitionData = { ...baseRegistryRecord }
    await expect(client.updateDefinition(record, updated)).rejects.toThrow('Update broadcast failed!')
  })
})

// -------------------- removeDefinition: unknown identifier -------------------- //

describe('RegistryClient.removeDefinition – itemIdentifier edge cases', () => {
  let wallet: jest.Mocked<Partial<WalletInterface>>
  let client: RegistryClient

  beforeEach(() => {
    wallet = buildWalletMock()
    client = buildClient(wallet)
    jest.clearAllMocks()
    mockBroadcast.mockClear()
    mockBroadcast.mockResolvedValue('broadcastSuccess')
  })

  it('uses basketID as itemIdentifier for basket records', async () => {
    const record = { ...baseRegistryRecord }
    await client.removeDefinition(record)
    expect(wallet.createAction).toHaveBeenCalledWith(
      expect.objectContaining({
        description: 'Remove basket item: testBasket'
      }),
      TEST_ORIGINATOR
    )
  })
})

// -------------------- listOwnRegistryEntries edge cases -------------------- //

describe('RegistryClient.listOwnRegistryEntries – edge cases', () => {
  let wallet: jest.Mocked<Partial<WalletInterface>>
  let client: RegistryClient

  beforeEach(() => {
    wallet = buildWalletMock()
    client = buildClient(wallet)
    jest.clearAllMocks()
  })

  it('returns empty array when no outputs are returned', async () => {
    ;(wallet.listOutputs as jest.Mock).mockResolvedValue({ outputs: [], BEEF: [] })
    const results = await client.listOwnRegistryEntries('basket')
    expect(results).toEqual([])
  })

  it('skips non-spendable outputs', async () => {
    ;(wallet.listOutputs as jest.Mock).mockResolvedValue({
      outputs: [
        { outpoint: 'tx1.0', satoshis: 1, spendable: false },
        { outpoint: 'tx2.0', satoshis: 1, spendable: false }
      ],
      BEEF: [1, 2, 3]
    })
    const results = await client.listOwnRegistryEntries('basket')
    expect(results).toEqual([])
    expect(PushDrop.decode).not.toHaveBeenCalled()
  })

  it('skips spendable outputs that fail to parse (catches error silently)', async () => {
    ;(wallet.listOutputs as jest.Mock).mockResolvedValue({
      outputs: [{ outpoint: 'badtx.0', satoshis: 1, spendable: true }],
      BEEF: [1, 2, 3]
    })
    // Make decode throw to simulate parse failure
    ;(PushDrop.decode as jest.Mock).mockImplementationOnce(() => {
      throw new Error('Invalid script')
    })
    const results = await client.listOwnRegistryEntries('basket')
    expect(results).toEqual([])
  })

  it('returns records for all valid spendable outputs', async () => {
    ;(wallet.listOutputs as jest.Mock).mockResolvedValue({
      outputs: [
        { outpoint: 'tx1.0', satoshis: 1, spendable: true },
        { outpoint: 'tx2.0', satoshis: 2, spendable: true }
      ],
      BEEF: [0, 1, 2, 3]
    })
    // Basket has 7 fields
    ;(PushDrop.decode as jest.Mock).mockReturnValue({
      fields: [
        [98],  // basketID: 'b'
        [97],  // name: 'a'
        [115], // iconURL: 's'
        [107], // description: 'k'
        [101], // documentationURL: 'e'
        [116], // operator: 't'
        [111]  // signature field
      ]
    })

    const results = await client.listOwnRegistryEntries('basket')
    expect(results).toHaveLength(2)
    expect(results[0].txid).toBe('tx1')
    expect(results[1].txid).toBe('tx2')
  })

  it('uses protomap basket for protocol definition type', async () => {
    ;(wallet.listOutputs as jest.Mock).mockResolvedValue({ outputs: [], BEEF: [] })
    await client.listOwnRegistryEntries('protocol')
    expect(wallet.listOutputs).toHaveBeenCalledWith({
      basket: 'protomap',
      include: 'entire transactions'
    })
  })

  it('uses certmap basket for certificate definition type', async () => {
    ;(wallet.listOutputs as jest.Mock).mockResolvedValue({ outputs: [], BEEF: [] })
    await client.listOwnRegistryEntries('certificate')
    expect(wallet.listOutputs).toHaveBeenCalledWith({
      basket: 'certmap',
      include: 'entire transactions'
    })
  })
})

// -------------------- resolve: protocol and certificate parsing -------------------- //

describe('RegistryClient.resolve – protocol and certificate parsing', () => {
  let wallet: jest.Mocked<Partial<WalletInterface>>
  let client: RegistryClient

  beforeEach(() => {
    wallet = buildWalletMock()
    client = buildClient(wallet)
    jest.clearAllMocks()
  })

  it('parses a protocol output from the resolver', async () => {
    ;(client as any).resolver.query = jest.fn().mockResolvedValue({
      type: 'output-list',
      outputs: [{ beef: [1, 2, 3], outputIndex: 0 }]
    })

    // protocol has 7 fields: protocolID, name, iconURL, description, docURL, operator, sig
    ;(PushDrop.decode as jest.Mock).mockReturnValueOnce({
      fields: [
        Array.from('[1,"proto"]').map((c) => c.charCodeAt(0)), // protocolID JSON
        [110, 97, 109, 101],  // 'name'
        [105, 99, 111, 110],  // 'icon'
        [100, 101, 115, 99],  // 'desc'
        [100, 111, 99],       // 'doc'
        [111, 112],           // 'op' - operator
        [115, 105, 103]       // signature
      ]
    })

    const result = await client.resolve('protocol', { name: 'proto' })
    expect(result).toHaveLength(1)
    expect(result[0].definitionType).toBe('protocol')
  })

  it('parses a certificate output from the resolver', async () => {
    ;(client as any).resolver.query = jest.fn().mockResolvedValue({
      type: 'output-list',
      outputs: [{ beef: [1, 2, 3], outputIndex: 0 }]
    })

    // certificate has 8 fields: type, name, iconURL, desc, docURL, fieldsJSON, operator, sig
    const fieldsJSON = JSON.stringify({ field1: { friendlyName: 'Field One', description: 'd', type: 'text', fieldIcon: 'i' } })
    ;(PushDrop.decode as jest.Mock).mockReturnValueOnce({
      fields: [
        [116, 121, 112, 101],  // 'type'
        [110, 97, 109, 101],   // 'name'
        [105, 99, 111, 110],   // 'icon'
        [100, 101, 115, 99],   // 'desc'
        [100, 111, 99],        // 'doc'
        Array.from(fieldsJSON).map((c) => c.charCodeAt(0)), // fieldsJSON
        [111, 112],            // 'op' - operator
        [115, 105, 103]        // signature
      ]
    })

    const result = await client.resolve('certificate', { type: 'type' })
    expect(result).toHaveLength(1)
    expect(result[0].definitionType).toBe('certificate')
  })

  it('uses empty fields object when certificate fieldsJSON is invalid JSON', async () => {
    ;(client as any).resolver.query = jest.fn().mockResolvedValue({
      type: 'output-list',
      outputs: [{ beef: [1, 2, 3], outputIndex: 0 }]
    })

    // Invalid JSON for fieldsJSON
    ;(PushDrop.decode as jest.Mock).mockReturnValueOnce({
      fields: [
        [116, 121, 112, 101],   // 'type'
        [110, 97, 109, 101],    // 'name'
        [105, 99, 111, 110],    // 'icon'
        [100, 101, 115, 99],    // 'desc'
        [100, 111, 99],         // 'doc'
        [123, 105, 110, 118],   // '{inv' - invalid JSON
        [111, 112],             // operator
        [115, 105, 103]         // signature
      ]
    })

    const result = await client.resolve('certificate', { type: 'type' })
    expect(result).toHaveLength(1)
    expect((result[0] as CertificateDefinitionData).fields).toEqual({})
  })

  it('skips outputs with wrong field count for basket (not 7)', async () => {
    ;(client as any).resolver.query = jest.fn().mockResolvedValue({
      type: 'output-list',
      outputs: [{ beef: [1, 2, 3], outputIndex: 0 }]
    })

    // Return only 5 fields — should fail the basket field count check and be skipped
    ;(PushDrop.decode as jest.Mock).mockReturnValueOnce({
      fields: [[1], [2], [3], [4], [5]]
    })

    const result = await client.resolve('basket', {})
    expect(result).toEqual([])
  })

  it('skips outputs with wrong field count for certificate (not 8)', async () => {
    ;(client as any).resolver.query = jest.fn().mockResolvedValue({
      type: 'output-list',
      outputs: [{ beef: [1, 2, 3], outputIndex: 0 }]
    })

    // Return only 5 fields — should fail the certificate field count check
    ;(PushDrop.decode as jest.Mock).mockReturnValueOnce({
      fields: [[1], [2], [3], [4], [5]]
    })

    const result = await client.resolve('certificate', {})
    expect(result).toEqual([])
  })
})

// -------------------- registerDefinition: network preset used -------------------- //

describe('RegistryClient.registerDefinition – network preset', () => {
  it('passes testnet to TopicBroadcaster when wallet returns testnet', async () => {
    const wallet = buildWalletMock()
    ;(wallet.getNetwork as jest.Mock).mockResolvedValue({ network: 'testnet' })
    const client = buildClient(wallet)

    await client.registerDefinition({
      definitionType: 'basket',
      basketID: 'b1',
      name: 'Basket',
      iconURL: 'u',
      description: 'd',
      documentationURL: 'doc'
    })

    expect(TopicBroadcaster).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ networkPreset: 'testnet' })
    )
  })
})
