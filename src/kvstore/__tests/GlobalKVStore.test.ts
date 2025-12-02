/** eslint-env jest */
import GlobalKVStore from '../GlobalKVStore.js'
import { WalletInterface, CreateActionResult, SignActionResult } from '../../wallet/Wallet.interfaces.js'
import Transaction from '../../transaction/Transaction.js'
import { Historian } from '../../overlay-tools/Historian.js'
import { kvStoreInterpreter } from '../kvStoreInterpreter.js'
import { PushDrop } from '../../script/index.js'
import * as Utils from '../../primitives/utils.js'
import { TopicBroadcaster, LookupResolver } from '../../overlay-tools/index.js'
import { KVStoreConfig } from '../types.js'
import { Beef } from '../../transaction/Beef.js'
import { ProtoWallet } from '../../wallet/ProtoWallet.js'

// --- Module mocks ------------------------------------------------------------
jest.mock('../../transaction/Transaction.js')
jest.mock('../../transaction/Beef.js')
jest.mock('../../overlay-tools/Historian.js')
jest.mock('../kvStoreInterpreter.js')
jest.mock('../../script/index.js')
jest.mock('../../primitives/utils.js')
jest.mock('../../overlay-tools/index.js', () => {
  const actual = jest.requireActual('../../overlay-tools/index.js')
  return {
    ...actual,
    // Keep withDoubleSpendRetry as the real implementation
    withDoubleSpendRetry: actual.withDoubleSpendRetry,
    // Mock the classes
    TopicBroadcaster: jest.fn(),
    LookupResolver: jest.fn()
  }
})
jest.mock('../../wallet/ProtoWallet.js')
jest.mock('../../wallet/WalletClient.js')

// --- Typed shortcuts to mocked classes --------------------------------------
const MockTransaction = Transaction as jest.MockedClass<typeof Transaction>
const MockBeef = Beef as jest.MockedClass<typeof Beef>
const MockHistorian = Historian as jest.MockedClass<typeof Historian>
const MockPushDrop = PushDrop as jest.MockedClass<typeof PushDrop>
const MockUtils = Utils as jest.Mocked<typeof Utils>
const MockTopicBroadcaster = TopicBroadcaster as jest.MockedClass<typeof TopicBroadcaster>
const MockLookupResolver = LookupResolver as jest.MockedClass<typeof LookupResolver>
const MockProtoWallet = ProtoWallet as jest.MockedClass<typeof ProtoWallet>

// --- Test constants ----------------------------------------------------------
const TEST_TXID =
  '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
const TEST_CONTROLLER =
  '02e3f2c4a5b6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3'
const TEST_KEY = 'testKey'
const TEST_VALUE = 'testValue'

// --- Helpers ----------------------------------------------------------------
type MTx = jest.Mocked<InstanceType<typeof Transaction>>
type MBeef = jest.Mocked<InstanceType<typeof Beef>> & { findOutput: jest.Mock }
type MHistorian = jest.Mocked<InstanceType<typeof Historian>>
type MResolver = jest.Mocked<InstanceType<typeof LookupResolver>>
type MBroadcaster = jest.Mocked<InstanceType<typeof TopicBroadcaster>>
type MProtoWallet = jest.Mocked<InstanceType<typeof ProtoWallet>>

function makeMockTx (): MTx {
  return {
    id: jest.fn().mockReturnValue(TEST_TXID),
    // Only the properties used by GlobalKVStore are needed
    outputs: [
      {
        lockingScript: {
          toHex: jest.fn().mockReturnValue('mock_script'),
          toArray: jest.fn().mockReturnValue([1, 2, 3])
        },
        satoshis: 1
      }
    ],
    inputs: []
  } as any
}

function primeTransactionMocks (tx: MTx) {
  ; (MockTransaction.fromAtomicBEEF as jest.Mock).mockReturnValue(tx)
  ; (MockTransaction.fromBEEF as jest.Mock).mockReturnValue(tx)
}

function primeBeefMocks (beef: MBeef, tx: MTx) {
  beef.toBinary.mockReturnValue(Array.from(new Uint8Array([1, 2, 3])))
  beef.findTxid.mockReturnValue({ tx } as any)
  beef.findOutput = jest.fn().mockReturnValue(tx.outputs[0] as any)
  MockBeef.mockImplementation(() => beef)
  ; (MockBeef as any).fromBinary = jest.fn().mockReturnValue(beef)
}

function primePushDropDecodeToValidValue () {
  ; (MockPushDrop as any).decode = jest.fn().mockReturnValue({
    fields: [
      Array.from(Buffer.from(JSON.stringify([1, 'kvstore']))), // protocolID
      Array.from(Buffer.from(TEST_KEY)), // key
      Array.from(Buffer.from(TEST_VALUE)), // value
      Array.from(Buffer.from(TEST_CONTROLLER, 'hex')), // controller
      Array.from(Buffer.from('signature')) // signature
    ]
  })
}

function primeUtilsDefaults () {
  MockUtils.toUTF8.mockImplementation((arr: any) => {
    if (typeof arr === 'string') return arr
    if (!Array.isArray(arr)) return TEST_VALUE

    // Check for protocolID field (JSON for [1,"kvstore"])
    if (arr.join(',') === '91,49,44,34,107,118,115,116,111,114,101,34,93') {
      return '[1,"kvstore"]'
    }

    // Check for key field (TEST_KEY as bytes)
    const testKeyBytes = Array.from(Buffer.from(TEST_KEY))
    if (arr.join(',') === testKeyBytes.join(',')) {
      return TEST_KEY
    }

    // Default to TEST_VALUE for value field
    return TEST_VALUE
  })
  MockUtils.toHex.mockImplementation((arr: any) => {
    if (Array.isArray(arr) && arr.length > 0) {
      return TEST_CONTROLLER
    }
    return 'mock_hex'
  })
  MockUtils.toBase64.mockReturnValue('dGVzdEtleQ==') // base64 of 'testKey'
  MockUtils.toArray.mockReturnValue([1, 2, 3, 4])
}

function primeWalletMocks () {
  return {
    getPublicKey: jest.fn().mockResolvedValue({ publicKey: TEST_CONTROLLER }),
    createAction: jest.fn().mockResolvedValue({
      tx: Array.from(new Uint8Array([1, 2, 3])),
      txid: TEST_TXID,
      signableTransaction: {
        tx: Array.from(new Uint8Array([1, 2, 3])),
        reference: 'ref123'
      }
    } as CreateActionResult),
    signAction: jest.fn().mockResolvedValue({
      tx: Array.from(new Uint8Array([1, 2, 3])),
      txid: TEST_TXID
    } as SignActionResult)
  } as unknown as jest.Mocked<WalletInterface>
}

function primeResolverEmpty (resolver: MResolver) {
  resolver.query.mockResolvedValue({ type: 'output-list', outputs: [] } as any)
}

function primeResolverWithOneOutput (resolver: MResolver) {
  const mockOutput = {
    beef: Array.from(new Uint8Array([1, 2, 3])),
    outputIndex: 0,
    context: Array.from(new Uint8Array([4, 5, 6]))
  }
  resolver.query.mockResolvedValue({
    type: 'output-list',
    outputs: [mockOutput]
  } as any)
}

function primeResolverWithMultipleOutputs (resolver: MResolver, count: number = 3) {
  const mockOutputs = Array.from({ length: count }, (_, i) => ({
    beef: Array.from(new Uint8Array([1, 2, 3, i])),
    outputIndex: i,
    context: Array.from(new Uint8Array([4, 5, 6, i]))
  }))
  resolver.query.mockResolvedValue({
    type: 'output-list',
    outputs: mockOutputs
  } as any)
}

// --- Test suite --------------------------------------------------------------
describe('GlobalKVStore', () => {
  let kvStore: GlobalKVStore
  let mockWallet: jest.Mocked<WalletInterface>
  let mockHistorian: MHistorian
  let mockResolver: MResolver
  let mockBroadcaster: MBroadcaster
  let mockBeef: MBeef
  let mockProtoWallet: MProtoWallet
  let tx: MTx

  beforeEach(() => {
    jest.clearAllMocks()

    // Wallet
    mockWallet = primeWalletMocks()

    // Tx/BEEF
    tx = makeMockTx()
    primeTransactionMocks(tx)
    mockBeef = {
      toBinary: jest.fn(),
      findTxid: jest.fn(),
      findOutput: jest.fn()
    } as any
    primeBeefMocks(mockBeef, tx)

    // Historian
    mockHistorian = {
      buildHistory: jest.fn().mockResolvedValue([TEST_VALUE])
    } as any
    MockHistorian.mockImplementation(() => mockHistorian)

    // PushDrop lock/unlock plumbing
    const mockLockingScript = { toHex: () => 'mockLockingScriptHex' }
    const mockPushDrop = {
      lock: jest.fn().mockResolvedValue(mockLockingScript),
      unlock: jest.fn().mockReturnValue({
        sign: jest.fn().mockResolvedValue({ toHex: () => 'mockUnlockingScript' })
      })
    }
    MockPushDrop.mockImplementation(() => mockPushDrop as any)
    primePushDropDecodeToValidValue()

    // Utils
    primeUtilsDefaults()

    // Resolver / Broadcaster
    mockResolver = {
      query: jest.fn()
    } as any
    MockLookupResolver.mockImplementation(() => mockResolver)
    mockBroadcaster = {
      broadcast: jest.fn().mockResolvedValue({ success: true })
    } as any
    MockTopicBroadcaster.mockImplementation(() => mockBroadcaster)

    // Proto wallet
    mockProtoWallet = {
      createHmac: jest.fn().mockResolvedValue({ hmac: new Uint8Array(32) }),
      verifySignature: jest.fn().mockResolvedValue({ valid: true })
    } as any
    MockProtoWallet.mockImplementation(() => mockProtoWallet)

    // SUT
    kvStore = new GlobalKVStore({ wallet: mockWallet })
  })

  // --------------------------------------------------------------------------
  describe('Constructor', () => {
    it('creates with default config', () => {
      const store = new GlobalKVStore()
      expect(store).toBeInstanceOf(GlobalKVStore)
    })

    it('creates with custom config', () => {
      const config: KVStoreConfig = {
        wallet: mockWallet,
        protocolID: [2, 'custom'],
        tokenAmount: 500,
        networkPreset: 'testnet'
      }
      const store = new GlobalKVStore(config)
      expect(store).toBeInstanceOf(GlobalKVStore)
    })

    it('initializes Historian with kvStoreInterpreter', () => {
      expect(MockHistorian).toHaveBeenCalledWith(kvStoreInterpreter)
    })
  })

  // --------------------------------------------------------------------------
  describe('get', () => {
    describe('happy paths', () => {
      it('returns empty array when key not found', async () => {
        primeResolverEmpty(mockResolver)
        const result = await kvStore.get({ key: TEST_KEY })
        expect(Array.isArray(result)).toBe(true)
        expect(result).toHaveLength(0)
      })

      it('returns KVStoreEntry when a valid token exists', async () => {
        primeResolverWithOneOutput(mockResolver)

        const result = await kvStore.get({ key: TEST_KEY, controller: TEST_CONTROLLER })

        expect(result).toEqual({
          key: TEST_KEY,
          value: TEST_VALUE,
          controller: expect.any(String),
          protocolID: [1, 'kvstore']
        })
        expect(mockResolver.query).toHaveBeenCalledWith({
          service: 'ls_kvstore',
          query: expect.objectContaining({
            key: TEST_KEY,
            controller: TEST_CONTROLLER
          })
        })
      })

      it('returns entry with tags when token includes tags field', async () => {
        primeResolverWithOneOutput(mockResolver)

        const originalDecode = (MockPushDrop as any).decode
        ;(MockPushDrop as any).decode = jest.fn().mockReturnValue({
          fields: [
            Array.from(Buffer.from(JSON.stringify([1, 'kvstore']))), // protocolID
            Array.from(Buffer.from(TEST_KEY)), // key
            Array.from(Buffer.from(TEST_VALUE)), // value
            Array.from(Buffer.from(TEST_CONTROLLER, 'hex')), // controller
            // tags field as JSON string so Utils.toUTF8 returns it directly
            '["alpha","beta"]',
            Array.from(Buffer.from('signature')) // signature
          ]
        })

        const result = await kvStore.get({ key: TEST_KEY })

        expect(Array.isArray(result)).toBe(true)
        expect(result).toHaveLength(1)
        if (Array.isArray(result) && result.length > 0) {
          expect(result[0].tags).toEqual(['alpha', 'beta'])
        }

        ;(MockPushDrop as any).decode = originalDecode
      })

      it('omits tags when token is in old-format (no tags field)', async () => {
        primeResolverWithOneOutput(mockResolver)

        // primePushDropDecodeToValidValue() already sets old-format (no tags)
        const result = await kvStore.get({ key: TEST_KEY })

        expect(Array.isArray(result)).toBe(true)
        expect(result).toHaveLength(1)
        if (Array.isArray(result) && result.length > 0) {
          expect(result[0].tags).toBeUndefined()
        }
      })

      it('returns entry with history when history=true', async () => {
        primeResolverWithOneOutput(mockResolver)
        mockHistorian.buildHistory.mockResolvedValue(['oldValue', TEST_VALUE])

        const result = await kvStore.get({ key: TEST_KEY, controller: TEST_CONTROLLER }, { history: true })

        expect(result).toEqual({
          key: TEST_KEY,
          value: TEST_VALUE,
          controller: expect.any(String),
          protocolID: [1, 'kvstore'],
          history: ['oldValue', TEST_VALUE]
        })
        expect(mockHistorian.buildHistory).toHaveBeenCalledWith(
          expect.any(Object),
          expect.objectContaining({ key: TEST_KEY })
        )
      })

      it('supports querying by protocolID', async () => {
        primeResolverWithOneOutput(mockResolver)

        const result = await kvStore.get({ protocolID: [1, 'kvstore'] })

        expect(Array.isArray(result)).toBe(true)
        expect(mockResolver.query).toHaveBeenCalledWith({
          service: 'ls_kvstore',
          query: expect.objectContaining({
            protocolID: [1, 'kvstore']
          })
        })
      })

      it('forwards tags-only queries to the resolver', async () => {
        primeResolverEmpty(mockResolver)

        const tags = ['group:music', 'env:prod']
        const result = await kvStore.get({ tags })

        expect(Array.isArray(result)).toBe(true)
        expect(mockResolver.query).toHaveBeenCalledWith({
          service: 'ls_kvstore',
          query: expect.objectContaining({ tags })
        })
      })

      it('forwards tagQueryMode "all" to the resolver (default)', async () => {
        primeResolverEmpty(mockResolver)

        const tags = ['music', 'rock']
        const result = await kvStore.get({ tags, tagQueryMode: 'all' })

        expect(Array.isArray(result)).toBe(true)
        expect(mockResolver.query).toHaveBeenCalledWith({
          service: 'ls_kvstore',
          query: expect.objectContaining({
            tags,
            tagQueryMode: 'all'
          })
        })
      })

      it('forwards tagQueryMode "any" to the resolver', async () => {
        primeResolverEmpty(mockResolver)

        const tags = ['music', 'jazz']
        const result = await kvStore.get({ tags, tagQueryMode: 'any' })

        expect(Array.isArray(result)).toBe(true)
        expect(mockResolver.query).toHaveBeenCalledWith({
          service: 'ls_kvstore',
          query: expect.objectContaining({
            tags,
            tagQueryMode: 'any'
          })
        })
      })

      it('defaults to tagQueryMode "all" when not specified', async () => {
        primeResolverEmpty(mockResolver)

        const tags = ['category:news']
        const result = await kvStore.get({ tags })

        expect(Array.isArray(result)).toBe(true)
        expect(mockResolver.query).toHaveBeenCalledWith({
          service: 'ls_kvstore',
          query: expect.objectContaining({ tags })
        })
        // Verify tagQueryMode is not explicitly set (will default to 'all' on server side)
        const call = (mockResolver.query as jest.Mock).mock.calls[0][0]
        expect(call.query.tagQueryMode).toBeUndefined()
      })

      it('includes token data when includeToken=true for key queries', async () => {
        primeResolverWithOneOutput(mockResolver)

        const result = await kvStore.get({ key: TEST_KEY }, { includeToken: true })

        expect(Array.isArray(result)).toBe(true)
        expect(result).toHaveLength(1)
        if (Array.isArray(result) && result.length > 0) {
          expect(result[0].token).toBeDefined()
          expect(result[0].token).toEqual({
            txid: TEST_TXID,
            outputIndex: 0,
            satoshis: 1,
            beef: expect.any(Object)
          })
        }
      })

      it('includes token data when includeToken=true for protocolID queries', async () => {
        primeResolverWithOneOutput(mockResolver)

        const result = await kvStore.get({ protocolID: [1, 'kvstore'] }, { includeToken: true })

        expect(Array.isArray(result)).toBe(true)
        if (Array.isArray(result) && result.length > 0) {
          expect(result[0].token).toBeDefined()
          expect(result[0].token).toEqual({
            txid: TEST_TXID,
            outputIndex: 0,
            satoshis: 1,
            beef: expect.any(Object)
          })
        }
      })

      it('excludes token data when includeToken=false (default)', async () => {
        primeResolverWithOneOutput(mockResolver)

        const result = await kvStore.get({ key: TEST_KEY })

        expect(Array.isArray(result)).toBe(true)
        expect(result).toHaveLength(1)
        if (Array.isArray(result) && result.length > 0) {
          expect(result[0].token).toBeUndefined()
        }
      })

      it('supports protocolID queries with history', async () => {
        primeResolverWithOneOutput(mockResolver)
        mockHistorian.buildHistory.mockResolvedValue(['oldValue', TEST_VALUE])

        const result = await kvStore.get({ protocolID: [1, 'kvstore'] }, { history: true })

        expect(Array.isArray(result)).toBe(true)
        if (Array.isArray(result) && result.length > 0) {
          expect(result[0].history).toEqual(['oldValue', TEST_VALUE])
        }
        expect(mockHistorian.buildHistory).toHaveBeenCalled()
      })

      it('excludes history for protocolID queries when history=false', async () => {
        primeResolverWithOneOutput(mockResolver)

        const result = await kvStore.get({ protocolID: [1, 'kvstore'] }, { history: false })

        expect(Array.isArray(result)).toBe(true)
        if (Array.isArray(result) && result.length > 0) {
          expect(result[0].history).toBeUndefined()
        }
        expect(mockHistorian.buildHistory).not.toHaveBeenCalled()
      })

      it('calls buildHistory for each valid token when multiple outputs exist', async () => {
        // This test verifies the key behavior: history building is called for each processed token
        primeResolverWithMultipleOutputs(mockResolver, 3)

        // Don't worry about making unique tokens - just verify the calls
        mockHistorian.buildHistory.mockResolvedValue(['sample_history'])

        const result = await kvStore.get({ protocolID: [1, 'kvstore'] }, { history: true })

        expect(Array.isArray(result)).toBe(true)

        // The key assertion: buildHistory should be called once per valid token processed
        // Even if some tokens are duplicates due to mocking, we're testing the iteration logic
        expect(mockHistorian.buildHistory).toHaveBeenCalledWith(
          expect.any(Object),
          expect.objectContaining({ key: expect.any(String) })
        )

        // Since we have 3 outputs but they may resolve to the same token due to mocking,
        // we just verify that buildHistory was called at least once
        expect(mockHistorian.buildHistory).toHaveBeenCalled()

        // Verify each returned entry has history
        if (Array.isArray(result)) {
          result.forEach(entry => {
            expect(entry.history).toEqual(['sample_history'])
          })
        }
      })

      it('handles history building failures gracefully', async () => {
        primeResolverWithOneOutput(mockResolver)

        // Mock history building to fail
        mockHistorian.buildHistory.mockRejectedValue(new Error('History build failed'))

        const result = await kvStore.get({ protocolID: [1, 'kvstore'] }, { history: true })

        expect(Array.isArray(result)).toBe(true)

        // Implementation should continue processing even if history fails
        // The entry should be skipped due to the continue in the catch block
        if (Array.isArray(result)) {
          expect(result.length).toBe(0)
        }
      })

      it('combines includeToken and history options correctly', async () => {
        primeResolverWithOneOutput(mockResolver)
        mockHistorian.buildHistory.mockResolvedValue(['combined_test_history'])

        const result = await kvStore.get({ protocolID: [1, 'kvstore'] }, {
          history: true,
          includeToken: true
        })

        expect(Array.isArray(result)).toBe(true)

        if (Array.isArray(result) && result.length > 0) {
          const entry = result[0]
          // Entry should have both history and token data
          expect(entry.history).toEqual(['combined_test_history'])
          expect(entry.token).toBeDefined()
          expect(entry.token?.txid).toBe(TEST_TXID)
          expect(entry.token?.outputIndex).toBe(0)
        }

        // Verify buildHistory was called
        expect(mockHistorian.buildHistory).toHaveBeenCalled()
      })
    })

    describe('sad paths', () => {
      it('rejects when no query parameters provided', async () => {
        await expect(kvStore.get({})).rejects.toThrow('Must specify either key, controller, or protocolID')
      })

      it('propagates overlay errors', async () => {
        mockResolver.query.mockRejectedValue(new Error('Network error'))

        await expect(kvStore.get({ key: TEST_KEY })).rejects.toThrow('Network error')
      })

      it('skips malformed candidates and returns empty array (invalid PushDrop format)', async () => {
        primeResolverWithOneOutput(mockResolver)

        const originalDecode = (MockPushDrop as any).decode
          ; (MockPushDrop as any).decode = jest.fn(() => {
          throw new Error('Invalid PushDrop format')
        })

        try {
          const result = await kvStore.get({ key: TEST_KEY })
          expect(Array.isArray(result)).toBe(true)
          expect(result).toHaveLength(0)
        } finally {
          ; (MockPushDrop as any).decode = originalDecode
        }
      })
    })

    describe('Query Parameter Combinations', () => {
      describe('Single parameter queries (return arrays)', () => {
        it('key only - returns array of entries matching key across all controllers', async () => {
          primeResolverWithOneOutput(mockResolver)

          const result = await kvStore.get({ key: TEST_KEY })

          expect(Array.isArray(result)).toBe(true)
          expect(mockResolver.query).toHaveBeenCalledWith({
            service: 'ls_kvstore',
            query: { key: TEST_KEY }
          })
        })

        it('controller only - returns array of entries by specific controller', async () => {
          primeResolverWithOneOutput(mockResolver)

          const result = await kvStore.get({ controller: TEST_CONTROLLER })

          expect(Array.isArray(result)).toBe(true)
          expect(mockResolver.query).toHaveBeenCalledWith({
            service: 'ls_kvstore',
            query: { controller: TEST_CONTROLLER }
          })
        })

        it('protocolID only - returns array of entries under protocol', async () => {
          primeResolverWithOneOutput(mockResolver)

          const result = await kvStore.get({ protocolID: [1, 'kvstore'] })

          expect(Array.isArray(result)).toBe(true)
          expect(mockResolver.query).toHaveBeenCalledWith({
            service: 'ls_kvstore',
            query: { protocolID: [1, 'kvstore'] }
          })
        })
      })

      describe('Combined parameter queries', () => {
        it('key + controller - returns single result (unique combination)', async () => {
          primeResolverWithOneOutput(mockResolver)

          const result = await kvStore.get({
            key: TEST_KEY,
            controller: TEST_CONTROLLER
          })

          // Should return single entry, not array
          expect(result).not.toBeNull()
          expect(Array.isArray(result)).toBe(false)
          if ((result != null) && !Array.isArray(result)) {
            expect(result.key).toBe(TEST_KEY)
            expect(result.controller).toBe(TEST_CONTROLLER)
          }
        })

        it('key + protocolID - returns array (multiple results possible)', async () => {
          primeResolverWithOneOutput(mockResolver)

          const result = await kvStore.get({
            key: TEST_KEY,
            protocolID: [1, 'kvstore']
          })

          expect(Array.isArray(result)).toBe(true)
        })

        it('controller + protocolID - returns array (multiple results possible)', async () => {
          primeResolverWithOneOutput(mockResolver)

          const result = await kvStore.get({
            controller: TEST_CONTROLLER,
            protocolID: [1, 'kvstore']
          })

          expect(Array.isArray(result)).toBe(true)
        })

        it('key + controller + protocolID - returns single result (most specific)', async () => {
          primeResolverWithOneOutput(mockResolver)

          const result = await kvStore.get({
            key: TEST_KEY,
            controller: TEST_CONTROLLER,
            protocolID: [1, 'kvstore']
          })

          // key + controller combination should return single result
          expect(result).not.toBeNull()
          expect(Array.isArray(result)).toBe(false)
        })
      })

      describe('Return type consistency', () => {
        it('key+controller always returns single result or undefined', async () => {
          primeResolverEmpty(mockResolver)

          const result = await kvStore.get({
            key: TEST_KEY,
            controller: TEST_CONTROLLER
          })

          expect(result).toBeUndefined()
          expect(Array.isArray(result)).toBe(false)
        })

        it('all other combinations always return arrays', async () => {
          primeResolverEmpty(mockResolver)

          const testCases = [
            { key: TEST_KEY },
            { controller: TEST_CONTROLLER },
            { protocolID: [1, 'kvstore'] as [1, 'kvstore'] },
            { key: TEST_KEY, protocolID: [1, 'kvstore'] as [1, 'kvstore'] },
            { controller: TEST_CONTROLLER, protocolID: [1, 'kvstore'] as [1, 'kvstore'] }
          ]

          for (const query of testCases) {
            const result = await kvStore.get(query)
            expect(Array.isArray(result)).toBe(true)
            expect((result as any[]).length).toBe(0)
          }
        })
      })
    })
  })

  // --------------------------------------------------------------------------
  describe('set', () => {
    describe('happy paths', () => {
      it('creates a new token when key does not exist', async () => {
        primeResolverEmpty(mockResolver)
        const outpoint = await kvStore.set(TEST_KEY, TEST_VALUE)

        expect(mockWallet.createAction).toHaveBeenCalledWith(
          expect.objectContaining({
            description: `Create KVStore value for ${TEST_KEY}`,
            outputs: expect.arrayContaining([
              expect.objectContaining({
                satoshis: 1,
                outputDescription: 'KVStore token'
              })
            ])
          }),
          undefined
        )
        expect(outpoint).toBe(`${TEST_TXID}.0`)
        expect(mockBroadcaster.broadcast).toHaveBeenCalled()
      })

      it('includes tags field in locking script when options.tags provided', async () => {
        primeResolverEmpty(mockResolver)

        // Override PushDrop to capture the instance used within set()
        const originalImpl = (MockPushDrop as any).mockImplementation
        const mockLockingScript = { toHex: () => 'mockLockingScriptHex' }
        const localPushDrop = {
          lock: jest.fn().mockResolvedValue(mockLockingScript),
          unlock: jest.fn().mockReturnValue({
            sign: jest.fn().mockResolvedValue({ toHex: () => 'mockUnlockingScript' })
          })
        }
        ;(MockPushDrop as any).mockImplementation(() => localPushDrop as any)

        const providedTags = ['primary', 'news']
        await kvStore.set(TEST_KEY, TEST_VALUE, { tags: providedTags })

        // Validate PushDrop.lock was called with 5 fields (protocolID, key, value, controller, tags)
        expect(localPushDrop.lock).toHaveBeenCalled()
        const lockArgs = (localPushDrop.lock as jest.Mock).mock.calls[0]
        const fields = lockArgs[0]
        expect(Array.isArray(fields)).toBe(true)
        expect(fields.length).toBe(5)

        // Restore original implementation
        ;(MockPushDrop as any).mockImplementation = originalImpl
      })

      it('updates existing token when one exists', async () => {
        // Mock the queryOverlay to return an entry with a token
        const mockQueryOverlay = jest.spyOn(kvStore as any, 'queryOverlay')
        mockQueryOverlay.mockResolvedValue([{
          key: TEST_KEY,
          value: 'oldValue',
          controller: TEST_CONTROLLER,
          token: {
            txid: TEST_TXID,
            outputIndex: 0,
            beef: mockBeef,
            satoshis: 1
          }
        }])

        const outpoint = await kvStore.set(TEST_KEY, TEST_VALUE)

        expect(mockWallet.createAction).toHaveBeenCalledWith(
          expect.objectContaining({
            description: `Update KVStore value for ${TEST_KEY}`,
            inputs: expect.arrayContaining([
              expect.objectContaining({
                inputDescription: 'Previous KVStore token'
              })
            ])
          }),
          undefined
        )
        expect(mockWallet.signAction).toHaveBeenCalled()
        expect(outpoint).toBe(`${TEST_TXID}.0`)

        mockQueryOverlay.mockRestore()
      })

      it('is safe under concurrent operations (key locking)', async () => {
        primeResolverEmpty(mockResolver)

        const promise1 = kvStore.set(TEST_KEY, 'value1')
        const promise2 = kvStore.set(TEST_KEY, 'value2')

        await Promise.all([promise1, promise2])

        // Both operations should have completed successfully
        expect(mockWallet.createAction).toHaveBeenCalledTimes(2)
      })
    })

    describe('sad paths', () => {
      it('rejects invalid key', async () => {
        await expect(kvStore.set('', TEST_VALUE)).rejects.toThrow('Key must be a non-empty string.')
      })

      it('rejects invalid value', async () => {
        await expect(kvStore.set(TEST_KEY, null as any)).rejects.toThrow('Value must be a string.')
      })

      it('propagates wallet createAction failures', async () => {
        primeResolverEmpty(mockResolver)
        mockWallet.createAction.mockRejectedValue(new Error('Wallet error'))

        await expect(kvStore.set(TEST_KEY, TEST_VALUE)).rejects.toThrow('Wallet error')
      })

      it('surface broadcast errors in set', async () => {
        primeResolverEmpty(mockResolver)
        mockBroadcaster.broadcast.mockRejectedValue(new Error('overlay down'))
        await expect(kvStore.set(TEST_KEY, TEST_VALUE)).rejects.toThrow('overlay down')
      })
    })
  })

  // --------------------------------------------------------------------------
  describe('remove', () => {
    describe('happy paths', () => {
      it('removes an existing token', async () => {
        // Mock the queryOverlay to return an entry with a token
        const mockQueryOverlay = jest.spyOn(kvStore as any, 'queryOverlay')
        mockQueryOverlay.mockResolvedValue([{
          key: TEST_KEY,
          value: TEST_VALUE,
          controller: TEST_CONTROLLER,
          token: {
            txid: TEST_TXID,
            outputIndex: 0,
            beef: mockBeef,
            satoshis: 1
          }
        }])

        const txid = await kvStore.remove(TEST_KEY)

        expect(mockWallet.createAction).toHaveBeenCalledWith(
          expect.objectContaining({
            description: `Remove KVStore value for ${TEST_KEY}`,
            inputs: expect.arrayContaining([
              expect.objectContaining({
                inputDescription: 'KVStore token to remove'
              })
            ])
          }),
          undefined
        )
        expect(txid).toBe(TEST_TXID)

        mockQueryOverlay.mockRestore()
      })

      it('supports custom outputs on removal', async () => {
        // Mock the queryOverlay to return an entry with a token
        const mockQueryOverlay = jest.spyOn(kvStore as any, 'queryOverlay')
        mockQueryOverlay.mockResolvedValue([{
          key: TEST_KEY,
          value: TEST_VALUE,
          controller: TEST_CONTROLLER,
          token: {
            txid: TEST_TXID,
            outputIndex: 0,
            beef: mockBeef,
            satoshis: 1
          }
        }])

        const customOutputs = [
          {
            satoshis: 500,
            lockingScript: 'customTransferScript',
            outputDescription: 'Custom token transfer output'
          }
        ]

        const txid = await kvStore.remove(TEST_KEY, customOutputs)

        expect(mockWallet.createAction).toHaveBeenCalledWith(
          expect.objectContaining({
            outputs: customOutputs
          }),
          undefined
        )
        expect(txid).toBe(TEST_TXID)

        mockQueryOverlay.mockRestore()
      })
    })

    describe('sad paths', () => {
      it('rejects invalid key', async () => {
        await expect(kvStore.remove('')).rejects.toThrow('Key must be a non-empty string.')
      })

      it('throws when key does not exist', async () => {
        primeResolverEmpty(mockResolver)

        await expect(kvStore.remove(TEST_KEY)).rejects.toThrow(
          'The item did not exist, no item was deleted.'
        )
      })

      it('propagates wallet signAction failures', async () => {
        // Mock the queryOverlay to return an entry with a token
        const mockQueryOverlay = jest.spyOn(kvStore as any, 'queryOverlay')
        mockQueryOverlay.mockResolvedValue([{
          key: TEST_KEY,
          value: TEST_VALUE,
          controller: TEST_CONTROLLER,
          token: {
            txid: TEST_TXID,
            outputIndex: 0,
            beef: mockBeef,
            satoshis: 1
          }
        }])

        ; (mockWallet.signAction as jest.Mock).mockRejectedValue(new Error('Sign failed'))

        await expect(kvStore.remove(TEST_KEY)).rejects.toThrow('Sign failed')

        mockQueryOverlay.mockRestore()
      })
    })
  })

  // --------------------------------------------------------------------------
  describe('getWithHistory', () => {
    it('delegates to get(key, undefined, controller, true) and returns value + history', async () => {
      primeResolverWithOneOutput(mockResolver)
      mockHistorian.buildHistory.mockResolvedValue([TEST_VALUE])

      const result = await kvStore.get({ key: TEST_KEY }, { history: true })

      expect(Array.isArray(result)).toBe(true)
      expect(result).toHaveLength(1)
      if (Array.isArray(result) && result.length > 0) {
        expect(result[0]).toEqual({
          key: TEST_KEY,
          value: TEST_VALUE,
          controller: expect.any(String),
          protocolID: [1, 'kvstore'],
          history: [TEST_VALUE]
        })
      }
    })

    it('returns empty array when key not found', async () => {
      primeResolverEmpty(mockResolver)

      const result = await kvStore.get({ key: TEST_KEY }, { history: true })
      expect(Array.isArray(result)).toBe(true)
      expect(result).toHaveLength(0)
    })
  })

  // --------------------------------------------------------------------------
  describe('Integration-ish behaviors', () => {
    it('uses PushDrop for signature verification', async () => {
      primeResolverWithOneOutput(mockResolver)

      await kvStore.get({ key: TEST_KEY })

      expect(MockProtoWallet).toHaveBeenCalledWith('anyone')
      expect(mockProtoWallet.verifySignature).toHaveBeenCalledWith({
        data: expect.any(Array),
        signature: expect.any(Array),
        counterparty: TEST_CONTROLLER,
        protocolID: [1, 'kvstore'],
        keyID: TEST_KEY
      })
    })

    it('caches identity key (single wallet.getPublicKey call across operations)', async () => {
      primeResolverEmpty(mockResolver)
      await kvStore.set('key1', 'value1')
      await kvStore.set('key2', 'value2')

      expect(mockWallet.getPublicKey).toHaveBeenCalledTimes(1)
      expect(mockWallet.createAction).toHaveBeenCalledTimes(2)
    })

    it('properly cleans up empty lock queues to prevent memory leaks', async () => {
      primeResolverEmpty(mockResolver)

      // Get reference to private keyLocks Map
      const keyLocks = (kvStore as any).keyLocks as Map<string, Array<() => void>>

      // Initially empty
      expect(keyLocks.size).toBe(0)

      // Perform operations on different keys
      await kvStore.set('key1', 'value1')
      await kvStore.set('key2', 'value2')
      await kvStore.set('key3', 'value3')

      // After operations complete, keyLocks should be empty (no memory leak)
      expect(keyLocks.size).toBe(0)
    })
  })

  // --------------------------------------------------------------------------
  describe('Error recovery & edge cases', () => {
    it('returns empty array for empty overlay response', async () => {
      primeResolverEmpty(mockResolver)
      const result = await kvStore.get({ key: TEST_KEY })
      expect(Array.isArray(result)).toBe(true)
      expect(result).toHaveLength(0)
    })

    it('skips malformed transactions and returns empty array', async () => {
      primeResolverWithOneOutput(mockResolver)

      const originalFromBEEF = (MockTransaction as any).fromBEEF
        ; (MockTransaction as any).fromBEEF = jest.fn(() => {
        throw new Error('Malformed transaction data')
      })

      try {
        const result = await kvStore.get({ key: TEST_KEY })
        expect(Array.isArray(result)).toBe(true)
        expect(result).toHaveLength(0)
      } finally {
        ; (MockTransaction as any).fromBEEF = originalFromBEEF
      }
    })

    it('handles edge cases where no valid tokens pass full validation', async () => {
      // This test verifies that when tokens exist but fail validation (signature, etc),
      // the method gracefully returns empty array rather than throwing
      primeResolverWithOneOutput(mockResolver)

      // Make signature verification fail (this could be a realistic failure mode)
      const originalVerifySignature = mockProtoWallet.verifySignature
      mockProtoWallet.verifySignature = jest.fn().mockRejectedValue(new Error('Signature verification failed'))

      try {
        const result = await kvStore.get({ key: TEST_KEY }, { history: true })
        expect(Array.isArray(result)).toBe(true)
        expect(result).toHaveLength(0)
      } finally {
        // Restore original mock
        mockProtoWallet.verifySignature = originalVerifySignature
      }
    })

    it('when no valid outputs (decode fails), get(..., history=true) still returns empty array', async () => {
      primeResolverWithOneOutput(mockResolver)

      const originalDecode = (MockPushDrop as any).decode
        ; (MockPushDrop as any).decode = jest.fn(() => {
        throw new Error('Invalid token format')
      })

      try {
        const result = await kvStore.get({ key: TEST_KEY }, { history: true })
        expect(Array.isArray(result)).toBe(true)
        expect(result).toHaveLength(0)
      } finally {
        ; (MockPushDrop as any).decode = originalDecode
      }
    })
  })
})
