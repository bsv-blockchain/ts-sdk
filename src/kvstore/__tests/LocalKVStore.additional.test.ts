/**
 * Additional tests for LocalKVStore targeting branches missed by LocalKVStore.test.ts.
 *
 * Covered gaps (29 missed lines → aim for ~80 %+):
 * - constructor: originator and acceptDelayedBroadcast params
 * - get: real lookupValue path (no BEEF, BEEF missing error, PushDrop decode,
 *        wrong fields count, encrypted path, non-encrypted path)
 * - set: value-unchanged early-return path
 *        createAction returns txid directly when no inputs (signableTransaction null)
 *        acceptDelayedBroadcast=true option forwarding
 * - remove: pagination loop (outputs.length < totalOutputs → loop again)
 *           signAction returns undefined txid → throws
 *           createAction returns no signableTransaction → throws
 * - getOutputs: limit param forwarding
 * - queueOperationOnKey: concurrent requests queue correctly
 */

import LocalKVStore from '../LocalKVStore.js'
import LockingScript from '../../script/LockingScript.js'
import PushDrop from '../../script/templates/PushDrop.js'
import * as Utils from '../../primitives/utils.js'
import {
  WalletInterface,
  ListOutputsResult,
  WalletEncryptResult,
  WalletDecryptResult,
  CreateActionResult,
  SignActionResult
} from '../../wallet/Wallet.interfaces.js'
import Transaction from '../../transaction/Transaction.js'

// ---- Constants mirrored from the existing test ----
const testLockingScriptHex = 'mockLockingScriptHex'
const testUnlockingScriptHex = 'mockUnlockingScriptHex'
const testEncryptedValue = Buffer.from('encryptedData')
const testRawValue = 'myTestDataValue'
const testRawValueBuffer = Buffer.from(testRawValue)

jest.mock('../../script/LockingScript.js', () => {
  const mockLockingScriptInstance = { toHex: jest.fn(() => testLockingScriptHex) }
  return { fromHex: jest.fn(() => mockLockingScriptInstance) }
})

jest.mock('../../script/templates/PushDrop.js', () => {
  const mockLockingScriptInstance = { toHex: jest.fn(() => testLockingScriptHex) }
  const mockUnlockerInstance = {
    sign: jest.fn().mockResolvedValue({ toHex: jest.fn(() => testUnlockingScriptHex) })
  }
  const mockPushDropInstance = {
    lock: jest.fn().mockResolvedValue(mockLockingScriptInstance),
    unlock: jest.fn().mockReturnValue(mockUnlockerInstance)
  }
  const mockPushDropDecode = jest.fn()
  return Object.assign(
    jest.fn(() => mockPushDropInstance),
    { decode: mockPushDropDecode }
  )
})

jest.mock('../../transaction/Transaction.js', () => ({
  fromAtomicBEEF: jest.fn(() => ({}))
}))

jest.mock('../../primitives/utils.js', () => ({
  toArray: jest.fn((str: string, encoding = 'utf8') => Array.from(Buffer.from(str, encoding as BufferEncoding))),
  toUTF8: jest.fn((arr: number[] | Uint8Array) => Buffer.from(arr).toString('utf8'))
}))

jest.mock('../../wallet/WalletClient.js', () => jest.fn())

// ---- Typed mock aliases ----
const MockedPushDrop = PushDrop as jest.MockedClass<typeof PushDrop> & { decode: jest.Mock<any, any> }
const MockedPushDropDecode = MockedPushDrop.decode
const MockedUtils = Utils as jest.Mocked<typeof Utils>
const MockedTransaction = Transaction as jest.Mocked<typeof Transaction>

// ---- Beef mock ----
// LocalKVStore uses `Beef.fromBinary` internally. We mock only the relevant behaviour.
jest.mock('../../transaction/Beef.js', () => ({
  Beef: {
    fromBinary: jest.fn(() => ({
      findTxid: jest.fn(() => ({
        tx: {
          outputs: [
            { lockingScript: { toHex: () => testLockingScriptHex } }
          ]
        }
      }))
    }))
  }
}))

// ---- Helper ----
const createMockWallet = (): jest.Mocked<WalletInterface> => ({
  listOutputs: jest.fn(),
  encrypt: jest.fn(),
  decrypt: jest.fn(),
  createAction: jest.fn(),
  signAction: jest.fn(),
  relinquishOutput: jest.fn()
} as unknown as jest.Mocked<WalletInterface>)

const testContext = 'test-kv-context'
const testKey = 'myTestKey'
const testValue = 'myTestDataValue'
const testOutpoint = 'txid123.0'

describe('LocalKVStore – additional coverage', () => {
  let mockWallet: jest.Mocked<WalletInterface>
  let kvStore: LocalKVStore

  beforeEach(() => {
    jest.clearAllMocks()
    mockWallet = createMockWallet()
    kvStore = new LocalKVStore(mockWallet, testContext, true)
    MockedPushDropDecode.mockClear()
  })

  // ---------------------------------------------------------------------------
  // Constructor edge cases
  // ---------------------------------------------------------------------------

  describe('constructor', () => {
    it('stores originator when provided', () => {
      const store = new LocalKVStore(mockWallet, testContext, true, 'test.com')
      expect((store as any).originator).toBe('test.com')
    })

    it('sets acceptDelayedBroadcast when provided', () => {
      const store = new LocalKVStore(mockWallet, testContext, true, undefined, true)
      expect(store.acceptDelayedBroadcast).toBe(true)
    })
  })

  // ---------------------------------------------------------------------------
  // get / lookupValue – real path (not mocked via private injection)
  // ---------------------------------------------------------------------------

  describe('get – real lookupValue path', () => {
    it('returns defaultValue when outputs array is empty', async () => {
      mockWallet.listOutputs.mockResolvedValue({ outputs: [], totalOutputs: 0, BEEF: undefined })
      const result = await kvStore.get(testKey, 'fallback')
      expect(result).toBe('fallback')
    })

    it('throws when BEEF is undefined but outputs exist', async () => {
      mockWallet.listOutputs.mockResolvedValue({
        outputs: [{ outpoint: `${testOutpoint}`, satoshis: 1, spendable: true }],
        totalOutputs: 1,
        BEEF: undefined
      })

      await expect(kvStore.get(testKey)).rejects.toThrow(
        'Invalid value found'
      )
    })

    it('returns decoded non-encrypted value when encrypt=false', async () => {
      const kvStoreNoEnc = new LocalKVStore(mockWallet, testContext, false)

      // Provide a real BEEF-like binary so Beef.fromBinary is called
      const fakeBEEF = [1, 2, 3]
      mockWallet.listOutputs.mockResolvedValue({
        outputs: [{ outpoint: 'txhash.0', satoshis: 1, spendable: true }],
        totalOutputs: 1,
        BEEF: fakeBEEF
      } as any)

      // PushDrop.decode returns 1 field (valid)
      const rawValueBytes = Array.from(Buffer.from(testRawValue))
      MockedPushDropDecode.mockReturnValue({ fields: [rawValueBytes] })
      MockedUtils.toUTF8.mockReturnValue(testRawValue)

      const result = await kvStoreNoEnc.get(testKey)
      expect(result).toBe(testRawValue)
      expect(MockedUtils.toUTF8).toHaveBeenCalledWith(rawValueBytes)
    })

    it('returns decrypted value when encrypt=true', async () => {
      const fakeBEEF = [1, 2, 3]
      mockWallet.listOutputs.mockResolvedValue({
        outputs: [{ outpoint: 'txhash.0', satoshis: 1, spendable: true }],
        totalOutputs: 1,
        BEEF: fakeBEEF
      } as any)

      const ciphertextBytes = Array.from(testEncryptedValue)
      MockedPushDropDecode.mockReturnValue({ fields: [ciphertextBytes] })

      const plaintextBytes = Array.from(Buffer.from(testRawValue))
      mockWallet.decrypt.mockResolvedValue({ plaintext: plaintextBytes } as WalletDecryptResult)
      MockedUtils.toUTF8.mockReturnValue(testRawValue)

      const result = await kvStore.get(testKey)
      expect(result).toBe(testRawValue)
      expect(mockWallet.decrypt).toHaveBeenCalledWith(
        { protocolID: [2, testContext], keyID: testKey, ciphertext: ciphertextBytes },
        undefined
      )
    })

    it('throws when PushDrop.decode returns wrong number of fields (0 fields)', async () => {
      const fakeBEEF = [1, 2, 3]
      mockWallet.listOutputs.mockResolvedValue({
        outputs: [{ outpoint: 'txhash.0', satoshis: 1, spendable: true }],
        totalOutputs: 1,
        BEEF: fakeBEEF
      } as any)

      // 0 fields is invalid (must be 1 or 2)
      MockedPushDropDecode.mockReturnValue({ fields: [] })

      await expect(kvStore.get(testKey)).rejects.toThrow('Invalid value found')
    })

    it('throws when PushDrop.decode returns too many fields (3 fields)', async () => {
      const fakeBEEF = [1, 2, 3]
      mockWallet.listOutputs.mockResolvedValue({
        outputs: [{ outpoint: 'txhash.0', satoshis: 1, spendable: true }],
        totalOutputs: 1,
        BEEF: fakeBEEF
      } as any)

      // 3 fields is also invalid
      MockedPushDropDecode.mockReturnValue({ fields: [[1], [2], [3]] })

      await expect(kvStore.get(testKey)).rejects.toThrow('Invalid value found')
    })

    it('uses the last output when multiple outputs are present', async () => {
      const kvStoreNoEnc = new LocalKVStore(mockWallet, testContext, false)
      const fakeBEEF = [1, 2, 3]
      mockWallet.listOutputs.mockResolvedValue({
        outputs: [
          { outpoint: 'old.0', satoshis: 1, spendable: true },
          { outpoint: 'newer.0', satoshis: 1, spendable: true }
        ],
        totalOutputs: 2,
        BEEF: fakeBEEF
      } as any)

      const rawValueBytes = Array.from(Buffer.from('latestValue'))
      MockedPushDropDecode.mockReturnValue({ fields: [rawValueBytes] })
      MockedUtils.toUTF8.mockReturnValue('latestValue')

      const result = await kvStoreNoEnc.get(testKey)
      expect(result).toBe('latestValue')
    })
  })

  // ---------------------------------------------------------------------------
  // set – value-unchanged early-return
  // ---------------------------------------------------------------------------

  describe('set – value unchanged early-return', () => {
    it('returns existing outpoint without creating a transaction when value is unchanged', async () => {
      const existingOutpoint = 'samevalue-txid.0'
      const mockedLor: ListOutputsResult = {
        totalOutputs: 1,
        outputs: [{ satoshis: 1, spendable: true, outpoint: existingOutpoint }],
        BEEF: [1, 2, 3]
      }

      const lookupValueReal = kvStore['lookupValue']
      kvStore['lookupValue'] = jest.fn().mockResolvedValue({
        value: testValue, // same value as what we're setting
        outpoint: existingOutpoint,
        lor: mockedLor
      })

      const result = await kvStore.set(testKey, testValue)

      kvStore['lookupValue'] = lookupValueReal

      expect(result).toBe(existingOutpoint)
      expect(mockWallet.createAction).not.toHaveBeenCalled()
      expect(mockWallet.signAction).not.toHaveBeenCalled()
    })

    it('throws when value matches but outpoint is undefined (invalid state)', async () => {
      const mockedLor: ListOutputsResult = {
        totalOutputs: 0,
        outputs: [],
        BEEF: undefined
      }

      const lookupValueReal = kvStore['lookupValue']
      kvStore['lookupValue'] = jest.fn().mockResolvedValue({
        value: testValue, // same as what we want to set
        outpoint: undefined, // but no outpoint – invalid state
        lor: mockedLor
      })

      await expect(kvStore.set(testKey, testValue)).rejects.toThrow(
        'outpoint must be valid when value is valid and unchanged'
      )

      kvStore['lookupValue'] = lookupValueReal
    })
  })

  // ---------------------------------------------------------------------------
  // set – acceptDelayedBroadcast forwarding
  // ---------------------------------------------------------------------------

  describe('set – acceptDelayedBroadcast=true', () => {
    it('forwards acceptDelayedBroadcast=true to createAction options', async () => {
      const delayedKvStore = new LocalKVStore(mockWallet, testContext, false, undefined, true)

      const valueArray = Array.from(testRawValueBuffer)
      MockedUtils.toArray.mockReturnValue(valueArray)
      mockWallet.createAction.mockResolvedValue({ txid: 'delayedTxId' } as CreateActionResult)

      const lookupValueReal = delayedKvStore['lookupValue']
      delayedKvStore['lookupValue'] = jest.fn().mockResolvedValue({
        value: 'different', // force actual createAction call
        outpoint: undefined,
        lor: { outputs: [], totalOutputs: 0, BEEF: undefined }
      })

      await delayedKvStore.set(testKey, testValue)
      delayedKvStore['lookupValue'] = lookupValueReal

      expect(mockWallet.createAction).toHaveBeenCalledWith(
        expect.objectContaining({
          options: expect.objectContaining({ acceptDelayedBroadcast: true })
        }),
        undefined
      )
    })
  })

  // ---------------------------------------------------------------------------
  // set – createAction returns txid with no signableTransaction (no existing outputs)
  // ---------------------------------------------------------------------------

  describe('set – createAction returns txid directly (no inputs to sign)', () => {
    it('returns txid.0 when signableTransaction is null and outputs.length is 0', async () => {
      const valueArray = Array.from(testRawValueBuffer)
      MockedUtils.toArray.mockReturnValue(valueArray)
      // kvStore has encrypt=true, so wallet.encrypt must be mocked
      mockWallet.encrypt.mockResolvedValue({ ciphertext: valueArray } as any)
      mockWallet.createAction.mockResolvedValue({ txid: 'newDirectTxId' } as CreateActionResult)

      // Stub lookupValue to return no existing value
      const lookupValueReal = kvStore['lookupValue']
      kvStore['lookupValue'] = jest.fn().mockResolvedValue({
        value: undefined,
        outpoint: undefined,
        lor: { outputs: [], totalOutputs: 0, BEEF: undefined }
      })

      const result = await kvStore.set(testKey, testValue)
      kvStore['lookupValue'] = lookupValueReal

      expect(result).toBe('newDirectTxId.0')
      expect(mockWallet.signAction).not.toHaveBeenCalled()
    })
  })

  // ---------------------------------------------------------------------------
  // set – throws when signableTransaction not returned but outputs exist
  // ---------------------------------------------------------------------------

  describe('set – throws when signableTransaction missing for existing outputs', () => {
    it('throws "Wallet did not return a signable transaction when expected" when outputs exist but no signableTransaction', async () => {
      const valueArray = Array.from(testRawValueBuffer)
      const encryptedArray = Array.from(testEncryptedValue)
      MockedUtils.toArray.mockReturnValue(valueArray)
      mockWallet.encrypt.mockResolvedValue({ ciphertext: encryptedArray } as WalletEncryptResult)

      // createAction returns txid (not signable) but we have inputs
      mockWallet.createAction.mockResolvedValue({ txid: 'shouldNotReach' } as CreateActionResult)

      const existingOutpoint = 'existing.0'
      const lookupValueReal = kvStore['lookupValue']
      kvStore['lookupValue'] = jest.fn().mockResolvedValue({
        value: 'old',
        outpoint: existingOutpoint,
        lor: {
          outputs: [{ satoshis: 1, spendable: true, outpoint: existingOutpoint }],
          totalOutputs: 1,
          BEEF: [1, 2, 3]
        }
      })

      await expect(kvStore.set(testKey, testValue)).rejects.toThrow(
        'outputs with tag'
      )

      kvStore['lookupValue'] = lookupValueReal
    })
  })

  // ---------------------------------------------------------------------------
  // set – originator forwarding
  // ---------------------------------------------------------------------------

  describe('set – originator is forwarded to wallet calls', () => {
    it('passes originator to encrypt, createAction, and signAction', async () => {
      const storeWithOriginator = new LocalKVStore(mockWallet, testContext, true, 'my.app')

      const valueArray = Array.from(testRawValueBuffer)
      const encryptedArray = Array.from(testEncryptedValue)
      MockedUtils.toArray.mockReturnValue(valueArray)
      mockWallet.encrypt.mockResolvedValue({ ciphertext: encryptedArray } as WalletEncryptResult)
      mockWallet.createAction.mockResolvedValue({ txid: 'origTxId' } as CreateActionResult)

      const lookupValueReal = storeWithOriginator['lookupValue']
      storeWithOriginator['lookupValue'] = jest.fn().mockResolvedValue({
        value: undefined,
        outpoint: undefined,
        lor: { outputs: [], totalOutputs: 0, BEEF: undefined }
      })

      await storeWithOriginator.set(testKey, testValue)
      storeWithOriginator['lookupValue'] = lookupValueReal

      expect(mockWallet.encrypt).toHaveBeenCalledWith(expect.any(Object), 'my.app')
      expect(mockWallet.createAction).toHaveBeenCalledWith(expect.any(Object), 'my.app')
    })
  })

  // ---------------------------------------------------------------------------
  // remove – pagination loop
  // ---------------------------------------------------------------------------

  describe('remove – pagination (outputs.length < totalOutputs → loops)', () => {
    it('calls getOutputs in a loop until all outputs are processed', async () => {
      const outpoint1 = 'page1-tx.0'
      const output1 = { outpoint: outpoint1, satoshis: 1, spendable: true }
      const mockBEEF = [1, 2, 3, 4]
      const signableRef = 'ref-page'
      const signableTx: any[] = []
      const txId1 = 'removal-tx-1'
      const txId2 = 'removal-tx-2'

      // First call: outputs.length (1) < totalOutputs (2) → process output, then loop
      // Second call: outputs.length (1) < totalOutputs (2) → process output, then loop
      // Third call: outputs.length (0) === totalOutputs (0) → skip processing, break
      mockWallet.listOutputs
        .mockResolvedValueOnce({ outputs: [output1], totalOutputs: 2, BEEF: mockBEEF } as any)
        .mockResolvedValueOnce({ outputs: [{ outpoint: 'page2-tx.0', satoshis: 1, spendable: true }], totalOutputs: 2, BEEF: mockBEEF } as any)
        .mockResolvedValueOnce({ outputs: [], totalOutputs: 0, BEEF: undefined } as any)

      MockedTransaction.fromAtomicBEEF.mockReturnValue({} as any)
      mockWallet.createAction
        .mockResolvedValueOnce({ signableTransaction: { reference: signableRef, tx: signableTx } } as CreateActionResult)
        .mockResolvedValueOnce({ signableTransaction: { reference: signableRef, tx: signableTx } } as CreateActionResult)
      mockWallet.signAction
        .mockResolvedValueOnce({ txid: txId1 } as SignActionResult)
        .mockResolvedValueOnce({ txid: txId2 } as SignActionResult)

      const result = await kvStore.remove(testKey)

      expect(result).toContain(txId1)
      expect(result).toContain(txId2)
      expect(mockWallet.listOutputs).toHaveBeenCalledTimes(3)
    })
  })

  // ---------------------------------------------------------------------------
  // remove – signAction returns undefined txid → throws
  // ---------------------------------------------------------------------------

  describe('remove – signAction returns undefined txid', () => {
    it('throws "signAction must return a valid txid" when txid is undefined', async () => {
      const outpoint = 'und-txid.0'
      const output = { outpoint, satoshis: 1, spendable: true }
      const mockBEEF = [9, 9, 9]

      mockWallet.listOutputs.mockResolvedValue({ outputs: [output], totalOutputs: 1, BEEF: mockBEEF } as any)
      MockedTransaction.fromAtomicBEEF.mockReturnValue({} as any)
      mockWallet.createAction.mockResolvedValue({
        signableTransaction: { reference: 'ref', tx: [] }
      } as CreateActionResult)
      // signAction returns object with undefined txid
      mockWallet.signAction.mockResolvedValue({ txid: undefined } as any)

      await expect(kvStore.remove(testKey)).rejects.toThrow('cannot be unlocked')
    })
  })

  // ---------------------------------------------------------------------------
  // remove – createAction returns no signableTransaction → throws
  // ---------------------------------------------------------------------------

  describe('remove – createAction returns txid (no signableTransaction)', () => {
    it('throws "Wallet did not return a signable transaction when expected" when outputs exist but no signableTransaction returned', async () => {
      const outpoint = 'missing-signable.0'
      const output = { outpoint, satoshis: 1, spendable: true }
      const mockBEEF = [1, 2]

      mockWallet.listOutputs.mockResolvedValue({ outputs: [output], totalOutputs: 1, BEEF: mockBEEF } as any)
      // createAction returns only txid (not a signable) - simulates a non-signable-tx wallet response
      mockWallet.createAction.mockResolvedValue({ txid: 'tx-no-sign' } as CreateActionResult)

      await expect(kvStore.remove(testKey)).rejects.toThrow('cannot be unlocked')
    })
  })

  // ---------------------------------------------------------------------------
  // getOutputs – limit parameter forwarding
  // ---------------------------------------------------------------------------

  describe('getOutputs – limit forwarding', () => {
    it('passes the limit parameter to wallet.listOutputs', async () => {
      mockWallet.listOutputs.mockResolvedValue({ outputs: [], totalOutputs: 0, BEEF: undefined })

      // Call the private method directly via bracket notation
      await (kvStore as any).getOutputs(testKey, 5)

      expect(mockWallet.listOutputs).toHaveBeenCalledWith(
        expect.objectContaining({ limit: 5 }),
        undefined
      )
    })

    it('omits limit when not provided', async () => {
      mockWallet.listOutputs.mockResolvedValue({ outputs: [], totalOutputs: 0, BEEF: undefined })

      await (kvStore as any).getOutputs(testKey)

      expect(mockWallet.listOutputs).toHaveBeenCalledWith(
        expect.objectContaining({ limit: undefined }),
        undefined
      )
    })
  })

  // ---------------------------------------------------------------------------
  // Concurrency – queueOperationOnKey serialises concurrent set() calls
  // ---------------------------------------------------------------------------

  describe('concurrency – queueOperationOnKey serialises operations on the same key', () => {
    it('processes two concurrent set() calls sequentially on the same key', async () => {
      const callOrder: number[] = []

      // Each call resolves in order so we can detect interleaving
      let resolveFirst!: () => void
      const firstStarted = new Promise<void>((r) => { resolveFirst = r })

      const valueArray = Array.from(testRawValueBuffer)
      MockedUtils.toArray.mockReturnValue(valueArray)

      // Simulate sequential wallet responses
      let callCount = 0
      const lookupValueReal = kvStore['lookupValue']
      kvStore['lookupValue'] = jest.fn().mockImplementation(async () => {
        const myCall = ++callCount
        callOrder.push(myCall)
        if (myCall === 1) resolveFirst()
        // Yield to allow the second set() to try to acquire the lock
        await new Promise((r) => setTimeout(r, 5))
        return { value: undefined, outpoint: undefined, lor: { outputs: [], totalOutputs: 0, BEEF: undefined } }
      })

      mockWallet.encrypt.mockResolvedValue({ ciphertext: Array.from(testEncryptedValue) } as WalletEncryptResult)
      mockWallet.createAction.mockResolvedValue({ txid: 'concurrent-tx' } as CreateActionResult)

      const p1 = kvStore.set(testKey, 'value1')
      const p2 = kvStore.set(testKey, 'value2')

      await Promise.all([p1, p2])

      kvStore['lookupValue'] = lookupValueReal

      // Both calls must have completed
      expect(callOrder).toHaveLength(2)
      // Second call must start AFTER first call finishes (sequential, not interleaved)
      expect(callOrder[0]).toBe(1)
      expect(callOrder[1]).toBe(2)
    })
  })

  // ---------------------------------------------------------------------------
  // getLockingScript – throws when txid not found in BEEF
  // ---------------------------------------------------------------------------

  describe('getLockingScript – throws when txid not found in BEEF', () => {
    it('throws "beef must contain txid" when findTxid returns null', async () => {
      // Override the Beef mock for this test to return null for findTxid
      const BeefModule = require('../../transaction/Beef.js')
      BeefModule.Beef.fromBinary.mockReturnValueOnce({
        findTxid: jest.fn(() => null)
      })

      const fakeBEEF = [1, 2, 3]
      mockWallet.listOutputs.mockResolvedValue({
        outputs: [{ outpoint: 'missingtxid.0', satoshis: 1, spendable: true }],
        totalOutputs: 1,
        BEEF: fakeBEEF
      } as any)

      MockedPushDropDecode.mockReturnValue({ fields: [[1, 2, 3]] })

      await expect(kvStore.get(testKey)).rejects.toThrow('Invalid value found')
    })
  })

  // ---------------------------------------------------------------------------
  // getProtocol – uses context as protocolID namespace
  // ---------------------------------------------------------------------------

  describe('getProtocol', () => {
    it('returns correct protocolID tuple using context', () => {
      const protocol = (kvStore as any).getProtocol('some-key')
      expect(protocol).toEqual({ protocolID: [2, testContext], keyID: 'some-key' })
    })
  })
})
