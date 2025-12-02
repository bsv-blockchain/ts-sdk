/** eslint-env jest */
import LocalKVStore from '../LocalKVStore.js'
import LockingScript from '../../script/LockingScript.js'
import PushDrop from '../../script/templates/PushDrop.js'
import * as Utils from '../../primitives/utils.js'
import {
  WalletInterface,
  ListOutputsResult,
  WalletDecryptResult,
  WalletEncryptResult,
  CreateActionResult,
  SignActionResult
} from '../../wallet/Wallet.interfaces.js'
import Transaction from '../../transaction/Transaction.js'
import { Beef } from '../../transaction/Beef.js'
import { mock } from 'node:test'

// --- Constants for Mock Values ---
const testLockingScriptHex = 'mockLockingScriptHex'
const testUnlockingScriptHex = 'mockUnlockingScriptHex'
const testEncryptedValue = Buffer.from('encryptedData') // Use Buffer for ciphertext
const testRawValue = 'myTestDataValue'
const testRawValueBuffer = Buffer.from(testRawValue) // Buffer for raw value

jest.mock('../../script/LockingScript.js', () => {
  const mockLockingScriptInstance = {
    toHex: jest.fn(() => testLockingScriptHex) // Default value
  }
  return {
    fromHex: jest.fn(() => mockLockingScriptInstance) // Static method returns mock instance
  }
})

jest.mock('../../script/templates/PushDrop.js', () => {
  const mockLockingScriptInstance = {
    toHex: jest.fn(() => testLockingScriptHex) // Default value
  }
  const mockUnlockerInstance = {
    // Default sign behavior returns an object with a toHex mock
    sign: jest.fn().mockResolvedValue({ toHex: jest.fn(() => testUnlockingScriptHex) })
  }
  // --- Define the mock instance returned by the PushDrop constructor ---
  const mockPushDropInstance = {
    // Default lock behavior returns the mock script
    lock: jest.fn().mockResolvedValue(mockLockingScriptInstance),
    // Default unlock behavior returns the mock unlocker
    unlock: jest.fn().mockReturnValue(mockUnlockerInstance)
    // Add a mock for the static decode method directly here if needed,
    // or manage it separately as done below.
  }

  // --- Define the mock for the static decode method ---
  // It needs to be separate because it's static, not on the instance.
  const mockPushDropDecode = jest.fn()
  return Object.assign(
    jest.fn(() => mockPushDropInstance), // Constructor mock
    { decode: mockPushDropDecode } // Static method mock
  )
})
jest.mock('../../transaction/Transaction.js', () => ({
  // Static method returns a minimal mock object
  fromAtomicBEEF: jest.fn(() => ({ /* mock tx object if needed */ }))
}))

jest.mock('../../primitives/utils.js', () => ({
  // Ensure toArray returns Array<number> or Uint8Array
  toArray: jest.fn((str: string, encoding = 'utf8') => Array.from(Buffer.from(str, encoding as BufferEncoding))),
  toUTF8: jest.fn((arr: number[] | Uint8Array) => Buffer.from(arr).toString('utf8'))
}))

jest.mock('../../wallet/WalletClient.js', () => jest.fn())

// --- Typed Mocks for SDK Components ---
const MockedLockingScript = LockingScript as jest.Mocked<typeof LockingScript>
// Use MockedClass for the constructor and add static methods separately
const MockedPushDrop = PushDrop as jest.MockedClass<typeof PushDrop> & {
  decode: jest.Mock<any, any>
}
// Access the static mock assigned during jest.mock
const MockedPushDropDecode = MockedPushDrop.decode
const MockedUtils = Utils as jest.Mocked<typeof Utils>
const MockedTransaction = Transaction as jest.Mocked<typeof Transaction>

// --- Mock Wallet Setup ---
const createMockWallet = (): jest.Mocked<WalletInterface> => ({
  listOutputs: jest.fn(),
  encrypt: jest.fn(),
  decrypt: jest.fn(),
  createAction: jest.fn(),
  signAction: jest.fn(),
  relinquishOutput: jest.fn()
} as unknown as jest.Mocked<WalletInterface>)

describe('localKVStore', () => {
  let mockWallet: jest.Mocked<WalletInterface>
  let kvStore: LocalKVStore
  const testContext = 'test-kv-context'
  const testKey = 'myTestKey'
  const testValue = 'myTestDataValue' // Raw value string used in tests
  // Use the constants defined above for mock results
  // const testEncryptedValue = Buffer.from('encryptedData'); // Defined above
  const testOutpoint = 'txid123.0'
  // const testLockingScriptHex = 'mockLockingScriptHex'; // Defined above
  // const testUnlockingScriptHex = 'mockUnlockingScriptHex'; // Defined above

  beforeEach(() => {
    // Reset mocks before each test (clears calls and resets implementations)
    jest.clearAllMocks()

    // Create a fresh mock wallet for each test
    mockWallet = createMockWallet()

    // Create a kvStore instance with the mock wallet
    // Default encrypt=true unless specified otherwise in a test block
    kvStore = new LocalKVStore(mockWallet, testContext, true)

    // Reset specific mock implementations if needed after clearAllMocks
    // (e.g., if a test overrides a default implementation)
    MockedPushDropDecode.mockClear() // Clear calls/results for static decode
  })

  // --- Constructor Tests ---
  describe('constructor', () => {
    it('should create an instance with default wallet and encrypt=true', () => {
      // We need to mock the default WalletClient if the SUT uses it
      const MockedWalletClient = require('../../../mod.js').WalletClient
      const store = new LocalKVStore(undefined, 'default-context')
      expect(store).toBeInstanceOf(LocalKVStore)
      expect(MockedWalletClient).toHaveBeenCalledTimes(1) // Verify default was created
      expect((store as any).context).toEqual('default-context')
      expect((store as any).encrypt).toBe(true)
    })

    it('should create an instance with provided wallet, context, and encrypt=false', () => {
      const customWallet = createMockWallet()
      const store = new LocalKVStore(customWallet, 'custom-context', false)
      expect(store).toBeInstanceOf(LocalKVStore)
      expect((store as any).wallet).toBe(customWallet)
      expect((store as any).context).toEqual('custom-context')
      expect((store as any).encrypt).toBe(false)
    })

    it('should throw an error if context is missing or empty', () => {
      expect(() => new LocalKVStore(mockWallet, '')).toThrow('A context in which to operate is required.')
      expect(() => new LocalKVStore(mockWallet, null as any)).toThrow('A context in which to operate is required.')
    })
  })

  // --- Get Method Tests ---
  describe('get', () => {
    it('should return defaultValue if no output is found', async () => {
      const defaultValue = 'default'

      const mockedLor: ListOutputsResult = {
        totalOutputs: 0,
        outputs: [],
        BEEF: undefined
      }

      const lookupValueReal = kvStore.lookupValue
      kvStore.lookupValue = jest.fn().mockResolvedValue({
        value: defaultValue,
        outpoint: undefined,
        lor: mockedLor
      })

      const result = await kvStore.get(testKey, defaultValue)
      kvStore.lookupValue = lookupValueReal

      expect(result).toBe(defaultValue)
    })

    it('should return undefined if no output is found and no defaultValue provided', async () => {
      const defaultValue = undefined

      const mockedLor: ListOutputsResult = {
        totalOutputs: 0,
        outputs: [],
        BEEF: undefined
      }

      const lookupValueReal = kvStore.lookupValue
      kvStore.lookupValue = jest.fn().mockResolvedValue({
        value: defaultValue,
        outpoint: undefined,
        lor: mockedLor
      })

      const result = await kvStore.get(testKey, defaultValue)
      kvStore.lookupValue = lookupValueReal

      expect(result).toBe(defaultValue)
    })
  })

  // --- Set Method Tests ---
  describe('set', () => {
    let pushDropInstance: PushDrop // To access the instance methods

    beforeEach(() => {
      // Get the mock instance that will be created by `new PushDrop()`
      pushDropInstance = new (PushDrop as any)()
    })

    it('should create a new encrypted output if none exists', async () => {
      const valueArray = Array.from(testRawValueBuffer)
      const encryptedArray = Array.from(testEncryptedValue)
      MockedUtils.toArray.mockReturnValue(valueArray) // Mock toArray -> Array<number>
      mockWallet.encrypt.mockResolvedValue({ ciphertext: encryptedArray } as WalletEncryptResult) // Encrypt returns Array<number>
      mockWallet.listOutputs.mockResolvedValue({ outputs: [], totalOutputs: 0, BEEF: undefined })
      mockWallet.createAction.mockResolvedValue({ txid: 'newTxId' } as CreateActionResult)

      // Get the mock instance returned by the constructor
      const mockPDInstance = new MockedPushDrop(mockWallet)

      const result = await kvStore.set(testKey, testValue)

      expect(result).toBe('newTxId.0')
      expect(MockedUtils.toArray).toHaveBeenCalledWith(testValue, 'utf8')
      expect(mockWallet.encrypt).toHaveBeenCalledWith({
        plaintext: valueArray, // Should be Array<number>
        protocolID: [2, testContext],
        keyID: testKey
      }, undefined)
      // Check the mock instance's lock method
      expect(mockPDInstance.lock).toHaveBeenCalledWith(
        // The lock function expects Array<number[] | Uint8Array>
        // Ensure the encrypted value is passed correctly (as Uint8Array or Array<number>)
        [(encryptedArray)], // Pass buffer derived from encrypted array
        [2, testContext],
        testKey,
        'self'
      )
      // expect(mockWallet.listOutputs).toHaveBeenCalledWith({ basket: testContext, tags: [testKey], include: 'entire transactions' })
      // Verify createAction for NEW output
      expect(mockWallet.createAction).toHaveBeenCalledWith({
        description: `Update ${testKey} in ${testContext}`,
        inputBEEF: undefined,
        inputs: [],
        outputs: [{
          basket: 'test-kv-context',
          tags: ['myTestKey'],
          lockingScript: testLockingScriptHex, // From the mock lock result
          satoshis: 1,
          outputDescription: 'Key-value token'
        }],
        options: {
          acceptDelayedBroadcast: false,
          randomizeOutputs: false
        }
      }, undefined)
      expect(mockWallet.signAction).not.toHaveBeenCalled()
      expect(mockWallet.relinquishOutput).not.toHaveBeenCalled()
    })

    it('should create a new non-encrypted output if none exists and encrypt=false', async () => {
      kvStore = new LocalKVStore(mockWallet, testContext, false) // encrypt=false
      const valueArray = Array.from(testRawValueBuffer)
      MockedUtils.toArray.mockReturnValue(valueArray)
      mockWallet.listOutputs.mockResolvedValue({ outputs: [], totalOutputs: 0, BEEF: undefined })
      mockWallet.createAction.mockResolvedValue({ txid: 'newTxIdNonEnc' } as CreateActionResult)

      // Get the mock instance returned by the constructor
      const mockPDInstance = new MockedPushDrop(mockWallet)

      const result = await kvStore.set(testKey, testValue)

      expect(result).toBe('newTxIdNonEnc.0')
      expect(MockedUtils.toArray).toHaveBeenCalledWith(testValue, 'utf8')
      expect(mockWallet.encrypt).not.toHaveBeenCalled()
      // Check the mock instance's lock method
      expect(mockPDInstance.lock).toHaveBeenCalledWith(
        [(valueArray)], // Pass raw value buffer
        [2, testContext],
        testKey,
        'self'
      )
      // expect(mockWallet.listOutputs).toHaveBeenCalledWith({ basket: testContext, tags: [testKey], include: 'entire transactions' })
      expect(mockWallet.createAction).toHaveBeenCalledWith({
        description: `Update ${testKey} in ${testContext}`,
        inputBEEF: undefined,
        inputs: [],
        outputs: [{
          basket: 'test-kv-context',
          tags: ['myTestKey'],
          lockingScript: testLockingScriptHex, // From mock lock
          satoshis: 1,
          outputDescription: 'Key-value token'
        }],
        options: {
          acceptDelayedBroadcast: false,
          randomizeOutputs: false
        }
      }, undefined)
      expect(mockWallet.signAction).not.toHaveBeenCalled()
      expect(mockWallet.relinquishOutput).not.toHaveBeenCalled()
    })

    it('should update an existing output (spend and create)', async () => {
      const existingOutpoint = 'oldTxId.0'
      const existingOutput = { outpoint: existingOutpoint, txid: 'oldTxId', vout: 0, lockingScript: 'oldScriptHex' } // Added script
      const mockBEEF = [1, 2, 3, 4, 5, 6]
      const signableRef = 'signableTxRef123'
      const signableTx = []
      const updatedTxId = 'updatedTxId'

      const valueArray = Array.from(testRawValueBuffer)
      const encryptedArray = Array.from(testEncryptedValue)

      MockedUtils.toArray.mockReturnValue(valueArray)
      mockWallet.encrypt.mockResolvedValue({ ciphertext: encryptedArray } as WalletEncryptResult)
      mockWallet.listOutputs.mockResolvedValue({ outputs: [existingOutput], totalOutputs: 1, BEEF: mockBEEF } as any)

      // Mock createAction to return a signable transaction structure
      mockWallet.createAction.mockResolvedValue({
        signableTransaction: { reference: signableRef, tx: signableTx }
      } as CreateActionResult)

      // Mock Transaction.fromAtomicBEEF to return a mock TX object
      const mockTxObject = { /* Can add mock properties/methods if SUT uses them */ }
      MockedTransaction.fromAtomicBEEF.mockReturnValue(mockTxObject as any)

      mockWallet.signAction.mockResolvedValue({ txid: updatedTxId } as SignActionResult)

      // Get the mock instance returned by the constructor
      const mockPDInstance = new MockedPushDrop(mockWallet)

      const mockedLor: ListOutputsResult = {
        totalOutputs: 1,
        outputs: [{
          satoshis: 0,
          spendable: true,
          outpoint: existingOutpoint
        }],
        BEEF: mockBEEF
      }

      const lookupValueReal = kvStore.lookupValue
      kvStore.lookupValue = jest.fn().mockResolvedValue({
        value: 'oldValue',
        outpoint: existingOutpoint,
        lor: mockedLor
      })

      /**
       * set now starts by getting existing outputs, which are then checked for current value.
       * The current value must be decodable.
       */
      const result = await kvStore.set(testKey, testValue)

      kvStore.lookupValue = lookupValueReal

      expect(result).toBe(`${updatedTxId}.0`) // Assuming output 0 is the new KV token
      expect(mockWallet.encrypt).toHaveBeenCalled()
      expect(mockPDInstance.lock).toHaveBeenCalledWith([(encryptedArray)], [2, testContext], testKey, 'self')

      // Verify createAction for UPDATE
      expect(mockWallet.createAction).toHaveBeenCalledWith(expect.objectContaining({ // Use objectContaining for flexibility
        description: `Update ${testKey} in ${testContext}`,
        inputBEEF: mockBEEF,
        inputs: expect.arrayContaining([ // Check inputs array
          expect.objectContaining({ outpoint: existingOutpoint }) // Check specific input
        ]),
        outputs: expect.arrayContaining([ // Check outputs array
          expect.objectContaining({ lockingScript: testLockingScriptHex }) // Check the new output script
        ])
      }), undefined)

      // Verify signing steps
      expect(MockedTransaction.fromAtomicBEEF).toHaveBeenCalledWith(signableTx)
      // Check unlock was called on the instance
      expect(mockPDInstance.unlock).toHaveBeenCalledWith([2, testContext], testKey, 'self')

      // Get the unlocker returned by the mock unlock method
      const mockUnlocker = (mockPDInstance.unlock as jest.Mock).mock.results[0].value
      expect(mockUnlocker.sign).toHaveBeenCalledWith(mockTxObject, 0) // Check sign args

      // Verify signAction call
      expect(mockWallet.signAction).toHaveBeenCalledWith({
        reference: signableRef,
        spends: {
          0: { unlockingScript: testUnlockingScriptHex } // Check unlocking script from mock sign result
        }
      }, undefined)
      expect(mockWallet.relinquishOutput).not.toHaveBeenCalled()
    })

    it('should collapse multiple existing outputs into one', async () => {
      /**
       * The mocked state doesn't include a valid BEEF from which the locking script of the current value.
       */
      const existingOutpoint1 = 'oldTxId1.0'
      const existingOutpoint2 = 'oldTxId2.1'
      const existingOutput1 = { outpoint: existingOutpoint1, txid: 'oldTxId1', vout: 0, lockingScript: 's1' }
      const existingOutput2 = { outpoint: existingOutpoint2, txid: 'oldTxId2', vout: 1, lockingScript: 's2' }
      const mockBEEF = [1, 2, 3, 4, 5, 6]
      const signableRef = 'signableTxRefMulti'
      const signableTx = []
      const updatedTxId = 'updatedTxIdMulti'
      const mockTxObject = {} // Dummy TX object

      const valueArray = Array.from(testRawValueBuffer)
      const encryptedArray = Array.from(testEncryptedValue)

      MockedUtils.toArray.mockReturnValue(valueArray)
      mockWallet.encrypt.mockResolvedValue({ ciphertext: encryptedArray } as WalletEncryptResult)
      mockWallet.listOutputs.mockResolvedValue({ outputs: [existingOutput1, existingOutput2], totalOutputs: 2, BEEF: mockBEEF } as any)
      mockWallet.createAction.mockResolvedValue({
        signableTransaction: { reference: signableRef, tx: signableTx }
      } as CreateActionResult)
      MockedTransaction.fromAtomicBEEF.mockReturnValue(mockTxObject as any)
      mockWallet.signAction.mockResolvedValue({ txid: updatedTxId } as SignActionResult)

      // Get the mock instance
      const mockPDInstance = new MockedPushDrop(mockWallet)

      const mockedLor: ListOutputsResult = {
        totalOutputs: 1,
        outputs: [
          {
            satoshis: 0,
            spendable: true,
            outpoint: existingOutpoint1
          },
          {
            satoshis: 0,
            spendable: true,
            outpoint: existingOutpoint2
          }
        ],
        BEEF: mockBEEF
      }

      const lookupValueReal = kvStore.lookupValue
      kvStore.lookupValue = jest.fn().mockResolvedValue({
        value: 'oldValue',
        outpoint: existingOutpoint2,
        lor: mockedLor
      })

      const result = await kvStore.set(testKey, testValue)
      kvStore.lookupValue = lookupValueReal

      expect(result).toBe(`${updatedTxId}.0`)
      expect(mockWallet.encrypt).toHaveBeenCalled()
      expect(mockPDInstance.lock).toHaveBeenCalled()

      // Verify createAction with multiple inputs
      expect(mockWallet.createAction).toHaveBeenCalledWith(expect.objectContaining({
        inputBEEF: mockBEEF,
        inputs: expect.arrayContaining([
          expect.objectContaining({ outpoint: existingOutpoint1 }),
          expect.objectContaining({ outpoint: existingOutpoint2 })
        ]),
        outputs: expect.arrayContaining([
          expect.objectContaining({ lockingScript: testLockingScriptHex })
        ])
      }), undefined)

      // Verify signing loop
      expect(MockedTransaction.fromAtomicBEEF).toHaveBeenCalledWith(signableTx)
      expect(mockPDInstance.unlock).toHaveBeenCalledTimes(2) // Called for each input
      expect(mockPDInstance.unlock).toHaveBeenNthCalledWith(1, [2, testContext], testKey, 'self')
      expect(mockPDInstance.unlock).toHaveBeenNthCalledWith(2, [2, testContext], testKey, 'self')

      // Get the *same* mock unlocker instance (since unlock is mocked to always return it)
      const mockUnlocker = (mockPDInstance.unlock as jest.Mock).mock.results[0].value
      expect(mockUnlocker.sign).toHaveBeenCalledTimes(2)
      expect(mockUnlocker.sign).toHaveBeenNthCalledWith(1, mockTxObject, 0) // Input index 0
      expect(mockUnlocker.sign).toHaveBeenNthCalledWith(2, mockTxObject, 1) // Input index 1

      // Verify signAction call with multiple spends
      expect(mockWallet.signAction).toHaveBeenCalledWith({
        reference: signableRef,
        spends: {
          0: { unlockingScript: testUnlockingScriptHex }, // Same mock script for both
          1: { unlockingScript: testUnlockingScriptHex }
        }
      }, undefined)
      expect(mockWallet.relinquishOutput).not.toHaveBeenCalled()
    })

    it('should preserve original error message when createAction fails', async () => {
      const originalErrorMessage = 'Network connection timeout while creating transaction'
      const originalError = new Error(originalErrorMessage)

      // Mock the lookupValue to return a value that differs from what we're setting
      // to ensure set() will attempt to create a transaction
      const mockedLor: ListOutputsResult = {
        totalOutputs: 0,
        outputs: [],
        BEEF: undefined
      }

      const lookupValueReal = kvStore.lookupValue
      kvStore.lookupValue = jest.fn().mockResolvedValue({
        value: 'different_value', // Different from testValue to trigger createAction
        outpoint: undefined,
        lor: mockedLor
      })

      // Mock wallet.createAction to fail with a specific error
      mockWallet.createAction.mockRejectedValue(originalError)

      // Mock other required methods
      const valueArray = Array.from(testRawValueBuffer)
      const encryptedArray = Array.from(testEncryptedValue)
      MockedUtils.toArray.mockReturnValue(valueArray)
      mockWallet.encrypt.mockResolvedValue({ ciphertext: encryptedArray } as WalletEncryptResult)

      try {
        await kvStore.set(testKey, testValue)
        fail('Expected set() to throw an error but it succeeded')
      } catch (error) {
        // Verify that the thrown error contains both the contextual message and the original error
        expect(error).toBeInstanceOf(Error)
        const errorMessage = (error as Error).message
        expect(errorMessage).toContain('outputs with tag')
        expect(errorMessage).toContain('cannot be unlocked')
        expect(errorMessage).toContain('Original error:')
        expect(errorMessage).toContain(originalErrorMessage)
      } finally {
        // Restore the original method
        kvStore.lookupValue = lookupValueReal
      }
    })
  })

  // --- Remove Method Tests ---
  describe('remove', () => {
    let pushDropInstance: PushDrop // To access the instance methods

    beforeEach(() => {
      // Get the mock instance that will be created by `new PushDrop()`
      pushDropInstance = new (PushDrop as any)()
    })

    it('should do nothing and return void if key does not exist', async () => {
      mockWallet.listOutputs.mockResolvedValue({ outputs: [], totalOutputs: 0, BEEF: undefined })

      const result = await kvStore.remove(testKey)

      expect(result).toEqual([])
      /*
      expect(mockWallet.listOutputs).toHaveBeenCalledWith({
        basket: testContext,
        tags: [testKey],
        tagsQueryMode: 'all',
        include: 'entire transactions', // remove checks for entire transactions
        limit: undefined,
      })
        */
      expect(mockWallet.createAction).not.toHaveBeenCalled()
      expect(mockWallet.signAction).not.toHaveBeenCalled()
      expect(mockWallet.relinquishOutput).not.toHaveBeenCalled()
    })

    it('should remove an existing key by spending its output(s)', async () => {
      const existingOutpoint1 = 'removeTxId1.0'
      const existingOutpoint2 = 'removeTxId2.1'
      const existingOutput1 = { outpoint: existingOutpoint1, txid: 'removeTxId1', vout: 0, lockingScript: 's1' }
      const existingOutput2 = { outpoint: existingOutpoint2, txid: 'removeTxId2', vout: 1, lockingScript: 's2' }
      const mockBEEF = Buffer.from('mockBEEFRemove')
      const signableRef = 'signableTxRefRemove'
      const signableTx = []
      const removalTxId = 'removalTxId'
      const mockTxObject = {}

      mockWallet.listOutputs.mockResolvedValue({ outputs: [existingOutput1, existingOutput2], totalOutputs: 2, BEEF: mockBEEF } as any)
      mockWallet.createAction.mockResolvedValue({
        signableTransaction: { reference: signableRef, tx: signableTx }
      } as CreateActionResult) // Note: removal tx has NO outputs field in result
      MockedTransaction.fromAtomicBEEF.mockReturnValue(mockTxObject as any)
      mockWallet.signAction.mockResolvedValue({ txid: removalTxId } as SignActionResult)

      // Get the mock instance
      const mockPDInstance = new MockedPushDrop(mockWallet)

      const result = await kvStore.remove(testKey)

      expect(result).toEqual([removalTxId])
      // expect(mockWallet.listOutputs).toHaveBeenCalledWith({ basket: testContext, tags: [testKey], include: 'entire transactions', limit: undefined, tagsQueryMode: 'all' })

      // Verify createAction for REMOVE (no outputs in the action)
      expect(mockWallet.createAction).toHaveBeenCalledWith({
        // The description might still say "Update" depending on implementation reuse
        // description: `Remove ${testKey} from ${testContext}`, // Ideal description
        description: expect.stringContaining(testKey), // More general check
        inputBEEF: mockBEEF,
        inputs: expect.arrayContaining([
          expect.objectContaining({ outpoint: existingOutpoint1 }),
          expect.objectContaining({ outpoint: existingOutpoint2 })
        ]),
        // IMPORTANT: No 'outputs' key should be present for removal action
        outputs: undefined, // Or check that the key is not present
        options: {
          acceptDelayedBroadcast: false
        }
      }, undefined)
      // Check that outputs key is absent
      expect(mockWallet.createAction.mock.calls[0][0]).not.toHaveProperty('outputs')

      // Verify signing
      expect(MockedTransaction.fromAtomicBEEF).toHaveBeenCalledWith(signableTx)
      expect(mockPDInstance.unlock).toHaveBeenCalledTimes(2)
      expect(mockPDInstance.unlock).toHaveBeenNthCalledWith(1, [2, testContext], testKey, 'self')
      expect(mockPDInstance.unlock).toHaveBeenNthCalledWith(2, [2, testContext], testKey, 'self')
      const mockUnlocker = (mockPDInstance.unlock as jest.Mock).mock.results[0].value
      expect(mockUnlocker.sign).toHaveBeenCalledTimes(2)
      expect(mockUnlocker.sign).toHaveBeenNthCalledWith(1, mockTxObject, 0)
      expect(mockUnlocker.sign).toHaveBeenNthCalledWith(2, mockTxObject, 1)

      // Verify signAction call
      expect(mockWallet.signAction).toHaveBeenCalledWith({
        reference: signableRef,
        spends: {
          0: { unlockingScript: testUnlockingScriptHex },
          1: { unlockingScript: testUnlockingScriptHex }
        }
      }, undefined)
      expect(mockWallet.relinquishOutput).not.toHaveBeenCalled()
    })

    it('should relinquish outputs if signing fails during removal', async () => {
      const existingOutpoint1 = 'failRemoveTxId1.0'
      const existingOutput1 = { outpoint: existingOutpoint1, txid: 'failRemoveTxId1', vout: 0, lockingScript: 's1' }
      const mockBEEF = Buffer.from('mockBEEFFailRemove')
      const signableRef = 'signableTxRefFailRemove'
      const signableTx = []
      const mockTxObject = {}

      mockWallet.listOutputs.mockResolvedValue({ outputs: [existingOutput1], totalOutputs: 1, BEEF: mockBEEF } as any)
      mockWallet.createAction.mockResolvedValue({
        signableTransaction: { reference: signableRef, tx: signableTx }
      } as CreateActionResult)
      MockedTransaction.fromAtomicBEEF.mockReturnValue(mockTxObject as any)
      mockWallet.signAction.mockRejectedValue(new Error('Signature failed remove')) // Make signAction fail
      mockWallet.relinquishOutput.mockResolvedValue({ relinquished: true })

      // Get the mock instance
      const mockPDInstance = new MockedPushDrop(mockWallet)

      // Expect the error to be caught, method completes returning undefined/void
      await expect(kvStore.remove(testKey)).rejects.toThrow('There are')

      // Verify setup calls
      expect(mockWallet.listOutputs).toHaveBeenCalled()
      expect(mockWallet.createAction).toHaveBeenCalled() // createAction called for removal attempt
      expect(MockedTransaction.fromAtomicBEEF).toHaveBeenCalled()
      // expect(mockPDInstance.unlock).toHaveBeenCalledTimes(1) // unlock was called
      const mockUnlocker = (mockPDInstance.unlock as jest.Mock).mock.results[0].value
      expect(mockUnlocker.sign).toHaveBeenCalledTimes(1) // sign was called
      expect(mockWallet.signAction).toHaveBeenCalled() // Called but failed
    })

    it('should preserve original error message when wallet operations fail during removal', async () => {
      const originalErrorMessage = 'Insufficient funds to cover transaction fees'
      const originalError = new Error(originalErrorMessage)

      const existingOutpoint = 'failTxId.0'
      const existingOutput = { outpoint: existingOutpoint, txid: 'failTxId', vout: 0, lockingScript: 's1' }
      const mockBEEF = Buffer.from('mockBEEFFail')

      // Mock wallet to have outputs but createAction fails
      mockWallet.listOutputs.mockResolvedValue({ outputs: [existingOutput], totalOutputs: 1, BEEF: mockBEEF } as any)
      mockWallet.createAction.mockRejectedValue(originalError)

      try {
        await kvStore.remove(testKey)
        fail('Expected remove() to throw an error but it succeeded')
      } catch (error) {
        // Verify that the thrown error contains both the contextual message and the original error
        expect(error).toBeInstanceOf(Error)
        const errorMessage = (error as Error).message
        expect(errorMessage).toContain('1 outputs with tag')
        expect(errorMessage).toContain(testKey)
        expect(errorMessage).toContain('cannot be unlocked')
        expect(errorMessage).toContain('Original error:')
        expect(errorMessage).toContain(originalErrorMessage)
      }
    })
  })
})
