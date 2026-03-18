/** eslint-env jest */
import { kvStoreInterpreter, KVContext } from '../kvStoreInterpreter'
import { kvProtocol } from '../types'
import Transaction from '../../transaction/Transaction'
import PushDrop from '../../script/templates/PushDrop'
import * as Utils from '../../primitives/utils'

// --- Module mocks -----------------------------------------------------------

jest.mock('../../script/templates/PushDrop.js', () => {
  const mockPushDropDecode = jest.fn()
  return Object.assign(
    jest.fn(() => ({})),
    { decode: mockPushDropDecode }
  )
})

jest.mock('../../primitives/utils.js', () => ({
  toArray: jest.fn((str: string) => Array.from(Buffer.from(str, 'utf8'))),
  toUTF8: jest.fn((arr: number[] | Uint8Array) => Buffer.from(arr).toString('utf8'))
}))

// --- Typed mock refs --------------------------------------------------------

const MockedPushDrop = PushDrop as jest.MockedClass<typeof PushDrop> & {
  decode: jest.Mock<any, any>
}
const MockedPushDropDecode = MockedPushDrop.decode
const MockedUtils = Utils as jest.Mocked<typeof Utils>

// --- Helpers ----------------------------------------------------------------

/**
 * Number of fields in the new format (all kvProtocol keys).
 * Old format has one fewer (no tags field).
 */
const expectedFieldCount = Object.keys(kvProtocol).length // 6

function makeMockTransaction (outputs: Array<{ lockingScript?: any } | null>): Transaction {
  return {
    outputs
  } as unknown as Transaction
}

function makeFieldArray (
  protocolID: string,
  key: string,
  value: string,
  controller: string = 'controller',
  includeTagsField: boolean = true
): Array<number[]> {
  // Fields in kvProtocol order: protocolID(0), key(1), value(2), controller(3), tags(4), signature(5)
  const fields: Array<number[]> = [
    Array.from(Buffer.from(protocolID)),
    Array.from(Buffer.from(key)),
    Array.from(Buffer.from(value)),
    Array.from(Buffer.from(controller))
  ]
  if (includeTagsField) {
    fields.push(Array.from(Buffer.from('[]'))) // tags
    fields.push(Array.from(Buffer.from('sig'))) // signature
  } else {
    // Old format: no tags, signature at position 4
    fields.push(Array.from(Buffer.from('sig'))) // signature
  }
  return fields
}

import { SecurityLevel, WalletProtocol } from '../../wallet/Wallet.interfaces'

function makeCtx (key: string, protocolID: WalletProtocol = [2 as SecurityLevel, 'kvstore']): KVContext {
  return { key, protocolID }
}

// --- Tests ------------------------------------------------------------------

describe('kvStoreInterpreter', () => {
  const testKey = 'my-key'
  const testValue = 'my-value'
  const testProtocolID: WalletProtocol = [2 as SecurityLevel, 'kvstore']
  const testCtx = makeCtx(testKey, testProtocolID)
  const protocolIDStr = JSON.stringify(testProtocolID)

  beforeEach(() => {
    jest.clearAllMocks()
    // Default toUTF8 implementation: convert byte array to string
    MockedUtils.toUTF8.mockImplementation((arr: number[] | Uint8Array) =>
      Buffer.from(arr).toString('utf8')
    )
  })

  // --- Missing / null guard cases -------------------------------------------

  describe('returns undefined for missing/invalid inputs', () => {
    it('returns undefined when output at index does not exist', async () => {
      const tx = makeMockTransaction([])
      const result = await kvStoreInterpreter(tx, 0, testCtx)
      expect(result).toBeUndefined()
    })

    it('returns undefined when output lockingScript is null', async () => {
      const tx = makeMockTransaction([{ lockingScript: null }])
      const result = await kvStoreInterpreter(tx, 0, testCtx)
      expect(result).toBeUndefined()
    })

    it('returns undefined when output is null', async () => {
      const tx = makeMockTransaction([null])
      const result = await kvStoreInterpreter(tx, 0, testCtx)
      expect(result).toBeUndefined()
    })

    it('returns undefined when ctx is undefined', async () => {
      const tx = makeMockTransaction([{ lockingScript: {} }])
      const result = await kvStoreInterpreter(tx, 0, undefined)
      expect(result).toBeUndefined()
    })

    it('returns undefined when ctx is null', async () => {
      const tx = makeMockTransaction([{ lockingScript: {} }])
      const result = await kvStoreInterpreter(tx, 0, null as any)
      expect(result).toBeUndefined()
    })

    it('returns undefined when ctx.key is null', async () => {
      const tx = makeMockTransaction([{ lockingScript: {} }])
      const result = await kvStoreInterpreter(tx, 0, { key: null as any, protocolID: testProtocolID })
      expect(result).toBeUndefined()
    })

    it('returns undefined when ctx.key is undefined', async () => {
      const tx = makeMockTransaction([{ lockingScript: {} }])
      const result = await kvStoreInterpreter(tx, 0, { key: undefined as any, protocolID: testProtocolID })
      expect(result).toBeUndefined()
    })
  })

  // --- PushDrop.decode error cases ------------------------------------------

  describe('returns undefined when PushDrop.decode throws', () => {
    it('returns undefined when decode throws due to malformed script', async () => {
      MockedPushDropDecode.mockImplementation(() => {
        throw new Error('Malformed script')
      })
      const tx = makeMockTransaction([{ lockingScript: {} }])
      const result = await kvStoreInterpreter(tx, 0, testCtx)
      expect(result).toBeUndefined()
      expect(MockedPushDropDecode).toHaveBeenCalledTimes(1)
    })
  })

  // --- Wrong field count cases -----------------------------------------------

  describe('returns undefined when field count is wrong', () => {
    it('returns undefined when decoded fields length is too short (< expectedFieldCount - 1)', async () => {
      // e.g., only 3 fields — neither old nor new format
      MockedPushDropDecode.mockReturnValue({
        fields: [
          Array.from(Buffer.from('id')),
          Array.from(Buffer.from('key')),
          Array.from(Buffer.from('val'))
        ]
      })
      const tx = makeMockTransaction([{ lockingScript: {} }])
      const result = await kvStoreInterpreter(tx, 0, testCtx)
      expect(result).toBeUndefined()
    })

    it('returns undefined when decoded fields length is too long (> expectedFieldCount)', async () => {
      // More fields than the new format
      const fields = makeFieldArray(protocolIDStr, testKey, testValue)
      fields.push(Array.from(Buffer.from('extra')))
      MockedPushDropDecode.mockReturnValue({ fields })
      const tx = makeMockTransaction([{ lockingScript: {} }])
      const result = await kvStoreInterpreter(tx, 0, testCtx)
      expect(result).toBeUndefined()
    })
  })

  // --- Key / protocolID mismatch cases --------------------------------------

  describe('returns undefined when key or protocolID does not match ctx', () => {
    it('returns undefined when key does not match ctx.key (new format)', async () => {
      MockedPushDropDecode.mockReturnValue({
        fields: makeFieldArray(protocolIDStr, 'different-key', testValue)
      })
      // toUTF8 returns the string content of the byte arrays
      MockedUtils.toUTF8
        .mockReturnValueOnce(protocolIDStr) // protocolID field
        .mockReturnValueOnce('different-key') // key field
      const tx = makeMockTransaction([{ lockingScript: {} }])
      const result = await kvStoreInterpreter(tx, 0, testCtx)
      expect(result).toBeUndefined()
    })

    it('returns undefined when key does not match ctx.key (old format)', async () => {
      MockedPushDropDecode.mockReturnValue({
        fields: makeFieldArray(protocolIDStr, 'wrong-key', testValue, 'controller', false)
      })
      MockedUtils.toUTF8
        .mockReturnValueOnce('wrong-key') // key field
        .mockReturnValueOnce(protocolIDStr) // protocolID field
      const tx = makeMockTransaction([{ lockingScript: {} }])
      const result = await kvStoreInterpreter(tx, 0, testCtx)
      expect(result).toBeUndefined()
    })

    it('returns undefined when protocolID does not match ctx.protocolID (new format)', async () => {
      const differentProtocol: [number, string] = [1, 'other']
      MockedPushDropDecode.mockReturnValue({
        fields: makeFieldArray(JSON.stringify(differentProtocol), testKey, testValue)
      })
      MockedUtils.toUTF8
        .mockReturnValueOnce(testKey) // key field
        .mockReturnValueOnce(JSON.stringify(differentProtocol)) // protocolID field
      const tx = makeMockTransaction([{ lockingScript: {} }])
      const result = await kvStoreInterpreter(tx, 0, testCtx)
      expect(result).toBeUndefined()
    })
  })

  // --- Happy path: new format (expectedFieldCount fields) --------------------

  describe('returns decoded value string for matching outputs', () => {
    it('returns value for new format (expectedFieldCount fields) matching key and protocolID', async () => {
      const newFormatFields = makeFieldArray(protocolIDStr, testKey, testValue, 'controller', true)
      expect(newFormatFields.length).toBe(expectedFieldCount)

      MockedPushDropDecode.mockReturnValue({ fields: newFormatFields })
      MockedUtils.toUTF8
        .mockReturnValueOnce(testKey) // key field — kvProtocol.key = 1
        .mockReturnValueOnce(protocolIDStr) // protocolID field — kvProtocol.protocolID = 0
        .mockReturnValueOnce(testValue) // value field — kvProtocol.value = 2

      const tx = makeMockTransaction([{ lockingScript: {} }])
      const result = await kvStoreInterpreter(tx, 0, testCtx)

      expect(result).toBe(testValue)
      expect(MockedPushDropDecode).toHaveBeenCalledTimes(1)
    })

    it('returns value for old format (expectedFieldCount - 1 fields) matching key and protocolID', async () => {
      const oldFormatFields = makeFieldArray(protocolIDStr, testKey, testValue, 'controller', false)
      expect(oldFormatFields.length).toBe(expectedFieldCount - 1)

      MockedPushDropDecode.mockReturnValue({ fields: oldFormatFields })
      MockedUtils.toUTF8
        .mockReturnValueOnce(testKey) // key field
        .mockReturnValueOnce(protocolIDStr) // protocolID field
        .mockReturnValueOnce(testValue) // value field

      const tx = makeMockTransaction([{ lockingScript: {} }])
      const result = await kvStoreInterpreter(tx, 0, testCtx)

      expect(result).toBe(testValue)
      expect(MockedPushDropDecode).toHaveBeenCalledTimes(1)
    })

    it('uses the output at the correct outputIndex', async () => {
      const newFormatFields = makeFieldArray(protocolIDStr, testKey, testValue)
      MockedPushDropDecode.mockReturnValue({ fields: newFormatFields })
      MockedUtils.toUTF8
        .mockReturnValueOnce(testKey)
        .mockReturnValueOnce(protocolIDStr)
        .mockReturnValueOnce(testValue)

      const tx = makeMockTransaction([
        null, // index 0: non-existent
        { lockingScript: {} } // index 1: valid
      ])
      const result = await kvStoreInterpreter(tx, 1, testCtx)

      expect(result).toBe(testValue)
    })
  })

  // --- Inner catch: Utils.toUTF8 throws on value field ----------------------

  describe('returns undefined when Utils.toUTF8 throws on value field', () => {
    it('returns undefined when toUTF8 throws during value extraction (inner catch)', async () => {
      const newFormatFields = makeFieldArray(protocolIDStr, testKey, testValue)
      MockedPushDropDecode.mockReturnValue({ fields: newFormatFields })

      // First two calls succeed (key and protocolID match), third throws
      MockedUtils.toUTF8
        .mockReturnValueOnce(testKey)
        .mockReturnValueOnce(protocolIDStr)
        .mockImplementationOnce(() => {
          throw new Error('toUTF8 failed on value')
        })

      const tx = makeMockTransaction([{ lockingScript: {} }])
      const result = await kvStoreInterpreter(tx, 0, testCtx)

      expect(result).toBeUndefined()
    })

    it('returns undefined when toUTF8 throws during key extraction (outer catch)', async () => {
      const newFormatFields = makeFieldArray(protocolIDStr, testKey, testValue)
      MockedPushDropDecode.mockReturnValue({ fields: newFormatFields })

      // First call (key extraction) throws
      MockedUtils.toUTF8.mockImplementationOnce(() => {
        throw new Error('toUTF8 failed on key')
      })

      const tx = makeMockTransaction([{ lockingScript: {} }])
      const result = await kvStoreInterpreter(tx, 0, testCtx)

      expect(result).toBeUndefined()
    })
  })

  // --- Field index alignment check ------------------------------------------

  describe('kvProtocol field indices', () => {
    it('has the expected field indices for new format', () => {
      expect(kvProtocol.protocolID).toBe(0)
      expect(kvProtocol.key).toBe(1)
      expect(kvProtocol.value).toBe(2)
      expect(kvProtocol.controller).toBe(3)
      expect(kvProtocol.tags).toBe(4)
      expect(kvProtocol.signature).toBe(5)
      expect(Object.keys(kvProtocol).length).toBe(6)
    })
  })
})
