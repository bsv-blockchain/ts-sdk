/** eslint-env jest */
import { Historian, InterpreterFunction } from '../Historian.js'
import Transaction from '../../transaction/Transaction.js'
import { TransactionInput, TransactionOutput } from '../../transaction/index.js'

// --- Module mocks ------------------------------------------------------------
jest.mock('../../transaction/Transaction.js')

// --- Test constants ----------------------------------------------------------
const TEST_TXID_1 = '1111111111111111111111111111111111111111111111111111111111111111'
const TEST_TXID_2 = '2222222222222222222222222222222222222222222222222222222222222222'
const TEST_TXID_3 = '3333333333333333333333333333333333333333333333333333333333333333'

// --- Test types --------------------------------------------------------------
interface TestValue {
  data: string
  outputIndex?: number
}

interface TestContext {
  filter?: string
}

// --- Helpers ----------------------------------------------------------------
type MTx = jest.Mocked<InstanceType<typeof Transaction>>

function makeMockTx (txid: string, outputs: any[] = [], inputs: any[] = []): MTx {
  return {
    id: jest.fn().mockReturnValue(txid),
    outputs,
    inputs
  } as any
}

function makeMockOutput (scriptHex?: string): TransactionOutput {
  const hex = scriptHex || '76a914' // Default to P2PKH prefix if no script provided
  const scriptArray = ((hex.match(/.{2}/g)?.map(byte => parseInt(byte, 16))) != null) || [0x76, 0xa9, 0x14]

  return {
    satoshis: 1,
    lockingScript: {
      toHex: jest.fn().mockReturnValue(hex),
      toArray: jest.fn().mockReturnValue(scriptArray)
    }
  } as any
}

function makeMockInput (sourceTransaction?: MTx): TransactionInput {
  return {
    sourceTransaction,
    sourceTXID: sourceTransaction?.id('hex'),
    sourceOutputIndex: 0
  } as any
}

// Simple interpreter that extracts data from P2PKH scripts (starts with 76a914)
const simpleInterpreter: InterpreterFunction<TestValue, TestContext> = (
  tx: Transaction,
  outputIndex: number,
  ctx?: TestContext
): TestValue | undefined => {
  const output = tx.outputs[outputIndex]
  const scriptHex = output.lockingScript.toHex()

  // Only interpret P2PKH scripts (starts with 76a914)
  if (!scriptHex.startsWith('76a914')) {
    return undefined
  }

  // Apply context filter if provided (e.g., only certain script prefixes)
  if (ctx?.filter && !scriptHex.startsWith(ctx.filter)) {
    return undefined
  }

  return {
    data: `value_from_${scriptHex.slice(0, 8)}`, // Extract identifier from script
    outputIndex
  }
}

// Interpreter that throws errors for specific script patterns
const throwingInterpreter: InterpreterFunction<TestValue> = (
  tx: Transaction,
  outputIndex: number
): TestValue | undefined => {
  const output = tx.outputs[outputIndex]
  const scriptHex = output.lockingScript.toHex()

  // Throw error for scripts containing 'deadbeef' pattern
  if (scriptHex.includes('deadbeef')) {
    throw new Error('Interpreter error')
  }

  // Only interpret P2PKH scripts
  if (scriptHex.startsWith('76a914')) {
    return { data: `value_from_${scriptHex.slice(0, 8)}`, outputIndex }
  }

  return undefined
}

// Async interpreter for testing Promise handling
const asyncInterpreter: InterpreterFunction<TestValue> = async (
  tx: Transaction,
  outputIndex: number
): Promise<TestValue | undefined> => {
  await new Promise(resolve => setTimeout(resolve, 1)) // Simulate async work

  const output = tx.outputs[outputIndex]
  const scriptHex = output.lockingScript.toHex()

  if (scriptHex.startsWith('76a914')) {
    return { data: `async_value_from_${scriptHex.slice(0, 8)}`, outputIndex }
  }

  return undefined
}

// Async interpreter that rejects for testing Promise rejection
const asyncRejectingInterpreter: InterpreterFunction<TestValue> = async (
  tx: Transaction,
  outputIndex: number
): Promise<TestValue | undefined> => {
  await new Promise(resolve => setTimeout(resolve, 1))

  const output = tx.outputs[outputIndex]
  const scriptHex = output.lockingScript.toHex()

  // Reject for scripts containing 'badf00d' pattern
  if (scriptHex.includes('badf00d')) {
    throw new Error('Async interpreter error')
  }

  if (scriptHex.startsWith('76a914')) {
    return { data: `async_value_from_${scriptHex.slice(0, 8)}`, outputIndex }
  }

  return undefined
}

// Interpreter that returns falsy but valid values
const falsyValueInterpreter: InterpreterFunction<TestValue> = (
  tx: Transaction,
  outputIndex: number
): TestValue | undefined => {
  const output = tx.outputs[outputIndex]
  const scriptHex = output.lockingScript.toHex()

  // Return empty string for scripts ending with '00'
  if (scriptHex.endsWith('00')) {
    return { data: '' } // Falsy but valid
  }

  // Return '0' for scripts ending with '30' (ASCII '0')
  if (scriptHex.endsWith('30')) {
    return { data: '0' } // Falsy but valid
  }

  return undefined
}

// --- Test suite --------------------------------------------------------------
describe('Historian', () => {
  let historian: Historian<TestValue, TestContext>
  let mockConsoleLog: jest.SpyInstance

  beforeEach(() => {
    jest.clearAllMocks()
    mockConsoleLog = jest.spyOn(console, 'log').mockImplementation()
    historian = new Historian(simpleInterpreter)
  })

  afterEach(() => {
    mockConsoleLog.mockRestore()
  })

  // --------------------------------------------------------------------------
  describe('Constructor', () => {
    it('creates with interpreter function', () => {
      const testHistorian = new Historian(simpleInterpreter)
      expect(testHistorian).toBeInstanceOf(Historian)
    })

    it('accepts debug option', () => {
      const debugHistorian = new Historian(simpleInterpreter, { debug: true })
      expect(debugHistorian).toBeInstanceOf(Historian)
    })
  })

  // --------------------------------------------------------------------------
  describe('buildHistory', () => {
    describe('happy paths', () => {
      it('returns empty array for transaction with no interpretable outputs', async () => {
        const tx = makeMockTx(TEST_TXID_1, [
          makeMockOutput('6a'), // OP_RETURN script (not P2PKH)
          makeMockOutput('a914') // P2SH script (not P2PKH)
        ])

        const history = await historian.buildHistory(tx)

        expect(history).toEqual([])
      })

      it('extracts single value from transaction with one interpretable output', async () => {
        const tx = makeMockTx(TEST_TXID_1, [
          makeMockOutput('76a914abcdef1234567890abcdef1234567890abcdef88ac'), // P2PKH script
          makeMockOutput('6a') // OP_RETURN (not interpretable)
        ])

        const history = await historian.buildHistory(tx)

        expect(history).toHaveLength(1)
        expect(history[0]).toMatchObject({ data: 'value_from_76a914ab' })
      })

      it('extracts multiple values from transaction with multiple interpretable outputs', async () => {
        const tx = makeMockTx(TEST_TXID_1, [
          makeMockOutput('76a914abcdef1234567890abcdef1234567890abcdef88ac'), // P2PKH script 1
          makeMockOutput('76a914123456789012345678901234567890123456788ac'), // P2PKH script 2
          makeMockOutput('6a') // OP_RETURN (not interpretable)
        ])

        const history = await historian.buildHistory(tx)

        expect(history).toHaveLength(2)
        // The order is reversed due to history.reverse() at the end
        expect(history[0]).toMatchObject({ data: 'value_from_76a91412' })
        expect(history[1]).toMatchObject({ data: 'value_from_76a914ab' })
      })

      it('traverses input chain and returns history in chronological order', async () => {
        // Create a chain: tx1 <- tx2 <- tx3 (tx3 is newest)
        const tx1 = makeMockTx(TEST_TXID_1, [makeMockOutput('76a914111111111111111111111111111111111111111188ac')])
        const tx2 = makeMockTx(TEST_TXID_2, [makeMockOutput('76a914222222222222222222222222222222222222222288ac')], [
          makeMockInput(tx1)
        ])
        const tx3 = makeMockTx(TEST_TXID_3, [makeMockOutput('76a914333333333333333333333333333333333333333388ac')], [
          makeMockInput(tx2)
        ])

        const history = await historian.buildHistory(tx3)

        expect(history).toHaveLength(3)
        expect(history[0]).toMatchObject({ data: 'value_from_76a91411' }) // Chronological order
        expect(history[1]).toMatchObject({ data: 'value_from_76a91422' })
        expect(history[2]).toMatchObject({ data: 'value_from_76a91433' })
      })

      it('handles multiple inputs per transaction', async () => {
        const tx1 = makeMockTx(TEST_TXID_1, [makeMockOutput('76a914aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88ac')])
        const tx2 = makeMockTx(TEST_TXID_2, [makeMockOutput('76a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac')])
        const tx3 = makeMockTx(TEST_TXID_3, [makeMockOutput('76a914cccccccccccccccccccccccccccccccccccccccc88ac')], [
          makeMockInput(tx1),
          makeMockInput(tx2)
        ])

        const history = await historian.buildHistory(tx3)

        expect(history).toHaveLength(3)
        // The order depends on traversal: tx3 outputs first, then tx1, then tx2, then reversed
        expect(history.map(h => h.data)).toEqual(['value_from_76a914bb', 'value_from_76a914aa', 'value_from_76a914cc'])
      })

      it('passes context to interpreter function', async () => {
        const contextHistorian = new Historian(simpleInterpreter)
        const tx = makeMockTx(TEST_TXID_1, [
          makeMockOutput('76a914filtered123456789012345678901234567888ac'), // Matches filter
          makeMockOutput('76a914other1234567890123456789012345678988ac') // Doesn't match filter
        ])

        const history = await contextHistorian.buildHistory(tx, { filter: '76a914filtered' })

        expect(history).toHaveLength(1)
        expect(history[0]).toMatchObject({ data: 'value_from_76a914fi' })
      })

      it('works with async interpreter functions', async () => {
        const asyncHistorian = new Historian(asyncInterpreter)
        const tx = makeMockTx(TEST_TXID_1, [
          makeMockOutput('76a914async12345678901234567890123456789088ac')
        ])

        const history = await asyncHistorian.buildHistory(tx)

        expect(history).toHaveLength(1)
        expect(history[0]).toMatchObject({ data: 'async_value_from_76a914as' })
      })

      it('includes falsy but valid values from interpreter', async () => {
        const falsyHistorian = new Historian(falsyValueInterpreter)
        const tx = makeMockTx(TEST_TXID_1, [
          makeMockOutput('76a914123456789012345678901234567890123400'), // Returns { data: '' }
          makeMockOutput('76a914123456789012345678901234567890123430'), // Returns { data: '0' }
          makeMockOutput('76a914123456789012345678901234567890123456') // Returns undefined
        ])

        const history = await falsyHistorian.buildHistory(tx)

        expect(history).toHaveLength(2)
        expect(history[0]).toMatchObject({ data: '0' }) // Falsy but valid
        expect(history[1]).toMatchObject({ data: '' }) // Falsy but valid
      })
    })

    describe('sad paths', () => {
      it('handles interpreter errors gracefully', async () => {
        const errorHistorian = new Historian(throwingInterpreter)
        const tx = makeMockTx(TEST_TXID_1, [
          makeMockOutput('76a914abcdef1234567890abcdef1234567890abcdef88ac'), // Good P2PKH
          makeMockOutput('76a914deadbeef1234567890123456789012345688ac'), // Contains 'deadbeef' - will throw
          makeMockOutput('76a914fedcba0987654321fedcba0987654321fedcba88ac') // Good P2PKH
        ])

        const history = await errorHistorian.buildHistory(tx)

        expect(history).toHaveLength(2)
        // The order is reversed due to history.reverse() at the end
        expect(history[0]).toMatchObject({ data: 'value_from_76a914fe' })
        expect(history[1]).toMatchObject({ data: 'value_from_76a914ab' })
      })

      it('handles async interpreter rejection gracefully', async () => {
        const rejectingHistorian = new Historian(asyncRejectingInterpreter)
        const tx = makeMockTx(TEST_TXID_1, [
          makeMockOutput('76a914abcdef1234567890abcdef1234567890abcdef88ac'), // Good P2PKH
          makeMockOutput('76a914badf00d1234567890123456789012345688ac'), // Contains 'badf00d' - will reject
          makeMockOutput('76a914fedcba0987654321fedcba0987654321fedcba88ac') // Good P2PKH
        ])

        const history = await rejectingHistorian.buildHistory(tx)

        expect(history).toHaveLength(2)
        expect(history[0]).toMatchObject({ data: 'async_value_from_76a914fe' })
        expect(history[1]).toMatchObject({ data: 'async_value_from_76a914ab' })
      })

      it('handles missing sourceTransaction in inputs', async () => {
        const tx1 = makeMockTx(TEST_TXID_1, [makeMockOutput('76a914abcdef1234567890abcdef1234567890abcdef88ac')], [
          makeMockInput(), // No sourceTransaction
          makeMockInput() // No sourceTransaction
        ])

        const history = await historian.buildHistory(tx1)

        expect(history).toHaveLength(1)
        expect(history[0]).toMatchObject({ data: 'value_from_76a914ab' })
      })

      it('prevents infinite loops in circular transaction chains', async () => {
        const tx1 = makeMockTx(TEST_TXID_1, [makeMockOutput('76a914111111111111111111111111111111111111111188ac')])
        const tx2 = makeMockTx(TEST_TXID_2, [makeMockOutput('76a914222222222222222222222222222222222222222288ac')], [
          makeMockInput(tx1)
        ])

        // Create circular reference: tx1 -> tx2 -> tx1
        tx1.inputs = [makeMockInput(tx2)]

        const history = await historian.buildHistory(tx2)

        expect(history).toHaveLength(2)
        expect(history[0]).toMatchObject({ data: 'value_from_76a91411' })
        expect(history[1]).toMatchObject({ data: 'value_from_76a91422' })
      })
    })

    describe('debug mode', () => {
      it('logs debug information when debug=true', async () => {
        const debugHistorian = new Historian(simpleInterpreter, { debug: true })
        const tx = makeMockTx(TEST_TXID_1, [makeMockOutput('76a914abcdef1234567890abcdef1234567890abcdef88ac')])

        await debugHistorian.buildHistory(tx)

        expect(mockConsoleLog).toHaveBeenCalledWith(
          expect.stringContaining('[Historian] Processing transaction:')
        )
        expect(mockConsoleLog).toHaveBeenCalledWith(
          '[Historian] Added value to history:',
          expect.objectContaining({ data: 'value_from_76a914ab' })
        )
      })

      it('logs cycle detection in debug mode', async () => {
        const debugHistorian = new Historian(simpleInterpreter, { debug: true })
        const tx1 = makeMockTx(TEST_TXID_1, [makeMockOutput('76a914111111111111111111111111111111111111111188ac')])
        const tx2 = makeMockTx(TEST_TXID_2, [makeMockOutput('76a914222222222222222222222222222222222222222288ac')], [
          makeMockInput(tx1)
        ])

        // Create circular reference
        tx1.inputs = [makeMockInput(tx2)]

        await debugHistorian.buildHistory(tx2)

        expect(mockConsoleLog).toHaveBeenCalledWith(
          expect.stringContaining('[Historian] Skipping already visited transaction:')
        )
      })

      it('logs missing sourceTransaction in debug mode', async () => {
        const debugHistorian = new Historian(simpleInterpreter, { debug: true })
        const tx = makeMockTx(TEST_TXID_1, [makeMockOutput('76a914abcdef1234567890abcdef1234567890abcdef88ac')], [
          makeMockInput() // No sourceTransaction
        ])

        await debugHistorian.buildHistory(tx)

        // Precise assertion on exact log message
        expect(mockConsoleLog).toHaveBeenCalledWith(
          '[Historian] Input missing sourceTransaction, skipping'
        )
      })

      it('logs interpreter errors in debug mode', async () => {
        const debugHistorian = new Historian(throwingInterpreter, { debug: true })
        const tx = makeMockTx(TEST_TXID_1, [
          makeMockOutput('76a914deadbeef1234567890123456789012345688ac') // Contains 'deadbeef' - will throw
        ])

        await debugHistorian.buildHistory(tx)

        expect(mockConsoleLog).toHaveBeenCalledWith(
          expect.stringContaining('[Historian] Failed to interpret output'),
          expect.any(Error)
        )
      })

      it('does not log when debug=false', async () => {
        const quietHistorian = new Historian(simpleInterpreter, { debug: false })
        const tx = makeMockTx(TEST_TXID_1, [makeMockOutput('76a914abcdef1234567890abcdef1234567890abcdef88ac')])

        await quietHistorian.buildHistory(tx)

        expect(mockConsoleLog).not.toHaveBeenCalled()
      })
    })

    describe('caching', () => {
      it('accepts historyCache option in constructor', () => {
        const cache = new Map<string, readonly TestValue[]>()
        const cachedHistorian = new Historian(simpleInterpreter, { historyCache: cache })
        expect(cachedHistorian).toBeInstanceOf(Historian)
      })

      it('uses cache when provided and returns cached results', async () => {
        const cache = new Map<string, readonly TestValue[]>()
        const cachedHistorian = new Historian(simpleInterpreter, {
          historyCache: cache,
          debug: true // Enable debug to verify cache hit logs
        })

        const tx = makeMockTx(TEST_TXID_1, [makeMockOutput('76a914cached1234567890123456789012345678888ac')])

        // First call - should populate cache
        const history1 = await cachedHistorian.buildHistory(tx)
        expect(cache.size).toBe(1)
        expect(history1).toHaveLength(1)
        expect(history1[0]).toMatchObject({ data: 'value_from_76a914ca' })

        // Verify cache was populated (debug log should contain "cached")
        expect(mockConsoleLog).toHaveBeenCalledWith(
          expect.stringContaining('[Historian] History cached:'),
          expect.any(String)
        )

        // Second call - should use cache (returns shallow copy, not same reference)
        const history2 = await cachedHistorian.buildHistory(tx)
        expect(history1).toStrictEqual(history2) // Same content from cache
        expect(history1).not.toBe(history2) // Different references (shallow copy)
        expect(cache.size).toBe(1) // No new cache entries

        // Verify cache hit (debug log should contain "cache hit")
        expect(mockConsoleLog).toHaveBeenCalledWith(
          expect.stringContaining('[Historian] History cache hit:'),
          expect.any(String)
        )
      })

      it('generates different cache keys for different transactions', async () => {
        const cache = new Map<string, readonly TestValue[]>()
        const cachedHistorian = new Historian(simpleInterpreter, { historyCache: cache })

        const tx1 = makeMockTx(TEST_TXID_1, [makeMockOutput('76a914tx1data123456789012345678901234567888ac')])
        const tx2 = makeMockTx(TEST_TXID_2, [makeMockOutput('76a914tx2data123456789012345678901234567888ac')])

        await cachedHistorian.buildHistory(tx1)
        await cachedHistorian.buildHistory(tx2)

        expect(cache.size).toBe(2) // Different transactions = different cache keys

        // Verify both are cached independently
        const history1 = await cachedHistorian.buildHistory(tx1)
        const history2 = await cachedHistorian.buildHistory(tx2)
        expect(history1[0].data).toBe('value_from_76a914tx')
        expect(history2[0].data).toBe('value_from_76a914tx')
        expect(cache.size).toBe(2) // Still only 2 entries
      })

      it('generates different cache keys for different contexts', async () => {
        const cache = new Map<string, readonly TestValue[]>()
        const cachedHistorian = new Historian(simpleInterpreter, { historyCache: cache })

        const tx = makeMockTx(TEST_TXID_1, [
          makeMockOutput('76a914filtered123456789012345678901234567888ac'), // Matches filter
          makeMockOutput('76a914other1234567890123456789012345678988ac') // Doesn't match filter
        ])

        // Same transaction, different contexts
        await cachedHistorian.buildHistory(tx, { filter: '76a914filtered' })
        await cachedHistorian.buildHistory(tx, { filter: '76a914other' })
        await cachedHistorian.buildHistory(tx) // No context

        expect(cache.size).toBe(3) // Different contexts = different cache keys
      })

      it('invalidates cache when interpreterVersion changes', async () => {
        const cache = new Map<string, readonly TestValue[]>()
        const historian1 = new Historian(simpleInterpreter, {
          historyCache: cache,
          interpreterVersion: 'v1'
        })
        const historian2 = new Historian(simpleInterpreter, {
          historyCache: cache,
          interpreterVersion: 'v2'
        })

        const tx = makeMockTx(TEST_TXID_1, [makeMockOutput('76a914version123456789012345678901234567888ac')])

        await historian1.buildHistory(tx)
        await historian2.buildHistory(tx) // Different version = new cache entry

        expect(cache.size).toBe(2) // Two entries for different versions

        // Verify both versions work independently
        const history1 = await historian1.buildHistory(tx)
        const history2 = await historian2.buildHistory(tx)
        expect(history1).toBeDefined()
        expect(history2).toBeDefined()
        expect(cache.size).toBe(2) // Still only 2 entries
      })

      it('returns immutable cached results that cannot be mutated externally', async () => {
        const cache = new Map<string, readonly TestValue[]>()
        const cachedHistorian = new Historian(simpleInterpreter, { historyCache: cache })

        const tx = makeMockTx(TEST_TXID_1, [makeMockOutput('76a914immutable123456789012345678901234567888ac')])

        const history1 = await cachedHistorian.buildHistory(tx)
        const history2 = await cachedHistorian.buildHistory(tx)

        // Should be different references but same content (shallow copies from cache)
        expect(history1).toStrictEqual(history2)
        expect(history1).not.toBe(history2)

        // Original cached value should be frozen, but returned copies are mutable
        // Mutating returned copy should not affect the cache or future calls
        ; (history1 as any).push({ data: 'malicious', outputIndex: 999 })

        const history3 = await cachedHistorian.buildHistory(tx)
        expect(history3).toStrictEqual(history2) // Still original content from cache
        expect(history3).toHaveLength(1) // Original length preserved
        expect(history3).not.toStrictEqual(history1) // Different from mutated copy
      })

      it('works correctly with transaction chains when caching is enabled', async () => {
        const cache = new Map<string, readonly TestValue[]>()
        const cachedHistorian = new Historian(simpleInterpreter, { historyCache: cache })

        // Create a simple chain: tx1 <- tx2
        const tx1 = makeMockTx(TEST_TXID_1, [makeMockOutput('76a914chain11234567890123456789012345678888ac')])
        const tx2 = makeMockTx(TEST_TXID_2, [makeMockOutput('76a914chain21234567890123456789012345678888ac')], [
          makeMockInput(tx1)
        ])

        // First call - should cache the results
        const history1 = await cachedHistorian.buildHistory(tx2)
        expect(history1).toHaveLength(2)
        expect(cache.size).toBeGreaterThan(0)

        // Second call - should use cache (same content, different reference)
        const history2 = await cachedHistorian.buildHistory(tx2)
        expect(history1).toStrictEqual(history2) // Same content from cache
        expect(history1).not.toBe(history2) // Different references (shallow copy)

        // Individual transaction should also be cached
        const tx1History = await cachedHistorian.buildHistory(tx1)
        expect(tx1History).toHaveLength(1)
        expect(tx1History[0]).toMatchObject({ data: 'value_from_76a914ch' })
      })
    })
  })

  // --------------------------------------------------------------------------
  describe('Integration scenarios', () => {
    it('handles complex transaction chain with mixed interpretable outputs', async () => {
      // Build a realistic scenario with multiple transactions and branches
      const genesis = makeMockTx(TEST_TXID_1, [
        makeMockOutput('76a914genesis123456789012345678901234567888ac'), // P2PKH
        makeMockOutput('6a') // OP_RETURN (non-interpretable)
      ])

      const branch1 = makeMockTx(TEST_TXID_2, [
        makeMockOutput('76a914branch1123456789012345678901234567888ac') // P2PKH
      ], [makeMockInput(genesis)])

      const branch2 = makeMockTx(TEST_TXID_3, [
        makeMockOutput('76a914branch2123456789012345678901234567888ac'), // P2PKH
        makeMockOutput('76a914extrabr123456789012345678901234567888ac') // P2PKH
      ], [makeMockInput(genesis)])

      const merge = makeMockTx('4444444444444444444444444444444444444444444444444444444444444444', [
        makeMockOutput('76a914finalme123456789012345678901234567888ac') // P2PKH
      ], [
        makeMockInput(branch1),
        makeMockInput(branch2)
      ])

      const history = await historian.buildHistory(merge)

      expect(history).toHaveLength(5)
      // Verify all expected values are present by checking for the extracted prefixes
      const dataValues = history.map(h => h.data)
      expect(dataValues).toContain('value_from_76a914ge') // genesis
      expect(dataValues).toContain('value_from_76a914br') // branch1 or branch2
      expect(dataValues).toContain('value_from_76a914ex') // extrabr
      expect(dataValues).toContain('value_from_76a914fi') // finalme
      // All should be P2PKH interpretations
      expect(dataValues.every(data => data.startsWith('value_from_76a914'))).toBe(true)
    })

    it('handles deep transaction chains efficiently', async () => {
      // Create a chain of 10 transactions
      let currentTx = makeMockTx('0000000000000000000000000000000000000000000000000000000000000000', [
        makeMockOutput('76a914000000000000000000000000000000000000000088ac') // P2PKH for value_0
      ])

      for (let i = 1; i < 10; i++) { // Keep it reasonable for test performance
        const scriptHex = `76a914${i.toString(16).padStart(2, '0')}000000000000000000000000000000000000000088ac`
        const newTx = makeMockTx(
          i.toString().padStart(64, '0'),
          [makeMockOutput(scriptHex)], // P2PKH scripts
          [makeMockInput(currentTx)]
        )
        currentTx = newTx
      }

      const history = await historian.buildHistory(currentTx)

      expect(history).toHaveLength(10)
      expect(history[0]).toMatchObject({ data: 'value_from_76a91400' }) // Oldest first (genesis)
      expect(history[9]).toMatchObject({ data: 'value_from_76a91409' }) // Newest last (tx 9)
      // Verify the chain contains genesis and final transaction
      expect(history.map(h => h.data)).toContain('value_from_76a91400') // genesis
      expect(history.map(h => h.data)).toContain('value_from_76a91409') // tx 9
    })

    it('handles moderately large chains without stack overflow (sanity check)', async () => {
      // Test stack safety with 50 transactions - not a benchmark, just sanity
      const startTime = Date.now()

      let currentTx = makeMockTx('0000000000000000000000000000000000000000000000000000000000000000', [
        makeMockOutput('76a914genesis123456789012345678901234567888ac') // P2PKH for genesis
      ])

      // Build chain of 50 transactions
      for (let i = 1; i < 50; i++) {
        // Create unique P2PKH scripts for each transaction
        const scriptHex = `76a914${i.toString(16).padEnd(4, '0')}00000000000000000000000000000000000088ac`
        const newTx = makeMockTx(
          i.toString().padStart(64, '0'),
          [makeMockOutput(scriptHex)],
          [makeMockInput(currentTx)]
        )
        currentTx = newTx
      }

      const history = await historian.buildHistory(currentTx)
      const duration = Date.now() - startTime

      // Sanity checks: should complete quickly without errors
      expect(history).toHaveLength(50)
      expect(history[0]).toMatchObject({ data: 'value_from_76a914ge' }) // genesis - Oldest first
      // Verify we have genesis and some chain transactions
      expect(history.map(h => h.data)).toContain('value_from_76a914ge') // genesis
      expect(history.map(h => h.data)).toContain('value_from_76a91410') // tx 1
      expect(history.map(h => h.data)).toContain('value_from_76a91431') // tx 49 (31 in hex)
      expect(duration).toBeLessThan(1000) // Should complete in under 1 second
    })
  })
})
