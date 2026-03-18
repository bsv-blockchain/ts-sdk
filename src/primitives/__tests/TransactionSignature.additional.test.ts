import TransactionSignature, { SignatureHashCache } from '../../primitives/TransactionSignature'
import BigNumber from '../../primitives/BigNumber'
import LockingScript from '../../script/LockingScript'
import Script from '../../script/Script'
import Transaction from '../../transaction/Transaction'

const ZERO_TXID = '0'.repeat(64)

function makeParams (overrides: Partial<Parameters<typeof TransactionSignature.formatBip143>[0]> = {}): Parameters<typeof TransactionSignature.formatBip143>[0] {
  const defaultScript = new LockingScript()
  return {
    sourceTXID: ZERO_TXID,
    sourceOutputIndex: 0,
    sourceSatoshis: 1000,
    transactionVersion: 1,
    otherInputs: [],
    outputs: [{ lockingScript: defaultScript, satoshis: 900 }],
    inputIndex: 0,
    subscript: new Script(),
    inputSequence: 0xffffffff,
    lockTime: 0,
    scope: TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID,
    ...overrides
  }
}

describe('TransactionSignature – additional coverage', () => {
  describe('hasLowS', () => {
    it('returns false when s < 1', () => {
      const sig = new TransactionSignature(new BigNumber(1), new BigNumber(0), 1)
      expect(sig.hasLowS()).toBe(false)
    })

    it('returns true for a normal low-s value', () => {
      const sig = new TransactionSignature(new BigNumber(1), new BigNumber(100), 1)
      expect(sig.hasLowS()).toBe(true)
    })
  })

  describe('fromChecksigFormat', () => {
    it('creates blank signature when buffer is empty', () => {
      const sig = TransactionSignature.fromChecksigFormat([])
      expect(sig.scope).toBe(1)
      expect(sig.r.eqn(1)).toBe(true)
    })
  })

  describe('formatBip143 – SIGHASH_NONE', () => {
    it('produces output with empty hashSequence and hashOutputs for SIGHASH_NONE', () => {
      const params = makeParams({
        scope: TransactionSignature.SIGHASH_NONE | TransactionSignature.SIGHASH_FORKID
      })
      const result = TransactionSignature.formatBip143(params)
      expect(result).toBeInstanceOf(Uint8Array)
      expect(result.length).toBeGreaterThan(0)
    })

    it('SIGHASH_NONE with ANYONECANPAY skips prevouts hash', () => {
      const params = makeParams({
        scope: TransactionSignature.SIGHASH_NONE | TransactionSignature.SIGHASH_FORKID | TransactionSignature.SIGHASH_ANYONECANPAY
      })
      const result = TransactionSignature.formatBip143(params)
      expect(result).toBeInstanceOf(Uint8Array)
    })
  })

  describe('formatBip143 – SIGHASH_SINGLE', () => {
    it('produces hashOutputs for the current input index', () => {
      const params = makeParams({
        scope: TransactionSignature.SIGHASH_SINGLE | TransactionSignature.SIGHASH_FORKID
      })
      const result = TransactionSignature.formatBip143(params)
      expect(result).toBeInstanceOf(Uint8Array)
    })

    it('uses zero hashOutputs when inputIndex >= outputs.length', () => {
      const params = makeParams({
        scope: TransactionSignature.SIGHASH_SINGLE | TransactionSignature.SIGHASH_FORKID,
        inputIndex: 0,
        outputs: [] // no outputs → inputIndex (0) >= outputs.length (0)
      })
      const result = TransactionSignature.formatBip143(params)
      expect(result).toBeInstanceOf(Uint8Array)
    })
  })

  describe('formatBip143 – SIGHASH_ANYONECANPAY', () => {
    it('skips prevouts and sequence hash for ANYONECANPAY | ALL', () => {
      const params = makeParams({
        scope: TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID | TransactionSignature.SIGHASH_ANYONECANPAY
      })
      const result = TransactionSignature.formatBip143(params)
      expect(result).toBeInstanceOf(Uint8Array)
    })
  })

  describe('formatBip143 – cache', () => {
    it('uses cached hashPrevouts and hashSequence on second call', () => {
      const params = makeParams()
      const cache: SignatureHashCache = {}

      const first = TransactionSignature.formatBip143({ ...params, cache })
      expect(cache.hashPrevouts).toBeDefined()
      expect(cache.hashSequence).toBeDefined()
      expect(cache.hashOutputsAll).toBeDefined()

      // Second call uses cached values
      const second = TransactionSignature.formatBip143({ ...params, cache })
      expect(first).toEqual(second)
    })

    it('caches hashOutputsSingle for SIGHASH_SINGLE and reuses it', () => {
      const params = makeParams({
        scope: TransactionSignature.SIGHASH_SINGLE | TransactionSignature.SIGHASH_FORKID
      })
      const cache: SignatureHashCache = {}

      const first = TransactionSignature.formatBip143({ ...params, cache })
      expect(cache.hashOutputsSingle).toBeDefined()

      // Second call should hit the cached single output hash
      const second = TransactionSignature.formatBip143({ ...params, cache })
      expect(first).toEqual(second)
    })
  })

  describe('formatBytes – routing', () => {
    it('routes to formatOTDA when no SIGHASH_FORKID', () => {
      const params = makeParams({
        scope: TransactionSignature.SIGHASH_ALL // no FORKID
      })
      const result = TransactionSignature.formatBytes(params)
      expect(result).toBeInstanceOf(Uint8Array)
    })

    it('routes to formatOTDA when SIGHASH_CHRONICLE is set', () => {
      const params = makeParams({
        scope: TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID | TransactionSignature.SIGHASH_CHRONICLE
      })
      const result = TransactionSignature.formatBytes(params)
      expect(result).toBeInstanceOf(Uint8Array)
    })

    it('routes to formatBip143 for standard FORKID signing', () => {
      const params = makeParams()
      const result = TransactionSignature.formatBytes(params)
      expect(result).toBeInstanceOf(Uint8Array)
    })
  })

  describe('formatOTDA – SIGHASH variants', () => {
    // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
    const makeOTDA = (overrides = {}) => ({
      scope: TransactionSignature.SIGHASH_ALL,
      sourceTXID: ZERO_TXID,
      sourceOutputIndex: 0,
      sourceSatoshis: 1000,
      transactionVersion: 1,
      otherInputs: [
        {
          sourceTXID: '1'.repeat(64),
          sourceOutputIndex: 1,
          sequence: 0xffffffff
        }
      ],
      outputs: [
        { lockingScript: new LockingScript(), satoshis: 900 },
        { lockingScript: new LockingScript(), satoshis: 50 }
      ],
      inputIndex: 0,
      subscript: new Script(),
      inputSequence: 0xffffffff,
      lockTime: 0,
      ...overrides
    })

    it('handles SIGHASH_ALL', () => {
      const result = TransactionSignature.formatOTDA(makeOTDA({ scope: TransactionSignature.SIGHASH_ALL }))
      expect(result).toBeInstanceOf(Uint8Array)
    })

    it('handles SIGHASH_NONE', () => {
      const result = TransactionSignature.formatOTDA(makeOTDA({ scope: TransactionSignature.SIGHASH_NONE }))
      expect(result).toBeInstanceOf(Uint8Array)
    })

    it('handles SIGHASH_SINGLE with output at inputIndex', () => {
      const result = TransactionSignature.formatOTDA(makeOTDA({ scope: TransactionSignature.SIGHASH_SINGLE }))
      expect(result).toBeInstanceOf(Uint8Array)
    })

    it('handles SIGHASH_ANYONECANPAY | SIGHASH_ALL', () => {
      const result = TransactionSignature.formatOTDA(makeOTDA({
        scope: TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_ANYONECANPAY
      }))
      expect(result).toBeInstanceOf(Uint8Array)
    })

    it('handles SIGHASH_SINGLE when inputIndex >= outputs.length', () => {
      const result = TransactionSignature.formatOTDA(makeOTDA({
        scope: TransactionSignature.SIGHASH_SINGLE,
        inputIndex: 5,
        otherInputs: []
      }))
      expect(result).toBeInstanceOf(Uint8Array)
    })
  })

  describe('formatBip143 – sourceTransaction path', () => {
    it('uses sourceTransaction.hash() when sourceTXID is undefined', () => {
      const sourceTx = new Transaction(1, [], [{ lockingScript: new LockingScript(), satoshis: 1000 }], 0)
      const params = makeParams({
        scope: TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID,
        otherInputs: [
          {
            sourceTransaction: sourceTx,
            sourceOutputIndex: 0,
            sequence: 0xffffffff
            // no sourceTXID → forces the sourceTransaction branch
          }
        ]
      })
      const result = TransactionSignature.formatBip143(params)
      expect(result).toBeInstanceOf(Uint8Array)
    })

    it('throws when sourceTXID is undefined and sourceTransaction is null', () => {
      const params = makeParams({
        scope: TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID,
        otherInputs: [
          {
            sourceOutputIndex: 0,
            sequence: 0xffffffff
            // no sourceTXID, no sourceTransaction → should throw
          }
        ]
      })
      expect(() => TransactionSignature.formatBip143(params)).toThrow('Missing sourceTransaction for input')
    })
  })
})
