import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  DUAL_BASE_NEGATIVE_SIGN,
  DUAL_BASE_POSITIVE_SIGN,
  LOOKUP_BUS_LAYOUT,
  LOOKUP_BUS_TUPLE_ARITY,
  buildDualBaseLookupPrototype,
  buildDualBasePointPairTable,
  buildLookupBusAir,
  accumulateDualBasePointPairs,
  decomposeDualBaseSignedDigits,
  dualBaseLimbsToBigint,
  dualBaseLookupMetrics,
  dualBasePointToLimbs,
  dualBasePointPairFromTuple,
  dualBasePointsEqual,
  dualBaseSignedDigitTableIndex,
  estimateDualBaseLookupMetrics,
  evaluateAirTrace,
  proveLookupBus,
  proveDualBaseLookupPrototype,
  reconstructDualBaseSignedScalar,
  runDualBaseLookupMetricsSweep,
  selectedDualBasePointPairs,
  validateDualBaseLookupPrototype,
  verifyDualBaseLookupPrototypeProof
} from '../brc69/stark/index'
import {
  SECP256K1_G,
  scalarMultiply
} from '../brc69/circuit/index'

describe('BRC-69 dual-base signed lookup prototype', () => {
  it('decomposes scalars into canonical signed radix digits', () => {
    const config = { windowBits: 4, windowCount: 4 }
    const scalar = 0x1f8n
    const digits = decomposeDualBaseSignedDigits(scalar, config)

    expect(digits.map(digit => digit.digit)).toEqual([-8n, 0n, 2n, 0n])
    expect(digits.map(digit => digit.sign)).toEqual([
      DUAL_BASE_NEGATIVE_SIGN,
      DUAL_BASE_POSITIVE_SIGN,
      DUAL_BASE_POSITIVE_SIGN,
      DUAL_BASE_POSITIVE_SIGN
    ])
    expect(digits.map(digit => digit.magnitude)).toEqual([8, 0, 2, 0])
    expect(digits[0].tableIndex).toBe(
      dualBaseSignedDigitTableIndex(0, DUAL_BASE_NEGATIVE_SIGN, 8, config)
    )
    expect(digits[1].tableIndex).toBe(
      dualBaseSignedDigitTableIndex(1, DUAL_BASE_POSITIVE_SIGN, 0, config)
    )
    expect(reconstructDualBaseSignedScalar(digits, config)).toBe(scalar)
  })

  it('builds deterministic limb-encoded dual-base point-pair tables', () => {
    const config = { windowBits: 3, windowCount: 2 }
    const baseB = scalarMultiply(7n)
    const table = buildDualBasePointPairTable(baseB, config)

    expect(table).toHaveLength(16)
    table.forEach((row, index) => {
      expect(row.index).toBe(index)
      expect(row.values).toHaveLength(LOOKUP_BUS_TUPLE_ARITY)
      expect(row.values[0]).toBe(BigInt(row.window))
      expect(row.values[1]).toBe(BigInt(row.sign))
      expect(row.values[2]).toBe(BigInt(row.magnitude))
    })

    const zero = table[dualBaseSignedDigitTableIndex(
      0,
      DUAL_BASE_POSITIVE_SIGN,
      0,
      config
    )]
    expect(zero.g.infinity).toBe(true)
    expect(zero.b.infinity).toBe(true)
    expect(zero.values.slice(3)).toEqual(new Array(20).fill(0n))

    const negativeMax = table[dualBaseSignedDigitTableIndex(
      0,
      DUAL_BASE_NEGATIVE_SIGN,
      4,
      config
    )]
    expect(negativeMax.sign).toBe(DUAL_BASE_NEGATIVE_SIGN)
    expect(negativeMax.magnitude).toBe(4)
    expect(dualBasePointPairFromTuple(
      negativeMax.values,
      config
    )).toMatchObject({
      window: 0,
      sign: DUAL_BASE_NEGATIVE_SIGN,
      magnitude: 4
    })

    const gLimbs = dualBasePointToLimbs(SECP256K1_G)
    expect(gLimbs).toHaveLength(10)
    expect(dualBaseLimbsToBigint(gLimbs.slice(0, 5))).toBe(SECP256K1_G.x)
    expect(dualBaseLimbsToBigint(gLimbs.slice(5, 10))).toBe(SECP256K1_G.y)
  })

  it('proves selected signed-window point pairs came from the public table', () => {
    const config = { windowBits: 4, windowCount: 4, minTraceLength: 128 }
    const scalar = 0x1f8n
    const baseB = scalarMultiply(7n)
    const prototype = buildDualBaseLookupPrototype(scalar, baseB, config)
    expect(() => validateDualBaseLookupPrototype(prototype)).not.toThrow()

    prototype.digits.forEach(digit => {
      const row = prototype.table[digit.tableIndex]
      expect(row.window).toBe(digit.window)
      expect(row.sign).toBe(digit.sign)
      expect(row.magnitude).toBe(digit.magnitude)
    })

    const proof = proveDualBaseLookupPrototype(prototype, {
      ...FAST_LOOKUP_PROOF_OPTIONS,
      maskSeed: ascii('dual-base-lookup-mask')
    })

    expect(verifyDualBaseLookupPrototypeProof(
      prototype,
      proof,
      FAST_LOOKUP_PROOF_OPTIONS
    )).toBe(true)
    expect(dualBaseLookupMetrics(prototype, proof)).toMatchObject({
      activeRows: 68,
      paddedRows: 128,
      traceWidth: LOOKUP_BUS_LAYOUT.width,
      fixedTableRows: 64,
      lookupRequests: 4,
      lookupSupplies: 4,
      fixedLookups: 4,
      tableRows: 64,
      selectedRows: 4,
      tupleArity: LOOKUP_BUS_TUPLE_ARITY,
      committedWidth: LOOKUP_BUS_LAYOUT.width,
      lookupRows: 68,
      activeCells: 68 * LOOKUP_BUS_LAYOUT.width,
      paddedCells: 128 * LOOKUP_BUS_LAYOUT.width,
      overheadRowsPerLookup: 16
    })
  })

  it('accumulates selected point pairs to the expected dual scalar products', () => {
    const config = { windowBits: 4, windowCount: 4, minTraceLength: 128 }
    const scalar = 0x1f8n
    const baseB = scalarMultiply(7n)
    const prototype = buildDualBaseLookupPrototype(scalar, baseB, config)
    const accumulated = accumulateDualBasePointPairs(
      selectedDualBasePointPairs(prototype)
    )

    expect(dualBasePointsEqual(
      accumulated.g,
      scalarMultiply(scalar, SECP256K1_G)
    )).toBe(true)
    expect(dualBasePointsEqual(
      accumulated.b,
      scalarMultiply(scalar, baseB)
    )).toBe(true)
  })

  it('rejects a tampered private point-pair request', () => {
    const config = { windowBits: 4, windowCount: 4, minTraceLength: 128 }
    const prototype = buildDualBaseLookupPrototype(0x1f8n, scalarMultiply(7n), config)
    const rows = prototype.trace.baseRows.map(row => row.slice())
    const firstRequestRow = prototype.table.length
    rows[firstRequestRow][LOOKUP_BUS_LAYOUT.left + 2] += 1n

    expect(evaluateAirTrace(
      buildLookupBusAir(prototype.trace.publicInput),
      rows
    ).valid).toBe(true)
    expect(() => proveLookupBus({
      ...prototype.trace,
      baseRows: rows
    }, {
      maskSeed: ascii('dual-base-tampered-request-mask')
    })).toThrow()
  })

  it('estimates default signed radix-11 table shape without building the table', () => {
    expect(estimateDualBaseLookupMetrics()).toMatchObject({
      windowBits: 11,
      windowCount: 24,
      maxMagnitude: 1024,
      rowsPerWindow: 2048,
      tableRows: 49152,
      selectedRows: 24,
      activeRows: 49176,
      paddedRows: 65536,
      traceWidth: LOOKUP_BUS_LAYOUT.width,
      tupleArity: LOOKUP_BUS_TUPLE_ARITY,
      committedWidth: LOOKUP_BUS_LAYOUT.width,
      lookupRows: 49176,
      overheadRowsPerLookup: 2048
    })
  })

  it('runs metrics sweeps with proving and estimate-only safeguards', () => {
    const baseB = scalarMultiply(7n)
    const results = runDualBaseLookupMetricsSweep({
      prove: true,
      maxProveTableRows: 128,
      now: deterministicClock(),
      proofOptions: {
        ...FAST_LOOKUP_PROOF_OPTIONS,
        maskSeed: ascii('dual-base-sweep-mask')
      },
      cases: [
        {
          name: 'small-proved',
          scalar: 0x1f8n,
          baseB,
          parameters: { windowBits: 4, windowCount: 4, minTraceLength: 128 }
        },
        {
          name: 'default-estimated',
          scalar: 0x1f8n,
          baseB
        }
      ]
    })

    expect(results[0]).toMatchObject({
      name: 'small-proved',
      estimatedOnly: false,
      verified: true,
      buildMs: 1,
      proveMs: 1,
      verifyMs: 1,
      tableRows: 64,
      selectedRows: 4
    })
    expect(results[0].proofBytes).toBeGreaterThan(0)
    expect(results[0].proofBytesPerLookup).toBeGreaterThan(0)
    expect(results[1]).toMatchObject({
      name: 'default-estimated',
      estimatedOnly: true,
      buildMs: 0,
      tableRows: 49152,
      selectedRows: 24
    })
    expect(results[1].proofBytes).toBeUndefined()
  })
})

function ascii (value: string): number[] {
  return Array.from(value).map(char => char.charCodeAt(0))
}

const FAST_LOOKUP_PROOF_OPTIONS = {
  blowupFactor: 4,
  numQueries: 4,
  maxRemainderSize: 8,
  maskDegree: 1,
  cosetOffset: 3n
}

function deterministicClock (): () => number {
  let value = 0
  return () => value++
}
