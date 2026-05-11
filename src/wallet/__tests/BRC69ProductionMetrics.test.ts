import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  assertBRC69ActualSegmentsVerified,
  assertBRC69ProductionAcceptanceGate,
  brc69ProductionAcceptanceIssues,
  collectBRC69ProductionMetrics,
  formatBRC69ProductionMetrics,
  unverifiedBRC69ActualSegments
} from '../brc69/index'
import {
  BRC69_RADIX11_TABLE_ROWS,
  buildProductionRadix11LookupPrototype
} from '../brc69/stark/index'
import {
  SECP256K1_N,
  scalarMultiply
} from '../brc69/circuit/index'

describe('BRC-69 production metrics harness', () => {
  it('collects max-invoice compact-HMAC and radix-11 metrics in fast mode', () => {
    const report = collectBRC69ProductionMetrics({
      mode: 'fast',
      now: deterministicClock(),
      sampleColumns: 1,
      maxSampleTraceLength: 64,
      cpuCount: 8,
      gitCommit: 'test-commit'
    })

    expect(report.inputs.invoiceLength).toBe(1233)
    expect(report.inputs.innerBlocks).toBe(21)
    expect(report.inputs.outerBlocks).toBe(2)
    expect(report.inputs.totalBlocks).toBe(23)
    expect(report.inputs.scalarProfile).toBe('SECP256K1_N - 123456789')
    expect(report.inputs).not.toHaveProperty('scalarHex')

    expect(report.segments.maxInvoiceCompactHmac).toMatchObject({
      status: 'actual',
      activeRows: 1495,
      paddedRows: 2048,
      committedWidth: 551,
      proofBytes: undefined,
      lookupRequestsByTag: {
        shaRound: 1472,
        shaBitBoolean: 376832,
        hmacKeyByte: 33
      }
    })
    expect(report.segments.maxInvoiceCompactHmac.estimatedProofBytes)
      .toBeGreaterThan(0)

    expect(report.segments.radix11PointLookup).toMatchObject({
      status: 'actual',
      activeRows: 23608,
      paddedRows: 32768,
      committedWidth: 72,
      fixedPreprocessedRows: BRC69_RADIX11_TABLE_ROWS,
      proofBytes: undefined
    })
    expect(report.segments.radix11PointLookup.estimatedProofBytes)
      .toBeGreaterThan(0)
    expect(report.segments.scalarDigits).toMatchObject({
      status: 'actual',
      activeRows: 24,
      paddedRows: 32,
      committedWidth: 49,
      proofBytes: undefined,
      lookupRequestsByTag: {
        scalarDigit: 24,
        scalarRangeBit: 792
      }
    })
    expect(report.segments.scalarDigits.estimatedProofBytes)
      .toBeGreaterThan(0)
    expect(report.segments.ecArithmetic).toMatchObject({
      status: 'actual',
      activeRows: 5280,
      paddedRows: 8192,
      committedWidth: 526,
      proofBytes: undefined,
      verified: undefined
    })
    expect(report.segments.ecArithmetic.estimatedProofBytes)
      .toBeGreaterThan(0)
    expect(report.segments.compressionAndKeyBinding).toMatchObject({
      status: 'actual',
      activeRows: 257,
      paddedRows: 512,
      committedWidth: 78,
      proofBytes: undefined,
      lookupRequestsByTag: {
        compressedByte: 33,
        compressedXBit: 256
      }
    })
    expect(report.segments.compressionAndKeyBinding.estimatedProofBytes)
      .toBeGreaterThan(0)
    expect(report.segments.lookupEqualityBus).toMatchObject({
      status: 'actual',
      activeRows: 260,
      paddedRows: 32768,
      committedWidth: 217,
      fixedPreprocessedRows: 0,
      proofBytes: undefined,
      lookupRequestsByTag: {
        scalarDigit: 48,
        pointPairOutput: 48,
        ecSelectedGPoint: 48,
        ecSelectedBPoint: 48,
        ecPrivateSPoint: 2,
        compressedSKeyByte: 66
      }
    })
    expect(report.segments.lookupEqualityBus.estimatedProofBytes)
      .toBeGreaterThan(0)
    expect(report.segments.wholeStatement).toMatchObject({
      status: 'actual',
      paddedRows: 32768,
      fixedPreprocessedRows: BRC69_RADIX11_TABLE_ROWS,
      proofBytes: undefined
    })
    expect(report.segments.wholeStatement.committedWidth).toBeGreaterThan(1000)
    expect(report.segments.wholeStatement.committedCells)
      .toBeLessThan(60000000)
    expect(report.segments.wholeStatement.estimatedProofBytes)
      .toBeGreaterThan(0)
    expect(formatBRC69ProductionMetrics(report))
      .toContain('BRC69 Production Metrics')
    expect(formatBRC69ProductionMetrics(report))
      .toContain('| verified |')
    expect(() => assertBRC69ActualSegmentsVerified(report)).not.toThrow()
    expect(brc69ProductionAcceptanceIssues(report).join('; '))
      .not.toContain('projected segment')
    expect(brc69ProductionAcceptanceIssues(report).join('; '))
      .toContain('wholeStatement proof bytes')
    expect(() => assertBRC69ProductionAcceptanceGate(report))
      .toThrow('BRC69 production acceptance gate failed')
  })

  it('uses the production radix-11 table shape and final-window bound', () => {
    const scalar = SECP256K1_N - 123456789n
    const prototype = buildProductionRadix11LookupPrototype(
      scalar,
      scalarMultiply(7n)
    )
    const finalDigit = prototype.digits[prototype.digits.length - 1]

    expect(prototype.table).toHaveLength(23584)
    expect(prototype.selectedIndexes).toHaveLength(24)
    expect(finalDigit.magnitude).toBeLessThanOrEqual(8)
  })

  it('fails the metrics gate for any proved actual segment that does not verify', () => {
    const report = collectBRC69ProductionMetrics({
      mode: 'fast',
      now: deterministicClock(),
      sampleColumns: 1,
      maxSampleTraceLength: 64
    })
    report.segments.radix11PointLookup = {
      ...report.segments.radix11PointLookup,
      proofBytes: 123,
      estimatedProofBytes: undefined,
      proveMs: 1,
      verifyMs: 1,
      verified: false
    }

    expect(unverifiedBRC69ActualSegments(report))
      .toEqual(['radix11PointLookup'])
    expect(() => assertBRC69ActualSegmentsVerified(report))
      .toThrow('radix11PointLookup')
  })
})

function deterministicClock (): () => number {
  let value = 0
  return () => value++
}
