import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  BRC97_PRODUCTION_SCALAR_LAYOUT,
  SECP256K1_N,
  brc97ProductionScalarDigitTuple,
  brc97ProductionScalarMetrics,
  buildBRC97ProductionScalarAir,
  buildBRC97ProductionScalarTrace,
  buildProductionRadix11LookupPrototype,
  evaluateAirTrace,
  proveBRC97ProductionScalar,
  scalarMultiply,
  verifyBRC97ProductionScalar
} from '../brc97/index'

describe('BRC-97 production scalar digit segment', () => {
  it('proves canonical signed radix-11 digits and scalar range', () => {
    const lookup = buildProductionRadix11LookupPrototype(
      SECP256K1_N - 123456789n,
      scalarMultiply(7n)
    )
    const trace = buildBRC97ProductionScalarTrace(lookup)
    const air = buildBRC97ProductionScalarAir(trace)

    expect(trace.publicInput.activeRows).toBe(24)
    expect(trace.publicInput.traceLength).toBe(32)
    expect(trace.layout.width).toBe(49)
    expect(evaluateAirTrace(air, trace.rows).valid).toBe(true)
    expect(brc97ProductionScalarDigitTuple(trace, 0)).toEqual([
      0n,
      BigInt(lookup.digits[0].magnitude),
      lookup.digits[0].magnitude === 0 ? 1n : 0n,
      BigInt(lookup.digits[0].sign)
    ])

    const proof = proveBRC97ProductionScalar(trace, {
      maskSeed: ascii('production-scalar-mask')
    })

    expect(verifyBRC97ProductionScalar(trace.publicInput, proof)).toBe(true)
    expect(brc97ProductionScalarMetrics(trace, proof)).toMatchObject({
      activeRows: 24,
      paddedRows: 32,
      traceWidth: BRC97_PRODUCTION_SCALAR_LAYOUT.width,
      digitRows: 24,
      bitRows: 24 * 11 * 3
    })
    expect(brc97ProductionScalarMetrics(trace, proof).proofBytes)
      .toBeGreaterThan(0)
  })

  it('rejects non-canonical zero signs and altered reconstruction limbs', () => {
    const lookup = buildProductionRadix11LookupPrototype(
      SECP256K1_N - 123456789n,
      scalarMultiply(7n)
    )
    const trace = buildBRC97ProductionScalarTrace(lookup)
    const zeroRow = lookup.digits.findIndex(digit => digit.magnitude === 0)
    if (zeroRow < 0) throw new Error('zero digit missing')

    const wrongZeroSign = trace.rows.map(row => row.slice())
    wrongZeroSign[zeroRow][trace.layout.sign] = 1n
    expect(evaluateAirTrace(
      buildBRC97ProductionScalarAir(trace),
      wrongZeroSign
    ).valid).toBe(false)

    const wrongUnsignedLimb = trace.rows.map(row => row.slice())
    wrongUnsignedLimb[0][trace.layout.unsignedLimb] += 1n
    expect(evaluateAirTrace(
      buildBRC97ProductionScalarAir(trace),
      wrongUnsignedLimb
    ).valid).toBe(false)
  })

  it('rejects final-window overflow and reduced STARK parameters', () => {
    const lookup = buildProductionRadix11LookupPrototype(0x1f8n, scalarMultiply(7n))
    const trace = buildBRC97ProductionScalarTrace(lookup)
    const finalRow = trace.publicInput.activeRows - 1
    const finalOverflow = trace.rows.map(row => row.slice())
    finalOverflow[finalRow][trace.layout.magnitudeBits + 4] = 1n
    finalOverflow[finalRow][trace.layout.magnitude] += 16n
    expect(evaluateAirTrace(
      buildBRC97ProductionScalarAir(trace),
      finalOverflow
    ).valid).toBe(false)

    const weakProof = proveBRC97ProductionScalar(trace, {
      numQueries: 2,
      maskSeed: ascii('production-scalar-weak-mask')
    })
    expect(verifyBRC97ProductionScalar(trace.publicInput, weakProof))
      .toBe(false)
  })

  it('rejects out-of-range scalar fixtures before trace construction', () => {
    const baseB = scalarMultiply(7n)
    expect(() => buildProductionRadix11LookupPrototype(0n, baseB)).toThrow()
    expect(() => buildProductionRadix11LookupPrototype(SECP256K1_N, baseB))
      .toThrow()
  })
})

function ascii (value: string): number[] {
  return Array.from(value).map(char => char.charCodeAt(0))
}
