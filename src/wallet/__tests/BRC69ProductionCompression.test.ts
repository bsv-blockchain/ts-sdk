import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  BRC69_PRODUCTION_COMPRESSION_LAYOUT,
  brc69ProductionCompressionByteTuple,
  brc69ProductionCompressionBytes,
  brc69ProductionCompressionMetrics,
  brc69ProductionCompressionPointTuple,
  buildBRC69ProductionCompressionAir,
  buildBRC69ProductionCompressionTrace,
  proveBRC69ProductionCompression,
  verifyBRC69ProductionCompression
} from '../brc69/method2/index'
import {
  buildProductionRadix11EcTrace,
  buildProductionRadix11LookupPrototype,
  evaluateAirTrace
} from '../brc69/stark/index'
import {
  SECP256K1_N,
  compressPoint,
  scalarMultiply
} from '../brc69/circuit/index'

describe('BRC-69 production compression/key-binding segment', () => {
  it('proves compressed S bytes from private S with production parameters', () => {
    const ec = buildEcFixture()
    const trace = buildBRC69ProductionCompressionTrace(ec)
    const air = buildBRC69ProductionCompressionAir(trace)

    expect(trace.publicInput.activeRows).toBe(257)
    expect(trace.publicInput.traceLength).toBe(512)
    expect(trace.layout.width).toBe(BRC69_PRODUCTION_COMPRESSION_LAYOUT.width)
    expect(brc69ProductionCompressionBytes(trace)).toEqual(compressPoint(ec.privateS))
    expect(brc69ProductionCompressionPointTuple(trace)).toHaveLength(11)
    expect(brc69ProductionCompressionByteTuple(trace, 0)).toEqual([
      0n,
      BigInt(trace.compressedBytes[0])
    ])
    expect(evaluateAirTrace(air, trace.rows).valid).toBe(true)

    const proof = proveBRC69ProductionCompression(trace, {
      maskSeed: ascii('production-compression-mask')
    })

    expect(verifyBRC69ProductionCompression(trace.publicInput, proof)).toBe(true)
    expect(brc69ProductionCompressionMetrics(trace, proof)).toMatchObject({
      activeRows: 257,
      paddedRows: 512,
      traceWidth: BRC69_PRODUCTION_COMPRESSION_LAYOUT.width,
      compressedBytes: 33,
      xBitRows: 256
    })
    expect(brc69ProductionCompressionMetrics(trace, proof).proofBytes)
      .toBeGreaterThan(0)
  })

  it('rejects altered x bits, byte reconstruction, and prefix parity', () => {
    const trace = buildBRC69ProductionCompressionTrace(buildEcFixture())
    const air = buildBRC69ProductionCompressionAir(trace)

    const wrongBit = trace.rows.map(row => row.slice())
    wrongBit[0][trace.layout.xBit] = wrongBit[0][trace.layout.xBit] === 0n
      ? 1n
      : 0n
    expect(evaluateAirTrace(air, wrongBit).valid).toBe(false)

    const wrongByte = trace.rows.map(row => row.slice())
    wrongByte[7][trace.layout.byte] += 1n
    expect(evaluateAirTrace(air, wrongByte).valid).toBe(false)

    const wrongPrefix = trace.rows.map(row => row.slice())
    wrongPrefix[256][trace.layout.prefix] += 1n
    expect(evaluateAirTrace(air, wrongPrefix).valid).toBe(false)
  })

  it('rejects infinity inputs and reduced proof parameters', () => {
    expect(() => buildBRC69ProductionCompressionTrace({
      infinity: true,
      x: 0n,
      y: 0n
    })).toThrow('non-infinity')

    const trace = buildBRC69ProductionCompressionTrace(buildEcFixture())
    const weakProof = proveBRC69ProductionCompression(trace, {
      numQueries: 2,
      maskSeed: ascii('production-compression-weak-mask')
    })
    expect(verifyBRC69ProductionCompression(trace.publicInput, weakProof))
      .toBe(false)
  })
})

function buildEcFixture (): ReturnType<typeof buildProductionRadix11EcTrace> {
  const scalar = SECP256K1_N - 123456789n
  const baseB = scalarMultiply(7n)
  return buildProductionRadix11EcTrace(
    buildProductionRadix11LookupPrototype(scalar, baseB)
  )
}

function ascii (value: string): number[] {
  return Array.from(value).map(char => char.charCodeAt(0))
}
