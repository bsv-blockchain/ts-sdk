import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  BRC97_PRODUCTION_COMPRESSION_LAYOUT,
  SECP256K1_N,
  brc97ProductionCompressionByteTuple,
  brc97ProductionCompressionBytes,
  brc97ProductionCompressionMetrics,
  brc97ProductionCompressionPointTuple,
  buildBRC97ProductionCompressionAir,
  buildBRC97ProductionCompressionTrace,
  buildProductionRadix11EcTrace,
  buildProductionRadix11LookupPrototype,
  compressPoint,
  evaluateAirTrace,
  proveBRC97ProductionCompression,
  scalarMultiply,
  verifyBRC97ProductionCompression
} from '../brc97/index'

describe('BRC-97 production compression/key-binding segment', () => {
  it('proves compressed S bytes from private S with production parameters', () => {
    const ec = buildEcFixture()
    const trace = buildBRC97ProductionCompressionTrace(ec)
    const air = buildBRC97ProductionCompressionAir(trace)

    expect(trace.publicInput.activeRows).toBe(257)
    expect(trace.publicInput.traceLength).toBe(512)
    expect(trace.layout.width).toBe(BRC97_PRODUCTION_COMPRESSION_LAYOUT.width)
    expect(brc97ProductionCompressionBytes(trace)).toEqual(compressPoint(ec.privateS))
    expect(brc97ProductionCompressionPointTuple(trace)).toHaveLength(11)
    expect(brc97ProductionCompressionByteTuple(trace, 0)).toEqual([
      0n,
      BigInt(trace.compressedBytes[0])
    ])
    expect(evaluateAirTrace(air, trace.rows).valid).toBe(true)

    const proof = proveBRC97ProductionCompression(trace, {
      maskSeed: ascii('production-compression-mask')
    })

    expect(verifyBRC97ProductionCompression(trace.publicInput, proof)).toBe(true)
    expect(brc97ProductionCompressionMetrics(trace, proof)).toMatchObject({
      activeRows: 257,
      paddedRows: 512,
      traceWidth: BRC97_PRODUCTION_COMPRESSION_LAYOUT.width,
      compressedBytes: 33,
      xBitRows: 256
    })
    expect(brc97ProductionCompressionMetrics(trace, proof).proofBytes)
      .toBeGreaterThan(0)
  })

  it('rejects altered x bits, byte reconstruction, and prefix parity', () => {
    const trace = buildBRC97ProductionCompressionTrace(buildEcFixture())
    const air = buildBRC97ProductionCompressionAir(trace)

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
    expect(() => buildBRC97ProductionCompressionTrace({
      infinity: true,
      x: 0n,
      y: 0n
    })).toThrow('non-infinity')

    const trace = buildBRC97ProductionCompressionTrace(buildEcFixture())
    const weakProof = proveBRC97ProductionCompression(trace, {
      numQueries: 2,
      maskSeed: ascii('production-compression-weak-mask')
    })
    expect(verifyBRC97ProductionCompression(trace.publicInput, weakProof))
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
