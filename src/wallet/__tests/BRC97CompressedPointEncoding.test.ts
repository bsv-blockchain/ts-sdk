import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  buildCompressedPointEncodingTrace,
  buildDualBaseEcIntegratedTrace,
  buildDualBaseLookupPrototype,
  compressedPointBytesForHmac,
  compressedPointEncodingMetrics,
  compressPoint,
  proveCompressedPointEncoding,
  scalarMultiply,
  validateCompressedPointEncodingTrace,
  verifyCompressedPointEncoding
} from '../brc97/index'

describe('BRC-97 compressed point encoding proof boundary', () => {
  it('range-proves compressed S nibbles and preserves the HMAC byte boundary', () => {
    const integrated = buildIntegratedTrace()
    const trace = buildCompressedPointEncodingTrace(
      integrated.compressedS,
      { minTraceLength: 128 }
    )
    const proof = proveCompressedPointEncoding(trace, {
      maskSeed: ascii('compressed-point-encoding-mask')
    })
    const metrics = compressedPointEncodingMetrics(trace, proof)

    expect(verifyCompressedPointEncoding(trace, proof)).toBe(true)
    expect(trace.witness.bytes).toEqual(compressPoint(integrated.privateS))
    expect(compressedPointBytesForHmac(trace)).toEqual(integrated.compressedS.bytes)
    expect(metrics).toMatchObject({
      bytes: 33,
      nibbles: 66,
      uniqueRangeTableRows: 16,
      rangeRequests: 66,
      committedWidth: 85
    })
    expect(metrics.rangeSupplyRows).toBeGreaterThan(0)
    expect(metrics.totalProofBytes).toBeGreaterThan(0)
  })

  it('rejects tampered bytes, nibbles, prefix parity, and range traces', () => {
    const integrated = buildIntegratedTrace()
    const trace = buildCompressedPointEncodingTrace(
      integrated.compressedS,
      { minTraceLength: 128 }
    )
    const proof = proveCompressedPointEncoding(trace, {
      maskSeed: ascii('compressed-point-negative-mask')
    })

    const badByte = cloneTrace(trace)
    badByte.witness.bytes[1] ^= 1
    expect(() => validateCompressedPointEncodingTrace(badByte)).toThrow()
    expect(verifyCompressedPointEncoding(badByte, proof)).toBe(false)

    const badNibble = cloneTrace(trace)
    badNibble.witness.nibbles[2] = 16
    expect(() => validateCompressedPointEncodingTrace(badNibble)).toThrow()
    expect(verifyCompressedPointEncoding(badNibble, proof)).toBe(false)

    const badPrefix = cloneTrace(trace)
    badPrefix.witness.prefix = badPrefix.witness.prefix === 2 ? 3 : 2
    expect(() => validateCompressedPointEncodingTrace(badPrefix)).toThrow()
    expect(verifyCompressedPointEncoding(badPrefix, proof)).toBe(false)

    const badLookup = cloneTrace(trace)
    badLookup.lookup.rows[0][0] = 0n
    expect(() => validateCompressedPointEncodingTrace(badLookup)).toThrow()
    expect(verifyCompressedPointEncoding(badLookup, proof)).toBe(false)
  })
})

function buildIntegratedTrace (): ReturnType<typeof buildDualBaseEcIntegratedTrace> {
  const scalar = 0x1f8n
  const baseB = scalarMultiply(7n)
  const lookup = buildDualBaseLookupPrototype(
    scalar,
    baseB,
    { windowBits: 4, windowCount: 4, minTraceLength: 128 }
  )
  return buildDualBaseEcIntegratedTrace(lookup)
}

function cloneTrace (
  trace: ReturnType<typeof buildCompressedPointEncodingTrace>
): ReturnType<typeof buildCompressedPointEncodingTrace> {
  return {
    ...trace,
    point: { ...trace.point },
    witness: {
      point: { ...trace.witness.point },
      bytes: trace.witness.bytes.slice(),
      prefix: trace.witness.prefix,
      xBytes: trace.witness.xBytes.slice(),
      nibbles: trace.witness.nibbles.slice()
    },
    lookup: {
      publicInput: {
        traceLength: trace.lookup.publicInput.traceLength,
        expectedLookupRequests: trace.lookup.publicInput.expectedLookupRequests,
        scheduleRows: trace.lookup.publicInput.scheduleRows.map(row => ({
          kind: row.kind,
          tag: row.tag,
          publicTuple: row.publicTuple.slice()
        }))
      },
      rows: trace.lookup.rows.map(row => row.slice()),
      metrics: { ...trace.lookup.metrics }
    },
    rows: trace.rows.map(row => ({ ...row }))
  }
}

function ascii (value: string): number[] {
  return Array.from(value).map(char => char.charCodeAt(0))
}
