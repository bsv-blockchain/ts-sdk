import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  METHOD2_SHA256_INITIAL_STATE,
  buildMethod2Sha256CompressionBlockProofAir,
  buildMethod2Sha256CompressionBlockProofTrace,
  evaluateAirTrace,
  method2Sha256CompressBlockReference,
  method2Sha256CompressionBlockMetrics,
  proveMethod2Sha256CompressionBlock,
  sha256Pad,
  verifyMethod2Sha256CompressionBlock
} from '../brc97/index'

describe('BRC-97 SHA-256 compression block proof target', () => {
  it('proves one fixed SHA-256 compression block and rejects wrong public bindings', () => {
    const block = sha256Pad(ascii('abc')).slice(0, 64)
    const expected = method2Sha256CompressBlockReference(
      METHOD2_SHA256_INITIAL_STATE,
      block
    )
    const trace = buildMethod2Sha256CompressionBlockProofTrace(
      METHOD2_SHA256_INITIAL_STATE,
      block,
      expected
    )
    const air = buildMethod2Sha256CompressionBlockProofAir(trace)

    expect(evaluateAirTrace(air, trace.traceRows).valid).toBe(true)

    const proof = proveMethod2Sha256CompressionBlock(trace, {
      maskSeed: ascii('sha256-block-proof-mask')
    })
    const metrics = method2Sha256CompressionBlockMetrics(trace, proof)

    expect(verifyMethod2Sha256CompressionBlock(trace, proof)).toBe(true)
    expect(metrics).toMatchObject({
      traceLength: 128,
      traceWidth: 1616,
      activeRows: 65,
      roundRows: 64,
      committedCells: 128 * 1616
    })
    expect(metrics.proofBytes).toBeGreaterThan(0)

    const badBlock = {
      ...trace,
      block: trace.block.map((byte, index) => index === 0 ? byte ^ 1 : byte)
    }
    expect(verifyMethod2Sha256CompressionBlock(badBlock, proof)).toBe(false)

    const badOutput = {
      ...trace,
      expectedOutputState: trace.expectedOutputState.map((word, index) =>
        index === 0 ? ((word + 1) >>> 0) : word
      )
    }
    expect(verifyMethod2Sha256CompressionBlock(badOutput, proof)).toBe(false)
  })
})

function ascii (value: string): number[] {
  return Array.from(value).map(char => char.charCodeAt(0))
}
