import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  buildDualBaseAccumulationTrace,
  buildDualBaseLookupPrototype,
  dualBaseAccumulationMetrics,
  pointAdd,
  proveDualBaseAccumulation,
  scalarMultiply,
  validateDualBaseAccumulationTrace,
  verifyDualBaseAccumulation
} from '../brc97/index'

describe('BRC-97 dual-base EC accumulation prototype', () => {
  it('accumulates selected lookup point pairs into A and hidden S', () => {
    const scalar = 0x1f8n
    const baseB = scalarMultiply(7n)
    const lookup = buildDualBaseLookupPrototype(
      scalar,
      baseB,
      { windowBits: 4, windowCount: 4, minTraceLength: 128 }
    )
    const trace = buildDualBaseAccumulationTrace(lookup)

    expect(trace.finalG).toEqual(scalarMultiply(scalar))
    expect(trace.finalB).toEqual(scalarMultiply(scalar, baseB))
    expect(dualBaseAccumulationMetrics(trace)).toMatchObject({
      steps: 4,
      selectedRows: 4,
      gDistinctAdds: 1,
      bDistinctAdds: 1,
      selectedInfinityBranches: 4,
      accumulatorInfinityBranches: 2,
      oppositeBranches: 0,
      affineAddProofs: 2,
      totalFieldLinearProofs: 12,
      totalFieldMulProofs: 8
    })
  })

  it('proves distinct add rows in the dual accumulation trace', () => {
    const scalar = 0x1f8n
    const baseB = scalarMultiply(7n)
    const lookup = buildDualBaseLookupPrototype(
      scalar,
      baseB,
      { windowBits: 4, windowCount: 4, minTraceLength: 128 }
    )
    const trace = buildDualBaseAccumulationTrace(lookup)
    const proof = proveDualBaseAccumulation(trace, {
      numQueries: 2,
      maskSeed: ascii('dual-base-accumulation-mask')
    })

    expect(verifyDualBaseAccumulation(trace, proof)).toBe(true)
    expect(dualBaseAccumulationMetrics(trace, proof)).toMatchObject({
      affineAddProofs: 2,
      totalFieldLinearProofs: 12,
      totalFieldMulProofs: 8
    })
    expect(dualBaseAccumulationMetrics(trace, proof).totalProofBytes)
      .toBeGreaterThan(0)
  })

  it('rejects tampered accumulation rows', () => {
    const scalar = 0x1f8n
    const baseB = scalarMultiply(7n)
    const lookup = buildDualBaseLookupPrototype(
      scalar,
      baseB,
      { windowBits: 4, windowCount: 4, minTraceLength: 128 }
    )
    const trace = buildDualBaseAccumulationTrace(lookup)
    const tampered = {
      ...trace,
      steps: trace.steps.map(step => ({
        ...step,
        g: { ...step.g },
        b: { ...step.b }
      }))
    }
    tampered.steps[2].g.after = pointAdd(
      tampered.steps[2].g.after,
      scalarMultiply(3n)
    )

    expect(() => validateDualBaseAccumulationTrace(tampered)).toThrow()
  })
})

function ascii (value: string): number[] {
  return Array.from(value).map(char => char.charCodeAt(0))
}
