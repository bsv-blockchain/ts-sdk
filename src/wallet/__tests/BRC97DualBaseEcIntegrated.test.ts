import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  buildDualBaseEcIntegratedTrace,
  buildDualBaseLookupPrototype,
  compressPoint,
  dualBaseCompressedSForHmac,
  dualBaseEcIntegratedMetrics,
  hmacSha256,
  nibblesToBytes,
  proveDualBaseEcIntegrated,
  scalarMultiply,
  validateDualBaseCompressedPointWitness,
  validateDualBaseEcIntegratedTrace,
  verifyDualBaseEcIntegrated
} from '../brc97/index'

describe('BRC-97 integrated dual-base EC prototype', () => {
  it('builds compact EC rows and compressed private S for HMAC', () => {
    const scalar = 0x1f8n
    const baseB = scalarMultiply(7n)
    const lookup = buildDualBaseLookupPrototype(
      scalar,
      baseB,
      { windowBits: 4, windowCount: 4, minTraceLength: 128 }
    )
    const trace = buildDualBaseEcIntegratedTrace(lookup)
    const expectedS = scalarMultiply(scalar, baseB)

    expect(trace.rows).toHaveLength(4)
    expect(trace.rows[0].gBranchSelectors.accumulatorInfinity).toBe(1)
    expect(trace.rows[1].gBranchSelectors.selectedInfinity).toBe(1)
    expect(trace.rows[2].gBranchSelectors.distinctAdd).toBe(1)
    expect(trace.rows[1].bBranchSelectors.selectedInfinity).toBe(1)
    expect(trace.publicA).toEqual(scalarMultiply(scalar))
    expect(trace.privateS).toEqual(expectedS)
    expect(trace.compressedS.bytes).toEqual(compressPoint(expectedS))
    expect(trace.compressedS.xBytes).toHaveLength(32)
    expect(trace.compressedS.nibbles).toHaveLength(66)
    expect(nibblesToBytes(trace.compressedS.nibbles))
      .toEqual(trace.compressedS.bytes)
    expect(dualBaseCompressedSForHmac(trace)).toEqual(trace.compressedS.bytes)
    expect(hmacSha256(
      dualBaseCompressedSForHmac(trace),
      ascii('invoice')
    )).toHaveLength(32)
  })

  it('proves lookup membership and distinct EC add rows as one integrated bundle', () => {
    const scalar = 0x1f8n
    const baseB = scalarMultiply(7n)
    const lookup = buildDualBaseLookupPrototype(
      scalar,
      baseB,
      { windowBits: 4, windowCount: 4, minTraceLength: 128 }
    )
    const trace = buildDualBaseEcIntegratedTrace(lookup)
    const proof = proveDualBaseEcIntegrated(trace, {
      maskSeed: ascii('dual-base-ec-integrated-mask')
    })

    expect(verifyDualBaseEcIntegrated(trace, proof)).toBe(true)
    expect(dualBaseEcIntegratedMetrics(trace, proof)).toMatchObject({
      rows: 4,
      committedEcRows: 4,
      compressedSBytes: 33,
      compressedSNibbles: 66,
      branchSelectorColumns: 8
    })
    expect(dualBaseEcIntegratedMetrics(trace, proof).lookup.proofBytes)
      .toBeGreaterThan(0)
    expect(dualBaseEcIntegratedMetrics(trace, proof).accumulation.totalProofBytes)
      .toBeGreaterThan(0)
    expect(dualBaseEcIntegratedMetrics(trace, proof).totalProofBytes)
      .toBeGreaterThan(0)
  })

  it('rejects tampered public A and compressed S witnesses', () => {
    const scalar = 0x1f8n
    const baseB = scalarMultiply(7n)
    const lookup = buildDualBaseLookupPrototype(
      scalar,
      baseB,
      { windowBits: 4, windowCount: 4, minTraceLength: 128 }
    )
    const trace = buildDualBaseEcIntegratedTrace(lookup)
    const badPublicA = {
      ...trace,
      publicA: scalarMultiply(3n)
    }
    expect(() => validateDualBaseEcIntegratedTrace(badPublicA)).toThrow()

    const badCompressed = {
      ...trace.compressedS,
      bytes: trace.compressedS.bytes.map((byte, index) =>
        index === 1 ? byte ^ 1 : byte
      )
    }
    expect(() => validateDualBaseCompressedPointWitness(
      badCompressed,
      trace.privateS
    )).toThrow()

    const badSelector = {
      ...trace,
      rows: trace.rows.map(row => ({
        ...row,
        gBranchSelectors: { ...row.gBranchSelectors },
        bBranchSelectors: { ...row.bBranchSelectors }
      }))
    }
    badSelector.rows[0].gBranchSelectors.distinctAdd = 1
    expect(() => validateDualBaseEcIntegratedTrace(badSelector)).toThrow()
  })
})

function ascii (value: string): number[] {
  return Array.from(value).map(char => char.charCodeAt(0))
}
