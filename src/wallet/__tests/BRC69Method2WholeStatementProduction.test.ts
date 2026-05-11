import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS,
  BRC69_SEGMENT_BUS_KIND_SOURCE,
  assertBRC69SegmentBusBalanced,
  brc69SegmentBusChallengeInputFromRoot,
  brc69SegmentBusNonAdaptiveCollisionSecurityBits,
  brc69Method2WholeStatementDeterministicFixture,
  brc69Method2WholeStatementMetrics,
  brc69SegmentBusWrappedLayout,
  buildBRC69SegmentBusAccumulatorTrace,
  buildBRC69Method2LinkBridgeAir,
  diagnoseBRC69Method2WholeStatement,
  deriveBRC69SegmentBusChallenges,
  validateBRC69Method2WholeStatementPublicInput,
  verifyBRC69Method2WholeStatement
} from '../brc69/method2/index'
import {
  F,
  lookupBusNonAdaptiveCollisionSecurityBits,
  MultiTraceStarkProof,
  evaluateAirTrace
} from '../brc69/stark/index'

describe('BRC-69 Method 2 whole-statement proof', () => {
  it('builds production-shaped segment traces without verifier-facing secrets', () => {
    const statement = brc69Method2WholeStatementDeterministicFixture()
    const metrics = brc69Method2WholeStatementMetrics(statement)
    const publicInput = statement.publicInput as unknown as Record<string, unknown>

    expect(Object.keys(metrics.segments).sort()).toEqual(['base', 'bus'])
    expect(metrics.totalCommittedCells).toBe(
      Object.values(metrics.segments)
        .reduce((total, segment) => total + segment.committedCells, 0)
    )
    expect(metrics.segments.base.rows).toBe(32768)
    expect(metrics.segments.bus.rows).toBe(32768)
    expect(Object.values(metrics.segments)
      .every(segment => segment.rows === metrics.segments.base.rows))
      .toBe(true)
    expect(metrics.totalCommittedCells).toBeLessThan(60000000)
    expect(statement.baseSegment.rows).toHaveLength(metrics.segments.base.rows)
    expect(statement.baseSegment.air.traceWidth)
      .toBe(metrics.segments.base.width)
    expect(statement.publicInput.preprocessedTableRoot).toHaveLength(32)
    expect(Object.values(statement.publicInput.bus.segments)
      .reduce((total, segment) => total + segment.emissionCount, 0))
      .toBeGreaterThan(0)
    expect(() => assertBRC69SegmentBusBalanced(statement.publicInput.bus))
      .not.toThrow()
    expect(statement.publicInput.bus.segments.scalar.publicStart)
      .toEqual({ accumulator0: 0n, accumulator1: 0n })
    expect(statement.publicInput.bus.segments.hmac.publicEnd)
      .toEqual({ accumulator0: 0n, accumulator1: 0n })
    expect(statement.publicInput.bus.segments.ec)
      .not.toHaveProperty('accumulator0')
    expect(publicInput).not.toHaveProperty('scalarHex')
    expect(publicInput).not.toHaveProperty('privateS')
    expect(publicInput).not.toHaveProperty('compressedS')
    expect(publicInput).not.toHaveProperty('key')
    expect(publicInput).not.toHaveProperty('privateBusTuples')
    expect(publicInput.scalar as Record<string, unknown>)
      .not.toHaveProperty('scalar')
    expect(publicInput.lookup as Record<string, unknown>)
      .not.toHaveProperty('selectedIndexes')
    expect(publicInput.ec as Record<string, unknown>)
      .not.toHaveProperty('privateS')
    expect(publicInput.compression as Record<string, unknown>)
      .not.toHaveProperty('point')
    expect(publicInput.hmac as Record<string, unknown>)
      .not.toHaveProperty('key')
  })

  it('rejects public input mismatches before STARK verification', () => {
    const statement = brc69Method2WholeStatementDeterministicFixture()
    const badInput = clonePublicInput(statement.publicInput)
    badInput.hmac.linkage[0] ^= 1

    expect(() => validateBRC69Method2WholeStatementPublicInput(badInput))
      .toThrow('BRC69 Method 2 multi-trace linkage mismatch')
  })

  it('rejects tampered public segment-bus metadata', () => {
    const statement = brc69Method2WholeStatementDeterministicFixture()
    const badInput = clonePublicInput(statement.publicInput)
    badInput.bus.segments.hmac.publicEnd = { accumulator0: 1n, accumulator1: 0n }

    expect(() => validateBRC69Method2WholeStatementPublicInput(badInput))
      .toThrow('bus public end mismatch')
  })

  it('proves sign-applied EC selected points inside the committed bridge', () => {
    const statement = brc69Method2WholeStatementDeterministicFixture()
    const air = buildBRC69Method2LinkBridgeAir(statement.bridgeTrace)
    const rowIndex = statement.bridgeTrace.rows.findIndex(row =>
      row[statement.bridgeTrace.layout.active] === 1n &&
      row[statement.bridgeTrace.layout.isZero] === 0n
    )
    expect(rowIndex).toBeGreaterThanOrEqual(0)
    expect(transitionIsZero(air.evaluateTransition(
      statement.bridgeTrace.rows[rowIndex],
      statement.bridgeTrace.rows[rowIndex + 1],
      rowIndex
    ))).toBe(true)

    const tampered = statement.bridgeTrace.rows[rowIndex].slice()
    tampered[statement.bridgeTrace.layout.selectedGX] = F.add(
      tampered[statement.bridgeTrace.layout.selectedGX],
      1n
    )
    expect(transitionIsZero(air.evaluateTransition(
      tampered,
      statement.bridgeTrace.rows[rowIndex + 1],
      rowIndex
    ))).toBe(false)
  })

  it('shares one selector across multiple bus emissions on the same row', () => {
    const challengeInput = brc69SegmentBusChallengeInputFromRoot(
      new Array(32).fill(1),
      new Array(32).fill(2),
      'BRC69_TEST_SEGMENT_BUS_SELECTOR_SHARING'
    )
    const wrapped = buildBRC69SegmentBusAccumulatorTrace({
      name: 'selector-sharing-regression',
      baseRows: [
        [5n, 8n],
        [13n, 21n],
        [0n, 0n],
        [0n, 0n]
      ],
      emissions: [{
        row: 0,
        kind: BRC69_SEGMENT_BUS_KIND_SOURCE,
        tag: 1n,
        values: current => [current[0]]
      }, {
        row: 0,
        kind: BRC69_SEGMENT_BUS_KIND_SOURCE,
        tag: 2n,
        values: current => [current[1]]
      }],
      challenges: deriveBRC69SegmentBusChallenges(challengeInput)
    })

    expect(wrapped.selectorCount).toBe(1)
    expect(wrapped.contribution.emissionCount).toBe(2)
    expect(evaluateAirTrace(wrapped.air, wrapped.rows).valid).toBe(true)
    const layout = brc69SegmentBusWrappedLayout(0, wrapped.selectorCount)
    const tampered = wrapped.rows.map(row => row.slice())
    tampered[0][layout.selectorStart] = 0n
    expect(evaluateAirTrace(wrapped.air, tampered).valid).toBe(false)
  })

  it('fails closed for weak proof parameters', () => {
    const statement = brc69Method2WholeStatementDeterministicFixture()
    const weakProof = {
      transcriptDomain: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.transcriptDomain,
      contextDigest: new Array(32).fill(0),
      segments: [{
        name: 'whole',
        proof: {
          blowupFactor:
            BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.blowupFactor,
          numQueries: 2,
          maxRemainderSize:
            BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maxRemainderSize,
          maskDegree: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maskDegree,
          cosetOffset: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.cosetOffset
        }
      }],
      crossProofs: [],
      constantColumnProofs: []
    } as unknown as MultiTraceStarkProof

    expect(verifyBRC69Method2WholeStatement(
      statement.publicInput,
      weakProof
    )).toBe(false)
  })

  it('rejects proof type 1 degree bounds that do not match the verifier profile', () => {
    const statement = brc69Method2WholeStatementDeterministicFixture()
    const badProof = {
      transcriptDomain: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.transcriptDomain,
      contextDigest: new Array(32).fill(0),
      segments: [
        {
          name: 'base',
          proof: {
            ...dummyStarkSegment(
              statement.busProofTraceLength,
              statement.baseSegment.air.traceWidth
            ),
            traceDegreeBound: statement.busProofTraceLength +
              BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maskDegree + 1
          }
        },
        {
          name: 'bus',
          proof: dummyStarkSegment(statement.busProofTraceLength, 1)
        }
      ],
      crossProofs: [{}, {}],
      constantColumnProofs: []
    } as unknown as MultiTraceStarkProof

    const diagnostic = diagnoseBRC69Method2WholeStatement(
      statement.publicInput,
      badProof
    )
    expect(diagnostic).toMatchObject({
      ok: false,
      stage: 'proof-shape',
      detail: 'proof metadata does not match verifier-derived BRC69 Method 2 profile'
    })
    expect(verifyBRC69Method2WholeStatement(
      statement.publicInput,
      badProof
    )).toBe(false)
  })

  it('documents base-field bus compression collision estimates', () => {
    expect(brc69SegmentBusNonAdaptiveCollisionSecurityBits())
      .toBeGreaterThan(118)
    expect(lookupBusNonAdaptiveCollisionSecurityBits())
      .toBeGreaterThan(118)
  })
})

function dummyStarkSegment (
  traceLength: number,
  traceWidth: number
): Record<string, unknown> {
  return {
    traceLength,
    traceWidth,
    blowupFactor: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.blowupFactor,
    numQueries: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.numQueries,
    maxRemainderSize:
      BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maxRemainderSize,
    maskDegree: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maskDegree,
    traceDegreeBound: traceLength +
      BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maskDegree,
    compositionDegreeBound: traceLength + 1,
    cosetOffset: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.cosetOffset,
    publicInputDigest: new Array(32).fill(0),
    traceRoot: new Array(32).fill(0)
  }
}

function clonePublicInput<T> (value: T): T {
  return JSON.parse(JSON.stringify(value, (_, entry) =>
    typeof entry === 'bigint' ? `${entry}n` : entry
  ), (_, entry) => {
    if (
      typeof entry === 'string' &&
      /^-?\d+n$/.test(entry)
    ) {
      return BigInt(entry.slice(0, -1))
    }
    return entry
  })
}

function transitionIsZero (values: bigint[]): boolean {
  return values.every(value => F.normalize(value) === 0n)
}
