import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS,
  BRC69_SEGMENT_BUS_KIND_SOURCE,
  BRC69_PRODUCTION_SCALAR_LAYOUT,
  assertBRC69SegmentBusBalanced,
  brc69Method2WholeStatementDeterministicFixture,
  brc69Method2WholeStatementMetrics,
  brc69SegmentBusWrappedLayout,
  buildBRC69Method2LinkBridgeAir,
  validateBRC69Method2WholeStatementPublicInput,
  verifyBRC69Method2WholeStatement,
  wrapBRC69SegmentBusTrace
} from '../brc69/method2/index'
import {
  F,
  MultiTraceStarkProof,
  evaluateAirTrace,
  proveStark,
  verifyStark
} from '../brc69/stark/index'

describe('BRC-69 Method 2 whole-statement proof', () => {
  it('builds production-shaped segment traces without verifier-facing secrets', () => {
    const statement = brc69Method2WholeStatementDeterministicFixture()
    const metrics = brc69Method2WholeStatementMetrics(statement)
    const publicInput = statement.publicInput as unknown as Record<string, unknown>

    expect(Object.keys(metrics.segments).sort()).toEqual([
      'bridge',
      'compression',
      'ec',
      'hmac',
      'lookup',
      'scalar'
    ])
    expect(metrics.totalCommittedCells).toBe(
      Object.values(metrics.segments)
        .reduce((total, segment) => total + segment.committedCells, 0)
    )
    expect(metrics.segments.lookup.rows).toBe(32768)
    expect(metrics.segments.ec.rows).toBe(32768)
    expect(metrics.segments.hmac.rows).toBe(32768)
    expect(Object.values(metrics.segments)
      .every(segment => segment.rows === metrics.segments.lookup.rows))
      .toBe(true)
    expect(metrics.totalCommittedCells).toBeLessThan(50000000)
    expect(statement.wholeSegment.rows).toHaveLength(metrics.segments.lookup.rows)
    expect(statement.wholeSegment.air.traceWidth).toBe(
      Object.values(metrics.segments)
        .reduce((total, segment) => total + segment.width, 0)
    )
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

  it('makes bus emissions depend on committed selector columns', () => {
    const statement = brc69Method2WholeStatementDeterministicFixture()
    const segment = statement.busSegments.scalar
    const layout = brc69SegmentBusWrappedLayout(
      BRC69_PRODUCTION_SCALAR_LAYOUT.width,
      statement.publicInput.bus.segments.scalar.selectorCount ??
        statement.publicInput.bus.segments.scalar.emissionCount
    )
    const current = segment.rows[0].slice()
    const next = segment.rows[1]

    expect(transitionIsZero(segment.air.evaluateTransition(
      current,
      next,
      0
    ))).toBe(true)

    current[layout.selectorStart] = 0n
    expect(transitionIsZero(segment.air.evaluateTransition(
      current,
      next,
      0
    ))).toBe(false)
  })

  it('shares one selector across multiple bus emissions on the same row', () => {
    const wrapped = wrapBRC69SegmentBusTrace({
      name: 'selector-sharing-regression',
      air: {
        traceWidth: 2,
        boundaryConstraints: [],
        evaluateTransition: () => []
      },
      rows: [
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
      challengeDigest: ascii('selector-sharing-regression')
    })

    expect(wrapped.selectorCount).toBe(1)
    expect(wrapped.contribution.emissionCount).toBe(2)
    expect(evaluateAirTrace(wrapped.air, wrapped.rows).valid).toBe(true)
  })

  it('gates padded base transitions with a committed selector column', () => {
    const wrapped = wrapBRC69SegmentBusTrace({
      name: 'base-transition-selector-regression',
      air: {
        traceWidth: 1,
        transitionDegree: 1,
        boundaryConstraints: [],
        evaluateTransition: (current, next) => [
          F.sub(F.sub(next[0], current[0]), 1n)
        ]
      },
      rows: [
        [1n],
        [2n],
        [3n],
        [4n]
      ],
      proofTraceLength: 8,
      emissions: [],
      challengeDigest: ascii('base-transition-selector-regression')
    })
    const layout = brc69SegmentBusWrappedLayout(1, 0)

    expect(wrapped.rows.map(row => row[layout.baseTransitionActive]))
      .toEqual([1n, 1n, 1n, 0n, 0n, 0n, 0n, 0n])
    expect(evaluateAirTrace(wrapped.air, wrapped.rows).valid).toBe(true)

    const tampered = wrapped.rows.map(row => row.slice())
    tampered[3][layout.baseTransitionActive] = 1n
    expect(evaluateAirTrace(wrapped.air, tampered).valid).toBe(false)

    const proverOptions = {
      blowupFactor: 4,
      numQueries: 4,
      maxRemainderSize: 4,
      maskDegree: 1,
      cosetOffset: 7n,
      transcriptDomain: 'BRC69_TEST_SEGMENT_BUS_NO_STEP_BRANCH',
      maskSeed: ascii('base-transition-selector-regression-mask')
    }
    const verifierOptions = {
      blowupFactor: proverOptions.blowupFactor,
      numQueries: proverOptions.numQueries,
      maxRemainderSize: proverOptions.maxRemainderSize,
      maskDegree: proverOptions.maskDegree,
      cosetOffset: proverOptions.cosetOffset,
      transcriptDomain: proverOptions.transcriptDomain
    }
    const proof = proveStark(wrapped.air, wrapped.rows, proverOptions)
    expect(verifyStark(wrapped.air, proof, verifierOptions)).toBe(true)
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
})

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

function ascii (value: string): number[] {
  return Array.from(value).map(char => char.charCodeAt(0))
}
