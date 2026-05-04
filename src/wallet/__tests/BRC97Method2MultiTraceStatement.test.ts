import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  BRC97_METHOD2_MULTI_TRACE_STARK_OPTIONS,
  BRC97_SEGMENT_BUS_KIND_SOURCE,
  F,
  MultiTraceStarkProof,
  BRC97_PRODUCTION_SCALAR_LAYOUT,
  assertBRC97SegmentBusBalanced,
  brc97Method2MultiTraceDeterministicFixture,
  brc97Method2MultiTraceMetrics,
  brc97SegmentBusWrappedLayout,
  buildBRC97Method2LinkBridgeAir,
  evaluateAirTrace,
  proveStark,
  validateBRC97Method2MultiTracePublicInput,
  verifyStark,
  verifyBRC97Method2MultiTraceStatement,
  wrapBRC97SegmentBusTrace
} from '../brc97/index'

describe('BRC-97 Method 2 multi-trace statement', () => {
  it('builds production-shaped segment traces without verifier-facing secrets', () => {
    const statement = brc97Method2MultiTraceDeterministicFixture()
    const metrics = brc97Method2MultiTraceMetrics(statement)
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
    expect(statement.publicInput.preprocessedTableRoot).toHaveLength(32)
    expect(Object.values(statement.publicInput.bus.segments)
      .reduce((total, segment) => total + segment.emissionCount, 0))
      .toBeGreaterThan(0)
    expect(() => assertBRC97SegmentBusBalanced(statement.publicInput.bus))
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
    const statement = brc97Method2MultiTraceDeterministicFixture()
    const badInput = clonePublicInput(statement.publicInput)
    badInput.hmac.linkage[0] ^= 1

    expect(() => validateBRC97Method2MultiTracePublicInput(badInput))
      .toThrow('BRC97 Method 2 multi-trace linkage mismatch')
  })

  it('rejects tampered public segment-bus metadata', () => {
    const statement = brc97Method2MultiTraceDeterministicFixture()
    const badInput = clonePublicInput(statement.publicInput)
    badInput.bus.segments.hmac.publicEnd = { accumulator0: 1n, accumulator1: 0n }

    expect(() => validateBRC97Method2MultiTracePublicInput(badInput))
      .toThrow('bus public end mismatch')
  })

  it('proves sign-applied EC selected points inside the committed bridge', () => {
    const statement = brc97Method2MultiTraceDeterministicFixture()
    const air = buildBRC97Method2LinkBridgeAir(statement.bridgeTrace)
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
    const statement = brc97Method2MultiTraceDeterministicFixture()
    const segment = statement.busSegments.scalar
    const layout = brc97SegmentBusWrappedLayout(
      BRC97_PRODUCTION_SCALAR_LAYOUT.width,
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
    const wrapped = wrapBRC97SegmentBusTrace({
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
        kind: BRC97_SEGMENT_BUS_KIND_SOURCE,
        tag: 1n,
        values: current => [current[0]]
      }, {
        row: 0,
        kind: BRC97_SEGMENT_BUS_KIND_SOURCE,
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
    const wrapped = wrapBRC97SegmentBusTrace({
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
    const layout = brc97SegmentBusWrappedLayout(1, 0)

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
      transcriptDomain: 'BRC97_TEST_SEGMENT_BUS_NO_STEP_BRANCH',
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
    const statement = brc97Method2MultiTraceDeterministicFixture()
    const weakProof = {
      transcriptDomain: BRC97_METHOD2_MULTI_TRACE_STARK_OPTIONS.transcriptDomain,
      contextDigest: new Array(32).fill(0),
      segments: [
        'scalar',
        'lookup',
        'ec',
        'compression',
        'hmac',
        'bridge'
      ].map(name => ({
        name,
        proof: {
          blowupFactor:
            BRC97_METHOD2_MULTI_TRACE_STARK_OPTIONS.blowupFactor,
          numQueries: 2,
          maxRemainderSize:
            BRC97_METHOD2_MULTI_TRACE_STARK_OPTIONS.maxRemainderSize,
          maskDegree: BRC97_METHOD2_MULTI_TRACE_STARK_OPTIONS.maskDegree,
          cosetOffset: BRC97_METHOD2_MULTI_TRACE_STARK_OPTIONS.cosetOffset
        }
      }))
    } as unknown as MultiTraceStarkProof

    expect(verifyBRC97Method2MultiTraceStatement(
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
