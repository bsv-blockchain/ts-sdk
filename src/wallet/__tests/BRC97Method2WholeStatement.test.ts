import {
  beforeAll,
  describe,
  expect,
  it
} from '@jest/globals'
import {
  BRC97_METHOD2_MULTI_TRACE_STARK_OPTIONS,
  BRC97_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS,
  F,
  METHOD2_COMPACT_HMAC_SHA256_LAYOUT,
  SECP256K1_N,
  MultiTraceStarkProof,
  StarkProof,
  buildBRC97Method2ProductionStatement,
  buildBRC97Method2WholeStatementAir,
  buildBRC97Method2WholeStatementTrace,
  brc97Method2WholeStatementMetrics,
  brc97Method2WholeStatementPublicInputDigest,
  compressPoint,
  hmacSha256,
  scalarMultiply,
  verifyBRC97Method2ProductionStatement,
  verifyBRC97Method2WholeStatement
} from '../brc97/index'

describe('BRC-97 Method 2 whole-statement AIR', () => {
  let fixture: ReturnType<typeof buildBRC97Method2WholeStatementTrace>

  beforeAll(() => {
    fixture = buildFixture()
  })

  it('builds one unified committed trace without verifier-facing private values', () => {
    const trace = fixture
    const metrics = brc97Method2WholeStatementMetrics(trace)
    const publicInput = trace.publicInput as unknown as Record<string, unknown>
    const occupiedRows = [
      trace.publicInput.regions.scalar,
      trace.publicInput.regions.lookup,
      trace.publicInput.regions.bridge,
      trace.publicInput.regions.ec,
      trace.publicInput.regions.compression,
      trace.publicInput.regions.hmac
    ]
      .reduce((total, region) => total + region.length, 0)

    expect(metrics.activeRows).toBe(occupiedRows)
    expect(metrics.paddedRows).toBe(65536)
    expect(metrics.traceWidth).toBeLessThan(2000)
    expect(publicInput.scalar as Record<string, unknown>)
      .not.toHaveProperty('scalar')
    expect(publicInput.lookup as Record<string, unknown>)
      .not.toHaveProperty('scalar')
    expect(publicInput.lookup as Record<string, unknown>)
      .not.toHaveProperty('digits')
    expect(publicInput.lookup as Record<string, unknown>)
      .not.toHaveProperty('selectedIndexes')
    expect(publicInput.ec as Record<string, unknown>)
      .not.toHaveProperty('privateS')
    expect(publicInput.compression as Record<string, unknown>)
      .not.toHaveProperty('point')
    expect(publicInput.hmac as Record<string, unknown>)
      .not.toHaveProperty('key')
    expect(publicInput).not.toHaveProperty('equalitySchedule')
  })

  it('uses the single-trace AIR for the production-facing Method 2 API', () => {
    const scalar = SECP256K1_N - 123456789n
    const baseB = scalarMultiply(7n)
    const invoice = ascii('production api invoice')
    const trace = buildBRC97Method2ProductionStatement({
      scalar,
      baseB,
      invoice
    })
    const weakProof = {
      transcriptDomain:
        BRC97_METHOD2_MULTI_TRACE_STARK_OPTIONS.transcriptDomain,
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
      })),
      crossProofs: [],
      constantColumnProofs: []
    } as unknown as MultiTraceStarkProof

    expect(trace.publicInput).toHaveProperty('bus')
    expect(trace.publicInput).not.toHaveProperty('regions')
    expect(verifyBRC97Method2ProductionStatement(trace.publicInput, weakProof))
      .toBe(false)
  })

  it('evaluates representative cross-segment transitions as zero', () => {
    const trace = fixture
    const air = buildBRC97Method2WholeStatementAir(trace)
    const rowsToCheck = [
      trace.publicInput.regions.scalar.start,
      trace.publicInput.regions.lookup.start,
      trace.publicInput.regions.lookup.start + 23584,
      trace.publicInput.regions.bridge.start,
      trace.publicInput.regions.ec.start,
      trace.publicInput.regions.compression.start,
      trace.publicInput.regions.compression.start + 256,
      trace.publicInput.regions.hmac.start
    ]

    for (const row of rowsToCheck) {
      expect(transitionIsZero(air.evaluateTransition(
        trace.rows[row],
        trace.rows[row + 1],
        row
      ))).toBe(true)
    }
  })

  it('rejects non-committed key-byte swaps through the in-trace bus binding', () => {
    const trace = fixture
    const air = buildBRC97Method2WholeStatementAir(trace)
    const hmacStart = trace.publicInput.regions.hmac.start
    const tampered = trace.rows.map(row => row.slice())

    tampered[hmacStart][
      trace.layout.hmac + METHOD2_COMPACT_HMAC_SHA256_LAYOUT.keyBytes
    ] = F.add(
      tampered[hmacStart][
        trace.layout.hmac + METHOD2_COMPACT_HMAC_SHA256_LAYOUT.keyBytes
      ],
      1n
    )

    expect(transitionIsZero(air.evaluateTransition(
      tampered[hmacStart],
      tampered[hmacStart + 1],
      hmacStart
    ))).toBe(false)
  })

  it('binds verifier public input to deterministic table/profile metadata', () => {
    const trace = fixture
    const badPublicInput = clonePublicInput(trace.publicInput)
    badPublicInput.lookup.scheduleRows[0].publicTuple[3] = F.add(
      badPublicInput.lookup.scheduleRows[0].publicTuple[3],
      1n
    )

    expect(() => buildBRC97Method2WholeStatementAir(badPublicInput))
      .toThrow('lookup table does not match public B')
    expect(brc97Method2WholeStatementPublicInputDigest(trace.publicInput))
      .toHaveLength(32)
  })

  it('fails closed for reduced proof parameters before verification', () => {
    const trace = fixture
    const weakProof = {
      blowupFactor: BRC97_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.blowupFactor,
      numQueries: 2,
      maxRemainderSize:
        BRC97_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maxRemainderSize,
      maskDegree: BRC97_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maskDegree,
      cosetOffset: BRC97_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.cosetOffset,
      publicInputDigest: brc97Method2WholeStatementPublicInputDigest(
        trace.publicInput
      )
    } as unknown as StarkProof

    expect(verifyBRC97Method2WholeStatement(trace.publicInput, weakProof))
      .toBe(false)
  })
})

function buildFixture (): ReturnType<typeof buildBRC97Method2WholeStatementTrace> {
  const scalar = SECP256K1_N - 123456789n
  const baseB = scalarMultiply(7n)
  const invoice = ascii('whole statement invoice')
  const privateS = scalarMultiply(scalar, baseB)
  const linkage = hmacSha256(compressPoint(privateS), invoice)
  return buildBRC97Method2WholeStatementTrace({
    scalar,
    baseB,
    invoice,
    linkage
  })
}

function transitionIsZero (values: bigint[]): boolean {
  return values.every(value => F.normalize(value) === 0n)
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

function ascii (value: string): number[] {
  return Array.from(value).map(char => char.charCodeAt(0))
}
