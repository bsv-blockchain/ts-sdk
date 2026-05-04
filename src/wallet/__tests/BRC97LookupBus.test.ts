import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  F,
  LOOKUP_BUS_LAYOUT,
  LOOKUP_BUS_TRANSCRIPT_DOMAIN,
  LOOKUP_BUS_PROTOTYPE_STARK_OPTIONS,
  LOOKUP_BUS_ROW_KIND,
  LOOKUP_BUS_TAG_PRIVATE_EQUALITY,
  LOOKUP_BUS_TAG_PUBLIC_EQUALITY,
  LookupBusPublicInput,
  buildLookupBusAir,
  buildLookupBusRange16Table,
  buildLookupBusTrace,
  buildLookupBusToyPointPairTable,
  evaluateAirTrace,
  lookupBusFixedTableItems,
  lookupBusLookupRequestItems,
  lookupBusMetrics,
  proveLookupBus,
  serializeStarkProof,
  verifyStark,
  verifyLookupBusProof
} from '../brc97/stark/index'

describe('BRC-97 lookup/equality bus prototype', () => {
  it('proves fixed-table membership in the range16 table', () => {
    const table = buildLookupBusRange16Table()
    const trace = buildLookupBusTrace([
      ...lookupBusFixedTableItems(table, { 7: 1 }),
      ...lookupBusLookupRequestItems(table, [7])
    ], { minTraceLength: 32 })
    const proof = proveLookupBus(trace, {
      maskSeed: ascii('lookup-bus-range16-mask')
    })

    expect(verifyLookupBusProof(trace.publicInput, proof)).toBe(true)
    expect(lookupBusMetrics(trace, proof)).toMatchObject({
      activeRows: 17,
      paddedRows: 32,
      traceWidth: LOOKUP_BUS_LAYOUT.width,
      fixedTableRows: 16,
      lookupRequests: 1,
      lookupSupplies: 1,
      fixedLookups: 1,
      equalityRows: 0
    })
    expect(serializeStarkProof(proof).length).toBeGreaterThan(0)
  })

  it('proves private equality, public equality, and several lookup tags together', () => {
    const rangeTable = buildLookupBusRange16Table()
    const pointTable = buildLookupBusToyPointPairTable(2, 4)
    const publicValues = [77n, 88n]
    const trace = buildLookupBusTrace([
      ...lookupBusFixedTableItems(rangeTable, { 3: 1, 12: 2 }),
      ...lookupBusFixedTableItems(pointTable, { 5: 1 }),
      ...lookupBusLookupRequestItems(rangeTable, [3, 12, 12]),
      ...lookupBusLookupRequestItems(pointTable, [5]),
      {
        kind: LOOKUP_BUS_ROW_KIND.privateEquality,
        tag: LOOKUP_BUS_TAG_PRIVATE_EQUALITY,
        leftValues: [101n, 202n, 303n],
        rightValues: [101n, 202n, 303n],
        multiplicity: 1
      },
      {
        kind: LOOKUP_BUS_ROW_KIND.publicEquality,
        tag: LOOKUP_BUS_TAG_PUBLIC_EQUALITY,
        leftValues: publicValues,
        rightValues: publicValues,
        publicValues,
        multiplicity: 1
      }
    ], { minTraceLength: 32 })
    const proof = proveLookupBus(trace, {
      maskSeed: ascii('lookup-bus-mixed-mask')
    })

    expect(verifyLookupBusProof(trace.publicInput, proof)).toBe(true)
    expect(lookupBusMetrics(trace, proof)).toMatchObject({
      lookupRequests: 4,
      lookupSupplies: 4,
      fixedLookups: 4,
      equalityRows: 2
    })
  })

  it('rejects malformed requests, wrong multiplicity, and swapped tuple fields', () => {
    const table = buildLookupBusRange16Table()
    const unmatchedRequest = buildLookupBusTrace([
      ...lookupBusFixedTableItems(table, { 4: 1 }),
      ...lookupBusLookupRequestItems(table, [5])
    ], { minTraceLength: 32 })
    expect(evaluateAirTrace(
      buildLookupBusAir(unmatchedRequest.publicInput),
      unmatchedRequest.rows
    ).valid).toBe(false)

    const wrongMultiplicity = buildLookupBusTrace(
      [
        ...lookupBusFixedTableItems(table, { 4: 1 }),
        ...lookupBusLookupRequestItems(table, [4, 4])
      ],
      { minTraceLength: 32 }
    )
    expect(evaluateAirTrace(
      buildLookupBusAir(wrongMultiplicity.publicInput),
      wrongMultiplicity.rows
    ).valid).toBe(false)

    const swapped = buildLookupBusTrace([{
      kind: LOOKUP_BUS_ROW_KIND.privateEquality,
      tag: LOOKUP_BUS_TAG_PRIVATE_EQUALITY,
      leftValues: [5n, 9n],
      rightValues: [9n, 5n],
      multiplicity: 1
    }])
    expect(evaluateAirTrace(
      buildLookupBusAir(swapped.publicInput),
      swapped.rows
    ).valid).toBe(false)
  })

  it('rejects proofs verified against a wrong tag or weaker STARK parameters', () => {
    const table = buildLookupBusRange16Table()
    const trace = buildLookupBusTrace([
      ...lookupBusFixedTableItems(table, { 2: 1 }),
      ...lookupBusLookupRequestItems(table, [2])
    ],
    { minTraceLength: 32 }
    )
    const proof = proveLookupBus(trace, {
      maskSeed: ascii('lookup-bus-strict-mask')
    })
    const wrongTag = clonePublicInput(trace.publicInput)
    wrongTag.scheduleRows[2] = {
      ...wrongTag.scheduleRows[2],
      tag: F.add(wrongTag.scheduleRows[2].tag, 1n)
    }

    expect(verifyLookupBusProof(wrongTag, proof)).toBe(false)

    const weakProof = proveLookupBus(trace, {
      ...LOOKUP_BUS_PROTOTYPE_STARK_OPTIONS,
      numQueries: 2,
      maskSeed: ascii('lookup-bus-weak-mask')
    })
    expect(verifyLookupBusProof(trace.publicInput, weakProof)).toBe(false)
  })

  it('verifies a lookup proof with production STARK parameters', () => {
    const table = buildLookupBusRange16Table()
    const trace = buildLookupBusTrace([
      ...lookupBusFixedTableItems(table, { 7: 1 }),
      ...lookupBusLookupRequestItems(table, [7])
    ],
    { minTraceLength: 32 }
    )
    const air = buildLookupBusAir(trace.publicInput)
    const proof = proveLookupBus(trace, {
      blowupFactor: 16,
      numQueries: 48,
      maxRemainderSize: 16,
      maskDegree: 2,
      cosetOffset: 7n,
      maskSeed: ascii('lookup-bus-production-mask')
    })

    expect(proof.compositionDegreeBound).toBeGreaterThan(332)
    expect(verifyStark(air, proof, {
      blowupFactor: 16,
      numQueries: 48,
      maxRemainderSize: 16,
      maskDegree: 2,
      cosetOffset: 7n,
      publicInputDigest: air.publicInputDigest,
      transcriptDomain: LOOKUP_BUS_TRANSCRIPT_DOMAIN
    })).toBe(true)
  })
})

function clonePublicInput (
  publicInput: LookupBusPublicInput
): LookupBusPublicInput {
  return {
    traceLength: publicInput.traceLength,
    expectedLookupRequests: publicInput.expectedLookupRequests,
    scheduleRows: publicInput.scheduleRows.map(row => ({
      kind: row.kind,
      tag: row.tag,
      publicTuple: row.publicTuple.slice()
    }))
  }
}

function ascii (value: string): number[] {
  return Array.from(value).map(char => char.charCodeAt(0))
}
