import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  BRC97_PRODUCTION_BUS_TAG_HMAC_LINKAGE_BYTE,
  LOOKUP_BUS_LAYOUT,
  LOOKUP_BUS_TRANSCRIPT_DOMAIN,
  LookupBusPublicInput,
  SECP256K1_N,
  brc97ProductionBusMetrics,
  buildBRC97ProductionBusTrace,
  buildBRC97ProductionCompressionTrace,
  buildLookupBusAir,
  buildMethod2CompactHmacSha256Trace,
  buildProductionEcTrace,
  buildProductionRadix11EcTrace,
  buildProductionRadix11LookupPrototype,
  evaluateAirTrace,
  hmacSha256,
  productionEcTracePrivateS,
  proveBRC97ProductionBus,
  scalarMultiply,
  verifyBRC97ProductionBus,
  verifyStark
} from '../brc97/index'

describe('BRC-97 production lookup/equality bus', () => {
  it('proves current production links with the production STARK profile', () => {
    const fixture = buildFixture()
    const proof = proveBRC97ProductionBus(fixture.bus, {
      maskSeed: ascii('brc97-production-bus-mask')
    })
    const metrics = brc97ProductionBusMetrics(fixture.bus, proof)

    expect(verifyBRC97ProductionBus(fixture.bus.publicInput, proof)).toBe(true)
    expect(metrics).toMatchObject({
      activeRows: 163,
      paddedRows: 256,
      traceWidth: LOOKUP_BUS_LAYOUT.width,
      fixedTableRows: 0,
      lookupRequests: 0,
      equalityRows: 163,
      rowCountsByTag: {
        scalarDigit: 24,
        pointPairOutput: 24,
        ecSelectedGPoint: 24,
        ecSelectedBPoint: 24,
        ecFinalAPublic: 1,
        ecPrivateSPoint: 1,
        compressedSKeyByte: 33,
        hmacLinkageByte: 32
      }
    })
    expect(metrics.proofBytes).toBeGreaterThan(0)
  })

  it('rejects altered public boundary rows and reduced STARK parameters', () => {
    const fixture = buildFixture()
    const proof = proveBRC97ProductionBus(fixture.bus, {
      maskSeed: ascii('brc97-production-bus-boundary-mask')
    })
    const badPublicInput = clonePublicInput(fixture.bus.publicInput)
    const linkageRow = badPublicInput.scheduleRows.find(row =>
      row.tag === BRC97_PRODUCTION_BUS_TAG_HMAC_LINKAGE_BYTE
    )
    if (linkageRow === undefined) throw new Error('linkage row missing')
    linkageRow.publicTuple[1] += 1n

    expect(verifyBRC97ProductionBus(badPublicInput, proof)).toBe(false)

    const weakProof = proveBRC97ProductionBus(fixture.bus, {
      numQueries: 2,
      maskSeed: ascii('brc97-production-bus-weak-mask')
    })
    expect(verifyBRC97ProductionBus(fixture.bus.publicInput, weakProof))
      .toBe(false)
  })

  it('keeps private equality links in the AIR, independent of public rows', () => {
    const fixture = buildFixture()
    const tamperedRows = fixture.bus.trace.rows.map(row => row.slice())
    const keyRow = fixture.bus.publicInput.scheduleRows.findIndex(row =>
      row.tag !== BRC97_PRODUCTION_BUS_TAG_HMAC_LINKAGE_BYTE &&
      row.tag !== 0n
    )
    if (keyRow < 0) throw new Error('private equality row missing')
    tamperedRows[keyRow][LOOKUP_BUS_LAYOUT.right + 1] += 1n

    expect(evaluateAirTrace(
      buildLookupBusAir(fixture.bus.publicInput),
      tamperedRows
    ).valid).toBe(false)
  })

  it('can still be checked explicitly against its proof parameters', () => {
    const fixture = buildFixture()
    const proof = proveBRC97ProductionBus(fixture.bus, {
      maskSeed: ascii('brc97-production-bus-direct-mask')
    })
    const air = buildLookupBusAir(fixture.bus.publicInput)

    expect(verifyStark(air, proof, {
      blowupFactor: proof.blowupFactor,
      numQueries: proof.numQueries,
      maxRemainderSize: proof.maxRemainderSize,
      maskDegree: proof.maskDegree,
      cosetOffset: proof.cosetOffset,
      traceDegreeBound: proof.traceDegreeBound,
      compositionDegreeBound: proof.compositionDegreeBound,
      publicInputDigest: air.publicInputDigest,
      transcriptDomain: LOOKUP_BUS_TRANSCRIPT_DOMAIN
    })).toBe(true)
  })
})

function buildFixture (): ReturnType<typeof buildFixtureParts> {
  return buildFixtureParts()
}

function buildFixtureParts (): {
  bus: ReturnType<typeof buildBRC97ProductionBusTrace>
} {
  const scalar = SECP256K1_N - 123456789n
  const baseB = scalarMultiply(7n)
  const lookup = buildProductionRadix11LookupPrototype(scalar, baseB)
  const ec = buildProductionRadix11EcTrace(lookup)
  const productionEc = buildProductionEcTrace(ec)
  const compression = buildBRC97ProductionCompressionTrace(
    productionEcTracePrivateS(productionEc)
  )
  const invoice = ascii('production bus invoice')
  const linkage = hmacSha256(compression.compressedBytes, invoice)
  const hmac = buildMethod2CompactHmacSha256Trace(
    compression.compressedBytes,
    invoice,
    linkage
  )
  return {
    bus: buildBRC97ProductionBusTrace({
      lookup,
      compression,
      ec,
      productionEc,
      hmac
    })
  }
}

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
