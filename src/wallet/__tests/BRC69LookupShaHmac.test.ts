import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  buildMethod2LookupShaHmacTable,
  buildMethod2LookupShaHmacTrace,
  buildMethod2LookupBatchedHmacSha256Air,
  buildMethod2LookupBatchedHmacSha256Trace,
  buildMethod2CompactHmacSha256Air,
  buildMethod2CompactHmacSha256Trace,
  buildBRC69Method2WholeStatement,
  METHOD2_COMPACT_HMAC_SHA256_LAYOUT,
  METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT,
  method2LookupShaHmacIntegrationStatus,
  method2LookupShaHmacMetrics,
  method2LookupShaHmacPublicInputDigest,
  method2LookupShaHmacTableDigest,
  verifyMethod2LookupShaHmac
} from '../brc69/method2/index'
import {
  buildLogLookupBusAir,
  buildLogLookupBusTrace,
  evaluateAirTrace,
  LOG_LOOKUP_ROW_KIND,
  proveLogLookupBus,
  verifyLogLookupBusProof
} from '../brc69/stark/index'
import {
  hmacSha256,
  scalarMultiply
} from '../brc69/circuit/index'

describe('BRC-69 lookup-centric SHA/HMAC shape', () => {
  it('builds deterministic nibble lookup tables for SHA boolean helpers', () => {
    const table = buildMethod2LookupShaHmacTable()

    expect(table).toHaveLength(512)
    expect(method2LookupShaHmacTableDigest(table)).toHaveLength(32)
    expect(new Set(table.map(row =>
      `${row.tag}:${row.values.slice(0, 3).join(',')}`
    )).size).toBe(table.length)
  })

  it('builds a verifier-safe lookup request shape without exposing key material', () => {
    const key = Array.from({ length: 33 }, (_, index) => index)
    const invoice = [1, 2, 3, 4, 5]
    const linkage = hmacSha256(key, invoice)
    const trace = buildMethod2LookupShaHmacTrace(key, invoice, linkage)
    const metrics = method2LookupShaHmacMetrics(trace)
    const publicInput = trace.publicInput as unknown as Record<string, unknown>

    expect(metrics.totalBlocks).toBe(4)
    expect(metrics.lookupRequests).toBe(4 * 64 * 128)
    expect(metrics.tableRows).toBe(512)
    expect(metrics.lookupTraceWidth).toBeGreaterThan(0)
    expect(method2LookupShaHmacPublicInputDigest(trace.publicInput))
      .toHaveLength(32)
    expect(publicInput).not.toHaveProperty('key')
    expect(publicInput).not.toHaveProperty('innerDigest')
    expect(publicInput).not.toHaveProperty('scheduleRows')
  })

  it('rejects an incorrect linkage witness', () => {
    const key = Array.from({ length: 33 }, (_, index) => index)
    const invoice = [9, 8, 7]
    const linkage = hmacSha256(key, invoice)
    linkage[0] ^= 1

    expect(() => buildMethod2LookupShaHmacTrace(key, invoice, linkage))
      .toThrow('Lookup HMAC-SHA256 linkage does not match key and invoice')
  })

  it('proves private lookup multiplicities without putting them in the public schedule', () => {
    const trace = buildLogLookupBusTrace([{
      kind: LOG_LOOKUP_ROW_KIND.supply,
      tag: 77n,
      values: [1n, 2n, 3n, 0n],
      publicValues: [1n, 2n, 3n, 0n],
      multiplicity: 2n
    }, {
      kind: LOG_LOOKUP_ROW_KIND.request,
      tag: 77n,
      values: [1n, 2n, 3n, 0n],
      multiplicity: 1n
    }, {
      kind: LOG_LOOKUP_ROW_KIND.request,
      tag: 77n,
      values: [1n, 2n, 3n, 0n],
      multiplicity: 1n
    }], { expectedRequests: 2 })
    const proof = proveLogLookupBus(trace, {
      blowupFactor: 4,
      numQueries: 4,
      maxRemainderSize: 4,
      maskDegree: 1,
      cosetOffset: 7n,
      maskSeed: Array.from(Buffer.from('brc69-test-log-lookup-bus'))
    })

    expect(trace.publicInput.scheduleRows[0].publicTuple)
      .toEqual([1n, 2n, 3n, 0n])
    expect(trace.publicInput.scheduleRows[0])
      .not.toHaveProperty('multiplicity')
    expect(verifyLogLookupBusProof(trace.publicInput, proof)).toBe(true)
  })

  it('rejects an invalid private lookup multiplicity', () => {
    const trace = buildLogLookupBusTrace([{
      kind: LOG_LOOKUP_ROW_KIND.supply,
      tag: 77n,
      values: [1n, 2n, 3n, 0n],
      publicValues: [1n, 2n, 3n, 0n],
      multiplicity: 1n
    }, {
      kind: LOG_LOOKUP_ROW_KIND.request,
      tag: 77n,
      values: [1n, 2n, 3n, 0n],
      multiplicity: 1n
    }, {
      kind: LOG_LOOKUP_ROW_KIND.request,
      tag: 77n,
      values: [1n, 2n, 3n, 0n],
      multiplicity: 1n
    }], { expectedRequests: 2 })
    const air = buildLogLookupBusAir(trace.publicInput)

    expect(evaluateAirTrace(air, trace.rows).valid).toBe(false)
  })

  it('fails closed for malformed standalone lookup-HMAC proofs', () => {
    const key = Array.from({ length: 33 }, (_, index) => index)
    const invoice = [1]
    const trace = buildMethod2LookupShaHmacTrace(
      key,
      invoice,
      hmacSha256(key, invoice)
    )
    const emptyProof: never = JSON.parse('{}')

    expect(verifyMethod2LookupShaHmac(trace.publicInput, emptyProof))
      .toBe(false)
  })

  it('batches same-domain SHA helper lookups without serializing every request row', () => {
    const key = Array.from({ length: 33 }, (_, index) => index)
    const invoice = [1]
    const batched = buildMethod2LookupBatchedHmacSha256Trace(
      key,
      invoice,
      hmacSha256(key, invoice)
    )
    const air = buildMethod2LookupBatchedHmacSha256Air(batched.publicInput)

    expect(batched.publicInput.expectedLookupRequests).toBe(4 * 64 * 128)
    expect(batched.rows.length)
      .toBeLessThan(batched.publicInput.expectedLookupRequests)
    expect(batched.publicInput.lookupTableRows).toBe(512)
    expect(evaluateAirTrace(air, batched.rows).valid).toBe(true)
  })

  it('rejects a batched lookup inverse that does not match committed HMAC helpers', () => {
    const key = Array.from({ length: 33 }, (_, index) => index)
    const invoice = [1]
    const trace = buildMethod2LookupBatchedHmacSha256Trace(
      key,
      invoice,
      hmacSha256(key, invoice)
    )
    const air = buildMethod2LookupBatchedHmacSha256Air(trace.publicInput)
    const tampered = trace.rows.map(row => row.slice())
    tampered[0][
      METHOD2_LOOKUP_BATCHED_HMAC_SHA256_LAYOUT.requestInverse0
    ] ^= 1n

    expect(evaluateAirTrace(air, tampered).valid).toBe(false)
  })

  it('proves compact HMAC and rejects mutated key, invoice, linkage, and digest rows', () => {
    const key = Array.from({ length: 33 }, (_, index) => index)
    const invoice = [1, 2, 3, 4, 5]
    const linkage = hmacSha256(key, invoice)
    const trace = buildMethod2CompactHmacSha256Trace(key, invoice, linkage)
    const air = buildMethod2CompactHmacSha256Air(trace.publicInput)

    expect(evaluateAirTrace(air, trace.rows).valid).toBe(true)

    const mutatedKey = key.slice()
    mutatedKey[0] ^= 1
    expect(() => buildMethod2CompactHmacSha256Trace(
      mutatedKey,
      invoice,
      linkage
    )).toThrow('Compact HMAC-SHA256 linkage does not match key and invoice')

    const mutatedInvoice = invoice.slice()
    mutatedInvoice[0] ^= 1
    expect(() => buildMethod2CompactHmacSha256Trace(
      key,
      mutatedInvoice,
      linkage
    )).toThrow('Compact HMAC-SHA256 linkage does not match key and invoice')

    const mutatedLinkage = linkage.slice()
    mutatedLinkage[0] ^= 1
    expect(() => buildMethod2CompactHmacSha256Trace(
      key,
      invoice,
      mutatedLinkage
    )).toThrow('Compact HMAC-SHA256 linkage does not match key and invoice')

    const keyTamperedRows = trace.rows.map(row => row.slice())
    keyTamperedRows[0][METHOD2_COMPACT_HMAC_SHA256_LAYOUT.keyBytes] ^= 1n
    expect(evaluateAirTrace(air, keyTamperedRows).valid).toBe(false)

    const digestTamperedRows = trace.rows.map(row => row.slice())
    digestTamperedRows[
      trace.publicInput.activeRows - 1
    ][METHOD2_COMPACT_HMAC_SHA256_LAYOUT.state] ^= 1n
    expect(evaluateAirTrace(air, digestTamperedRows).valid).toBe(false)
  })

  it('keeps lookup HMAC standalone while proofType 1 uses compact HMAC', () => {
    const status = method2LookupShaHmacIntegrationStatus()
    const statement = buildBRC69Method2WholeStatement({
      scalar: 7n,
      baseB: scalarMultiply(3n),
      invoice: [1, 2, 3]
    })

    expect(status.readyForMethod2).toBe(true)
    expect(status.sameCommittedArithmeticDomain).toBe(true)
    expect((statement.publicInput.hmac as { relation?: string }).relation)
      .toBeUndefined()
  })
})
