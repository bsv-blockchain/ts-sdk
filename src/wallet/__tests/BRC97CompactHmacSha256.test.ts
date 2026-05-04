import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  METHOD2_COMPACT_HMAC_SHA256_STARK_OPTIONS,
  buildMethod2CompactHmacSha256Air,
  buildMethod2CompactHmacSha256Trace,
  evaluateAirTrace,
  hmacSha256,
  method2CompactHmacSha256KeyForLink,
  method2CompactHmacSha256Metrics,
  method2CompactHmacSha256PublicInput,
  proveMethod2CompactHmacSha256,
  verifyMethod2CompactHmacSha256
} from '../brc97/index'

describe('BRC-97 compact private HMAC-SHA256 proof target', () => {
  it('proves HMAC over a private compressed-S key with compact round rows', () => {
    const key = compressedSLikeKey()
    const invoice = ascii('invoice')
    const linkage = hmacSha256(key, invoice)
    const trace = buildMethod2CompactHmacSha256Trace(key, invoice, linkage)
    const air = buildMethod2CompactHmacSha256Air(trace.publicInput)

    expect(evaluateAirTrace(air, trace.rows).valid).toBe(true)
    expect(method2CompactHmacSha256KeyForLink(trace)).toEqual(key)

    const proof = proveMethod2CompactHmacSha256(trace, {
      maskSeed: ascii('compact-private-hmac-sha256-mask')
    })
    const metrics = method2CompactHmacSha256Metrics(trace, proof)

    expect(verifyMethod2CompactHmacSha256(trace.publicInput, proof)).toBe(true)
    expect(metrics).toMatchObject({
      invoiceLength: invoice.length,
      innerBlocks: 2,
      outerBlocks: 2,
      totalBlocks: 4,
      activeRows: 260,
      paddedRows: 512,
      traceWidth: 551,
      committedCells: 282112
    })
    expect(metrics.proofBytes).toBeGreaterThan(0)

    const badInvoice = method2CompactHmacSha256PublicInput(
      invoice.map((byte, index) => index === 0 ? byte ^ 1 : byte),
      linkage
    )
    expect(verifyMethod2CompactHmacSha256(badInvoice, proof)).toBe(false)

    const badLinkage = method2CompactHmacSha256PublicInput(
      invoice,
      linkage.map((byte, index) => index === 0 ? byte ^ 1 : byte)
    )
    expect(verifyMethod2CompactHmacSha256(badLinkage, proof)).toBe(false)
  })

  it('rejects weak STARK parameters at verification time', () => {
    const key = compressedSLikeKey()
    const invoice = ascii('invoice')
    const linkage = hmacSha256(key, invoice)
    const trace = buildMethod2CompactHmacSha256Trace(key, invoice, linkage)
    const weakProof = proveMethod2CompactHmacSha256(trace, {
      ...METHOD2_COMPACT_HMAC_SHA256_STARK_OPTIONS,
      numQueries: 2,
      maskSeed: ascii('compact-private-hmac-sha256-weak-mask')
    })

    expect(verifyMethod2CompactHmacSha256(trace.publicInput, weakProof))
      .toBe(false)
  })

  it('rejects wrong private keys and tampered private witnesses', () => {
    const key = compressedSLikeKey()
    const invoice = ascii('invoice')
    const linkage = hmacSha256(key, invoice)
    const badKey = key.map((byte, index) => index === 1 ? byte ^ 1 : byte)

    expect(() => buildMethod2CompactHmacSha256Trace(
      badKey,
      invoice,
      linkage
    )).toThrow()

    const trace = buildMethod2CompactHmacSha256Trace(key, invoice, linkage)
    const air = buildMethod2CompactHmacSha256Air(trace.publicInput)
    const badKeyRows = trace.rows.map(row => row.slice())
    badKeyRows[0][trace.layout.keyBytes] =
      badKeyRows[0][trace.layout.keyBytes] === 0n ? 1n : 0n
    expect(evaluateAirTrace(air, badKeyRows).valid).toBe(false)

    const badScheduleRows = trace.rows.map(row => row.slice())
    badScheduleRows[65][trace.layout.schedule] += 1n
    expect(evaluateAirTrace(air, badScheduleRows).valid).toBe(false)
  })

  it('keeps padding edge cases valid in the compact AIR', () => {
    const key = compressedSLikeKey()
    for (const length of [0, 55, 56, 119]) {
      const invoice = new Array<number>(length).fill(0).map((_, index) =>
        index & 0xff
      )
      const trace = buildMethod2CompactHmacSha256Trace(
        key,
        invoice,
        hmacSha256(key, invoice)
      )
      expect(evaluateAirTrace(
        buildMethod2CompactHmacSha256Air(trace.publicInput),
        trace.rows
      ).valid).toBe(true)
    }
  })

  it('validates the max-invoice production HMAC shape', () => {
    const key = compressedSLikeKey()
    const invoice = new Array<number>(1233).fill(0).map((_, index) =>
      (index * 19 + 11) & 0xff
    )
    const trace = buildMethod2CompactHmacSha256Trace(
      key,
      invoice,
      hmacSha256(key, invoice)
    )

    expect(trace.publicInput).toMatchObject({
      innerBlocks: 21,
      outerBlocks: 2,
      totalBlocks: 23,
      activeRows: 1495,
      traceLength: 2048
    })
    expect(trace.layout.width).toBe(551)
    expect(evaluateAirTrace(
      buildMethod2CompactHmacSha256Air(trace.publicInput),
      trace.rows
    ).valid).toBe(true)
  })
})

function compressedSLikeKey (): number[] {
  return Array.from({ length: 33 }, (_, index) =>
    index === 0 ? 2 : (index * 17 + 3) & 0xff
  )
}

function ascii (value: string): number[] {
  return Array.from(value).map(char => char.charCodeAt(0))
}
