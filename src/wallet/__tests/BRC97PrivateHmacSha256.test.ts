import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  buildDualBaseEcIntegratedTrace,
  buildDualBaseLookupPrototype,
  buildMethod2PrivateHmacSha256Air,
  buildMethod2PrivateHmacSha256Trace,
  evaluateAirTrace,
  hmacSha256,
  method2PrivateHmacSha256KeyForLink,
  method2PrivateHmacSha256Metrics,
  method2PrivateHmacSha256PublicInput,
  proveMethod2PrivateHmacSha256,
  scalarMultiply,
  verifyMethod2PrivateHmacSha256
} from '../brc97/index'

describe('BRC-97 private HMAC-SHA256 proof target', () => {
  it('proves HMAC over a private compressed-S key and public invoice/linkage', () => {
    const key = compressedS()
    const invoice = ascii('invoice')
    const linkage = hmacSha256(key, invoice)
    const trace = buildMethod2PrivateHmacSha256Trace(key, invoice, linkage)
    const air = buildMethod2PrivateHmacSha256Air(trace.publicInput)

    expect(evaluateAirTrace(air, trace.rows).valid).toBe(true)
    expect(method2PrivateHmacSha256KeyForLink(trace)).toEqual(key)

    const proof = proveMethod2PrivateHmacSha256(trace, {
      maskSeed: ascii('private-hmac-sha256-mask')
    })
    const metrics = method2PrivateHmacSha256Metrics(trace, proof)

    expect(verifyMethod2PrivateHmacSha256(trace.publicInput, proof)).toBe(true)
    expect(metrics).toMatchObject({
      invoiceLength: invoice.length,
      innerBlocks: 2,
      outerBlocks: 2,
      totalBlocks: 4,
      activeRows: 260,
      paddedRows: 512,
      privateKeyBits: 264,
      privateInnerDigestBits: 256
    })
    expect(metrics.traceWidth).toBeGreaterThan(1600)
    expect(metrics.proofBytes).toBeGreaterThan(0)

    const badInvoice = method2PrivateHmacSha256PublicInput(
      invoice.map((byte, index) => index === 0 ? byte ^ 1 : byte),
      linkage
    )
    expect(verifyMethod2PrivateHmacSha256(badInvoice, proof)).toBe(false)

    const badLinkage = method2PrivateHmacSha256PublicInput(
      invoice,
      linkage.map((byte, index) => index === 0 ? byte ^ 1 : byte)
    )
    expect(verifyMethod2PrivateHmacSha256(badLinkage, proof)).toBe(false)
  })

  it('rejects wrong private keys, tampered private schedule bits, and padding edges', () => {
    const key = compressedS()
    const invoice = ascii('invoice')
    const linkage = hmacSha256(key, invoice)
    const badKey = key.map((byte, index) => index === 1 ? byte ^ 1 : byte)

    expect(() => buildMethod2PrivateHmacSha256Trace(
      badKey,
      invoice,
      linkage
    )).toThrow()

    const trace = buildMethod2PrivateHmacSha256Trace(key, invoice, linkage)
    const badRows = trace.rows.map(row => row.slice())
    badRows[0][trace.layout.keyBits] =
      badRows[0][trace.layout.keyBits] === 0n ? 1n : 0n
    expect(evaluateAirTrace(
      buildMethod2PrivateHmacSha256Air(trace.publicInput),
      badRows
    ).valid).toBe(false)

    for (const length of [0, 55, 56, 119]) {
      const edgeInvoice = new Array<number>(length).fill(0).map((_, index) =>
        index & 0xff
      )
      const edgeTrace = buildMethod2PrivateHmacSha256Trace(
        key,
        edgeInvoice,
        hmacSha256(key, edgeInvoice)
      )
      expect(evaluateAirTrace(
        buildMethod2PrivateHmacSha256Air(edgeTrace.publicInput),
        edgeTrace.rows
      ).valid).toBe(true)
    }
  })
})

function compressedS (): number[] {
  const scalar = 0x1f8n
  const baseB = scalarMultiply(7n)
  const lookup = buildDualBaseLookupPrototype(
    scalar,
    baseB,
    { windowBits: 4, windowCount: 4, minTraceLength: 128 }
  )
  return buildDualBaseEcIntegratedTrace(lookup).compressedS.bytes
}

function ascii (value: string): number[] {
  return Array.from(value).map(char => char.charCodeAt(0))
}
