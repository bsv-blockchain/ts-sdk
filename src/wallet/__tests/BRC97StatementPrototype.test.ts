import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  buildBRC97StatementPrototype,
  brc97StatementMetrics,
  hmacSha256,
  method2CompactHmacSha256KeyForLink,
  proveBRC97StatementPrototype,
  proveLookupBus,
  scalarMultiply,
  validateBRC97StatementPrototype,
  verifyBRC97StatementPrototype,
  verifyLookupBusProof
} from '../brc97/index'

describe('BRC-97 whole-statement prototype wiring', () => {
  it('wires compressed S into the private HMAC key through the equality bus', () => {
    const invoice = ascii('invoice')
    const statement = buildBRC97StatementPrototype(
      0x1f8n,
      scalarMultiply(7n),
      invoice,
      undefined,
      {
        windowBits: 4,
        windowCount: 4,
        minTraceLength: 128,
        encodingMinTraceLength: 128,
        keyLinkMinTraceLength: 64
      }
    )

    expect(() => validateBRC97StatementPrototype(statement)).not.toThrow()
    expect(method2CompactHmacSha256KeyForLink(statement.hmac))
      .toEqual(statement.compressedS.witness.bytes)
    expect(statement.linkage)
      .toEqual(hmacSha256(statement.compressedS.witness.bytes, invoice))
    expect(brc97StatementMetrics(statement).hmac.traceWidth).toBeLessThan(1000)

    const keyLinkProof = proveLookupBus(statement.keyLink, {
      maskSeed: ascii('brc97-statement-key-link-mask')
    })
    expect(verifyLookupBusProof(
      statement.keyLink.publicInput,
      keyLinkProof
    )).toBe(true)
    expect(brc97StatementMetrics(statement).keyLink).toMatchObject({
      activeRows: 33,
      paddedRows: 64,
      equalityRows: 33,
      lookupRequests: 0
    })
  })

  it('rejects attempts to HMAC a key different from compressed S', () => {
    const statement = buildBRC97StatementPrototype(
      0x1f8n,
      scalarMultiply(7n),
      ascii('invoice'),
      undefined,
      {
        windowBits: 4,
        windowCount: 4,
        minTraceLength: 128,
        encodingMinTraceLength: 128,
        keyLinkMinTraceLength: 64
      }
    )
    const bad = {
      ...statement,
      hmac: {
        ...statement.hmac,
        key: statement.hmac.key.map((byte, index) =>
          index === 0 ? byte ^ 1 : byte
        )
      }
    }

    expect(() => validateBRC97StatementPrototype(bad)).toThrow()
  })

  it('proves and verifies the compact whole-statement bundle', () => {
    const statement = buildBRC97StatementPrototype(
      0x1f8n,
      scalarMultiply(7n),
      ascii('invoice'),
      undefined,
      {
        windowBits: 4,
        windowCount: 4,
        minTraceLength: 128,
        encodingMinTraceLength: 128,
        keyLinkMinTraceLength: 64
      }
    )
    const proof = proveBRC97StatementPrototype(statement, {
      maskSeed: ascii('brc97-whole-statement-mask')
    })
    const metrics = brc97StatementMetrics(statement, proof)

    expect(verifyBRC97StatementPrototype(statement, proof)).toBe(true)
    expect(metrics.hmac).toMatchObject({
      traceWidth: 551,
      committedCells: 282112
    })
    expect(metrics.totalProofBytes).toBeGreaterThan(0)
  })
})

function ascii (value: string): number[] {
  return Array.from(value).map(char => char.charCodeAt(0))
}
