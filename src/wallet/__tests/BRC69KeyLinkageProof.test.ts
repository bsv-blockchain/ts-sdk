import {
  describe,
  expect,
  it
} from '@jest/globals'
import {
  BRC69_METHOD2_MAX_PROOF_BYTES,
  BRC69_METHOD2_MAX_PUBLIC_INPUT_BYTES,
  BRC69_METHOD2_PROOF_PAYLOAD_MAGIC,
  BRC69_METHOD2_PROOF_PAYLOAD_VERSION,
  normalizeSpecificKeyLinkageCounterparty,
  parseSpecificKeyLinkageProofPayload,
  serializeBRC69Method2WholeStatementPublicInput,
  serializeBRC69SpecificKeyLinkageProof,
  serializeSpecificKeyLinkageProofPayload,
  verifySpecificKeyLinkageProof
} from '../brc69/index'
import {
  BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS,
  brc69Method2WholeStatementDeterministicFixture
} from '../brc69/method2/index'
import {
  MultiTraceStarkProof,
  StarkProof
} from '../brc69/stark/index'
import { SECP256K1_G, compressPoint } from '../brc69/circuit/index'

describe('BRC-69 key linkage proof payload', () => {
  it('serializes and parses the whole-statement payload envelope', () => {
    const fixture = brc69Method2WholeStatementDeterministicFixture()
    const proof = {
      publicInput: fixture.publicInput,
      proof: dummyWholeStatementProof()
    }

    const payload = serializeSpecificKeyLinkageProofPayload(proof)
    const parsed = parseSpecificKeyLinkageProofPayload(payload)

    expect(parsed.proofType).toBe(1)
    if (parsed.proofType !== 1) throw new Error('unexpected proof type')
    expect(parsed.proof.proof.segments.map(segment => segment.name))
      .toEqual(['whole'])
    expect(parsed.proof.proof.crossProofs).toEqual([])
  })

  it('keeps proof type 0 isolated', () => {
    expect(parseSpecificKeyLinkageProofPayload([0])).toEqual({ proofType: 0 })
    expect(() => parseSpecificKeyLinkageProofPayload([0, 1]))
      .toThrow('Proof type 0 payload must not contain proof bytes')
  })

  it('rejects malformed and trailing proof payload bytes', () => {
    const fixture = brc69Method2WholeStatementDeterministicFixture()
    const payload = serializeSpecificKeyLinkageProofPayload({
      publicInput: fixture.publicInput,
      proof: dummyWholeStatementProof()
    })
    expect(() => parseSpecificKeyLinkageProofPayload([1]))
      .toThrow()
    expect(() => parseSpecificKeyLinkageProofPayload(payload.slice(0, -1)))
      .toThrow()
    expect(() => parseSpecificKeyLinkageProofPayload([...payload, 0]))
      .toThrow('Unexpected trailing bytes in BRC69 proof payload')
  })

  it('rejects oversized declared public input and proof sections', () => {
    expect(() => parseSpecificKeyLinkageProofPayload([
      1,
      ...proofPayloadPrefix(),
      ...encodeVarInt(BRC69_METHOD2_MAX_PUBLIC_INPUT_BYTES + 1)
    ])).toThrow('BRC69 Method 2 public input is too large')

    const fixture = brc69Method2WholeStatementDeterministicFixture()
    const publicInput = publicInputBytes(fixture.publicInput)
    expect(() => parseSpecificKeyLinkageProofPayload([
      1,
      ...proofPayloadPrefix(),
      ...encodeVarInt(publicInput.length),
      ...publicInput,
      ...encodeVarInt(BRC69_METHOD2_MAX_PROOF_BYTES + 1)
    ])).toThrow('BRC69 Method 2 STARK proof is too large')
  })

  it('rejects non-versioned or unknown-version proof envelopes', () => {
    const fixture = brc69Method2WholeStatementDeterministicFixture()
    const payload = serializeSpecificKeyLinkageProofPayload({
      publicInput: fixture.publicInput,
      proof: dummyWholeStatementProof()
    })
    const versionOffset = 1 + ascii(BRC69_METHOD2_PROOF_PAYLOAD_MAGIC).length
    const wrongVersion = payload.slice()
    wrongVersion[versionOffset] = BRC69_METHOD2_PROOF_PAYLOAD_VERSION + 1

    expect(() => parseSpecificKeyLinkageProofPayload(wrongVersion))
      .toThrow('Unsupported BRC69 key linkage proof payload version')
    const wrongMagic = ascii(BRC69_METHOD2_PROOF_PAYLOAD_MAGIC)
    wrongMagic[0] ^= 1
    expect(() => parseSpecificKeyLinkageProofPayload([
      1,
      ...wrongMagic,
      BRC69_METHOD2_PROOF_PAYLOAD_VERSION
    ])).toThrow('Invalid BRC69_KEY_LINKAGE_PROOF_PAYLOAD magic')
  })

  it('rejects HMAC public-input mismatches before serialization', () => {
    const fixture = brc69Method2WholeStatementDeterministicFixture()
    const publicInput = {
      ...fixture.publicInput,
      hmac: {
        ...fixture.publicInput.hmac,
        linkage: fixture.publicInput.hmac.linkage.map((byte, index) =>
          index === 0 ? byte ^ 1 : byte
        )
      }
    }

    expect(() => serializeBRC69SpecificKeyLinkageProof({
      publicInput,
      proof: dummyWholeStatementProof()
    })).toThrow('BRC69 Method 2 multi-trace linkage mismatch')
  })

  it('rejects statement/public-input mismatches', () => {
    const fixture = brc69Method2WholeStatementDeterministicFixture()
    const statement = {
      prover: compressPoint(fixture.publicInput.publicA)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join(''),
      counterparty: compressPoint(fixture.publicInput.baseB)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join(''),
      protocolID: [0, 'tests'] as [0, string],
      keyID: 'test key',
      linkage: fixture.publicInput.linkage
    }

    expect(verifySpecificKeyLinkageProof(statement, {
      publicInput: fixture.publicInput,
      proof: dummyWholeStatementProof()
    })).toBe(false)
  })

  it('requires explicit counterparties for proof type 1 sentinel policy', () => {
    const fixture = brc69Method2WholeStatementDeterministicFixture()
    const prover = bytesToHex(compressPoint(fixture.publicInput.publicA))

    expect(() => normalizeSpecificKeyLinkageCounterparty('self', prover))
      .toThrow('sentinel counterparties require proofType 0')
    expect(() => normalizeSpecificKeyLinkageCounterparty('anyone', prover))
      .toThrow('sentinel counterparties require proofType 0')
    expect(normalizeSpecificKeyLinkageCounterparty('self', prover, {
      allowSentinelCounterparty: true
    })).toBe(prover)
    expect(normalizeSpecificKeyLinkageCounterparty('anyone', prover, {
      allowSentinelCounterparty: true
    })).toBe(bytesToHex(compressPoint(SECP256K1_G)))
  })
})

function bytesToHex (bytes: number[]): string {
  return bytes.map(byte => byte.toString(16).padStart(2, '0')).join('')
}

function dummyWholeStatementProof (): MultiTraceStarkProof {
  return {
    transcriptDomain: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.transcriptDomain,
    contextDigest: new Array(32).fill(0),
    segments: [{
      name: 'whole',
      proof: dummyStarkProof()
    }],
    crossProofs: [],
    constantColumnProofs: []
  }
}

function dummyStarkProof (): StarkProof {
  const traceLength = 64
  const blowupFactor = BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.blowupFactor
  const ldeSize = traceLength * blowupFactor
  return {
    traceLength,
    traceWidth: 1,
    blowupFactor,
    numQueries: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.numQueries,
    maxRemainderSize:
      BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maxRemainderSize,
    maskDegree: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maskDegree,
    traceDegreeBound: traceLength +
      BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maskDegree,
    compositionDegreeBound: traceLength + 16,
    cosetOffset: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.cosetOffset,
    publicInputDigest: new Array(32).fill(0),
    traceRoot: new Array(32).fill(0),
    traceCombinationRoot: new Array(32).fill(0),
    compositionRoot: new Array(32).fill(0),
    traceLowDegreeOpenings: [],
    traceOpenings: [],
    nextTraceOpenings: [],
    compositionOpenings: [],
    traceFriProof: dummyFriProof(ldeSize, traceLength + 2),
    friProof: dummyFriProof(ldeSize, traceLength + 16)
  }
}

function dummyFriProof (domainSize: number, degreeBound: number): StarkProof['friProof'] {
  return {
    domainSize,
    degreeBound,
    numQueries: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.numQueries,
    maxRemainderSize:
      BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.maxRemainderSize,
    domainOffset: BRC69_METHOD2_WHOLE_STATEMENT_STARK_OPTIONS.cosetOffset,
    roots: [new Array(32).fill(0)],
    finalValues: [0n],
    queries: []
  }
}

function publicInputBytes (publicInput: unknown): number[] {
  return serializeBRC69Method2WholeStatementPublicInput(
    publicInput as Parameters<typeof serializeBRC69Method2WholeStatementPublicInput>[0]
  )
}

function proofPayloadPrefix (): number[] {
  return [
    ...ascii(BRC69_METHOD2_PROOF_PAYLOAD_MAGIC),
    BRC69_METHOD2_PROOF_PAYLOAD_VERSION
  ]
}

function ascii (value: string): number[] {
  return Array.from(value).map(char => char.charCodeAt(0))
}

function encodeVarInt (value: number): number[] {
  if (value < 0xfd) return [value]
  if (value <= 0xffff) return [0xfd, value & 0xff, value >> 8]
  if (value <= 0xffffffff) {
    return [
      0xfe,
      value & 0xff,
      (value >>> 8) & 0xff,
      (value >>> 16) & 0xff,
      (value >>> 24) & 0xff
    ]
  }
  throw new Error('test varint value is too large')
}
